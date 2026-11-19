"""
End-to-End Cryptography & Role-Based Decryption Engine.

Implements the exact cryptographic suite specified in SecureFast Table 3.1 + RBAC:
  - Key Agreement : ECDH over NIST curve P-256 (SECP256R1), SPKI DER public keys
  - Key Derivation: RFC 5869 HKDF-SHA256 (executed in C11 native core) with 16-byte salt
  - RBAC Subkeys  : Separate 256-bit AES-GCM key & 32-byte glyph seed per clearance role
                    (GUEST < MEMBER < ADMIN); devices retain only keys <= their role!
  - Encryption    : AES-256-GCM (128-bit auth tag, fresh 96-bit random IV per chunk,
                    bound with chunk metadata AAD)
  - Verification  : Signal-style 30-digit Safety Number fingerprint
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securefast.models import Role, role_can_decrypt
from securefast.native_bridge import hkdf_sha256, secure_zero, sha256_bytes


class CryptoError(Exception):
    """Base error for cryptographic failures."""


class RoleAccessDeniedError(CryptoError):
    """Raised when the local device's role lacks decryption clearance for a message."""


class DecryptionFailedError(CryptoError):
    """Raised when AES-256-GCM authentication fails (wrong key, wrong IV, or tampering)."""


@dataclass
class DeviceKeyPair:
    """Ephemeral ECDH P-256 key pair — private key never leaves the local device."""

    _private_key: ec.EllipticCurvePrivateKey
    public_key_spki_der: bytes

    @classmethod
    def generate(cls) -> "DeviceKeyPair":
        priv = ec.generate_private_key(ec.SECP256R1())
        pub_der = priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cls(_private_key=priv, public_key_spki_der=pub_der)

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_spki_der).decode("ascii")

    def derive_shared_secret(self, peer_public_key_b64: str) -> bytes:
        try:
            peer_der = base64.b64decode(peer_public_key_b64, validate=True)
            peer_pub = serialization.load_der_public_key(peer_der)
            if not isinstance(peer_pub, ec.EllipticCurvePublicKey):
                raise CryptoError("Peer key is not an Elliptic Curve public key")
            return self._private_key.exchange(ec.ECDH(), peer_pub)
        except CryptoError:
            raise
        except Exception as exc:
            raise CryptoError(f"ECDH key agreement failed: {exc}") from exc


@dataclass
class RoleKeyMaterial:
    """Cryptographically isolated AES-256 key and Anti-OCR Glyph Seed for one RBAC role."""

    role: Role
    aes_key: bytearray     # 32 bytes (256-bit AES-GCM)
    glyph_seed: bytearray  # 32 bytes (HKDF seed for C11 secret glyph alphabet)

    def scrub(self) -> None:
        secure_zero(self.aes_key)
        secure_zero(self.glyph_seed)


@dataclass
class SessionKeyring:
    """
    Holds the derived role keys authorized for this device + the session Safety Number.
    Devices with a lower role (e.g. GUEST) do NOT retain higher-role keys in memory.
    """

    local_role: Role
    safety_number: str
    salt: bytes
    _role_keys: dict[Role, RoleKeyMaterial] = field(default_factory=dict)

    @classmethod
    def establish(
        cls,
        local_keypair: DeviceKeyPair,
        peer_public_key_b64: str,
        salt: bytes,
        local_role: Role,
        allow_sending_higher_roles: bool = False,
    ) -> "SessionKeyring":
        if len(salt) < 16:
            raise CryptoError("HKDF salt must be at least 16 bytes")

        shared = bytearray(local_keypair.derive_shared_secret(peer_public_key_b64))
        try:
            # Compute deterministic 30-digit Signal-style Safety Number from sorted public keys
            peer_der = base64.b64decode(peer_public_key_b64, validate=True)
            safety_number = compute_safety_number(
                local_keypair.public_key_spki_der, peer_der, salt
            )

            role_keys: dict[Role, RoleKeyMaterial] = {}
            for role in (Role.GUEST, Role.MEMBER, Role.ADMIN):
                if allow_sending_higher_roles or role_can_decrypt(local_role, role):
                    aes_key = bytearray(
                        hkdf_sha256(
                            bytes(shared),
                            salt,
                            f"securefast-v2-aes256-{role.value}".encode("ascii"),
                            32,
                        )
                    )
                    glyph_seed = bytearray(
                        hkdf_sha256(
                            bytes(shared),
                            salt,
                            f"securefast-v2-glyph-seed-{role.value}".encode("ascii"),
                            32,
                        )
                    )
                    role_keys[role] = RoleKeyMaterial(
                        role=role, aes_key=aes_key, glyph_seed=glyph_seed
                    )

            return cls(
                local_role=local_role,
                safety_number=safety_number,
                salt=salt,
                _role_keys=role_keys,
            )
        finally:
            # Immediately zero out the raw ECDH shared secret in memory via C11
            secure_zero(shared)

    def can_access(self, required_role: Role) -> bool:
        return role_can_decrypt(self.local_role, required_role) and required_role in self._role_keys

    def get_role_material(self, required_role: Role) -> RoleKeyMaterial:
        if not self.can_access(required_role):
            raise RoleAccessDeniedError(
                f"Role '{self.local_role.value}' cannot decrypt '{required_role.value}' payload"
            )
        return self._role_keys[required_role]

    def encrypt_chunk(
        self,
        plaintext: bytes,
        required_role: Role,
        aad: bytes,
    ) -> tuple[bytes, bytes]:
        """
        Encrypt a chunk with AES-256-GCM using a fresh 96-bit (12-byte) random IV.
        Returns `(iv_12bytes, ciphertext_with_16byte_tag)`.
        """
        mat = self.get_role_material(required_role)
        iv = os.urandom(12)  # Fresh 96-bit nonce — never reused!
        aesgcm = AESGCM(bytes(mat.aes_key))
        ciphertext = aesgcm.encrypt(iv, plaintext, aad)
        return iv, ciphertext

    def decrypt_chunk(
        self,
        iv: bytes,
        ciphertext: bytes,
        required_role: Role,
        aad: bytes,
    ) -> bytes:
        """Verify 128-bit GCM tag and decrypt ciphertext for `required_role`."""
        if len(iv) != 12:
            raise DecryptionFailedError("Invalid IV length (expected 12 bytes / 96 bits)")
        mat = self.get_role_material(required_role)
        aesgcm = AESGCM(bytes(mat.aes_key))
        try:
            return aesgcm.decrypt(iv, ciphertext, aad)
        except InvalidTag as exc:
            raise DecryptionFailedError(
                "AES-256-GCM authentication failed (wrong key, wrong role, or tampered chunk)"
            ) from exc

    def scrub_all(self) -> None:
        """Securely wipe all derived session keys and glyph seeds from memory."""
        for mat in self._role_keys.values():
            mat.scrub()
        self._role_keys.clear()


def compute_safety_number(pub_a_der: bytes, pub_b_der: bytes, salt: bytes) -> str:
    """
    Compute a deterministic, symmetric 30-digit Signal-style Safety Number
    (formatted as 6 groups of 5 digits, e.g. '48210 77394 10583 62947 35106 90472').
    Both peers compute the exact same digits regardless of who initiated the handshake.
    """
    ordered = sorted([pub_a_der, pub_b_der])
    digest = sha256_bytes(b"SF-SAFETY-V2|" + ordered[0] + b"|" + ordered[1] + b"|" + salt)
    # Use 6 x 4-byte unsigned chunks mod 100000 -> 30 uniform decimal digits
    groups: list[str] = []
    for i in range(6):
        chunk_val = int.from_bytes(digest[i * 4 : i * 4 + 4], "big") % 100_000
        groups.append(f"{chunk_val:05d}")
    return " ".join(groups)


def build_chunk_aad(
    path_id: str,
    message_id: str,
    chunk_index: int,
    total_chunks: int,
    required_role: Role,
) -> bytes:
    """Bind chunk position, path, message ID, and RBAC tier into AES-GCM AAD."""
    return f"{path_id}|{message_id}|{chunk_index}/{total_chunks}|{required_role.value}".encode("utf-8")


def generate_salt() -> bytes:
    return os.urandom(16)
