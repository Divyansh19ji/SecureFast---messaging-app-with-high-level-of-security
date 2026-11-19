"""
Chunking, Authenticated Encryption & Reliable Reassembly Engine.

Guarantees every requirement from SecureFast Section 3.7 & Table 6.1:
  - Ciphertext strictly <= 2048 bytes (2 KB) per chunk
  - Fresh 96-bit (12-byte) random IV per chunk
  - FIPS 180-4 SHA-256 integrity checksum verified in constant time (C11) before acceptance
  - Out-of-order arrival sorting by chunk_index
  - Duplicate chunk deduplication
  - Missing chunk gap detection for resend requests
  - Role-Based Decryption enforcement on reassembly
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from typing import Literal

from securefast.crypto_engine import (
    DecryptionFailedError,
    RoleAccessDeniedError,
    SessionKeyring,
    build_chunk_aad,
)
from securefast.models import EncryptedChunkPayload, Role
from securefast.native_bridge import chunk_count, sha256_hex, verify_sha256

GCM_TAG_BYTES = 16
MAX_CIPHERTEXT_BYTES = 2048


class ChunkTamperedError(ValueError):
    """Raised when a chunk fails SHA-256 checksum verification."""


def encrypt_and_chunk_bundle(
    bundle_bytes: bytes,
    path_id: str,
    message_id: str,
    keyring: SessionKeyring,
    required_role: Role,
    self_destruct_sec: int = 0,
    kind: Literal["chat", "vault"] = "chat",
    max_ciphertext_bytes: int = MAX_CIPHERTEXT_BYTES,
) -> list[EncryptedChunkPayload]:
    """
    Slice `bundle_bytes` so every AES-256-GCM ciphertext chunk is strictly <= 2 KB,
    encrypt each chunk with a fresh 96-bit IV, and attach a C11 SHA-256 checksum.
    """
    max_ct = min(MAX_CIPHERTEXT_BYTES, max(64, max_ciphertext_bytes))
    max_pt = max_ct - GCM_TAG_BYTES
    total = chunk_count(len(bundle_bytes), max_pt)

    chunks: list[EncryptedChunkPayload] = []
    for idx in range(total):
        start = idx * max_pt
        pt_slice = bundle_bytes[start : start + max_pt]
        aad = build_chunk_aad(path_id, message_id, idx, total, required_role)
        iv, ciphertext = keyring.encrypt_chunk(pt_slice, required_role, aad)
        assert len(ciphertext) <= max_ct, f"Chunk ciphertext exceeded {max_ct} bytes"

        checksum = sha256_hex(iv + ciphertext)
        chunks.append(
            EncryptedChunkPayload(
                message_id=message_id,
                path_id=path_id,
                chunk_index=idx,
                total_chunks=total,
                iv_b64=base64.b64encode(iv).decode("ascii"),
                ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
                checksum_hex=checksum,
                required_role=required_role,
                self_destruct_sec=self_destruct_sec,
                kind=kind,
            )
        )
    return chunks


def verify_chunk_checksum(chunk: EncryptedChunkPayload) -> tuple[bytes, bytes]:
    """Decode IV & ciphertext and verify the C11 SHA-256 checksum in constant time."""
    try:
        iv = base64.b64decode(chunk.iv_b64, validate=True)
        ciphertext = base64.b64decode(chunk.ciphertext_b64, validate=True)
    except Exception as exc:
        raise ChunkTamperedError(f"Invalid Base64 in chunk {chunk.chunk_index}") from exc

    if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise ChunkTamperedError(
            f"Chunk {chunk.chunk_index} exceeds 2 KB limit ({len(ciphertext)} bytes)"
        )

    if not verify_sha256(iv + ciphertext, chunk.checksum_hex):
        raise ChunkTamperedError(
            f"SHA-256 integrity check failed on chunk {chunk.chunk_index} of {chunk.message_id}"
        )
    return iv, ciphertext


@dataclass
class ChunkReassemblyBuffer:
    """
    Out-of-order chunk reassembler for a single logical message.
    Verifies SHA-256 on arrival, drops duplicates, tracks gaps, and decrypts in index order.
    """

    message_id: str
    path_id: str
    total_chunks: int
    required_role: Role
    self_destruct_sec: int = 0
    kind: Literal["chat", "vault"] = "chat"
    created_at: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)
    _chunks: dict[int, tuple[bytes, bytes, EncryptedChunkPayload]] = field(default_factory=dict)

    def add_chunk(self, chunk: EncryptedChunkPayload) -> bool:
        """
        Verify SHA-256 and store chunk.
        Returns True if newly stored, False if duplicate.
        Raises ChunkTamperedError on checksum failure or mismatched metadata.
        """
        if chunk.message_id != self.message_id or chunk.path_id != self.path_id:
            raise ChunkTamperedError("Chunk message_id/path_id mismatch")
        if chunk.total_chunks != self.total_chunks:
            raise ChunkTamperedError("Chunk total_chunks mismatch")
        if chunk.chunk_index < 0 or chunk.chunk_index >= self.total_chunks:
            raise ChunkTamperedError("Chunk index out of range")

        iv, ciphertext = verify_chunk_checksum(chunk)
        self.last_activity = time.monotonic()

        if chunk.chunk_index in self._chunks:
            return False  # Duplicate safely dropped

        self._chunks[chunk.chunk_index] = (iv, ciphertext, chunk)
        return True

    @property
    def received_count(self) -> int:
        return len(self._chunks)

    @property
    def is_complete(self) -> bool:
        return len(self._chunks) == self.total_chunks

    def missing_indices(self) -> list[int]:
        return [i for i in range(self.total_chunks) if i not in self._chunks]

    def ordered_raw_chunks(self) -> list[EncryptedChunkPayload]:
        return [self._chunks[i][2] for i in sorted(self._chunks.keys())]

    def decrypt_and_reassemble(self, keyring: SessionKeyring) -> bytes:
        """
        Decrypt all verified chunks in index order [0 .. total_chunks - 1] using
        the role-specific AES-256-GCM key and return the original glyph bundle bytes.
        """
        if not self.is_complete:
            raise ValueError(f"Cannot reassemble incomplete message; missing {self.missing_indices()}")

        if not keyring.can_access(self.required_role):
            raise RoleAccessDeniedError(
                f"Role '{keyring.local_role.value}' does not have decryption access for "
                f"'{self.required_role.value}' content"
            )

        plaintext_parts: list[bytes] = []
        for idx in range(self.total_chunks):
            iv, ciphertext, _ = self._chunks[idx]
            aad = build_chunk_aad(
                self.path_id, self.message_id, idx, self.total_chunks, self.required_role
            )
            try:
                pt = keyring.decrypt_chunk(iv, ciphertext, self.required_role, aad)
            except DecryptionFailedError:
                raise
            plaintext_parts.append(pt)

        return b"".join(plaintext_parts)
