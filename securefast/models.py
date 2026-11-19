"""Strict Pydantic v2 data models matching SecureFast's ER Diagram & Zero-Knowledge Protocol."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, field_validator


class Role(str, Enum):
    """Role-Based Decryption clearance levels (RBAC)."""

    ADMIN = "ADMIN"    # Highest clearance: decrypts ADMIN, MEMBER, and GUEST data
    MEMBER = "MEMBER"  # Standard receiver: decrypts MEMBER and GUEST data
    GUEST = "GUEST"    # Observer role: decrypts only GUEST data; higher tiers remain glyph-locked


ROLE_RANK: dict[Role, int] = {
    Role.GUEST: 1,
    Role.MEMBER: 2,
    Role.ADMIN: 3,
}


def role_can_decrypt(user_role: Role, required_role: Role) -> bool:
    """Return True if `user_role` has clearance for `required_role`."""
    return ROLE_RANK[user_role] >= ROLE_RANK[required_role]


class PathStatus(str, Enum):
    WAITING = "WAITING"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    DESTROYED = "DESTROYED"


class MessageStatus(str, Enum):
    ENCRYPTING = "encrypting"
    SENDING = "sending"
    DELIVERED = "delivered"
    READ = "read"
    BURNED = "burned"
    LOCKED_ROLE = "locked_role"


class EncryptedChunkPayload(BaseModel):
    """
    A single zero-knowledge chunk transmitted over The Path.
    The relay ONLY sees this opaque envelope (max 2048 B decoded ciphertext).
    """

    message_id: str = Field(min_length=4, max_length=64)
    path_id: str = Field(min_length=4, max_length=64)
    chunk_index: int = Field(ge=0, le=100_000)
    total_chunks: int = Field(ge=1, le=100_000)
    iv_b64: str = Field(min_length=12, max_length=32)          # 96-bit random IV (Base64)
    ciphertext_b64: str = Field(min_length=1, max_length=4096) # <= 2048 bytes raw ciphertext
    checksum_hex: str = Field(min_length=64, max_length=64)    # FIPS 180-4 SHA-256 hex
    required_role: Role = Role.MEMBER
    self_destruct_sec: int = Field(default=0, ge=0, le=86400)
    kind: Literal["chat", "vault"] = "chat"

    @field_validator("checksum_hex")
    @classmethod
    def validate_hex(cls, value: str) -> str:
        int(value, 16)
        return value.lower()


class ChunkAckPayload(BaseModel):
    message_id: str = Field(min_length=4, max_length=64)
    chunk_index: int = Field(ge=0, le=100_000)
    status: Literal["RECEIVED", "CHECKSUM_FAILED"] = "RECEIVED"


class ChunkResendRequest(BaseModel):
    message_id: str = Field(min_length=4, max_length=64)
    missing_indices: list[int] = Field(min_length=1, max_length=512)


class HandshakeInitPayload(BaseModel):
    peer_id: str = Field(min_length=4, max_length=64)
    username: str = Field(min_length=1, max_length=40)
    role: Role = Role.ADMIN
    public_key_b64: str = Field(min_length=32, max_length=512)  # ECDH P-256 SPKI DER (Base64)
    salt_b64: str = Field(min_length=16, max_length=64)         # 16-byte random HKDF salt


class HandshakeResponsePayload(BaseModel):
    peer_id: str = Field(min_length=4, max_length=64)
    username: str = Field(min_length=1, max_length=40)
    role: Role = Role.MEMBER
    public_key_b64: str = Field(min_length=32, max_length=512)


class RelayEnvelope(BaseModel):
    """Top-level WebSocket frame validated by the Zero-Knowledge Relay."""

    type: Literal[
        "path:create",
        "path:join",
        "handshake:init",
        "handshake:response",
        "chunk:send",
        "chunk:ack",
        "chunk:resend_req",
        "message:read",
        "peer:typing",
        "path:destroy",
        "ping",
    ]
    path_id: Optional[str] = Field(default=None, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)
