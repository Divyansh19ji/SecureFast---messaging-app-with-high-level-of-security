"""Tests for <= 2 KB Chunking, SHA-256 Tampering Detection, Out-of-Order & Duplicates."""

from __future__ import annotations

import base64
import random

import pytest

from securefast.chunk_engine import (
    MAX_CIPHERTEXT_BYTES,
    ChunkReassemblyBuffer,
    ChunkTamperedError,
    encrypt_and_chunk_bundle,
)
from securefast.crypto_engine import (
    DeviceKeyPair,
    RoleAccessDeniedError,
    SessionKeyring,
    generate_salt,
)
from securefast.models import Role


def _make_keyrings(role_b: Role = Role.ADMIN):
    kp_a = DeviceKeyPair.generate()
    kp_b = DeviceKeyPair.generate()
    salt = generate_salt()
    return (
        SessionKeyring.establish(kp_a, kp_b.public_key_b64, salt, Role.ADMIN),
        SessionKeyring.establish(kp_b, kp_a.public_key_b64, salt, role_b),
    )


def test_every_chunk_strictly_under_or_equal_2kb():
    kr_a, _ = _make_keyrings()
    payload = b"X" * 15_000
    chunks = encrypt_and_chunk_bundle(payload, "SF-TEST", "msg-1", kr_a, Role.MEMBER)
    assert len(chunks) >= 8
    for c in chunks:
        raw_ct = base64.b64decode(c.ciphertext_b64)
        assert len(raw_ct) <= MAX_CIPHERTEXT_BYTES


def test_out_of_order_and_duplicate_chunks_reassemble_cleanly():
    kr_a, kr_b = _make_keyrings()
    payload = bytes(range(256)) * 45  # 11,520 bytes -> 6 chunks
    chunks = encrypt_and_chunk_bundle(payload, "SF-TEST", "msg-ooo", kr_a, Role.MEMBER)

    shuffled = list(chunks)
    random.Random(42).shuffle(shuffled)
    # Add duplicates
    shuffled.insert(2, chunks[0])
    shuffled.append(chunks[-1])

    buf = ChunkReassemblyBuffer("msg-ooo", "SF-TEST", len(chunks), Role.MEMBER)
    new_count = 0
    for c in shuffled:
        if buf.add_chunk(c):
            new_count += 1

    assert new_count == len(chunks)
    assert buf.is_complete is True
    assert buf.missing_indices() == []
    assert buf.decrypt_and_reassemble(kr_b) == payload


def test_missing_chunk_gap_detection_and_recovery():
    kr_a, kr_b = _make_keyrings()
    payload = b"Reliable delivery gap recovery test " * 250
    chunks = encrypt_and_chunk_bundle(payload, "SF-TEST", "msg-gap", kr_a, Role.MEMBER)
    assert len(chunks) >= 4

    buf = ChunkReassemblyBuffer("msg-gap", "SF-TEST", len(chunks), Role.MEMBER)
    dropped = {1, 3}
    for c in chunks:
        if c.chunk_index not in dropped:
            buf.add_chunk(c)

    assert buf.is_complete is False
    assert buf.missing_indices() == [1, 3]

    # Resend missing chunks
    for idx in buf.missing_indices():
        buf.add_chunk(chunks[idx])

    assert buf.is_complete is True
    assert buf.decrypt_and_reassemble(kr_b) == payload


def test_tampered_chunk_rejected_by_sha256_before_acceptance():
    """Table 6.1 Quality Target: Modified chunk fails SHA-256 check."""
    kr_a, _ = _make_keyrings()
    chunks = encrypt_and_chunk_bundle(b"Sensitive contract terms", "SF-TEST", "msg-t", kr_a, Role.MEMBER)
    tampered = chunks[0].model_copy()
    raw_ct = bytearray(base64.b64decode(tampered.ciphertext_b64))
    raw_ct[0] ^= 0xFF
    tampered.ciphertext_b64 = base64.b64encode(bytes(raw_ct)).decode("ascii")

    buf = ChunkReassemblyBuffer("msg-t", "SF-TEST", len(chunks), Role.MEMBER)
    with pytest.raises(ChunkTamperedError):
        buf.add_chunk(tampered)
    assert buf.received_count == 0


def test_role_denied_on_reassembly():
    kr_admin, kr_guest = _make_keyrings(role_b=Role.GUEST)
    chunks = encrypt_and_chunk_bundle(b"Admin payroll", "SF-TEST", "msg-rbac", kr_admin, Role.ADMIN)
    buf = ChunkReassemblyBuffer("msg-rbac", "SF-TEST", len(chunks), Role.ADMIN)
    for c in chunks:
        buf.add_chunk(c)

    with pytest.raises(RoleAccessDeniedError):
        buf.decrypt_and_reassemble(kr_guest)
