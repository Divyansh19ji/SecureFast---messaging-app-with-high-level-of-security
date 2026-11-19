"""Tests for ECDH P-256, HKDF-SHA256, AES-256-GCM, Safety Numbers & Role-Based Decryption."""

from __future__ import annotations

import pytest

from securefast.crypto_engine import (
    DecryptionFailedError,
    DeviceKeyPair,
    RoleAccessDeniedError,
    SessionKeyring,
    build_chunk_aad,
    generate_salt,
)
from securefast.models import Role


def _pair(role_a: Role = Role.ADMIN, role_b: Role = Role.ADMIN):
    kp_a = DeviceKeyPair.generate()
    kp_b = DeviceKeyPair.generate()
    salt = generate_salt()
    kr_a = SessionKeyring.establish(kp_a, kp_b.public_key_b64, salt, role_a)
    kr_b = SessionKeyring.establish(kp_b, kp_a.public_key_b64, salt, role_b)
    return kr_a, kr_b


def test_ecdh_and_safety_number_symmetry():
    kr_a, kr_b = _pair(Role.ADMIN, Role.MEMBER)
    assert kr_a.safety_number == kr_b.safety_number
    parts = kr_a.safety_number.split(" ")
    assert len(parts) == 6
    assert all(len(g) == 5 and g.isdigit() for g in parts)


def test_different_peers_produce_different_safety_numbers_mitm_detection():
    kp_a = DeviceKeyPair.generate()
    kp_b = DeviceKeyPair.generate()
    kp_eve = DeviceKeyPair.generate()
    salt = generate_salt()
    kr_ab = SessionKeyring.establish(kp_a, kp_b.public_key_b64, salt, Role.ADMIN)
    kr_ae = SessionKeyring.establish(kp_a, kp_eve.public_key_b64, salt, Role.ADMIN)
    assert kr_ab.safety_number != kr_ae.safety_number


def test_aes256_gcm_roundtrip_and_fresh_nonces():
    kr_a, kr_b = _pair()
    aad = build_chunk_aad("SF-1", "msg-1", 0, 1, Role.MEMBER)
    iv1, ct1 = kr_a.encrypt_chunk(b"same plaintext", Role.MEMBER, aad)
    iv2, ct2 = kr_a.encrypt_chunk(b"same plaintext", Role.MEMBER, aad)
    assert len(iv1) == 12
    assert iv1 != iv2
    assert ct1 != ct2
    assert kr_b.decrypt_chunk(iv1, ct1, Role.MEMBER, aad) == b"same plaintext"
    assert kr_b.decrypt_chunk(iv2, ct2, Role.MEMBER, aad) == b"same plaintext"


def test_aes256_gcm_rejects_tampered_ciphertext_and_aad():
    kr_a, kr_b = _pair()
    aad = build_chunk_aad("SF-1", "msg-1", 0, 2, Role.MEMBER)
    iv, ct = kr_a.encrypt_chunk(b"secret bank wire", Role.MEMBER, aad)

    bad_ct = bytearray(ct)
    bad_ct[0] ^= 0x80
    with pytest.raises(DecryptionFailedError):
        kr_b.decrypt_chunk(iv, bytes(bad_ct), Role.MEMBER, aad)

    wrong_aad = build_chunk_aad("SF-1", "msg-1", 1, 2, Role.MEMBER)
    with pytest.raises(DecryptionFailedError):
        kr_b.decrypt_chunk(iv, ct, Role.MEMBER, wrong_aad)


def test_wrong_session_key_cannot_decrypt():
    kr_a, _ = _pair()
    _, kr_other = _pair()
    aad = build_chunk_aad("SF-1", "msg-1", 0, 1, Role.MEMBER)
    iv, ct = kr_a.encrypt_chunk(b"private payload", Role.MEMBER, aad)
    with pytest.raises(DecryptionFailedError):
        kr_other.decrypt_chunk(iv, ct, Role.MEMBER, aad)


def test_rbac_admin_member_guest_key_isolation():
    """Verify strict Role-Based Decryption hierarchy: ADMIN > MEMBER > GUEST."""
    kp_admin = DeviceKeyPair.generate()
    kp_peer = DeviceKeyPair.generate()
    salt = generate_salt()

    kr_admin = SessionKeyring.establish(kp_admin, kp_peer.public_key_b64, salt, Role.ADMIN)
    kr_member = SessionKeyring.establish(kp_peer, kp_admin.public_key_b64, salt, Role.MEMBER)
    kr_guest = SessionKeyring.establish(kp_peer, kp_admin.public_key_b64, salt, Role.GUEST)

    # Admin encrypts 3 messages at 3 clearance levels
    aad_g = build_chunk_aad("P1", "M1", 0, 1, Role.GUEST)
    aad_m = build_chunk_aad("P1", "M2", 0, 1, Role.MEMBER)
    aad_a = build_chunk_aad("P1", "M3", 0, 1, Role.ADMIN)

    iv_g, ct_g = kr_admin.encrypt_chunk(b"Public notice", Role.GUEST, aad_g)
    iv_m, ct_m = kr_admin.encrypt_chunk(b"Team schedule", Role.MEMBER, aad_m)
    iv_a, ct_a = kr_admin.encrypt_chunk(b"Board $42M merger", Role.ADMIN, aad_a)

    # GUEST can decrypt ONLY GUEST
    assert kr_guest.decrypt_chunk(iv_g, ct_g, Role.GUEST, aad_g) == b"Public notice"
    with pytest.raises(RoleAccessDeniedError):
        kr_guest.decrypt_chunk(iv_m, ct_m, Role.MEMBER, aad_m)
    with pytest.raises(RoleAccessDeniedError):
        kr_guest.decrypt_chunk(iv_a, ct_a, Role.ADMIN, aad_a)
    # Even if GUEST tries using its GUEST key directly on MEMBER ciphertext, GCM fails!
    with pytest.raises(DecryptionFailedError):
        kr_guest.decrypt_chunk(iv_m, ct_m, Role.GUEST, aad_m)

    # MEMBER can decrypt GUEST + MEMBER, NOT ADMIN
    assert kr_member.decrypt_chunk(iv_g, ct_g, Role.GUEST, aad_g) == b"Public notice"
    assert kr_member.decrypt_chunk(iv_m, ct_m, Role.MEMBER, aad_m) == b"Team schedule"
    with pytest.raises(RoleAccessDeniedError):
        kr_member.decrypt_chunk(iv_a, ct_a, Role.ADMIN, aad_a)


def test_scrub_all_destroys_session_keys():
    kr_a, _ = _pair()
    assert kr_a.can_access(Role.ADMIN) is True
    kr_a.scrub_all()
    assert kr_a.can_access(Role.ADMIN) is False
    assert kr_a.can_access(Role.GUEST) is False
