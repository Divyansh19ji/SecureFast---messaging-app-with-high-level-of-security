"""Tests for the compiled C11 Native Core (`native/securefast_core.c`)."""

from __future__ import annotations

import hashlib
import os

import pytest

from securefast.native_bridge import (
    GlyphDecodeError,
    chunk_count,
    decode_token_rgba,
    hkdf_sha256,
    native_version,
    png_to_rgba,
    render_token_rgba,
    rgba_to_png,
    secure_zero,
    sha256_bytes,
    sha256_hex,
    verify_sha256,
)


def test_native_library_loads_and_reports_version():
    ver = native_version()
    assert "SecureFast-C11-Core" in ver


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"abc",
        b"The quick brown fox jumps over the lazy dog",
        b"A" * 64,
        b"B" * 5000,
        bytes(range(256)),
    ],
)
def test_c11_sha256_matches_fips_180_4(payload: bytes):
    expected = hashlib.sha256(payload).digest()
    assert sha256_bytes(payload) == expected
    assert sha256_hex(payload) == expected.hex()
    assert verify_sha256(payload, expected.hex()) is True


def test_c11_sha256_detects_single_bit_flip():
    data = bytearray(b"SecureFast integrity test payload")
    digest = sha256_hex(bytes(data))
    data[5] ^= 0x01
    assert verify_sha256(bytes(data), digest) is False


def test_c11_sha256_rejects_malformed_hex():
    assert verify_sha256(b"hello", "not-hex") is False
    assert verify_sha256(b"hello", "deadbeef") is False


def test_c11_hkdf_matches_rfc5869_test_vector_1():
    """RFC 5869 Appendix A.1 official test vector."""
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    okm = hkdf_sha256(ikm, salt, info, 42)
    assert okm == expected_okm


def test_c11_hkdf_domain_separation():
    ikm = os.urandom(32)
    salt = os.urandom(16)
    k_admin = hkdf_sha256(ikm, salt, b"role-ADMIN", 32)
    k_member = hkdf_sha256(ikm, salt, b"role-MEMBER", 32)
    k_guest = hkdf_sha256(ikm, salt, b"role-GUEST", 32)
    assert len({k_admin, k_member, k_guest}) == 3


def test_c11_secure_zero_scrubs_memory():
    secret = bytearray(b"TOP-SECRET-KEY-MATERIAL-12345678")
    secure_zero(secret)
    assert secret == bytearray(len(secret))


def test_c11_chunk_count_boundaries():
    assert chunk_count(0, 2048) == 1
    assert chunk_count(1, 2048) == 1
    assert chunk_count(2048, 2048) == 1
    assert chunk_count(2049, 2048) == 2
    assert chunk_count(5000, 2048) == 3


def test_c11_glyph_render_png_roundtrip_ascii_and_utf8():
    seed = os.urandom(32)
    for idx, sample in enumerate([b"Hello", b"$42M", b"2026-11-18", "नमस्ते 🔐".encode("utf-8")]):
        rgba, w, h = render_token_rgba(sample, seed, token_index=idx, noise_nonce=idx + 42)
        png = rgba_to_png(rgba, w, h)
        rgba2, w2, h2 = png_to_rgba(png)
        assert (w2, h2) == (w, h)
        assert rgba2 == rgba
        recovered, conf = decode_token_rgba(rgba2, w2, h2, seed, token_index=idx)
        assert recovered == sample
        assert conf >= 0.92


def test_c11_glyph_wrong_seed_fails():
    seed_a = os.urandom(32)
    seed_b = bytes([seed_a[0] ^ 0xFF]) + seed_a[1:]
    rgba, w, h = render_token_rgba(b"Confidential", seed_a, token_index=0, noise_nonce=777)
    with pytest.raises(GlyphDecodeError):
        decode_token_rgba(rgba, w, h, seed_b, token_index=0)


def test_png_rejects_corrupt_crc():
    seed = os.urandom(32)
    rgba, w, h = render_token_rgba(b"Test", seed, token_index=0, noise_nonce=1)
    png = bytearray(rgba_to_png(rgba, w, h))
    png[-20] ^= 0x55
    with pytest.raises(GlyphDecodeError):
        png_to_rgba(bytes(png))
