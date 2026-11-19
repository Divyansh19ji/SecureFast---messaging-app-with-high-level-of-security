"""Tests for Key-Derived Secret Glyph Imaging & Anti-OCR Resistance (Table 6.1)."""

from __future__ import annotations

import os
import secrets
import string

import pytest

from securefast.glyph_engine import (
    decode_glyph_bundle,
    encode_text_to_glyph_tokens,
    pack_glyph_bundle,
    tokenize_message,
)
from securefast.native_bridge import GlyphDecodeError, png_to_rgba


@pytest.mark.parametrize(
    "text",
    [
        "Hi Ana, send the file",
        "The deal closes Friday at $42M.",
        "Meet at 9:30 PM — room #404!",
        "Line 1\nLine 2\tTabbed   spaces",
        "API_KEY=sk-live-9876543210_ABCDEF",
        "Unicode test: नमस्ते 🔒🚀✨",
    ],
)
def test_lossless_tokenization_and_glyph_roundtrip(text: str):
    seed = os.urandom(32)
    tokens = tokenize_message(text)
    assert "".join(tokens) == text

    _, rendered = encode_text_to_glyph_tokens(text, seed)
    bundle = pack_glyph_bundle(rendered)

    # Zero plaintext bytes inside the packed glyph PNG bundle!
    for word in ("Friday", "send", "API_KEY", "Confidential"):
        if word in text:
            assert word.encode("utf-8") not in bundle

    decoded = decode_glyph_bundle(bundle, seed)
    assert decoded.text == text
    assert decoded.tokens == tokens
    assert decoded.avg_confidence >= 0.92


def test_1000_random_tokens_100_percent_roundtrip_accuracy():
    """Table 6.1 Quality Target: 100% round-trip accuracy over 1000 random tokens."""
    seed = os.urandom(32)
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?/"
    passed = 0
    for _ in range(1000):
        tok = "".join(secrets.choice(alphabet) for _ in range(secrets.randbelow(12) + 1))
        _, rendered = encode_text_to_glyph_tokens(tok, seed)
        bundle = pack_glyph_bundle(rendered)
        decoded = decode_glyph_bundle(bundle, seed)
        if decoded.text == tok:
            passed += 1
    assert passed == 1000


def test_wrong_seed_fails_glyph_decoding():
    """Table 6.1 Quality Target: Decoding with wrong seed must fail."""
    seed = os.urandom(32)
    wrong_seed = os.urandom(32)
    _, rendered = encode_text_to_glyph_tokens("Secret deal closes at 9 PM", seed)
    bundle = pack_glyph_bundle(rendered)
    with pytest.raises(GlyphDecodeError):
        decode_glyph_bundle(bundle, wrong_seed)


def test_same_token_different_positions_and_sessions_produce_different_glyphs():
    """Defeats monoalphabetic frequency analysis & cross-session scraping."""
    seed1 = os.urandom(32)
    seed2 = os.urandom(32)

    _, r1 = encode_text_to_glyph_tokens("SECRET SECRET", seed1)
    _, r2 = encode_text_to_glyph_tokens("SECRET", seed2)

    # Same word at token index 0 vs token index 2 produces completely different pixel images
    assert r1[0].png_bytes != r1[2].png_bytes
    # Different session key produces completely different pixel images
    assert r1[0].png_bytes != r2[0].png_bytes


def test_anti_ocr_adversarial_features_present_in_rendered_pixels():
    """
    Verify rendered glyph images contain:
      - Dark slate rounded background
      - Warm off-white geometric rune ink
      - Coral-orange decoy strokes / noise dots (disrupting OCR binarization)
      - Valid non-trivial pixel variance (never blank or monochrome)
    """
    seed = os.urandom(32)
    _, rendered = encode_text_to_glyph_tokens("MEET", seed)
    rgba, w, h = png_to_rgba(rendered[0].png_bytes)
    assert w > 100 and h == 40

    dark_bg = 0
    rune_ink = 0
    coral_decoy = 0
    for i in range(0, len(rgba), 4):
        r, g, b = rgba[i], rgba[i + 1], rgba[i + 2]
        if r < 60 and g < 60 and b < 75:
            dark_bg += 1
        elif r > 180 and g > 175 and b > 165:
            rune_ink += 1
        elif r > 120 and (r - b) > 55:
            coral_decoy += 1

    assert dark_bg > 500
    assert rune_ink > 150
    assert coral_decoy > 25
