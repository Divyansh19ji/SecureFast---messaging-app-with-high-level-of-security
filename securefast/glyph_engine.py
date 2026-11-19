"""
Anti-OCR Key-Derived Secret Glyph Imaging Pipeline (Python + C11 Native Core).

Implements Steps 2 & 3 of SecureFast's "One Message, Five Forms":
  1. Lossless Tokenization into words, numbers, punctuation/symbols, and whitespace
  2. C11 Adversarial Glyph Rendering (per-token secret geometric rune PNG image,
     seeded via HKDF from the shared session + role key, with jitter, noise & decoys)
  3. Binary Glyph Bundle Packing (contains ONLY PNG image bytes — zero plaintext!)
  4. C11 Visual Template-Correlation Decoding (recovers exact original text strictly
     from the decrypted PNG pixels using the receiver's matching glyph seed)
"""

from __future__ import annotations

import base64
import re
import secrets
import struct
from dataclasses import dataclass

from securefast.native_bridge import (
    GlyphDecodeError,
    decode_token_rgba,
    png_to_rgba,
    render_token_rgba,
    rgba_to_png,
)

# Lossless tokenizer: splits into words, numbers, whitespace runs, and individual symbols
_TOKEN_RE = re.compile(r"[A-Za-z]+|\d+(?:\.\d+)?|\s+|[^\w\s]", re.UNICODE)

# Binary glyph bundle header: 4-byte magic + uint16 token_count
_BUNDLE_MAGIC = b"SFGL"


@dataclass(slots=True)
class RenderedGlyphToken:
    token_index: int
    png_bytes: bytes
    width: int
    height: int

    @property
    def png_data_url(self) -> str:
        return "data:image/png;base64," + base64.b64encode(self.png_bytes).decode("ascii")


@dataclass(slots=True)
class DecodedGlyphMessage:
    text: str
    tokens: list[str]
    glyph_images: list[RenderedGlyphToken]
    avg_confidence: float


def tokenize_message(text: str) -> list[str]:
    """
    Split `text` into atomic tokens (words, numbers, whitespace, symbols)
    such that `"".join(tokenize_message(text)) == text` always holds.
    """
    if not text:
        return []
    tokens = _TOKEN_RE.findall(text)
    # Guard against any exotic character missed by regex
    if "".join(tokens) != text:
        return list(text)
    # Split overly long tokens (> 24 bytes) so each glyph image stays compact
    bounded: list[str] = []
    for tok in tokens:
        if len(tok.encode("utf-8")) <= 24:
            bounded.append(tok)
        else:
            for i in range(0, len(tok), 16):
                bounded.append(tok[i : i + 16])
    return bounded


def encode_text_to_glyph_tokens(
    text: str,
    glyph_seed: bytes,
) -> tuple[list[str], list[RenderedGlyphToken]]:
    """
    Convert plaintext into tokens and render each token as an individual
    Anti-OCR secret glyph PNG image via the C11 native engine.
    """
    tokens = tokenize_message(text)
    rendered: list[RenderedGlyphToken] = []
    for idx, tok in enumerate(tokens):
        noise_nonce = secrets.randbits(32)
        rgba, width, height = render_token_rgba(
            tok.encode("utf-8"),
            glyph_seed,
            token_index=idx,
            noise_nonce=noise_nonce,
        )
        png_bytes = rgba_to_png(rgba, width, height)
        rendered.append(
            RenderedGlyphToken(
                token_index=idx,
                png_bytes=png_bytes,
                width=width,
                height=height,
            )
        )
    return tokens, rendered


def pack_glyph_bundle(glyph_tokens: list[RenderedGlyphToken]) -> bytes:
    """
    Pack rendered PNG glyph images into a compact binary envelope for AES-256-GCM
    chunking. Contains ONLY PNG image bytes — ZERO plaintext characters!
    """
    parts = [_BUNDLE_MAGIC, struct.pack(">H", len(glyph_tokens))]
    for item in glyph_tokens:
        parts.append(struct.pack(">I", len(item.png_bytes)))
        parts.append(item.png_bytes)
    return b"".join(parts)


def unpack_glyph_bundle_images(bundle: bytes) -> list[bytes]:
    """Extract raw PNG byte blobs from a decrypted glyph bundle."""
    if len(bundle) < 6 or bundle[:4] != _BUNDLE_MAGIC:
        raise GlyphDecodeError("Invalid glyph bundle magic header")
    (count,) = struct.unpack(">H", bundle[4:6])
    pos = 6
    images: list[bytes] = []
    for _ in range(count):
        if pos + 4 > len(bundle):
            raise GlyphDecodeError("Truncated glyph bundle token header")
        (png_len,) = struct.unpack(">I", bundle[pos : pos + 4])
        pos += 4
        if pos + png_len > len(bundle):
            raise GlyphDecodeError("Truncated glyph bundle PNG payload")
        images.append(bundle[pos : pos + png_len])
        pos += png_len
    if pos != len(bundle):
        raise GlyphDecodeError("Unexpected trailing bytes in glyph bundle")
    return images


def decode_glyph_bundle(bundle: bytes, glyph_seed: bytes) -> DecodedGlyphMessage:
    """
    Decode a binary glyph bundle back into exact plaintext by decoding every PNG
    into raw RGBA pixels and matching against the C11 key-derived rune alphabet.
    """
    png_list = unpack_glyph_bundle_images(bundle)
    tokens: list[str] = []
    glyph_images: list[RenderedGlyphToken] = []
    confidences: list[float] = []

    for idx, png_bytes in enumerate(png_list):
        rgba, width, height = png_to_rgba(png_bytes)
        raw_bytes, conf = decode_token_rgba(rgba, width, height, glyph_seed, token_index=idx)
        try:
            tok_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GlyphDecodeError(f"Decoded bytes at token {idx} are not valid UTF-8") from exc
        tokens.append(tok_text)
        glyph_images.append(
            RenderedGlyphToken(
                token_index=idx,
                png_bytes=png_bytes,
                width=width,
                height=height,
            )
        )
        confidences.append(conf)

    avg_conf = sum(confidences) / len(confidences) if confidences else 1.0
    return DecodedGlyphMessage(
        text="".join(tokens),
        tokens=tokens,
        glyph_images=glyph_images,
        avg_confidence=avg_conf,
    )
