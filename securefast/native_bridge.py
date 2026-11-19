"""
Python <-> C11 Native Core Bridge (`ctypes`) + Lossless PNG Codec.

Loads the compiled C11 shared library (`securefast_core.dll` / `.so` / `.dylib`)
built from `native/securefast_core.c` for high-speed:
  - FIPS 180-4 SHA-256 & constant-time verification
  - RFC 5869 HKDF-SHA256
  - Key-derived Anti-OCR Secret Glyph rendering & BCH(15,7,5) pixel decoding
  - Constant-time memory scrubbing (`sf_secure_zero`)
"""

from __future__ import annotations

import ctypes
import platform
import struct
import zlib
from pathlib import Path
from typing import Optional


class GlyphDecodeError(ValueError):
    """Raised when glyph pixel decoding fails (wrong seed, tampering, or corrupt image)."""


def _find_native_library() -> Optional[Path]:
    sys_name = platform.system().lower()
    if sys_name == "windows":
        fname = "securefast_core.dll"
    elif sys_name == "darwin":
        fname = "libsecurefast_core.dylib"
    else:
        fname = "libsecurefast_core.so"

    candidates = [
        Path(__file__).resolve().parent / "native_bin" / fname,
        Path.cwd() / "securefast" / "native_bin" / fname,
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


class _NativeCore:
    """Thin ctypes binding to `native/securefast_core.c`."""

    def __init__(self) -> None:
        self.lib_path = _find_native_library()
        if self.lib_path is None:
            raise RuntimeError(
                "Compiled C11 engine not found. Run `python build_native.py` first."
            )
        self.lib = ctypes.CDLL(str(self.lib_path))
        self._bind_signatures()

    def _bind_signatures(self) -> None:
        lib = self.lib

        lib.sf_version.argtypes = []
        lib.sf_version.restype = ctypes.c_char_p

        lib.sf_secure_zero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.sf_secure_zero.restype = None

        lib.sf_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        lib.sf_sha256.restype = None

        lib.sf_hmac_sha256.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p,
        ]
        lib.sf_hmac_sha256.restype = None

        lib.sf_hkdf_sha256.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
        ]
        lib.sf_hkdf_sha256.restype = ctypes.c_int

        lib.sf_verify_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        lib.sf_verify_sha256.restype = ctypes.c_int

        lib.sf_glyph_count_for_bytes.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        lib.sf_glyph_count_for_bytes.restype = ctypes.c_size_t

        lib.sf_glyph_image_dims.argtypes = [
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int),
        ]
        lib.sf_glyph_image_dims.restype = None

        lib.sf_render_token_glyphs.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
        ]
        lib.sf_render_token_glyphs.restype = ctypes.c_int

        lib.sf_decode_token_glyphs.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_double),
        ]
        lib.sf_decode_token_glyphs.restype = ctypes.c_int

        lib.sf_chunk_count.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
        lib.sf_chunk_count.restype = ctypes.c_size_t


_CORE: Optional[_NativeCore] = None


def get_native_core() -> _NativeCore:
    global _CORE
    if _CORE is None:
        _CORE = _NativeCore()
    return _CORE


def native_version() -> str:
    return get_native_core().lib.sf_version().decode("utf-8")


def secure_zero(buf: bytearray) -> None:
    """Scrub a mutable bytearray in-place via C11 `sf_secure_zero`."""
    if not buf:
        return
    c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
    get_native_core().lib.sf_secure_zero(ctypes.addressof(c_buf), len(buf))


def sha256_bytes(data: bytes) -> bytes:
    out = ctypes.create_string_buffer(32)
    get_native_core().lib.sf_sha256(data, len(data), out)
    return out.raw


def sha256_hex(data: bytes) -> str:
    return sha256_bytes(data).hex()


def verify_sha256(data: bytes, expected_hex: str) -> bool:
    try:
        expected = bytes.fromhex(expected_hex)
    except ValueError:
        return False
    if len(expected) != 32:
        return False
    return bool(get_native_core().lib.sf_verify_sha256(data, len(data), expected))


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    out = ctypes.create_string_buffer(length)
    rc = get_native_core().lib.sf_hkdf_sha256(
        ikm, len(ikm),
        salt, len(salt),
        info, len(info),
        out, length,
    )
    if rc != 0:
        raise RuntimeError(f"C11 HKDF-SHA256 failed with code {rc}")
    return out.raw


def chunk_count(payload_len: int, max_chunk_bytes: int = 2048) -> int:
    return int(get_native_core().lib.sf_chunk_count(payload_len, max_chunk_bytes))


def render_token_rgba(
    token_bytes: bytes,
    glyph_seed: bytes,
    token_index: int,
    noise_nonce: int,
) -> tuple[bytes, int, int]:
    """Render a token into an adversarial Anti-OCR RGBA pixel buffer via C11."""
    if len(glyph_seed) != 32:
        raise ValueError("glyph_seed must be exactly 32 bytes")
    if not token_bytes:
        raise ValueError("token_bytes cannot be empty")

    lib = get_native_core().lib
    gcount = lib.sf_glyph_count_for_bytes(token_bytes, len(token_bytes))
    w = ctypes.c_int(0)
    h = ctypes.c_int(0)
    lib.sf_glyph_image_dims(gcount, ctypes.byref(w), ctypes.byref(h))

    width, height = w.value, h.value
    out_rgba = ctypes.create_string_buffer(width * height * 4)
    rc = lib.sf_render_token_glyphs(
        token_bytes,
        len(token_bytes),
        glyph_seed,
        ctypes.c_uint32(token_index),
        ctypes.c_uint32(noise_nonce),
        out_rgba,
        width,
        height,
    )
    if rc != 0:
        raise RuntimeError(f"C11 glyph render failed with code {rc}")
    return out_rgba.raw, width, height


def decode_token_rgba(
    rgba: bytes,
    width: int,
    height: int,
    glyph_seed: bytes,
    token_index: int,
) -> tuple[bytes, float]:
    """Decode raw RGBA glyph pixels back to token bytes via C11 template matching."""
    if len(glyph_seed) != 32:
        raise ValueError("glyph_seed must be exactly 32 bytes")
    if len(rgba) != width * height * 4:
        raise GlyphDecodeError("RGBA buffer size does not match width * height * 4")

    lib = get_native_core().lib
    max_out = max(64, (width // 32) * 2)
    out_buf = ctypes.create_string_buffer(max_out)
    conf = ctypes.c_double(0.0)
    rc = lib.sf_decode_token_glyphs(
        rgba,
        width,
        height,
        glyph_seed,
        ctypes.c_uint32(token_index),
        out_buf,
        max_out,
        ctypes.byref(conf),
    )
    if rc < 0:
        raise GlyphDecodeError(
            f"Glyph decoding failed (code={rc}, confidence={conf.value:.3f}) — "
            "wrong glyph seed, wrong role key, or tampered image"
        )
    return out_buf.raw[:rc], float(conf.value)


# =============================================================================
# Fast Lossless PNG Codec (Zero Pillow Dependency — uses C-backed zlib)
# =============================================================================

_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def rgba_to_png(rgba: bytes, width: int, height: int) -> bytes:
    """Encode an 8-bit RGBA buffer into a standard lossless PNG file."""
    row_bytes = width * 4
    if len(rgba) != row_bytes * height:
        raise ValueError("Invalid RGBA buffer dimensions")

    # Prepend filter byte 0x00 (None) to every scanline
    raw_scanlines = bytearray(height * (row_bytes + 1))
    mv = memoryview(rgba)
    for y in range(height):
        dst_start = y * (row_bytes + 1)
        raw_scanlines[dst_start] = 0
        raw_scanlines[dst_start + 1 : dst_start + 1 + row_bytes] = mv[
            y * row_bytes : (y + 1) * row_bytes
        ]

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(raw_scanlines), level=6)
    return _PNG_SIG + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", idat) + _png_chunk(b"IEND", b"")


def png_to_rgba(png_bytes: bytes) -> tuple[bytes, int, int]:
    """Decode a standard 8-bit RGBA PNG into `(rgba_bytes, width, height)`."""
    if not png_bytes.startswith(_PNG_SIG):
        raise GlyphDecodeError("Invalid PNG signature")

    pos = len(_PNG_SIG)
    width = height = 0
    idat_parts: list[bytes] = []

    while pos + 8 <= len(png_bytes):
        length, ctype = struct.unpack(">I4s", png_bytes[pos : pos + 8])
        pos += 8
        if pos + length + 4 > len(png_bytes):
            raise GlyphDecodeError("Truncated PNG chunk")
        chunk_data = png_bytes[pos : pos + length]
        expected_crc = struct.unpack(">I", png_bytes[pos + length : pos + length + 4])[0]
        actual_crc = zlib.crc32(ctype + chunk_data) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise GlyphDecodeError("Corrupt PNG CRC")
        pos += length + 4

        if ctype == b"IHDR":
            width, height, bit_depth, color_type, comp, filt, interlace = struct.unpack(
                ">IIBBBBB", chunk_data
            )
            if bit_depth != 8 or color_type != 6 or comp != 0 or filt != 0 or interlace != 0:
                raise GlyphDecodeError("Unsupported PNG format (expected 8-bit RGBA)")
        elif ctype == b"IDAT":
            idat_parts.append(chunk_data)
        elif ctype == b"IEND":
            break

    if width <= 0 or height <= 0 or not idat_parts:
        raise GlyphDecodeError("Incomplete PNG data")

    try:
        raw = zlib.decompress(b"".join(idat_parts))
    except zlib.error as exc:
        raise GlyphDecodeError(f"PNG decompression failed: {exc}") from exc

    row_bytes = width * 4
    expected_raw_len = height * (row_bytes + 1)
    if len(raw) != expected_raw_len:
        raise GlyphDecodeError("Decompressed PNG size mismatch")

    rgba = bytearray(height * row_bytes)
    for y in range(height):
        src_start = y * (row_bytes + 1)
        filter_type = raw[src_start]
        if filter_type != 0:
            raise GlyphDecodeError(f"Unsupported PNG scanline filter: {filter_type}")
        rgba[y * row_bytes : (y + 1) * row_bytes] = raw[
            src_start + 1 : src_start + 1 + row_bytes
        ]

    return bytes(rgba), width, height
