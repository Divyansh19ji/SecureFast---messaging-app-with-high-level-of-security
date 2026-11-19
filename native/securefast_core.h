#ifndef SECUREFAST_CORE_H
#define SECUREFAST_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
  #ifdef SECUREFAST_BUILD_DLL
    #define SF_API __declspec(dllexport)
  #else
    #define SF_API __declspec(dllimport)
  #endif
#else
  #define SF_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SF_SHA256_DIGEST_LEN 32
#define SF_SEED_LEN          32
#define SF_GLYPH_TILE_SIZE   32
#define SF_GLYPH_PAD         4
#define SF_GLYPH_GAP         4
#define SF_MAX_CHUNK_BYTES   2048
#define SF_ALPHABET_SIZE     128

/* Library version and capability string */
SF_API const char* sf_version(void);

/* Constant-time memory zeroing (scrubbing keys / plaintext buffers) */
SF_API void sf_secure_zero(void* ptr, size_t len);

/* FIPS 180-4 SHA-256 */
SF_API void sf_sha256(const uint8_t* data, size_t len, uint8_t out_digest[SF_SHA256_DIGEST_LEN]);

/* RFC 2104 HMAC-SHA256 */
SF_API void sf_hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t out_mac[SF_SHA256_DIGEST_LEN]
);

/* RFC 5869 HKDF-SHA256 (Extract + Expand) */
SF_API int sf_hkdf_sha256(
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* salt, size_t salt_len,
    const uint8_t* info, size_t info_len,
    uint8_t* out_okm, size_t out_len
);

/* Verify a chunk's SHA-256 digest in constant time (returns 1 if match, 0 otherwise) */
SF_API int sf_verify_sha256(
    const uint8_t* data, size_t len,
    const uint8_t expected_digest[SF_SHA256_DIGEST_LEN]
);

/*
 * Calculate required RGBA image dimensions for a token of `byte_len` bytes.
 * Each UTF-8 byte is encoded as two 4-bit secret glyphs (or direct 7-bit ASCII
 * runes for printable ASCII, with an escape glyph for extended UTF-8).
 * Using 2 secret glyphs per byte gives exact 100% lossless support for ALL UTF-8
 * (English, Hindi, Emoji, symbols, binary) with 16 ultra-distinct keyed runes
 * from a 128-rune geometric codebook!
 *
 * Wait: to keep tiles compact like Figure 3.2 (1 glyph per character for standard
 * ASCII text, 2 glyphs for non-ASCII UTF-8 bytes), we use a 128-symbol geometric
 * rune codebook covering all 0x00..0x7F ASCII directly (1 tile per char!) and
 * escape 0x7F + two hex runes for >= 0x80 UTF-8 bytes!
 */
SF_API size_t sf_glyph_count_for_bytes(const uint8_t* token_bytes, size_t token_len);

SF_API void sf_glyph_image_dims(size_t glyph_count, int* out_width, int* out_height);

/*
 * Render a token's bytes into an adversarial Anti-OCR RGBA raster buffer:
 * - Key-derived secret geometric glyph alphabet (seeded from 32-byte `glyph_seed`)
 * - Position-dependent rolling permutation (defeats frequency analysis)
 * - Micro-jitter (+-1 px), subtle gradient dithering, faint decoy dashed lines,
 *   and optical noise dots (matches SecureFast Figure 3.2!)
 * - `token_index` shifts the keyed alphabet per token so identical words in the
 *   same message produce visually distinct glyph sequences!
 * - `noise_nonce` controls per-render decoy lines & noise dots.
 *
 * `out_rgba` must have size >= width * height * 4 bytes.
 * Returns 0 on success, negative on error.
 */
SF_API int sf_render_token_glyphs(
    const uint8_t* token_bytes, size_t token_len,
    const uint8_t glyph_seed[SF_SEED_LEN],
    uint32_t token_index,
    uint32_t noise_nonce,
    uint8_t* out_rgba,
    int width,
    int height
);

/*
 * Decode an RGBA glyph image back into the original token bytes using ONLY
 * the raw RGBA pixel buffer and the receiver's HKDF-derived `glyph_seed`.
 * Uses foreground luminance extraction + shift-tolerant Normalized Cross-Correlation
 * against the key-derived clean geometric rune templates.
 *
 * Returns decoded byte length (>= 0) on success, or negative error code if the
 * seed does not match (low correlation confidence) or image dimensions are invalid.
 * Also writes average match confidence (0.0 .. 1.0) into `out_confidence` if non-NULL.
 */
SF_API int sf_decode_token_glyphs(
    const uint8_t* rgba,
    int width,
    int height,
    const uint8_t glyph_seed[SF_SEED_LEN],
    uint32_t token_index,
    uint8_t* out_bytes,
    size_t out_capacity,
    double* out_confidence
);

/*
 * Fast 2 KB chunk slicing helper: returns total chunks for a payload of `payload_len`
 * given `max_chunk_bytes` (clamped to 1..SF_MAX_CHUNK_BYTES).
 */
SF_API size_t sf_chunk_count(size_t payload_len, size_t max_chunk_bytes);

#ifdef __cplusplus
}
#endif

#endif /* SECUREFAST_CORE_H */
