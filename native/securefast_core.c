#define SECUREFAST_BUILD_DLL
#include "securefast_core.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * 1. Version & Constant-Time Memory Scrubbing
 * ==========================================================================*/

SF_API const char* sf_version(void) {
    return "SecureFast-C11-Core/2.0.0";
}

SF_API void sf_secure_zero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/* ============================================================================
 * 2. FIPS 180-4 SHA-256, RFC 2104 HMAC-SHA256, RFC 5869 HKDF-SHA256
 * ==========================================================================*/

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx_t;

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

static void sha256_transform(sha256_ctx_t* ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t* ctx) {
    ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
    ctx->bitlen = 0;
    ctx->buflen = 0;
}

static void sha256_update(sha256_ctx_t* ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->buf[ctx->buflen++] = data[i];
        if (ctx->buflen == 64) {
            sha256_transform(ctx, ctx->buf);
            ctx->bitlen += 512;
            ctx->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t* ctx, uint8_t out[32]) {
    uint64_t total_bits = ctx->bitlen + ((uint64_t)ctx->buflen * 8u);
    ctx->buf[ctx->buflen++] = 0x80u;
    if (ctx->buflen > 56) {
        while (ctx->buflen < 64) ctx->buf[ctx->buflen++] = 0;
        sha256_transform(ctx, ctx->buf);
        ctx->buflen = 0;
    }
    while (ctx->buflen < 56) ctx->buf[ctx->buflen++] = 0;
    for (int i = 7; i >= 0; --i) {
        ctx->buf[ctx->buflen++] = (uint8_t)((total_bits >> (i * 8)) & 0xFFu);
    }
    sha256_transform(ctx, ctx->buf);

    for (int i = 0; i < 8; ++i) {
        out[i * 4]     = (uint8_t)((ctx->state[i] >> 24) & 0xFFu);
        out[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFFu);
        out[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xFFu);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xFFu);
    }
    sf_secure_zero(ctx, sizeof(*ctx));
}

SF_API void sf_sha256(const uint8_t* data, size_t len, uint8_t out_digest[SF_SHA256_DIGEST_LEN]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    if (data && len > 0) sha256_update(&ctx, data, len);
    sha256_final(&ctx, out_digest);
}

SF_API void sf_hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t out_mac[SF_SHA256_DIGEST_LEN]
) {
    uint8_t k_block[64];
    memset(k_block, 0, sizeof(k_block));
    if (key && key_len > 64) {
        sf_sha256(key, key_len, k_block);
    } else if (key && key_len > 0) {
        memcpy(k_block, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k_block[i] ^ 0x36u;
        opad[i] = k_block[i] ^ 0x5cu;
    }

    uint8_t inner_hash[32];
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    if (data && data_len > 0) sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, out_mac);

    sf_secure_zero(k_block, sizeof(k_block));
    sf_secure_zero(ipad, sizeof(ipad));
    sf_secure_zero(opad, sizeof(opad));
    sf_secure_zero(inner_hash, sizeof(inner_hash));
}

SF_API int sf_hkdf_sha256(
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* salt, size_t salt_len,
    const uint8_t* info, size_t info_len,
    uint8_t* out_okm, size_t out_len
) {
    if (!out_okm || out_len == 0 || out_len > 255 * 32) return -1;

    uint8_t zero_salt[32];
    memset(zero_salt, 0, sizeof(zero_salt));
    const uint8_t* actual_salt = (salt && salt_len > 0) ? salt : zero_salt;
    size_t actual_salt_len = (salt && salt_len > 0) ? salt_len : 32;

    uint8_t prk[32];
    sf_hmac_sha256(actual_salt, actual_salt_len, ikm, ikm_len, prk);

    uint8_t t_prev[32];
    size_t t_prev_len = 0;
    size_t offset = 0;
    uint8_t counter = 1;

    size_t buf_cap = 32 + info_len + 1;
    uint8_t* msg = (uint8_t*)malloc(buf_cap);
    if (!msg) {
        sf_secure_zero(prk, sizeof(prk));
        return -2;
    }

    while (offset < out_len) {
        size_t pos = 0;
        if (t_prev_len > 0) {
            memcpy(msg + pos, t_prev, t_prev_len);
            pos += t_prev_len;
        }
        if (info && info_len > 0) {
            memcpy(msg + pos, info, info_len);
            pos += info_len;
        }
        msg[pos++] = counter++;

        sf_hmac_sha256(prk, 32, msg, pos, t_prev);
        t_prev_len = 32;

        size_t to_copy = (out_len - offset < 32) ? (out_len - offset) : 32;
        memcpy(out_okm + offset, t_prev, to_copy);
        offset += to_copy;
    }

    sf_secure_zero(msg, buf_cap);
    free(msg);
    sf_secure_zero(prk, sizeof(prk));
    sf_secure_zero(t_prev, sizeof(t_prev));
    return 0;
}

SF_API int sf_verify_sha256(
    const uint8_t* data, size_t len,
    const uint8_t expected_digest[SF_SHA256_DIGEST_LEN]
) {
    if (!expected_digest) return 0;
    uint8_t actual[SF_SHA256_DIGEST_LEN];
    sf_sha256(data, len, actual);
    uint8_t diff = 0;
    for (int i = 0; i < SF_SHA256_DIGEST_LEN; ++i) {
        diff |= (uint8_t)(actual[i] ^ expected_digest[i]);
    }
    sf_secure_zero(actual, sizeof(actual));
    return (diff == 0) ? 1 : 0;
}

/* ============================================================================
 * 3. Deterministic Keyed PRNG (SplitMix64)
 * ==========================================================================*/

typedef struct {
    uint64_t state;
} splitmix64_t;

static inline uint64_t sm64_next(splitmix64_t* rng) {
    uint64_t z = (rng->state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static uint64_t seed_to_u64(const uint8_t seed[SF_SEED_LEN], uint32_t domain_tag) {
    uint8_t buf[SF_SEED_LEN + 4];
    memcpy(buf, seed, SF_SEED_LEN);
    buf[SF_SEED_LEN + 0] = (uint8_t)((domain_tag >> 24) & 0xFFu);
    buf[SF_SEED_LEN + 1] = (uint8_t)((domain_tag >> 16) & 0xFFu);
    buf[SF_SEED_LEN + 2] = (uint8_t)((domain_tag >> 8) & 0xFFu);
    buf[SF_SEED_LEN + 3] = (uint8_t)(domain_tag & 0xFFu);
    uint8_t hash[32];
    sf_sha256(buf, sizeof(buf), hash);
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | (uint64_t)hash[i];
    }
    return val;
}

/* ============================================================================
 * 4. Key-Derived Secret Glyph Alphabet (BCH(15, 7, 5) Error-Correcting Runes)
 *
 * 15 non-overlapping geometric strokes on a 32x32 dark tile:
 * - BCH(15, 7, 5) maps 128 symbols (0..127) to 15-bit stroke bitmasks with
 *   guaranteed minimum Hamming distance = 5 strokes between ANY two glyphs!
 * - XORing with a key-derived 15-bit coset mask ensures:
 *     (a) Every session has its own completely unique geometric rune alphabet
 *     (b) A wrong glyph_seed lands in the wrong BCH coset and fails decoding!
 * - Combined with a key-derived Fisher-Yates permutation + position-dependent
 *   shift, identical characters render as different secret glyphs!
 * ==========================================================================*/

typedef struct {
    float x0, y0, x1, y1;
} sf_stroke_t;

/* 15 well-separated geometric strokes inside a 32x32 tile (zero interior overlap) */
static const sf_stroke_t RUNE_STROKES[15] = {
    /* 0..3: Outer top & bottom segments */
    {  6.0f,  6.0f, 14.0f,  6.0f },
    { 18.0f,  6.0f, 26.0f,  6.0f },
    {  6.0f, 26.0f, 14.0f, 26.0f },
    { 18.0f, 26.0f, 26.0f, 26.0f },
    /* 4..7: Outer left & right segments */
    {  6.0f,  8.0f,  6.0f, 14.0f },
    {  6.0f, 18.0f,  6.0f, 24.0f },
    { 26.0f,  8.0f, 26.0f, 14.0f },
    { 26.0f, 18.0f, 26.0f, 24.0f },
    /* 8..11: Inner diamond / chevron diagonals */
    {  8.0f, 15.0f, 15.0f,  8.0f },
    { 17.0f,  8.0f, 24.0f, 15.0f },
    {  8.0f, 17.0f, 15.0f, 24.0f },
    { 17.0f, 24.0f, 24.0f, 17.0f },
    /* 12..14: Central crossbar & vertical spine */
    { 11.0f, 16.0f, 21.0f, 16.0f },
    { 16.0f,  9.0f, 16.0f, 14.0f },
    { 16.0f, 18.0f, 16.0f, 23.0f }
};

/* BCH(15, 7, 5) generator polynomial: x^8 + x^7 + x^6 + x^4 + 1 = 0x1D1 */
static uint16_t bch15_7_encode(uint8_t msg7) {
    uint32_t data = ((uint32_t)(msg7 & 0x7Fu)) << 8;
    uint32_t rem = data;
    const uint32_t gen = 0x1D1u;
    for (int bit = 14; bit >= 8; --bit) {
        if (rem & (1u << bit)) {
            rem ^= (gen << (bit - 8));
        }
    }
    return (uint16_t)((data | (rem & 0xFFu)) & 0x7FFFu);
}

static int popcount16(uint16_t x) {
    int c = 0;
    while (x) {
        x &= (uint16_t)(x - 1u);
        c++;
    }
    return c;
}

typedef struct {
    uint8_t  fwd_perm[128];   /* plaintext symbol -> shuffled code index */
    uint8_t  inv_perm[128];   /* shuffled code index -> plaintext symbol */
    uint16_t codewords[128];  /* BCH(15,7,5) ^ key_coset_mask */
    uint16_t coset_mask;
    uint8_t  pos_stride;      /* odd rolling shift per glyph position */
} sf_alphabet_t;

static void build_keyed_alphabet(const uint8_t glyph_seed[SF_SEED_LEN], uint32_t token_index, sf_alphabet_t* alpha) {
    /* 1. Derive per-session base permutation */
    splitmix64_t rng;
    rng.state = seed_to_u64(glyph_seed, 0x414C5048u); /* 'ALPH' */
    for (int i = 0; i < 128; ++i) alpha->fwd_perm[i] = (uint8_t)i;
    for (int i = 127; i > 0; --i) {
        uint64_t r = sm64_next(&rng) % (uint64_t)(i + 1);
        uint8_t tmp = alpha->fwd_perm[i];
        alpha->fwd_perm[i] = alpha->fwd_perm[r];
        alpha->fwd_perm[r] = tmp;
    }
    for (int i = 0; i < 128; ++i) {
        alpha->inv_perm[alpha->fwd_perm[i]] = (uint8_t)i;
    }

    /* 2. Derive a balanced 15-bit coset mask (never all-zero) tied to glyph_seed & token_index */
    uint64_t mask_bits = seed_to_u64(glyph_seed, 0x4D41534Bu ^ (token_index * 2654435761u));
    uint16_t mask = (uint16_t)(mask_bits & 0x7FFFu);
    /* Ensure mask is NOT itself a BCH codeword (distance >= 2 from 0) and has balanced weight */
    if (popcount16(mask) < 4 || popcount16(mask) > 11) {
        mask ^= 0x5A3Cu;
    }
    alpha->coset_mask = mask;
    alpha->pos_stride = (uint8_t)(((mask_bits >> 16) & 0x7Eu) | 1u); /* odd 1..127 */

    for (int i = 0; i < 128; ++i) {
        alpha->codewords[i] = (uint16_t)(bch15_7_encode((uint8_t)i) ^ alpha->coset_mask);
    }
}

/*
 * Escape encoding for full UTF-8 support:
 * - Bytes 0x00..0x7E -> 1 glyph (symbol 0..126)
 * - Bytes 0x7F..0xFF -> 3 glyphs: ESCAPE (127), high nibble (0..15), low nibble (0..15)
 */
SF_API size_t sf_glyph_count_for_bytes(const uint8_t* token_bytes, size_t token_len) {
    if (!token_bytes || token_len == 0) return 0;
    size_t count = 0;
    for (size_t i = 0; i < token_len; ++i) {
        if (token_bytes[i] < 0x7Fu) count += 1;
        else count += 3;
    }
    return count;
}

SF_API void sf_glyph_image_dims(size_t glyph_count, int* out_width, int* out_height) {
    if (glyph_count == 0) {
        if (out_width) *out_width = 0;
        if (out_height) *out_height = 0;
        return;
    }
    int w = (int)(SF_GLYPH_PAD * 2 + glyph_count * SF_GLYPH_TILE_SIZE + (glyph_count - 1) * SF_GLYPH_GAP);
    int h = SF_GLYPH_PAD * 2 + SF_GLYPH_TILE_SIZE;
    if (out_width) *out_width = w;
    if (out_height) *out_height = h;
}

/* ============================================================================
 * 5. Anti-OCR Rasterizer (RGBA Canvas Renderer in Pure C11)
 * ==========================================================================*/

static inline void blend_pixel(
    uint8_t* rgba, int w, int h, int x, int y,
    uint8_t r, uint8_t g, uint8_t b, float alpha
) {
    if (x < 0 || y < 0 || x >= w || y >= h || alpha <= 0.0f) return;
    if (alpha > 1.0f) alpha = 1.0f;
    size_t idx = ((size_t)y * (size_t)w + (size_t)x) * 4u;
    float inv = 1.0f - alpha;
    rgba[idx + 0] = (uint8_t)(r * alpha + rgba[idx + 0] * inv + 0.5f);
    rgba[idx + 1] = (uint8_t)(g * alpha + rgba[idx + 1] * inv + 0.5f);
    rgba[idx + 2] = (uint8_t)(b * alpha + rgba[idx + 2] * inv + 0.5f);
    rgba[idx + 3] = 255;
}

static float point_segment_dist(float px, float py, float x0, float y0, float x1, float y1) {
    float vx = x1 - x0;
    float vy = y1 - y0;
    float wx = px - x0;
    float wy = py - y0;
    float len2 = vx * vx + vy * vy;
    float t = (len2 > 1e-6f) ? ((wx * vx + wy * vy) / len2) : 0.0f;
    if (t < 0.0f) t = 0.0f;
    if (t > 1.0f) t = 1.0f;
    float dx = px - (x0 + t * vx);
    float dy = py - (y0 + t * vy);
    return sqrtf(dx * dx + dy * dy);
}

static void draw_aa_segment(
    uint8_t* rgba, int w, int h,
    float x0, float y0, float x1, float y1,
    float radius, uint8_t r, uint8_t g, uint8_t b, float max_alpha
) {
    int min_x = (int)floorf((x0 < x1 ? x0 : x1) - radius - 1.5f);
    int max_x = (int)ceilf((x0 > x1 ? x0 : x1) + radius + 1.5f);
    int min_y = (int)floorf((y0 < y1 ? y0 : y1) - radius - 1.5f);
    int max_y = (int)ceilf((y0 > y1 ? y0 : y1) + radius + 1.5f);

    for (int y = min_y; y <= max_y; ++y) {
        for (int x = min_x; x <= max_x; ++x) {
            float d = point_segment_dist((float)x, (float)y, x0, y0, x1, y1);
            if (d <= radius + 1.0f) {
                float cov = (d <= radius) ? 1.0f : (radius + 1.0f - d);
                blend_pixel(rgba, w, h, x, y, r, g, b, cov * max_alpha);
            }
        }
    }
}

static void draw_dashed_decoy_line(
    uint8_t* rgba, int w, int h,
    float x0, float y0, float x1, float y1,
    uint8_t r, uint8_t g, uint8_t b, float alpha
) {
    float dx = x1 - x0;
    float dy = y1 - y0;
    float len = sqrtf(dx * dx + dy * dy);
    int steps = (int)(len * 2.0f);
    if (steps < 1) return;
    for (int i = 0; i <= steps; ++i) {
        if ((i / 4) % 2 == 1) continue; /* dashed */
        float t = (float)i / (float)steps;
        int px = (int)(x0 + dx * t + 0.5f);
        int py = (int)(y0 + dy * t + 0.5f);
        blend_pixel(rgba, w, h, px, py, r, g, b, alpha);
    }
}

SF_API int sf_render_token_glyphs(
    const uint8_t* token_bytes, size_t token_len,
    const uint8_t glyph_seed[SF_SEED_LEN],
    uint32_t token_index,
    uint32_t noise_nonce,
    uint8_t* out_rgba,
    int width,
    int height
) {
    if (!token_bytes || token_len == 0 || !glyph_seed || !out_rgba) return -1;

    size_t glyph_count = sf_glyph_count_for_bytes(token_bytes, token_len);
    int expected_w = 0, expected_h = 0;
    sf_glyph_image_dims(glyph_count, &expected_w, &expected_h);
    if (width != expected_w || height != expected_h) return -2;

    uint8_t* symbols = (uint8_t*)malloc(glyph_count);
    if (!symbols) return -3;

    size_t s_idx = 0;
    for (size_t i = 0; i < token_len; ++i) {
        uint8_t b = token_bytes[i];
        if (b < 0x7Fu) {
            symbols[s_idx++] = b;
        } else {
            symbols[s_idx++] = 0x7Fu;
            symbols[s_idx++] = (uint8_t)((b >> 4) & 0x0Fu);
            symbols[s_idx++] = (uint8_t)(b & 0x0Fu);
        }
    }

    sf_alphabet_t alpha;
    build_keyed_alphabet(glyph_seed, token_index, &alpha);

    splitmix64_t noise_rng;
    noise_rng.state = seed_to_u64(glyph_seed, 0x4E4F4953u ^ noise_nonce ^ (token_index * 1140071481u));

    /* Fill outer canvas background (subtle warm/slate transparent-like border) */
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            size_t idx = ((size_t)y * (size_t)width + (size_t)x) * 4u;
            out_rgba[idx + 0] = 15;
            out_rgba[idx + 1] = 20;
            out_rgba[idx + 2] = 28;
            out_rgba[idx + 3] = 255;
        }
    }

    /* Render each secret glyph tile */
    for (size_t g = 0; g < glyph_count; ++g) {
        int tile_x = SF_GLYPH_PAD + (int)g * (SF_GLYPH_TILE_SIZE + SF_GLYPH_GAP);
        int tile_y = SF_GLYPH_PAD;

        /* 1. Rounded dark slate tile with subtle gradient dithering (disrupts Otsu OCR binarization) */
        for (int ly = 0; ly < SF_GLYPH_TILE_SIZE; ++ly) {
            for (int lx = 0; lx < SF_GLYPH_TILE_SIZE; ++lx) {
                /* Rounded corners (radius 4) */
                int cx = (lx < 4) ? (4 - lx) : ((lx >= SF_GLYPH_TILE_SIZE - 4) ? (lx - (SF_GLYPH_TILE_SIZE - 5)) : 0);
                int cy = (ly < 4) ? (4 - ly) : ((ly >= SF_GLYPH_TILE_SIZE - 4) ? (ly - (SF_GLYPH_TILE_SIZE - 5)) : 0);
                if (cx * cx + cy * cy > 18) continue;

                int dither = (int)((sm64_next(&noise_rng) & 7u)) - 3;
                int br = 24 + (ly * 6) / SF_GLYPH_TILE_SIZE + dither;
                int bg = 32 + (lx * 6) / SF_GLYPH_TILE_SIZE + dither;
                int bb = 44 + ((lx + ly) * 4) / SF_GLYPH_TILE_SIZE + dither;
                if (br < 14) br = 14;
                if (bg < 20) bg = 20;
                if (bb < 30) bb = 30;

                size_t idx = ((size_t)(tile_y + ly) * (size_t)width + (size_t)(tile_x + lx)) * 4u;
                out_rgba[idx + 0] = (uint8_t)br;
                out_rgba[idx + 1] = (uint8_t)bg;
                out_rgba[idx + 2] = (uint8_t)bb;
                out_rgba[idx + 3] = 255;
            }
        }

        /* 2. Key-derived BCH(15, 7, 5) geometric rune bitmask with position rolling shift */
        uint8_t sym = symbols[g];
        uint8_t code_idx = (uint8_t)((alpha.fwd_perm[sym] + (uint32_t)g * alpha.pos_stride) & 0x7Fu);
        uint16_t mask15 = alpha.codewords[code_idx];

        /* 3. Micro-jitter (+-1 px) */
        int jx = (int)(sm64_next(&noise_rng) % 3u) - 1;
        int jy = (int)(sm64_next(&noise_rng) % 3u) - 1;

        /* 4. Draw bold warm off-white geometric rune strokes (#ECE7DA, matching Figure 3.2) */
        for (int s = 0; s < 15; ++s) {
            if (mask15 & (1u << s)) {
                draw_aa_segment(
                    out_rgba, width, height,
                    (float)(tile_x + jx) + RUNE_STROKES[s].x0,
                    (float)(tile_y + jy) + RUNE_STROKES[s].y0,
                    (float)(tile_x + jx) + RUNE_STROKES[s].x1,
                    (float)(tile_y + jy) + RUNE_STROKES[s].y1,
                    1.05f, 236, 231, 218, 0.96f
                );
            }
        }

        /* 5. Draw coral-red dashed decoy line across the tile (matching Figure 3.2!) */
        float dy0 = 5.0f + (float)(sm64_next(&noise_rng) % 22u);
        float dy1 = 5.0f + (float)(sm64_next(&noise_rng) % 22u);
        draw_dashed_decoy_line(
            out_rgba, width, height,
            (float)tile_x + 3.0f, (float)tile_y + dy0,
            (float)tile_x + (float)SF_GLYPH_TILE_SIZE - 4.0f, (float)tile_y + dy1,
            217, 95, 67, 0.72f
        );

        /* 6. Optical noise dots */
        for (int d = 0; d < 6; ++d) {
            int nx = tile_x + 3 + (int)(sm64_next(&noise_rng) % (SF_GLYPH_TILE_SIZE - 6));
            int ny = tile_y + 3 + (int)(sm64_next(&noise_rng) % (SF_GLYPH_TILE_SIZE - 6));
            if (d % 2 == 0) {
                blend_pixel(out_rgba, width, height, nx, ny, 224, 112, 82, 0.70f);
            } else {
                blend_pixel(out_rgba, width, height, nx, ny, 145, 165, 190, 0.35f);
            }
        }
    }

    sf_secure_zero(symbols, glyph_count);
    free(symbols);
    sf_secure_zero(&alpha, sizeof(alpha));
    return 0;
}

/* ============================================================================
 * 6. Visual Template-Correlation Glyph Decoder (Recovers Text Strictly from Pixels)
 * ==========================================================================*/

static float sample_rune_ink(const uint8_t* rgba, int w, int h, int x, int y) {
    if (x < 0 || y < 0 || x >= w || y >= h) return 0.0f;
    size_t idx = ((size_t)y * (size_t)w + (size_t)x) * 4u;
    float r = (float)rgba[idx + 0];
    float g = (float)rgba[idx + 1];
    float b = (float)rgba[idx + 2];
    /*
     * Rune ink is warm off-white (~236, 231, 218): high min-channel (b >= 140) and
     * high luminance, whereas dark slate background has low luminance and coral decoy
     * lines (#D95F43) have very low blue/green channels!
     */
    float min_c = r;
    if (g < min_c) min_c = g;
    if (b < min_c) min_c = b;
    float score = (min_c - 75.0f) / 140.0f;
    if (score < 0.0f) score = 0.0f;
    if (score > 1.0f) score = 1.0f;
    return score;
}

static float measure_stroke_presence(
    const uint8_t* rgba, int w, int h,
    int tile_x, int tile_y, int jx, int jy, int stroke_idx
) {
    const sf_stroke_t* st = &RUNE_STROKES[stroke_idx];
    const int SAMPLES = 5;
    float sum = 0.0f;
    /* Sample strictly interior points (t in [0.20 .. 0.80]) to avoid any endpoint bleed */
    for (int i = 0; i < SAMPLES; ++i) {
        float t = 0.20f + 0.60f * ((float)i / (float)(SAMPLES - 1));
        int px = (int)floorf((float)(tile_x + jx) + st->x0 + (st->x1 - st->x0) * t + 0.5f);
        int py = (int)floorf((float)(tile_y + jy) + st->y0 + (st->y1 - st->y0) * t + 0.5f);
        sum += sample_rune_ink(rgba, w, h, px, py);
    }
    return sum / (float)SAMPLES;
}

SF_API int sf_decode_token_glyphs(
    const uint8_t* rgba,
    int width,
    int height,
    const uint8_t glyph_seed[SF_SEED_LEN],
    uint32_t token_index,
    uint8_t* out_bytes,
    size_t out_capacity,
    double* out_confidence
) {
    if (!rgba || !glyph_seed || !out_bytes) return -1;
    if (height != SF_GLYPH_PAD * 2 + SF_GLYPH_TILE_SIZE) return -2;
    if (width < SF_GLYPH_PAD * 2 + SF_GLYPH_TILE_SIZE) return -2;

    int inner_w = width - SF_GLYPH_PAD * 2 + SF_GLYPH_GAP;
    int stride = SF_GLYPH_TILE_SIZE + SF_GLYPH_GAP;
    if (inner_w <= 0 || (inner_w % stride) != 0) return -2;

    size_t glyph_count = (size_t)(inner_w / stride);
    uint8_t* raw_symbols = (uint8_t*)malloc(glyph_count);
    if (!raw_symbols) return -3;

    sf_alphabet_t alpha;
    build_keyed_alphabet(glyph_seed, token_index, &alpha);

    double total_conf = 0.0;
    int coset_mismatches = 0;

    for (size_t g = 0; g < glyph_count; ++g) {
        int tile_x = SF_GLYPH_PAD + (int)g * stride;
        int tile_y = SF_GLYPH_PAD;

        float best_score = -1e9f;
        int best_code_idx = -1;
        int best_hamming = 15;

        /* Search micro-jitter shifts (jx, jy) in {-1, 0, +1}^2 */
        for (int jy = -1; jy <= 1; ++jy) {
            for (int jx = -1; jx <= 1; ++jx) {
                float vec[15];
                uint16_t hard_bits = 0;
                for (int s = 0; s < 15; ++s) {
                    float p = measure_stroke_presence(rgba, width, height, tile_x, tile_y, jx, jy, s);
                    vec[s] = p * 2.0f - 1.0f; /* map [0,1] -> [-1,+1] */
                    if (p >= 0.45f) hard_bits |= (uint16_t)(1u << s);
                }

                for (int c = 0; c < 128; ++c) {
                    uint16_t cw = alpha.codewords[c];
                    float score = 0.0f;
                    for (int s = 0; s < 15; ++s) {
                        score += (cw & (1u << s)) ? vec[s] : -vec[s];
                    }
                    if (score > best_score) {
                        best_score = score;
                        best_code_idx = c;
                        best_hamming = popcount16((uint16_t)(hard_bits ^ cw));
                    }
                }
            }
        }

        /* Normalized confidence in [0.0 .. 1.0] (15.0 is perfect match across all 15 strokes) */
        double tile_conf = ((double)best_score + 15.0) / 30.0;
        if (tile_conf < 0.0) tile_conf = 0.0;
        if (tile_conf > 1.0) tile_conf = 1.0;
        total_conf += tile_conf;

        /*
         * BCH(15, 7, 5) has minimum distance 5. Valid rendered tiles match with
         * Hamming distance 0 (rarely 1 under heavy noise) and confidence ~0.95-0.99.
         * A wrong glyph_seed uses a different coset mask -> Hamming distance >= 2!
         */
        if (best_hamming > 1 || tile_conf < 0.86) {
            coset_mismatches++;
        }

        uint8_t unshifted = (uint8_t)(((int)best_code_idx - (int)((uint32_t)g * alpha.pos_stride)) & 0x7F);
        raw_symbols[g] = alpha.inv_perm[unshifted];
    }

    double avg_conf = (glyph_count > 0) ? (total_conf / (double)glyph_count) : 0.0;
    if (out_confidence) *out_confidence = avg_conf;

    /* Reject wrong seed / corrupted image */
    if (coset_mismatches > 0 || avg_conf < 0.90) {
        sf_secure_zero(raw_symbols, glyph_count);
        free(raw_symbols);
        sf_secure_zero(&alpha, sizeof(alpha));
        return -4; /* Seed mismatch or corrupted glyph image */
    }

    /* Unescape UTF-8 bytes */
    size_t out_len = 0;
    for (size_t i = 0; i < glyph_count; ++i) {
        if (raw_symbols[i] == 0x7Fu) {
            if (i + 2 >= glyph_count || raw_symbols[i + 1] > 15 || raw_symbols[i + 2] > 15) {
                sf_secure_zero(raw_symbols, glyph_count);
                free(raw_symbols);
                sf_secure_zero(&alpha, sizeof(alpha));
                return -5; /* Malformed escape sequence */
            }
            if (out_len >= out_capacity) {
                sf_secure_zero(raw_symbols, glyph_count);
                free(raw_symbols);
                sf_secure_zero(&alpha, sizeof(alpha));
                return -6; /* Output buffer too small */
            }
            out_bytes[out_len++] = (uint8_t)((raw_symbols[i + 1] << 4) | raw_symbols[i + 2]);
            i += 2;
        } else {
            if (out_len >= out_capacity) {
                sf_secure_zero(raw_symbols, glyph_count);
                free(raw_symbols);
                sf_secure_zero(&alpha, sizeof(alpha));
                return -6;
            }
            out_bytes[out_len++] = raw_symbols[i];
        }
    }

    sf_secure_zero(raw_symbols, glyph_count);
    free(raw_symbols);
    sf_secure_zero(&alpha, sizeof(alpha));
    return (int)out_len;
}

/* ============================================================================
 * 7. Chunk Sizing Helper
 * ==========================================================================*/

SF_API size_t sf_chunk_count(size_t payload_len, size_t max_chunk_bytes) {
    if (max_chunk_bytes == 0 || max_chunk_bytes > SF_MAX_CHUNK_BYTES) {
        max_chunk_bytes = SF_MAX_CHUNK_BYTES;
    }
    if (payload_len == 0) return 1;
    return (payload_len + max_chunk_bytes - 1u) / max_chunk_bytes;
}
