#define SECUREFAST_BUILD_DLL
#include "securefast_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(void) {
    printf("===================================================\n");
    printf("  %s - Native C11 Benchmark & Self-Test\n", sf_version());
    printf("===================================================\n");

    uint8_t ikm[32], salt[16], seed[32], wrong_seed[32];
    for (int i = 0; i < 32; ++i) ikm[i] = (uint8_t)(i * 7 + 3);
    for (int i = 0; i < 16; ++i) salt[i] = (uint8_t)(i * 13 + 5);

    const char* info = "securefast-glyph-seed-v2";
    if (sf_hkdf_sha256(ikm, 32, salt, 16, (const uint8_t*)info, strlen(info), seed, 32) != 0) {
        fprintf(stderr, "HKDF failed!\n");
        return 1;
    }
    memcpy(wrong_seed, seed, 32);
    wrong_seed[0] ^= 0xFFu;

    const char* sample = "Meet at 9:00 PM! Deal = $42M (Confidential #1)";
    size_t len = strlen(sample);

    clock_t t0 = clock();
    const int ITERATIONS = 1000;
    int passed = 0;

    for (int i = 0; i < ITERATIONS; ++i) {
        size_t gcount = sf_glyph_count_for_bytes((const uint8_t*)sample, len);
        int w = 0, h = 0;
        sf_glyph_image_dims(gcount, &w, &h);
        uint8_t* rgba = (uint8_t*)malloc((size_t)w * (size_t)h * 4u);
        uint8_t out[256];
        double conf = 0.0;

        int rc_r = sf_render_token_glyphs((const uint8_t*)sample, len, seed, (uint32_t)i, (uint32_t)(i * 997), rgba, w, h);
        int rc_d = sf_decode_token_glyphs(rgba, w, h, seed, (uint32_t)i, out, sizeof(out), &conf);

        if (rc_r == 0 && rc_d == (int)len && memcmp(out, sample, len) == 0) {
            passed++;
        }
        free(rgba);
    }

    clock_t t1 = clock();
    double elapsed_ms = 1000.0 * (double)(t1 - t0) / (double)CLOCKS_PER_SEC;

    /* Test wrong seed rejection */
    size_t gcount = sf_glyph_count_for_bytes((const uint8_t*)sample, len);
    int w = 0, h = 0;
    sf_glyph_image_dims(gcount, &w, &h);
    uint8_t* rgba = (uint8_t*)malloc((size_t)w * (size_t)h * 4u);
    uint8_t out[256];
    double wrong_conf = 0.0;
    sf_render_token_glyphs((const uint8_t*)sample, len, seed, 0, 12345, rgba, w, h);
    int rc_wrong = sf_decode_token_glyphs(rgba, w, h, wrong_seed, 0, out, sizeof(out), &wrong_conf);
    free(rgba);

    printf("Round-trip accuracy : %d / %d (%.2f%%)\n", passed, ITERATIONS, 100.0 * passed / ITERATIONS);
    printf("Total time (1000x)  : %.2f ms (%.3f ms / render+decode)\n", elapsed_ms, elapsed_ms / ITERATIONS);
    printf("Wrong-seed rejected : %s (rc=%d, conf=%.3f)\n", (rc_wrong < 0) ? "PASS" : "FAIL", rc_wrong, wrong_conf);

    return (passed == ITERATIONS && rc_wrong < 0) ? 0 : 1;
}
