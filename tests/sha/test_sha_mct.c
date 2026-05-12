#include "sha.h"
#include "utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <msg>\n", argv[0]);
        return 1;
    }

    const char *seed = argv[1];
    size_t seed_len = strlen(seed);
    if (seed_len == 0)
    {
        fprintf(stderr, "Invalid message length\n");
        return 1;
    }

    // Convert string to hex
    size_t seed_bytes_len = seed_len / 2;
    uint8_t *seed_bytes = malloc(seed_bytes_len);
    if (!seed_bytes)
    {
        fprintf(stderr, "Failed to allocate memory for msg_bytes buffer\n");
        return 1;
    }

    if (hex_to_bytes(seed, seed_bytes, seed_bytes_len) != 0)
    {
        fprintf(stderr, "Invalid test message: full hex bytes are expected\n");
        free(seed_bytes);
        return 1;
    }

    uint8_t *md_bytes = malloc(seed_bytes_len);
    uint8_t *buf1 = malloc(seed_bytes_len);
    uint8_t *buf2 = malloc(seed_bytes_len);
    uint8_t *buf3 = malloc(seed_bytes_len);
    uint8_t *msg = malloc(seed_bytes_len * 3U);

    uint8_t *a = buf1;
    uint8_t *b = buf2;
    uint8_t *c = buf3;

    memcpy(a, seed_bytes, seed_bytes_len);
    memcpy(b, seed_bytes, seed_bytes_len);
    memcpy(c, seed_bytes, seed_bytes_len);

    for (int i = 0; i < 999; i++)
    {
        memcpy((void *)((uintptr_t)msg + seed_bytes_len * 0U), a, seed_bytes_len);
        memcpy((void *)((uintptr_t)msg + seed_bytes_len * 1U), b, seed_bytes_len);
        memcpy((void *)((uintptr_t)msg + seed_bytes_len * 2U), c, seed_bytes_len);

        if (sha256(msg, seed_bytes_len * 3U, md_bytes) != 0)
        {
            fprintf(stderr, "SHA256 hash operation failed\n");
            free(seed_bytes);
            free(md_bytes);
            free(buf1);
            free(buf2);
            free(buf3);
            free(msg);
            return 1;
        }

        memcpy(a, b, seed_bytes_len);
        memcpy(b, c, seed_bytes_len);
        memcpy(c, md_bytes, seed_bytes_len);
    }

    // Convert digest from byte array to hex string
    const size_t md_len = sizeof(seed_bytes) * 2U + 1U;
    char *md = malloc(md_len);
    if (!md)
    {
        fprintf(stderr, "Failed to allocate memory for md buffer\n");
        free(seed_bytes);
        return 1;
    }

    bytes_to_hex(seed_bytes, sizeof(seed_bytes), md);
    md[md_len - 1U] = '\0';

    printf("%s\n", md);

    // Clean
    free(seed_bytes);
    free(md_bytes);
    free(buf1);
    free(buf2);
    free(buf3);
    free(msg);
    free(md);

    return 0;
}
