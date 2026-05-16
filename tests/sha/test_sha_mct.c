#include "sha.h"
#include "utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <msg> <msg_len_bytes>\n", argv[0]);
        return 1;
    }

    const char *seed = argv[1];
    int seed_len     = atoi(argv[2]);

    // Convert string to hex
    uint8_t *seed_bytes = malloc(seed_len);
    if (!seed_bytes)
    {
        fprintf(stderr, "Failed to allocate memory for msg_bytes buffer\n");
        return 1;
    }

    if (hex_to_bytes(seed, seed_bytes, seed_len) != 0)
    {
        fprintf(stderr, "Invalid test message: full hex bytes are expected\n");
        free(seed_bytes);
        return 1;
    }

    uint8_t *a   = malloc(seed_len);
    uint8_t *b   = malloc(seed_len);
    uint8_t *c   = malloc(seed_len);
    uint8_t *msg = malloc(seed_len * 3U);
    uint8_t md_bytes[SHA256_MD_SZ];

    memcpy(a, seed_bytes, seed_len);
    memcpy(b, seed_bytes, seed_len);
    memcpy(c, seed_bytes, seed_len);

    for (int i = 0; i < 1000; i++)
    {
        memcpy((void *)(msg + seed_len * 0U), a, seed_len);
        memcpy((void *)(msg + seed_len * 1U), b, seed_len);
        memcpy((void *)(msg + seed_len * 2U), c, seed_len);

        if (sha256(msg, seed_len * 3U, md_bytes) != 0)
        {
            fprintf(stderr, "SHA256 hash operation failed\n");
            free(seed_bytes);
            free(a);
            free(b);
            free(c);
            free(msg);
            return 1;
        }

        memcpy(a, b, seed_len);
        memcpy(b, c, seed_len);
        memcpy(c, md_bytes, seed_len);
    }

    // Convert digest from byte array to hex string
    const size_t md_len = seed_len * 2U + 1U;
    char *md            = malloc(md_len);
    if (!md)
    {
        fprintf(stderr, "Failed to allocate memory for md buffer\n");
        free(seed_bytes);
        return 1;
    }

    bytes_to_hex(md_bytes, seed_len, md);
    md[md_len - 1U] = '\0';

    printf("%s\n", md);

    // Clean
    free(seed_bytes);
    free(msg);
    free(md);

    return 0;
}
