#include "hmac.h"
#include "sha.h"
#include "utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if (argc != 6)
    {
        fprintf(stderr,
                "Usage: %s <key_hex> <klen_bytes> <msg_hex> <msglen_bytes> <tlen_bytes>\n",
                argv[0]);
        return 1;
    }

    const char *key_hex = argv[1];
    int klen            = atoi(argv[2]);
    const char *msg_hex = argv[3];
    int msglen          = atoi(argv[4]);
    int tlen            = atoi(argv[5]);

    if (tlen <= 0 || tlen > SHA256_MD_SZ)
    {
        fprintf(stderr, "Invalid tag length: must be in [1, %u]\n", SHA256_MD_SZ);
        return 1;
    }

    uint8_t *key = malloc(klen);
    if (!key)
    {
        fprintf(stderr, "Failed to allocate memory for key buffer\n");
        return 1;
    }

    uint8_t *msg = malloc(msglen);
    if (!msg)
    {
        fprintf(stderr, "Failed to allocate memory for msg buffer\n");
        free(key);
        return 1;
    }

    if (hex_to_bytes(key_hex, key, klen) != 0)
    {
        fprintf(stderr, "Invalid key: full hex bytes are expected\n");
        free(key);
        free(msg);
        return 1;
    }

    if (hex_to_bytes(msg_hex, msg, msglen) != 0)
    {
        fprintf(stderr, "Invalid test message: full hex bytes are expected\n");
        free(key);
        free(msg);
        return 1;
    }

    hash_fn_t sha = { .fn = sha256, .md_len = SHA256_MD_SZ };

    uint8_t tag[SHA256_MD_SZ];
    if (hmac(&sha, key, klen, msg, msglen, tag) != 0)
    {
        fprintf(stderr, "HMAC operation failed\n");
        free(key);
        free(msg);
        return 1;
    }

    // Truncate the tag to the first tlen bytes (FIPS CAVP Tlen semantics)
    char out[SHA256_MD_SZ * 2U + 1U];
    bytes_to_hex(tag, tlen, out);
    out[tlen * 2] = '\0';

    printf("%s\n", out);

    free(key);
    free(msg);

    return 0;
}
