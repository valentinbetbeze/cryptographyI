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

    const char *msg = argv[1];
    size_t msg_len = strlen(msg);
    if (msg_len == 0)
    {
        fprintf(stderr, "Invalid message length\n");
        return 1;
    }

    // Convert string to hex
    size_t msg_bytes_len = msg_len / 2;
    uint8_t *msg_bytes = malloc(msg_bytes_len);
    if (!msg_bytes)
    {
        fprintf(stderr, "Failed to allocate memory for msg_bytes buffer\n");
        return 1;
    }

    if (hex_to_bytes(msg, msg_bytes, msg_bytes_len) != 0)
    {
        fprintf(stderr, "Invalid test message: full hex bytes are expected\n");
        free(msg_bytes);
        return 1;
    }

    uint8_t md_bytes[SHA256_DIGEST_SZ];
    if (sha256(msg_bytes, msg_bytes_len, md_bytes) != 0)
    {
        fprintf(stderr, "SHA256 hash operation failed\n");
        free(msg_bytes);
        return 1;
    }

    // Convert digest from byte array to hex string
    const size_t md_len = sizeof(md_bytes) * 2U + 1U;
    char *md = malloc(md_len);
    if (!md)
    {
        fprintf(stderr, "Failed to allocate memory for md buffer\n");
        free(msg_bytes);
        return 1;
    }

    bytes_to_hex(md_bytes, sizeof(md_bytes), md);
    md[md_len - 1U] = '\0';

    printf("%s\n", md);

    // Clean
    free(msg_bytes);
    free(md);

    return 0;
}
