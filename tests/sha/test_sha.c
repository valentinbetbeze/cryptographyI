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

    const char *msg = argv[1];
    int msg_len     = atoi(argv[2]);

    // Convert string to hex
    uint8_t *msg_bytes = malloc(msg_len);
    if (!msg_bytes)
    {
        fprintf(stderr, "Failed to allocate memory for msg_bytes buffer\n");
        return 1;
    }

    if (hex_to_bytes(msg, msg_bytes, msg_len) != 0)
    {
        fprintf(stderr, "Invalid test message: full hex bytes are expected\n");
        free(msg_bytes);
        return 1;
    }

    uint8_t md_bytes[SHA256_MD_SZ];
    if (sha256(msg_bytes, msg_len, md_bytes) != 0)
    {
        fprintf(stderr, "SHA256 hash operation failed\n");
        free(msg_bytes);
        return 1;
    }

    // Convert digest from byte array to hex string
    const size_t md_len = sizeof(md_bytes) * 2U + 1U;
    char *md            = malloc(md_len);
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
