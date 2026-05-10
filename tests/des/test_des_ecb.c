#include "des.h"
#include "utils.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        fprintf(stderr,
                "Usage: %s <encrypt|decrypt> <key_hex> <data_hex>\n",
                argv[0]);
        return 1;
    }

    const char *operation = argv[1];
    const char *key_hex   = argv[2];
    const char *data_hex  = argv[3];

    // Parse key (8 bytes / 64 bits for DES)
    uint8_t key_bytes[8];
    if (hex_to_bytes(key_hex, key_bytes, 8) != 0)
    {
        fprintf(stderr,
                "Invalid key hex (must be 16 hex chars for 64-bit key)\n");
        return 1;
    }
    uint64_t key = bytes_to_u64(key_bytes);

    // Parse data (8 bytes / 64 bits for DES block)
    uint8_t data_bytes[8];
    if (hex_to_bytes(data_hex, data_bytes, 8) != 0)
    {
        fprintf(stderr,
                "Invalid data hex (must be 16 hex chars for 64-bit block)\n");
        return 1;
    }
    uint64_t data = bytes_to_u64(data_bytes);

    // Perform operation
    uint64_t result;
    if (strcmp(operation, "encrypt") == 0)
    {
        result = des_encrypt(key, data);
    }
    else if (strcmp(operation, "decrypt") == 0)
    {
        result = des_decrypt(key, data);
    }
    else
    {
        fprintf(stderr,
                "Invalid operation: %s (must be 'encrypt' or 'decrypt')\n",
                operation);
        return 1;
    }

    // Convert result to hex and print
    uint8_t result_bytes[8];
    u64_to_bytes(result, result_bytes);

    char result_hex[17];
    bytes_to_hex(result_bytes, 8, result_hex);
    result_hex[16] = '\0';

    printf("%s\n", result_hex);
    return 0;
}
