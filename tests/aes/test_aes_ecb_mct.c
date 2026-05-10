#include "aes.h"
#include "utils.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if (argc != 5)
    {
        fprintf(stderr,
                "Usage: %s <encrypt|decrypt> <key_len> <key_hex> <data_hex>\n",
                argv[0]);
        return EINVAL;
    }

    const char *operation = argv[1];
    int key_bits          = atoi(argv[2]);
    const char *key_hex   = argv[3];
    const char *data_hex  = argv[4];

    // Determine key length
    aes_key_len_e key_len;
    if (key_bits == 128)
    {
        key_len = AES128_KEY_LEN;
    }
    else if (key_bits == 192)
    {
        key_len = AES192_KEY_LEN;
    }
    else if (key_bits == 256)
    {
        key_len = AES256_KEY_LEN;
    }
    else
    {
        fprintf(stderr, "Invalid key length: %d\n", key_bits);
        return EINVAL;
    }

    // Parse key (convert hex to uint32_t array)
    uint8_t key_bytes[32];
    uint32_t key_words[8];
    size_t key_byte_len = key_bits / 8;

    if (hex_to_bytes(key_hex, key_bytes, key_byte_len) != 0)
    {
        fprintf(stderr, "Invalid key hex\n");
        return EINVAL;
    }

    // Convert bytes to words (big-endian)
    for (size_t i = 0; i < key_len; i++)
    {
        key_words[i] = ((uint32_t)key_bytes[i * 4] << 24) |
                       ((uint32_t)key_bytes[i * 4 + 1] << 16) |
                       ((uint32_t)key_bytes[i * 4 + 2] << 8) |
                       ((uint32_t)key_bytes[i * 4 + 3]);
    }

    // Setup key structure
    aes_key_t key = {.Nk = key_len, .key = key_words};

    // Parse data (16 bytes for AES block)
    uint8_t data_bytes[16];
    uint32_t data_words[4];

    if (hex_to_bytes(data_hex, data_bytes, sizeof(data_bytes)) != 0)
    {
        fprintf(stderr, "Invalid data hex\n");
        return 1;
    }

    // Convert bytes to words (big-endian)
    for (int i = 0; i < 4; i++)
    {
        data_words[i] = ((uint32_t)data_bytes[i * 4] << 24) |
                        ((uint32_t)data_bytes[i * 4 + 1] << 16) |
                        ((uint32_t)data_bytes[i * 4 + 2] << 8) |
                        ((uint32_t)data_bytes[i * 4 + 3]);
    }

    // Initialize AES
    aes_init();

    // Perform ECB Monte Carlo Test
    uint32_t result[4];
    if (strcmp(operation, "encrypt") == 0)
    {
        for (int j = 0; j < 1000; j++)
        {
            aes_encrypt(data_words, result, &key);
            memcpy(data_words, result, sizeof(data_words));
        }
    }
    else if (strcmp(operation, "decrypt") == 0)
    {
        for (int j = 0; j < 1000; j++)
        {
            aes_decrypt(data_words, result, &key);
            memcpy(data_words, result, sizeof(data_words));
        }
    }
    else
    {
        fprintf(stderr, "Invalid operation: %s\n", operation);
        return EINVAL;
    }

    // Convert result to hex and print
    uint8_t result_bytes[16];
    for (int i = 0; i < 4; i++)
    {
        result_bytes[i * 4]     = (result[i] >> 24) & 0xFF;
        result_bytes[i * 4 + 1] = (result[i] >> 16) & 0xFF;
        result_bytes[i * 4 + 2] = (result[i] >> 8) & 0xFF;
        result_bytes[i * 4 + 3] = result[i] & 0xFF;
    }

    char result_hex[33];
    bytes_to_hex(result_bytes, sizeof(result_bytes), result_hex);
    result_hex[32] = '\0';

    printf("%s\n", result_hex);
    return 0;
}
