#include "aes.h"
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
                "Usage: %s decrypt <key_len> <key_hex> <iv_hex> <data_hex>\n",
                argv[0]);
        fprintf(
            stderr,
            "Note: Only decrypt is supported (encrypt not implemented yet)\n");
        return 1;
    }

    const char *operation = argv[1];
    int key_bits          = atoi(argv[2]);
    const char *key_hex   = argv[3];
    const char *iv_hex    = argv[4];
    const char *data_hex  = argv[5];

    // Only support decrypt for now
    if (strcmp(operation, "encrypt") == 0)
    {
        fprintf(stderr, "Encryption not yet implemented\n");
        return 1;
    }

    if (strcmp(operation, "decrypt") != 0)
    {
        fprintf(stderr, "Invalid operation: %s\n", operation);
        return 1;
    }

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
        return 1;
    }

    // Parse key
    size_t key_byte_len = key_bits / 8;
    uint8_t *key_bytes  = malloc(key_byte_len);
    uint32_t *key_words = malloc(key_len * sizeof(uint32_t));

    if (hex_to_bytes(key_hex, key_bytes, key_byte_len) != 0)
    {
        fprintf(stderr, "Invalid key hex\n");
        free(key_bytes);
        free(key_words);
        return 1;
    }
    bytes_to_words(key_bytes, key_words, key_byte_len);

    // Setup key structure
    aes_key_t key = {.Nk = key_len, .key = key_words};

    // Parse IV (16 bytes / 4 words)
    uint8_t iv_bytes[16];
    uint32_t iv_words[4];
    if (hex_to_bytes(iv_hex, iv_bytes, 16) != 0)
    {
        fprintf(stderr, "Invalid IV hex\n");
        free(key_bytes);
        free(key_words);
        return 1;
    }
    bytes_to_words(iv_bytes, iv_words, BLK_SZ);

    uint8_t ct_bytes[BLK_SZ];
    uint32_t ct_words[Nb];
    if (hex_to_bytes(data_hex, ct_bytes, sizeof(ct_bytes)) != 0)
    {
        fprintf(stderr, "Invalid ciphertext hex\n");
        free(key_bytes);
        free(key_words);
        return 1;
    }
    bytes_to_words(ct_bytes, ct_words, sizeof(ct_bytes));

    // Initialize AES
    aes_init();

    // Perform Monte Carlo Test
    uint32_t result[Nb];
    uint32_t tmp[Nb] = {iv_words[0], iv_words[1], iv_words[2], iv_words[3]};

    for (int j = 0; j < 1000; j++)
    {
        int ret = aes_cbc_decrypt(iv_words, ct_words, sizeof(ct_words), result, &key);
        if (ret != 0)
        {
            fprintf(stderr, "Decryption failed with error code: %d\n", ret);
            free(key_bytes);
            free(key_words);
            return 1;
        }

        memcpy(iv_words, ct_words, sizeof(iv_words));
        memcpy(ct_words, tmp, sizeof(ct_words));
        memcpy(tmp, result, sizeof(tmp));
    }

    // Convert result to hex and print
    uint8_t result_bytes[BLK_SZ];
    words_to_bytes(result, result_bytes, sizeof(result_bytes));

    char result_hex[2U * BLK_SZ + 1U];
    bytes_to_hex(result_bytes, sizeof(result_bytes), result_hex);
    result_hex[2U * BLK_SZ] = '\0';

    printf("%s\n", result_hex);

    // Cleanup
    free(key_bytes);
    free(key_words);

    return 0;
}
