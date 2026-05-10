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
    bytes_to_words(iv_bytes, iv_words, 16);

    // Parse ciphertext (variable length for multi-block)
    size_t ct_len = strlen(data_hex) / 2;
    if (ct_len % 16 != 0)
    {
        fprintf(stderr,
                "Ciphertext length must be multiple of 16 bytes (got %zu)\n",
                ct_len);
        free(key_bytes);
        free(key_words);
        return 1;
    }

    uint8_t *ct_bytes  = malloc(ct_len);
    uint32_t *ct_words = malloc(ct_len);
    if (hex_to_bytes(data_hex, ct_bytes, ct_len) != 0)
    {
        fprintf(stderr, "Invalid ciphertext hex\n");
        free(key_bytes);
        free(key_words);
        free(ct_bytes);
        free(ct_words);
        return 1;
    }
    bytes_to_words(ct_bytes, ct_words, ct_len);

    // Initialize AES
    aes_init();

    // Perform decryption
    uint32_t *result = malloc(ct_len);
    int ret = aes_cbc_decrypt(iv_words, ct_words, ct_len, result, &key);

    if (ret != 0)
    {
        fprintf(stderr, "Decryption failed with error code: %d\n", ret);
        free(key_bytes);
        free(key_words);
        free(ct_bytes);
        free(ct_words);
        free(result);
        return 1;
    }

    // Convert result to hex and print
    uint8_t *result_bytes = malloc(ct_len);
    words_to_bytes(result, result_bytes, ct_len);

    char *result_hex = malloc(ct_len * 2 + 1);
    bytes_to_hex(result_bytes, ct_len, result_hex);
    result_hex[ct_len * 2] = '\0';

    printf("%s\n", result_hex);

    // Cleanup
    free(key_bytes);
    free(key_words);
    free(ct_bytes);
    free(ct_words);
    free(result);
    free(result_bytes);
    free(result_hex);

    return 0;
}
