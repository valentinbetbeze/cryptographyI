#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stdlib.h>

#define Nb     (4U)                    // Number of words in a block
#define BLK_SZ (Nb * sizeof(uint32_t)) // Size of a block in byte

/**
 * @brief Key length in words.
 */
typedef enum
{
    AES128_KEY_LEN = 4U,
    AES192_KEY_LEN = 6U,
    AES256_KEY_LEN = 8U,

} aes_key_len_e;

/**
 * @brief AES key descriptor.
 */
typedef struct
{
    // Public
    aes_key_len_e Nk;
    uint32_t *key;

    // Private
    uint8_t Nr;

} aes_key_t;

void aes_init(void);

// Core AES
int aes_encrypt(const uint32_t *pt, uint32_t *ct, aes_key_t *k);
int aes_decrypt(const uint32_t *ct, uint32_t *pt, aes_key_t *k);

// AES w/ modes of operation
int aes_cbc_decrypt(const uint32_t *iv,
                    const uint32_t *ct,
                    size_t sz,
                    uint32_t *pt,
                    aes_key_t *k);
int aes_ctr_decrypt(const uint32_t *iv,
                    const uint32_t *ct,
                    size_t sz,
                    uint32_t *pt,
                    aes_key_t *k);

#endif // AES_H
