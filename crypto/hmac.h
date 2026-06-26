#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Underlying hash algorithm supported by this HMAC implementation.
 */
typedef enum hash_alg_t
{
    SHA256 = 1,
    SHA384 = 2,
    SHA512 = 3,
} hash_alg_t;

/**
 * @brief Descriptor of the hash function to use with the keyed HMAC.
 */
typedef struct hash_descriptor_t
{
    hash_alg_t alg; // Underlying hash algorithm to use
    int (*fn)(const uint8_t *, size_t, uint8_t *); // Hash function pointer
} hash_descriptor_t;

int hmac(const hash_descriptor_t *hash,
         const uint8_t *key,
         size_t keylen,
         const uint8_t *msg,
         size_t msglen,
         uint8_t *tag);

#endif // HMAC_H
