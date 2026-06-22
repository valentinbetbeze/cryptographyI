#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Descriptor of the hash function to use with the keyed HMAC.
 */
typedef struct hash_fn_t
{
    int (*fn)(const uint8_t *, size_t, uint8_t *); // Hash function pointer
    size_t md_len; // Hash's message digest length in byte

} hash_fn_t;

/**
 * @brief Hash-based Message Authentication Code algorithm.
 *
 * @param [in]  hash    Description of the underlying hash function
 * @param [in]  key     Secret key
 * @param [in]  keylen  Secret key length in byte
 * @param [in]  msg     Message to authenticate
 * @param [in]  msglen  Message length in byte
 * @param [out] tag     Output message authentication code
 *
 * @return 0 if successful; else 1
 */
int hmac(const hash_fn_t *hash,
         const uint8_t *key,
         size_t keylen,
         const uint8_t *msg,
         size_t msglen,
         uint8_t *tag);

#endif // HMAC_H
