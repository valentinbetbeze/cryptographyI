#include "hmac.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IPAD (0x36) // HMAC inner pad value
#define OPAD (0x5c) // HMAC outer pad value

#define TO_BYTES(b) ((b) / 8) // Bit to byte conversion macro

/**
 * @brief Hash-based Message Authentication Code algorithm.
 *
 * @param [in]  hash    Description of the underlying hash function
 * @param [in]  key     Secret key
 * @param [in]  keylen  Secret key length in byte
 * @param [in]  msg     Message to authenticate
 * @param [in]  msglen  Message length in byte
 * @param [out] tag     Buffer storing the output message authentication code.
 *                      The size of the buffer must be equal to the digest
 *                      length of the underlying hash in bytes.
 *
 * @return 0 if successful; else 1
 */
int hmac(const hash_descriptor_t *hash,
         const uint8_t *key,
         size_t keylen,
         const uint8_t *msg,
         size_t msglen,
         uint8_t *tag)
{
    int ret         = 0;
    uint8_t *buf    = NULL; // Buffer for intermediate results
    uint8_t *k0     = NULL;
    uint8_t *digest = NULL;
    size_t buflen   = 0;
    size_t l_bytes  = 0; // Length of the output of the underlying hash
    size_t b_bytes  = 0; // Length of the input of the underlying hash

    do
    {
        // Sanity checks on pointers
        if (!hash || !hash->fn || !key || (!msg && msglen != 0) || !tag)
        {
            fprintf(stderr, "Input argument has NULL pointer.\n");
            ret = 1;
            break;
        }

        // Check if the underlying hash algorithm is supported.
        switch (hash->alg)
        {
            case SHA256:
                l_bytes = TO_BYTES(256);
                b_bytes = TO_BYTES(512);
                break;
            case SHA384:
                l_bytes = TO_BYTES(384);
                b_bytes = TO_BYTES(1024);
                break;
            case SHA512:
                l_bytes = TO_BYTES(512);
                b_bytes = TO_BYTES(1024);
                break;
            default:
                fprintf(stderr,
                        "The selected hash function is not supported. Please "
                        "choose between SHA-256, SHA-384, and SHA-512.\n");
                ret = 1;
                break;
        }
        if (ret != 0)
        {
            // Exit the do-while
            break;
        }

        // Limit message length to prevent integer overflows
        if (msglen > SIZE_MAX - b_bytes)
        {
            fprintf(stderr, "Message length is too large.\n");
            ret = 1;
            break;
        }

        // Check key length against FIPS HMAC R2
        if (keylen < TO_BYTES(128))
        {
            fprintf(stderr,
                    "As per FIPS SP 800-224 specification requirement R2, the "
                    "length of the HMAC key shall be at least 128 bits.\n");
            ret = 1;
            break;
        }

        if (keylen > b_bytes)
        {
            fprintf(stderr,
                    "Warning (FIPS SP 800-224 R2): HMAC key is larger than the "
                    "hash block size and will be hashed; this is permitted but "
                    "not recommended.\n");
        }

        // ==================================================
        // Key Processing Stage
        // ==================================================

        k0 = calloc(b_bytes, 1);
        if (!k0)
        {
            fprintf(stderr, "Failed to allocate memory for k0.\n");
            ret = 1;
            break;
        }

        if (keylen <= b_bytes)
        {
            memcpy(k0, key, keylen);
        }
        else
        {
            if (0 != hash->fn(key, keylen, k0))
            {
                fprintf(stderr,
                        "Failed to hash key during key processing stage.\n");
                ret = 1;
                break;
            }
        }

        // ==================================================
        // Output Tag Generation
        // ==================================================

        // Step 1: compute the inner digest
        buflen = b_bytes + ((msglen > l_bytes) ? msglen : l_bytes);
        buf    = (uint8_t *)malloc(buflen);
        if (!buf)
        {
            fprintf(stderr, "Failed to allocate memory for buf.\n");
            ret = 1;
            break;
        }

        memcpy(buf, k0, b_bytes);
        memcpy(buf + b_bytes, msg, msglen);
        for (size_t i = 0; i < b_bytes; i++)
        {
            buf[i] ^= IPAD;
        }

        digest = (uint8_t *)malloc(l_bytes);
        if (!digest)
        {
            fprintf(stderr, "Failed to allocate memory for digest.\n");
            ret = 1;
            break;
        }

        if (0 != hash->fn(buf, b_bytes + msglen, digest))
        {
            fprintf(stderr, "Failed to hash ((K0 ^ IPAD) || M)\n");
            ret = 1;
            break;
        }

        // Step 2: Compute the outer (final) digest
        memcpy(buf, k0, b_bytes);
        memcpy(buf + b_bytes, digest, l_bytes);
        for (size_t i = 0; i < b_bytes; i++)
        {
            buf[i] ^= OPAD;
        }

        if (0 != hash->fn(buf, b_bytes + l_bytes, digest))
        {
            fprintf(stderr, "Failed to hash ((K0 ^ OPAD) || digest)\n");
            ret = 1;
            break;
        }

        // Return tag
        memcpy(tag, digest, l_bytes);

    } while (0);

    // Clean
    if (buf)
    {
        explicit_bzero(buf, buflen);
        free(buf);
    }
    if (k0)
    {
        explicit_bzero(k0, b_bytes);
        free(k0);
    }
    if (digest)
    {
        explicit_bzero(digest, l_bytes);
        free(digest);
    }

    return ret;
}
