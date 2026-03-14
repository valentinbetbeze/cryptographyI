#include "aes.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

/**
 * @brief AES Cipher Block Chaining decryption using PKCS7 padding scheme.
 *
 * @param[in]  iv    Pointer to 4-word initialization vector (MSB first)
 * @param[in]  ct    Buffer storing the ciphertext (including the IV).
 * @param[in]  sz    Ciphertext size in bytes.
 * @param[out] pt    Buffer to store the decrypted plaintext.
 * @param[in]  k     Secret key
 */
int aes_cbc_decrypt(const uint32_t *iv,
                    const uint32_t *ct,
                    size_t sz,
                    uint32_t *pt,
                    aes_key_t *k)
{
    if (!iv || !ct || sz < BLK_SZ || !pt || !k || !k->key)
    {
        return EINVAL;
    }

    // End address of ciphertext
    const uintptr_t limit = (uintptr_t)ct + sz;

    uint32_t blk0[Nb]  = {iv[0], iv[1], iv[2], iv[3]};
    uint32_t blk1[Nb]  = {0U};
    uint32_t *blk_prev = blk0;
    uint32_t *blk_curr = blk1;

    while ((uintptr_t)ct < limit)
    {
        memcpy(blk_curr, ct, BLK_SZ);
        if (0 != aes_decrypt(blk_curr, pt, k))
        {
            return 1;
        }

        pt[0] ^= blk_prev[0];
        pt[1] ^= blk_prev[1];
        pt[2] ^= blk_prev[2];
        pt[3] ^= blk_prev[3];

        uint32_t *blk = blk_prev;
        blk_prev      = blk_curr;
        blk_curr      = blk;

        ct += 4U;
        pt += 4U;
    }

    return 0;
}
