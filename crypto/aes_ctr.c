#include "aes.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

/**
 * @brief AES Counter-mode decryption.
 *
 * @param[in]  iv    Pointer to 4-word initialization vector (MSB first)
 * @param[in]  ct    Ciphertext
 * @param[in]  sz    Ciphertext size in bytes
 * @param[out] pt    Buffer to store the decrypted plaintext
 * @param[in]  key   Secret key
 */
int aes_ctr_decrypt(const uint32_t *iv,
                    const uint32_t *ct,
                    size_t sz,
                    uint32_t *pt,
                    aes_key_t *k)
{
    if (!iv || !ct || sz < BLK_SZ || !pt || !k || !k->key)
    {
        return EINVAL;
    }

    const size_t num_blk = sz / BLK_SZ;
    uint32_t iv_cpy[Nb]  = {iv[0], iv[1], iv[2], iv[3]};

    for (size_t i_blk = 0U; i_blk < num_blk; i_blk++)
    {
        uint32_t iv_enc[Nb] = {0U};
        size_t i_w          = i_blk * Nb; // current word index

        int ret = aes_encrypt(iv_cpy, iv_enc, k);
        if (ret != 0)
        {
            return ret;
        }

        pt[i_w + 0U] = ct[i_w + 0U] ^ iv_enc[0];
        pt[i_w + 1U] = ct[i_w + 1U] ^ iv_enc[1];
        pt[i_w + 2U] = ct[i_w + 2U] ^ iv_enc[2];
        pt[i_w + 3U] = ct[i_w + 3U] ^ iv_enc[3];

        // Increment IV and propagate the carry
        for (int j = 3; j >= 0; j--)
        {
            if (++iv_cpy[j] != 0U)
            {
                break;
            }
        }
    }

    return 0;
}
