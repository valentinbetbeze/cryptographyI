#include "aes.h"
#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define IV_SIZE (BLK_SZ) // IV size in bytes

/**
 * @brief Remove PKCS7 padding from a given 16-byte block.
 *
 * @param[in] blk Start address of the 4-word block
 *
 * @return 0 if successful; else 1.
 */
static int remove_pkcs7_padding(uint32_t *blk)
{
    assert(blk);

    /* Bytes in words are stored MSB first, hence the 'last' byte is the 12th
       byte from the start of the block. */
    size_t i_blk   = 3U;
    uint8_t *pbyte = (uint8_t *)&blk[i_blk];

    // Check the last byte value
    uint8_t padding_bytes = blk[3] & 0xff;
    if (padding_bytes > BLK_SZ)
    {
        fprintf(stderr, "Found invalid padding, aborting.\n");
        return 1;
    }

    while (padding_bytes-- > 0U)
    {
        // clear the padding byte
        *pbyte = 0U;
        padding_bytes--;

        // move to next padding byte
        if (padding_bytes % sizeof(uint32_t) == 0U)
        {
            i_blk--;
            pbyte = (uint8_t *)&blk[i_blk];
        }
        else
        {
            pbyte++;
        }
    }

    return 0;
}

/**
 * @brief Print an MSB-first plaintext.
 *
 * @param[in] pt Plaintext to print
 * @param sz
 */
static void print_msb_plaintext(const uint32_t *pt, size_t sz)
{
    assert(pt);

    uint32_t *w = (uint32_t *)pt; // word-based pointer
    char *b     = (char *)w + 3U; // byte-based pointer, start at first MSB

    while (sz--)
    {
        putc(*b, stdout);
        if ((uintptr_t)b == (uintptr_t)w)
        {
            w++;
            b = (char *)w + 3U;
        }
        else
        {
            b--;
        }
    }

    putc('\n', stdout);
}

int main(void)
{
    /* In this project, we have two encryption/decryption systems:

           AES in CBC mode
           AES in counter mode (CTR)

       In both cases the 16-byte encryption IV is chosen at random and is
       prepended to the ciphertext. For CBC encryption, we use the PKCS7 padding
       scheme.

       In this assignment, we are given an AES key and a ciphertext (both are
       hex encoded) and our goal is to recover the plaintext. */

    char k1[] = "140b41b22a29beb4061bda66b6747e14";
    char k3[] = "36f18357be4dbd77f050515c73fcf9f2";

    char ct1[] =
        "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a789"
        "7ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
    char ct2[] =
        "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac"
        "646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";
    char ct3[] =
        "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20"
        "fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d5"
        "9ce29f5f51eeca32eabedd9afa9329";
    char ct4[] =
        "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa895"
        "2aa0e311bde9d4e01726d3184c34451";

    // Parse keys
    uint8_t k1_bytes[(sizeof(k1) - 1U) / 2U]               = {0U};
    uint32_t k1_words[sizeof(k1_bytes) / sizeof(uint32_t)] = {0U};
    hex_to_bytes(k1, k1_bytes, sizeof(k1));
    bytes_to_words(k1_bytes, k1_words, sizeof(k1_bytes));

    uint8_t k3_bytes[(sizeof(k3) - 1U) / 2U]               = {0U};
    uint32_t k3_words[sizeof(k3_bytes) / sizeof(uint32_t)] = {0U};
    hex_to_bytes(k3, k3_bytes, sizeof(k3));
    bytes_to_words(k3_bytes, k3_words, sizeof(k3_bytes));

    aes_key_t aes_key1 = {.Nk = AES128_KEY_LEN, .key = k1_words};
    aes_key_t aes_key3 = {.Nk = AES128_KEY_LEN, .key = k3_words};

    // Get IVs
    uint8_t iv1_bytes[IV_SIZE] = {0U};
    uint32_t iv1_words[Nb]     = {0U};
    hex_to_bytes(ct1, iv1_bytes, sizeof(iv1_bytes));
    bytes_to_words(iv1_bytes, iv1_words, sizeof(iv1_bytes));

    uint8_t iv2_bytes[IV_SIZE] = {0U};
    uint32_t iv2_words[Nb]     = {0U};
    hex_to_bytes(ct2, iv2_bytes, sizeof(iv2_bytes));
    bytes_to_words(iv2_bytes, iv2_words, sizeof(iv2_bytes));

    uint8_t iv3_bytes[IV_SIZE] = {0U};
    uint32_t iv3_words[Nb]     = {0U};
    hex_to_bytes(ct3, iv3_bytes, sizeof(iv3_bytes));
    bytes_to_words(iv3_bytes, iv3_words, sizeof(iv3_bytes));

    uint8_t iv4_bytes[IV_SIZE] = {0U};
    uint32_t iv4_words[Nb]     = {0U};
    hex_to_bytes(ct4, iv4_bytes, sizeof(iv4_bytes));
    bytes_to_words(iv4_bytes, iv4_words, sizeof(iv4_bytes));

    // Parse ciphertexts
    uint8_t ct1_bytes[(sizeof(ct1) - 1U) / 2U - IV_SIZE]     = {0U};
    uint32_t ct1_words[sizeof(ct1_bytes) / sizeof(uint32_t)] = {0U};
    hex_to_bytes(&ct1[IV_SIZE * 2], ct1_bytes, sizeof(ct1_bytes));
    bytes_to_words(ct1_bytes, ct1_words, sizeof(ct1_bytes));

    uint8_t ct2_bytes[(sizeof(ct2) - 1U) / 2U - IV_SIZE]     = {0U};
    uint32_t ct2_words[sizeof(ct2_bytes) / sizeof(uint32_t)] = {0U};
    hex_to_bytes(&ct2[IV_SIZE * 2], ct2_bytes, sizeof(ct2_bytes));
    bytes_to_words(ct2_bytes, ct2_words, sizeof(ct2_bytes));

    uint8_t ct3_bytes[(sizeof(ct3) - 1U) / 2U - IV_SIZE]          = {0U};
    uint32_t ct3_words[sizeof(ct3_bytes) / sizeof(uint32_t) + 1U] = {0U};
    hex_to_bytes(&ct3[IV_SIZE * 2], ct3_bytes, sizeof(ct3_bytes));
    bytes_to_words(ct3_bytes, ct3_words, sizeof(ct3_bytes));

    uint8_t ct4_bytes[(sizeof(ct4) - 1U) / 2U + 2U - IV_SIZE]     = {0U};
    uint32_t ct4_words[sizeof(ct4_bytes) / sizeof(uint32_t) + 1U] = {0U};
    hex_to_bytes(&ct4[IV_SIZE * 2], ct4_bytes, sizeof(ct4_bytes));
    bytes_to_words(ct4_bytes, ct4_words, sizeof(ct4_bytes));

    // Buffer for plaintext result
    uint32_t pt[256] = {0};
    char *const p    = (char *)pt;

    aes_init();

    // ----------- Problem 1 -----------

    if (aes_cbc_decrypt(iv1_words,
                        ct1_words,
                        sizeof(ct1_words),
                        pt,
                        &aes_key1) != 0)
    {
        fprintf(stderr, "Error decrypting ciphertext 1\n");
        return 1;
    }
    remove_pkcs7_padding(&pt[sizeof(ct1_words) - Nb]);
    print_msb_plaintext(pt, sizeof(ct1_bytes));
    memset(pt, 0, sizeof(pt));

    // ----------- Problem 2 -----------

    if (aes_cbc_decrypt(iv2_words,
                        ct2_words,
                        sizeof(ct2_words),
                        pt,
                        &aes_key1) != 0)
    {
        fprintf(stderr, "Error decrypting ciphertext 2\n");
        return 1;
    }
    remove_pkcs7_padding(&pt[sizeof(ct2_words) - Nb]);
    print_msb_plaintext(pt, sizeof(ct2_bytes));
    memset(pt, 0, sizeof(pt));

    // ----------- Problem 3 -----------

    if (aes_ctr_decrypt(iv3_words,
                        ct3_words,
                        sizeof(ct3_words),
                        pt,
                        &aes_key3) != 0)
    {
        fprintf(stderr, "Error decrypting ciphertext 3\n");
        return 1;
    }
    print_msb_plaintext(pt, sizeof(ct3_bytes));
    memset(pt, 0, sizeof(pt));

    // ----------- Problem 4 -----------

    if (aes_ctr_decrypt(iv4_words,
                        ct4_words,
                        sizeof(ct4_words),
                        pt,
                        &aes_key3) != 0)
    {
        fprintf(stderr, "Error decrypting ciphertext 4\n");
        return 1;
    }
    print_msb_plaintext(pt, sizeof(ct4_words));
    memset(pt, 0, sizeof(pt));

    return 0;
}
