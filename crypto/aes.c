#include "aes.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

// Reduced polynomial used as module for finite field multiplications.
#define MOD_POLY (0x1BU)

#define AES128_ROUNDS (10U)
#define AES192_ROUNDS (12U)
#define AES256_ROUNDS (14U)

// Lookup tables holding MixColumns() and SubBytes()
static uint32_t t0[256];
static uint32_t t1[256];
static uint32_t t2[256];
static uint32_t t3[256];

// Lookup tables holding InvMixColumns() and InvSubBytes()
static uint32_t t4[256];
static uint32_t t5[256];
static uint32_t t6[256];
static uint32_t t7[256];

static uint8_t sbox[256] = {
    // clang-format off
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    // clang-format on
};

static uint8_t inv_sbox[256] = {
    // clang-format off
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    // clang-format on
};

/**
 * @brief Finite field multiplication of an 8-bit polynomial by 2.
 */
static uint8_t x_times(uint8_t a)
{
    return (a & 0x80U) ? (a << 1) ^ MOD_POLY : (uint8_t)(a << 1);
}

/**
 * @brief Finite field multiplication of two 8-bit polymials.
 */
static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    // Precompute the multiples of a that are powers of 2
    uint8_t mul_p2[8];
    mul_p2[0] = a;
    for (uint8_t i = 1U; i < sizeof(mul_p2) / sizeof(mul_p2[0]); i++)
    {
        mul_p2[i] = x_times(mul_p2[i - 1]);
    }

    // Sum (in Finite Field) each term
    uint8_t r = 0U;
    for (uint8_t i = 0U; i < 8; i++)
    {
        if (b & (1U << i))
        {
            r ^= mul_p2[i];
        }
    }

    return r;
}

/**
 * @brief Helper for Equivalent Inverse Cipher key schedule. Applies
 * inv_mix_columns to a 32-bit word.
 */
static uint32_t inv_mix_columns(uint32_t w)
{
    uint8_t b0 = (w >> 24) & 0xffU;
    uint8_t b1 = (w >> 16) & 0xffU;
    uint8_t b2 = (w >> 8) & 0xffU;
    uint8_t b3 = w & 0xffU;

    // clang-format off
    uint8_t c0 = gf_mul(0x0e, b0) ^ gf_mul(0x0b, b1) ^ gf_mul(0x0d, b2) ^ gf_mul(0x09, b3);
    uint8_t c1 = gf_mul(0x09, b0) ^ gf_mul(0x0e, b1) ^ gf_mul(0x0b, b2) ^ gf_mul(0x0d, b3);
    uint8_t c2 = gf_mul(0x0d, b0) ^ gf_mul(0x09, b1) ^ gf_mul(0x0e, b2) ^ gf_mul(0x0b, b3);
    uint8_t c3 = gf_mul(0x0b, b0) ^ gf_mul(0x0d, b1) ^ gf_mul(0x09, b2) ^ gf_mul(0x0e, b3);
    // clang-format on

    return ((uint32_t)c0 << 24) | ((uint32_t)c1 << 16) | ((uint32_t)c2 << 8) |
           (uint32_t)c3;
}

/**
 * @brief Expand the key into 4-word round keys.
 *
 * @param  k AES key description
 * @param  w Array containing the round keys. 44 words of memory must be
 * provided by the caller function.
 */
static void key_expansion(const aes_key_t *k, uint32_t *w)
{
    assert(k);
    assert(k->key);
    assert(k->Nk == AES128_KEY_LEN || k->Nk == AES192_KEY_LEN ||
           k->Nk == AES256_KEY_LEN);
    assert(w);

    uint8_t rcon        = 1U;
    size_t i            = 0;
    const size_t Nk     = k->Nk;
    const size_t Nr     = k->Nr;
    const uint32_t *key = k->key;

    while (i < Nk)
    {
        w[i] = key[i];
        i++;
    }
    while (i < Nb * (Nr + 1))
    {
        uint32_t tmp = w[i - 1];
        if (i % Nk == 0U)
        {
            tmp = (sbox[(tmp >> 16) & 0xff] << 24) |
                  (sbox[(tmp >> 8) & 0xff] << 16) |
                  (sbox[(tmp >> 0) & 0xff] << 8) |
                  (sbox[(tmp >> 24) & 0xff] << 0);
            tmp ^= (uint32_t)rcon << 24;
            rcon = x_times(rcon);
        }
        else
        {
            if (Nk == AES256_KEY_LEN && (i % Nk == 4U))
            {
                tmp = (sbox[(tmp >> 24) & 0xff] << 24) |
                      (sbox[(tmp >> 16) & 0xff] << 16) |
                      (sbox[(tmp >> 8) & 0xff] << 8) |
                      (sbox[(tmp >> 0) & 0xff] << 0);
            }
        }
        w[i] = w[i - Nk] ^ tmp;
        i++;
    }
}

/**
 * @brief Key expansion function for the equivalent inverse cipher
 * implementation.
 *
 * @param[in]  k AES key
 * @param[out] w Round keys
 */
static void key_expansion_eic(const aes_key_t *k, uint32_t *w)
{
    assert(k);
    assert(k->key);
    assert(k->Nk == AES128_KEY_LEN || k->Nk == AES192_KEY_LEN ||
           k->Nk == AES256_KEY_LEN);
    assert(w);

    key_expansion(k, w);
    for (size_t r = 1U; r < k->Nr; r++)
    {
        w[Nb * r + 0U] = inv_mix_columns(w[Nb * r + 0U]);
        w[Nb * r + 1U] = inv_mix_columns(w[Nb * r + 1U]);
        w[Nb * r + 2U] = inv_mix_columns(w[Nb * r + 2U]);
        w[Nb * r + 3U] = inv_mix_columns(w[Nb * r + 3U]);
    }
}

/**
 * @brief AES cipher.
 *
 * @param[in]  in  Array of input words to encipher
 * @param[out] out Placeholder for enciphered words
 * @param[in]  nr  Number of rounds
 * @param[in]  rk  Array of round keys
 */
static void cipher(const uint32_t *in,
                   uint32_t *out,
                   size_t nr,
                   const uint32_t *rk)
{
    assert(in);
    assert(out);
    assert(rk);
    assert(nr == AES128_ROUNDS || nr == AES192_ROUNDS || nr == AES256_ROUNDS);

    uint32_t t[Nb];
    uint32_t s[Nb] = {
        in[0] ^ rk[0],
        in[1] ^ rk[1],
        in[2] ^ rk[2],
        in[3] ^ rk[3],
    };

    // clang-format off
    for (size_t r = 1U; r < nr; r++)
    {
        t[0] = t0[s[0] >> 24] ^ t1[(s[1] >> 16) & 0xff] ^ t2[(s[2] >> 8) & 0xff] ^ t3[s[3] & 0xff] ^ rk[Nb*r+0U];
        t[1] = t0[s[1] >> 24] ^ t1[(s[2] >> 16) & 0xff] ^ t2[(s[3] >> 8) & 0xff] ^ t3[s[0] & 0xff] ^ rk[Nb*r+1U];
        t[2] = t0[s[2] >> 24] ^ t1[(s[3] >> 16) & 0xff] ^ t2[(s[0] >> 8) & 0xff] ^ t3[s[1] & 0xff] ^ rk[Nb*r+2U];
        t[3] = t0[s[3] >> 24] ^ t1[(s[0] >> 16) & 0xff] ^ t2[(s[1] >> 8) & 0xff] ^ t3[s[2] & 0xff] ^ rk[Nb*r+3U];

        s[0] = t[0];
        s[1] = t[1];
        s[2] = t[2];
        s[3] = t[3];
    }

    out[0] = (sbox[s[0] >> 24] << 24) ^ (sbox[(s[1] >> 16) & 0xff] << 16) ^ (sbox[(s[2] >> 8) & 0xff] << 8) ^ sbox[s[3] & 0xff] ^ rk[Nb*nr+0U];
    out[1] = (sbox[s[1] >> 24] << 24) ^ (sbox[(s[2] >> 16) & 0xff] << 16) ^ (sbox[(s[3] >> 8) & 0xff] << 8) ^ sbox[s[0] & 0xff] ^ rk[Nb*nr+1U];
    out[2] = (sbox[s[2] >> 24] << 24) ^ (sbox[(s[3] >> 16) & 0xff] << 16) ^ (sbox[(s[0] >> 8) & 0xff] << 8) ^ sbox[s[1] & 0xff] ^ rk[Nb*nr+2U];
    out[3] = (sbox[s[3] >> 24] << 24) ^ (sbox[(s[0] >> 16) & 0xff] << 16) ^ (sbox[(s[1] >> 8) & 0xff] << 8) ^ sbox[s[2] & 0xff] ^ rk[Nb*nr+3U];
    // clang-format on
}

/**
 * @brief AES equivalent inverse cipher
 *
 * @param[in]  in  Array of input words to decipher
 * @param[out] out Placeholder for enciphered words
 * @param[in]  nr  Number of rounds
 * @param[in]  rk  Array of round keys
 */
static void eq_inv_cipher(const uint32_t *in,
                          uint32_t *out,
                          size_t nr,
                          const uint32_t *rk)
{
    assert(in);
    assert(out);
    assert(rk);
    assert(nr == AES128_ROUNDS || nr == AES192_ROUNDS || nr == AES256_ROUNDS);

    uint32_t t[Nb];
    uint32_t s[Nb] = {in[0] ^ rk[Nb * nr + 0],
                      in[1] ^ rk[Nb * nr + 1],
                      in[2] ^ rk[Nb * nr + 2],
                      in[3] ^ rk[Nb * nr + 3]};

    // clang-format off
    for (size_t r = nr - 1U; r > 0U; r--)
    {
        t[0] = t4[s[0] >> 24] ^ t5[(s[3] >> 16) & 0xff] ^ t6[(s[2] >> 8) & 0xff] ^ t7[s[1] & 0xff] ^ rk[Nb*r+0U];
        t[1] = t4[s[1] >> 24] ^ t5[(s[0] >> 16) & 0xff] ^ t6[(s[3] >> 8) & 0xff] ^ t7[s[2] & 0xff] ^ rk[Nb*r+1U];
        t[2] = t4[s[2] >> 24] ^ t5[(s[1] >> 16) & 0xff] ^ t6[(s[0] >> 8) & 0xff] ^ t7[s[3] & 0xff] ^ rk[Nb*r+2U];
        t[3] = t4[s[3] >> 24] ^ t5[(s[2] >> 16) & 0xff] ^ t6[(s[1] >> 8) & 0xff] ^ t7[s[0] & 0xff] ^ rk[Nb*r+3U];

        s[0] = t[0];
        s[1] = t[1];
        s[2] = t[2];
        s[3] = t[3];
    }

    out[0] = (inv_sbox[s[0] >> 24] << 24) ^ (inv_sbox[(s[3] >> 16) & 0xff] << 16) ^ (inv_sbox[(s[2] >> 8) & 0xff] << 8) ^ inv_sbox[s[1] & 0xff] ^ rk[0];
    out[1] = (inv_sbox[s[1] >> 24] << 24) ^ (inv_sbox[(s[0] >> 16) & 0xff] << 16) ^ (inv_sbox[(s[3] >> 8) & 0xff] << 8) ^ inv_sbox[s[2] & 0xff] ^ rk[1];
    out[2] = (inv_sbox[s[2] >> 24] << 24) ^ (inv_sbox[(s[1] >> 16) & 0xff] << 16) ^ (inv_sbox[(s[0] >> 8) & 0xff] << 8) ^ inv_sbox[s[3] & 0xff] ^ rk[2];
    out[3] = (inv_sbox[s[3] >> 24] << 24) ^ (inv_sbox[(s[2] >> 16) & 0xff] << 16) ^ (inv_sbox[(s[1] >> 8) & 0xff] << 8) ^ inv_sbox[s[0] & 0xff] ^ rk[3];
    // clang-format on
}

/**
 * @brief Precomputes the lookup tables embedding the SubBytes and MixColumns
 * operations.
 */
void aes_init(void)
{
    for (size_t i = 0U; i < 256U; i++)
    {
        uint32_t s1 = sbox[i];
        uint32_t s2 = gf_mul(2, sbox[i]);
        uint32_t s3 = gf_mul(3, sbox[i]);

        uint32_t se = gf_mul(0xe, inv_sbox[i]);
        uint32_t s9 = gf_mul(0x9, inv_sbox[i]);
        uint32_t sd = gf_mul(0xd, inv_sbox[i]);
        uint32_t sb = gf_mul(0xb, inv_sbox[i]);

        t0[i] = (s2 << 24) ^ (s1 << 16) ^ (s1 << 8) ^ s3;
        t1[i] = (s3 << 24) ^ (s2 << 16) ^ (s1 << 8) ^ s1;
        t2[i] = (s1 << 24) ^ (s3 << 16) ^ (s2 << 8) ^ s1;
        t3[i] = (s1 << 24) ^ (s1 << 16) ^ (s3 << 8) ^ s2;

        t4[i] = (se << 24) ^ (s9 << 16) ^ (sd << 8) ^ sb;
        t5[i] = (sb << 24) ^ (se << 16) ^ (s9 << 8) ^ sd;
        t6[i] = (sd << 24) ^ (sb << 16) ^ (se << 8) ^ s9;
        t7[i] = (s9 << 24) ^ (sd << 16) ^ (sb << 8) ^ se;
    }
}

/**
 * @brief AES encryption function
 *
 * @param[in]  pt Plaintext to encrypt
 * @param[out] ct Resulting ciphertext
 * @param[in]  k  AES secret key
 *
 * @return 0 if successful; else error code.
 */
int aes_encrypt(const uint32_t *pt, uint32_t *ct, aes_key_t *k)
{
    if (!pt || !ct || !k || !k->key)
    {
        return EINVAL;
    }
    if (k->Nk != AES128_KEY_LEN && k->Nk != AES192_KEY_LEN &&
        k->Nk != AES256_KEY_LEN)
    {
        return EINVAL;
    }

    k->Nr = (k->Nk == AES128_KEY_LEN) ? AES128_ROUNDS :
            (k->Nk == AES192_KEY_LEN) ? AES192_ROUNDS :
                                        AES256_ROUNDS;

    // Maximum number of round keys is given by AES-256.
    uint32_t rk[Nb * (AES256_ROUNDS + 1U)];
    key_expansion(k, rk);

    cipher(pt, ct, k->Nr, rk);

    return 0;
}

/**
 * @brief AES decryption function
 *
 * @param[in]  ct Ciphertext to decrypt
 * @param[out] pt Resulting plaintext
 * @param[in]  k  AES secret key
 *
 * @return 0 if successful; else error code.
 */
int aes_decrypt(const uint32_t *ct, uint32_t *pt, aes_key_t *k)
{
    if (!pt || !ct || !k || !k->key)
    {
        return EINVAL;
    }
    if (k->Nk != AES128_KEY_LEN && k->Nk != AES192_KEY_LEN &&
        k->Nk != AES256_KEY_LEN)
    {
        return EINVAL;
    }

    k->Nr = (k->Nk == AES128_KEY_LEN) ? AES128_ROUNDS :
            (k->Nk == AES192_KEY_LEN) ? AES192_ROUNDS :
                                        AES256_ROUNDS;

    // Maximum number of round keys is determined by AES-256.
    uint32_t rk[Nb * (AES256_ROUNDS + 1U)];
    key_expansion_eic(k, rk);

    eq_inv_cipher(ct, pt, k->Nr, rk);

    return 0;
}
