#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define FEISTEL_ROUNDS (16U)
#define MASK_28BITS    ((1U << 28) - 1U)

/**
 * @brief DES permutation table id
 */
typedef enum des_table_e
{
    DES_IP = 0,
    DES_FP,
    DES_E,
    DES_P,
    DES_PC1,
    DES_PC2,

    DES_NUM_TABLE,

} des_table_e;

/**
 * @brief Permute a number based on a DES permutation table.
 *
 * @param[in] in Input number.
 * @param[in] id Permutation table to use.
 *
 * @return Permutated number.
 */
static uint64_t des_permute(uint64_t in, des_table_e id)
{
    assert(id < DES_NUM_TABLE);

    // clang-format off
    static const uint8_t IP[64] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };
    static const uint8_t FP[64] = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41,  9, 49, 17, 57, 25
    };
    static const uint8_t E[48] = {
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
    };
    static const uint8_t P[32] = {
        16,  7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26,  5, 18, 31, 10,
         2,  8, 24, 14, 32, 27,  3,  9,
        19, 13, 30,  6, 22, 11,  4, 25
    };
    static const uint8_t PC1[56] = {
        57, 49, 41, 33, 25, 17,  9,  1,
        58, 50, 42, 34, 26, 18, 10,  2,
        59, 51, 43, 35, 27, 19, 11,  3,
        60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15,  7, 62, 54, 46, 38,
        30, 22, 14,  6, 61, 53, 45, 37,
        29, 21, 13,  5, 28, 20, 12,  4
    };
    static const uint8_t PC2[48] = {
        14, 17, 11, 24,  1,  5,  3, 28,
        15,  6, 21, 10, 23, 19, 12,  4,
        26,  8, 16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
    };
    // clang-format on

    struct perm_t
    {
        const uint8_t *t;
        const size_t in_width;
        const size_t out_width;
    };

    static const struct perm_t tables[] = {
        {&IP[0], 64U, 64U},
        {&FP[0], 64U, 64U},
        {&E[0], 32U, 48U},
        {&P[0], 32U, 32U},
        {&PC1[0], 64U, 56U},
        {&PC2[0], 56U, 48U},
    };
    const struct perm_t *perm = &tables[id];

    if (perm->in_width < 64U)
    {
        in &= ((1LU << perm->in_width) - 1LU);
    }

    uint64_t output = 0U;

    for (size_t i = 0U; i < perm->out_width; i++)
    {
        const uint64_t bit = (in >> (perm->in_width - perm->t[i])) & 1U;
        output |= bit << (perm->out_width - 1U - i);
    }

    return output;
}

/**
 * @brief Substitue a number based on a DES substitution table (s-box).
 *
 * @param[in] i Substitution table index: {1..8}
 * @param[in] x Input value.
 *
 * @return Substitued value.
 */
static uint8_t des_substitute(uint8_t i, uint8_t x)
{
    // clang-format off
    static const uint8_t S[8][4][16] =
    {
        // S1
        {
            {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
            { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
            { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
            {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
        },
        // S2
        {
            {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
            { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
            { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
            {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
        },
        // S3
        {
            {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
            {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
            {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
            { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
        },
        // S4
        {
            { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
            {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
            {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
            { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
        },
        // S5
        {
            { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
            {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
            { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
            {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
        },
        // S6
        {
            {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
            {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
            { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
            { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
        },
        // S7
        {
            { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
            {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
            { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
            { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
        },
        {
            {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
            { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
            { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
            { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
        },
    };
    // clang-format on

    assert(x < 64);
    assert(i < 9 && i > 0);

    const uint8_t row = ((x >> 4) & 0x2U) | (x & 1U);
    const uint8_t col = ((x >> 1) & 0xfU);

    return S[i - 1][row][col];
}

/**
 * @brief DES F function
 *
 * @param[in] ki Round key.
 * @param[in] x  32-bit block.
 *
 * @return 32-bit output block.
 */
static uint32_t des_f(uint64_t ki, uint32_t x)
{
    const uint64_t exk = ki ^ des_permute(x, DES_E);
    const uint32_t s_exk =
        ((uint32_t)des_substitute(1, (exk >> 42) & 0x3fU) << 28) |
        ((uint32_t)des_substitute(2, (exk >> 36) & 0x3fU) << 24) |
        ((uint32_t)des_substitute(3, (exk >> 30) & 0x3fU) << 20) |
        ((uint32_t)des_substitute(4, (exk >> 24) & 0x3fU) << 16) |
        ((uint32_t)des_substitute(5, (exk >> 18) & 0x3fU) << 12) |
        ((uint32_t)des_substitute(6, (exk >> 12) & 0x3fU) << 8) |
        ((uint32_t)des_substitute(7, (exk >> 6) & 0x3fU) << 4) |
        ((uint32_t)des_substitute(8, (exk >> 0) & 0x3fU) << 0);

    return des_permute(s_exk, DES_P);
}

/**
 * @brief Compute the DES round keys based on the 64-bit key.
 *
 * @param[in]  key  64-bit secret key.
 * @param[out] rkey Array to store the computed round keys.
 *
 * @warning rkey array must be large enough to store 16 64-bit integers.
 */
static void des_get_round_keys(uint64_t key, uint64_t *rkey)
{
    assert(rkey != NULL);

    const uint64_t kpc1 = des_permute(key, DES_PC1);
    uint32_t c          = (kpc1 >> 28) & MASK_28BITS;
    uint32_t d          = kpc1 & MASK_28BITS;

    for (uint8_t i = 0U; i < FEISTEL_ROUNDS; i++)
    {
        static const uint8_t ROT[] =
            {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

        // Left rotation
        const unsigned int shift = ROT[i];
        c = ((c << shift) | (c >> (28U - shift))) & MASK_28BITS;
        d = ((d << shift) | (d >> (28U - shift))) & MASK_28BITS;

        // Permutated choice 2
        const uint64_t tmp = (uint64_t)c << 28 | (uint64_t)d;
        rkey[i]            = des_permute(tmp, DES_PC2);
    }
}

/**
 * @brief DES encryption/decryption algorithm.
 *
 * @param[in] key     Secret key.
 * @param[in] block   Input block.
 * @param[in] encrypt Encryption/Decryption switch.
 *
 * @return Encrypted/Decrypted block.
 */
uint64_t des(uint64_t key, uint64_t block, bool encrypt)
{
    // Compute all round keys
    uint64_t rkey[16] = {0};
    des_get_round_keys(key, &rkey[0]);

    // Initial permutation
    const uint64_t m = des_permute(block, DES_IP);
    uint32_t l       = (uint32_t)(m >> 32);
    uint32_t r       = (uint32_t)m;

    // 16-rounds feistel network
    for (size_t i = 0U; i < FEISTEL_ROUNDS; i++)
    {
        const size_t round = (encrypt) ? i : (FEISTEL_ROUNDS - 1U) - i;
        uint32_t tmp       = r;

        r = l ^ des_f(rkey[round], r);
        l = tmp;
    }

    // Final permutation
    const uint64_t preoutput = ((uint64_t)r << 32) | (uint64_t)l;
    return des_permute(preoutput, DES_FP);
}
