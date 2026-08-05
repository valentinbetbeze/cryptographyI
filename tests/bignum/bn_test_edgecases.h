#ifndef BN_TEST_EDGECASES_H
#define BN_TEST_EDGECASES_H

#include <stdbool.h>

/**
 * Curated magnitude strings covering zero, one, and exact word/limb
 * boundaries (bignum.c treats buffers as arrays of uint32_t words, so 2^32
 * and 2^64 boundaries are where carry-propagation bugs cluster).
 */
static const char *bn_edge_magnitudes[] = {
    "0",
    "1",
    "2",
    "4294967295",                              // 2^32 - 1
    "4294967296",                              // 2^32
    "4294967297",                              // 2^32 + 1
    "18446744073709551615",                    // 2^64 - 1
    "18446744073709551616",                    // 2^64
    "18446744073709551617",                    // 2^64 + 1
    "340282366920938463463374607431768211455", // 2^128 - 1
    // ~470-bit scale value for coverage beyond small boundary cases.
    "32317006071311007300714876688669951960444102"
    "66716662868294783267521580466514540754147241"
    "31494613571617023329880178521022590259901468"
    "9758374231",
};

#define BN_EDGE_MAGNITUDES_COUNT                                               \
    (sizeof(bn_edge_magnitudes) / sizeof(bn_edge_magnitudes[0]))

/* All four sign combinations for binary signed ops (+/+, +/-, -/+, -/-). */
typedef struct
{
    bool neg_a;
    bool neg_b;
} bn_sign_combo_t;

static const bn_sign_combo_t bn_sign_combos[] = {
    {false, false},
    {false, true},
    {true, false},
    {true, true},
};

#define BN_SIGN_COMBOS_COUNT                                                   \
    (sizeof(bn_sign_combos) / sizeof(bn_sign_combos[0]))

/* Curated (base, exp, mod) triples for bn_modexp; a full cross-product of
 * bn_edge_magnitudes^3 would combinatorially explode, so this is a small,
 * deliberately chosen set instead. */
typedef struct
{
    const char *base;
    const char *exp;
    const char *mod;
} bn_modexp_case_t;

static const bn_modexp_case_t bn_modexp_cases[] = {
    {"2", "10", "1000"},
    {"5", "0", "7"},      // exponent 0 -> result 1
    {"0", "5", "7"},      // base 0
    {"3", "4", "1"},      // modulus 1 -> result 0
    {"10", "3", "10"},    // base == mod
    {"4", "13", "497"},   // classic RSA-style textbook example
    {"17", "-1", "3120"}, // negative exponent -> modular inverse
    {"123456789", "65537", "1000000007"},
};

#define BN_MODEXP_CASES_COUNT                                                  \
    (sizeof(bn_modexp_cases) / sizeof(bn_modexp_cases[0]))

#endif // BN_TEST_EDGECASES_H
