#ifndef BN_TEST_GMP_BRIDGE_H
#define BN_TEST_GMP_BRIDGE_H

#include "bignum.h"

#include <gmp.h>
#include <stdbool.h>
#include <stdint.h>

/* Converts a bn_t's value into an already mpz_init'd mpz_t. */
void bn_to_mpz(const bn_t *bn, mpz_t out);

/* Converts an mpz_t's value into a bn_t placeholder, replacing any prior
 * contents. */
void mpz_to_bn(const mpz_t in, bn_t *out);

/* True iff bn's value equals expected's value. Zero is sign-agnostic on both
 * sides. */
bool bn_mpz_equal(const bn_t *bn, const mpz_t expected);

/**
 * Euclidean division: q, r such that a = q*b + r and r is always >= 0
 * (0 <= r < |b|), matching bn_div()'s documented convention. GMP has no
 * built-in Euclidean divmod (only floor/trunc/ceiling variants), so this is
 * assembled from mpz_fdiv_qr/mpz_cdiv_qr depending on the sign of b. Caller
 * must ensure b != 0.
 */
void mpz_euclidean_divmod(mpz_t q, mpz_t r, const mpz_t a, const mpz_t b);

/* Deep-copies src's value into dst, replacing any prior contents of dst. */
void bn_test_copy(const bn_t *src, bn_t *dst);

/* Renders bn as a base-10 string into buf for debug/failure printing. */
void bn_render_for_debug(const bn_t *bn, char *buf, size_t buflen);

/* Round-trips known values through the bridge. Returns true iff every check
 * passes. */
bool bn_test_gmp_bridge_selftest(void);

#endif // BN_TEST_GMP_BRIDGE_H
