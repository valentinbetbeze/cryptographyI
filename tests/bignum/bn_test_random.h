#ifndef BN_TEST_RANDOM_H
#define BN_TEST_RANDOM_H

#include "bignum.h"
#include "bn_test_gmp_bridge.h"
#include "bn_test_prng.h"

#include <gmp.h>

/**
 * Generates a random signed value on the GMP side first (single source of
 * ground truth), then derives the bn_t mirror. Bit-length is weighted toward
 * small and word/limb-boundary-adjacent values, since that's where bugs
 * cluster, rather than sampled uniformly.
 */
static void gen_random_value(bn_prng_t *prng,
                             gmp_randstate_t gmp_rng,
                             mpz_t out_m,
                             bn_t *out_bn)
{
    const uint64_t roll = bn_prng_next(prng) % 100;
    unsigned long bits;
    if (roll < 40)
    {
        bits = (unsigned long)bn_prng_range(prng, 0, 64);
    }
    else if (roll < 80)
    {
        bits = (unsigned long)bn_prng_range(prng, 64, 1024);
    }
    else
    {
        bits = (unsigned long)bn_prng_range(prng, 1024, 4096);
    }

    if (bits == 0)
    {
        mpz_set_ui(out_m, 0);
    }
    else if (bn_prng_chance(prng, 10))
    {
        // Boundary-biased draw: land exactly on 2^bits, 2^bits - 1, or 2^bits
        // + 1.
        mpz_ui_pow_ui(out_m, 2, bits);
        const unsigned which = (unsigned)(bn_prng_next(prng) % 3);
        if (which == 1)
        {
            mpz_sub_ui(out_m, out_m, 1);
        }
        else if (which == 2)
        {
            mpz_add_ui(out_m, out_m, 1);
        }
    }
    else
    {
        mpz_urandomb(out_m, gmp_rng, bits);
    }

    if (bn_prng_chance(prng, 50))
    {
        mpz_neg(out_m, out_m);
    }

    mpz_to_bn(out_m, out_bn);
}

#endif // BN_TEST_RANDOM_H
