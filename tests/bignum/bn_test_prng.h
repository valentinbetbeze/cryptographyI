#ifndef BN_TEST_PRNG_H
#define BN_TEST_PRNG_H

#include <stdint.h>

/**
 * Self-contained, platform-independent PRNG (splitmix64) used for random
 * bignum test generation. libc rand() is deliberately avoided: its sequence
 * is implementation-defined per platform, which would break reproducing a
 * CI-reported --seed locally on a different OS/libc.
 */
typedef struct
{
    uint64_t state;
} bn_prng_t;

static inline void bn_prng_seed(bn_prng_t *prng, uint64_t seed)
{
    prng->state = seed;
}

static inline uint64_t bn_prng_next(bn_prng_t *prng)
{
    uint64_t z = (prng->state += 0x9E3779B97F4A7C15ULL);
    z          = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z          = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Returns a value uniformly distributed in [lo, hi] inclusive. */
static inline uint64_t bn_prng_range(bn_prng_t *prng, uint64_t lo, uint64_t hi)
{
    const uint64_t span = hi - lo + 1;
    return lo + (span ? (bn_prng_next(prng) % span) : 0);
}

/* Returns non-zero with probability percent/100. */
static inline int bn_prng_chance(bn_prng_t *prng, int percent)
{
    return (int)(bn_prng_next(prng) % 100) < percent;
}

#endif // BN_TEST_PRNG_H
