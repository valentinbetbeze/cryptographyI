/**
 * White-box test for bignum.c's internal (static) helpers.
 *
 * is_greater_or_equal_abs() has static linkage and is not part of the public
 * bignum API (bignum.h), so it can't be exercised via a normal link against
 * libbignum. Instead this file #includes bignum.c directly, making it part
 * of this translation unit so the static symbol becomes reachable, exactly
 * like tests/bignum/test_bignum.c does for the public API but one level
 * deeper.
 */
#include "bignum.c"
#include "bn_test_edgecases.h"
#include "bn_test_gmp_bridge.h"
#include "bn_test_random.h"
#include "bn_test_report.h"

#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t make_default_seed(void)
{
    return ((uint64_t)time(NULL) << 32) ^ (uint64_t)clock();
}

/* Builds a bn_t and mpz_t pair holding the same signed value, from a decimal
 * magnitude string. */
static void build_pair(const char *magnitude, bool negative, bn_t *bn, mpz_t m)
{
    char buf[600];
    snprintf(buf, sizeof(buf), "%s%s", negative ? "-" : "", magnitude);
    bn_init(bn, buf, 10);
    mpz_set_str(m, buf, 10);
}

static void check_bool(bn_test_report_t *r,
                       uint64_t seed,
                       const char *desc,
                       bool expected,
                       bool actual)
{
    if (actual == expected)
    {
        bn_report_pass(r);
        return;
    }

    bn_report_fail(r,
                   seed,
                   desc,
                   expected ? "true" : "false",
                   actual ? "true" : "false");
}

/* Cross product of every edge magnitude against every other, under all four
 * sign combinations. Since is_greater_or_equal_abs() is documented to ignore
 * sign, the sign combination should never affect the expected result: only
 * the magnitudes (i.e. mpz_cmpabs) do. */
static void run_edge_cases(bn_test_report_t *r, uint64_t seed)
{
    for (size_t i = 0; i < BN_EDGE_MAGNITUDES_COUNT; i++)
    {
        for (size_t j = 0; j < BN_EDGE_MAGNITUDES_COUNT; j++)
        {
            for (size_t c = 0; c < BN_SIGN_COMBOS_COUNT; c++)
            {
                bn_t a = {0};
                bn_t b = {0};
                mpz_t ma, mb;
                mpz_inits(ma, mb, NULL);

                build_pair(bn_edge_magnitudes[i],
                           bn_sign_combos[c].neg_a,
                           &a,
                           ma);
                build_pair(bn_edge_magnitudes[j],
                           bn_sign_combos[c].neg_b,
                           &b,
                           mb);

                const bool expected = mpz_cmpabs(ma, mb) >= 0;
                const bool actual   = is_greater_or_equal_abs(&a, &b);

                char desc[300];
                snprintf(desc,
                         sizeof(desc),
                         "is_greater_or_equal_abs(%s%s, %s%s)",
                         bn_sign_combos[c].neg_a ? "-" : "",
                         bn_edge_magnitudes[i],
                         bn_sign_combos[c].neg_b ? "-" : "",
                         bn_edge_magnitudes[j]);

                check_bool(r, seed, desc, expected, actual);

                bn_reset(&a);
                bn_reset(&b);
                mpz_clears(ma, mb, NULL);
            }
        }
    }
}

static void run_random_iterations(bn_test_report_t *r,
                                  uint64_t seed,
                                  unsigned iterations)
{
    bn_prng_t prng;
    bn_prng_seed(&prng, seed);
    gmp_randstate_t gmp_rng;
    gmp_randinit_default(gmp_rng);
    gmp_randseed_ui(gmp_rng, (unsigned long)seed);

    for (unsigned i = 0; i < iterations; i++)
    {
        mpz_t ma, mb;
        mpz_inits(ma, mb, NULL);
        bn_t a = {0};
        bn_t b = {0};

        gen_random_value(&prng, gmp_rng, ma, &a);
        gen_random_value(&prng, gmp_rng, mb, &b);

        const bool expected = mpz_cmpabs(ma, mb) >= 0;
        const bool actual   = is_greater_or_equal_abs(&a, &b);

        char desc[64];
        snprintf(desc,
                 sizeof(desc),
                 "is_greater_or_equal_abs() random iteration %u",
                 i);

        check_bool(r, seed, desc, expected, actual);

        bn_reset(&a);
        bn_reset(&b);
        mpz_clears(ma, mb, NULL);
    }

    gmp_randclear(gmp_rng);
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [--seed N] [--iterations N]\n", prog);
}

int main(int argc, char *argv[])
{
    uint64_t seed       = 0;
    bool seed_set       = false;
    unsigned iterations = 1000;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc)
        {
            seed     = (uint64_t)strtoull(argv[++i], NULL, 0);
            seed_set = true;
        }
        else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc)
        {
            iterations = (unsigned)strtoul(argv[++i], NULL, 10);
        }
        else
        {
            fprintf(stderr, "Unrecognized argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (!seed_set || seed == 0)
    {
        seed = make_default_seed();
    }

    printf(
        "[bignum-internal-test] op=is_greater_or_equal_abs "
        "seed=0x%016llx iterations=%u\n",
        (unsigned long long)seed,
        iterations);

    bn_test_report_t report;
    bn_report_init(&report, "is_greater_or_equal_abs");

    run_edge_cases(&report, seed);
    run_random_iterations(&report, seed, iterations);

    return bn_report_finish(&report);
}
