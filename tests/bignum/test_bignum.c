#include "bignum.h"
#include "bn_test_edgecases.h"
#include "bn_test_gmp_bridge.h"
#include "bn_test_prng.h"
#include "bn_test_report.h"

#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ==================================================
// Shared helpers
// ==================================================

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

static void check_bn_eq_mpz(bn_test_report_t *r,
                            uint64_t seed,
                            const char *desc,
                            const bn_t *actual_bn,
                            const mpz_t expected)
{
    if (bn_mpz_equal(actual_bn, expected))
    {
        bn_report_pass(r);
        return;
    }

    char actual_buf[256];
    bn_render_for_debug(actual_bn, actual_buf, sizeof(actual_buf));
    char *expected_str = mpz_get_str(NULL, 10, expected);
    bn_report_fail(r, seed, desc, expected_str, actual_buf);
    free(expected_str);
}

static void check_ret(bn_test_report_t *r,
                      uint64_t seed,
                      const char *desc,
                      bn_ret_t expected_ret,
                      bn_ret_t actual_ret)
{
    if (actual_ret == expected_ret)
    {
        bn_report_pass(r);
        return;
    }

    char expected_buf[32];
    char actual_buf[32];
    snprintf(expected_buf, sizeof(expected_buf), "ret=%d", expected_ret);
    snprintf(actual_buf, sizeof(actual_buf), "ret=%d", actual_ret);
    bn_report_fail(r, seed, desc, expected_buf, actual_buf);
}

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

// ==================================================
// bn_init / bn_reset / bn_tostring
// ==================================================

static void run_init_tests(bn_test_report_t *r, uint64_t seed)
{
    for (size_t i = 0; i < BN_EDGE_MAGNITUDES_COUNT; i++)
    {
        for (int base = 2; base <= 36; base++)
        {
            mpz_t expected;
            mpz_init(expected);
            mpz_set_str(expected, bn_edge_magnitudes[i], 10);

            char *based_str = mpz_get_str(NULL, base, expected);

            bn_t bn      = {0};
            bn_ret_t ret = bn_init(&bn, based_str, base);

            char desc[300];
            snprintf(desc,
                     sizeof(desc),
                     "bn_init(\"%s\", base=%d)",
                     based_str,
                     base);

            if (ret != BN_OK)
            {
                char expected_buf[32];
                snprintf(expected_buf, sizeof(expected_buf), "BN_OK");
                char actual_buf[32];
                snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
                bn_report_fail(r, seed, desc, expected_buf, actual_buf);
            }
            else
            {
                check_bn_eq_mpz(r, seed, desc, &bn, expected);
            }

            free(based_str);
            bn_reset(&bn);
            mpz_clear(expected);
        }
    }

    // Invalid input cases: expect specific error codes, not just failure.
    struct
    {
        const char *str;
        int base;
        bn_ret_t expected;
    } invalid_cases[] = {
        {"", 10, BN_ERR_BAD_LENGTH},
        {"123", 1, BN_ERR_BAD_VALUE},
        {"123", 37, BN_ERR_BAD_VALUE},
        {"12a", 10, BN_ERR_BAD_ENC},
        {" 123", 10, BN_ERR_BAD_ENC},
        {"123 ", 10, BN_ERR_BAD_ENC},
        {"0x123", 16, BN_ERR_BAD_ENC},
    };

    for (size_t i = 0; i < sizeof(invalid_cases) / sizeof(invalid_cases[0]);
         i++)
    {
        bn_t bn      = {0};
        bn_ret_t ret = bn_init(&bn,
                               invalid_cases[i].str,
                               invalid_cases[i].base);

        char desc[128];
        snprintf(desc,
                 sizeof(desc),
                 "bn_init(\"%s\", base=%d) [invalid input]",
                 invalid_cases[i].str,
                 invalid_cases[i].base);
        check_ret(r, seed, desc, invalid_cases[i].expected, ret);
        bn_reset(&bn);
    }
}

static void run_reset_tests(bn_test_report_t *r, uint64_t seed)
{
    for (size_t i = 0; i < BN_EDGE_MAGNITUDES_COUNT; i++)
    {
        bn_t bn = {0};
        bn_init(&bn, bn_edge_magnitudes[i], 10);

        bn_ret_t ret = bn_reset(&bn);

        char desc[128];
        snprintf(desc,
                 sizeof(desc),
                 "bn_reset() after init(\"%s\")",
                 bn_edge_magnitudes[i]);

        if (ret != BN_OK)
        {
            bn_report_fail(r, seed, desc, "ret=BN_OK", "ret!=BN_OK");
            continue;
        }

        if (bn.len != 0 || bn.is_negative != false)
        {
            char actual_buf[64];
            snprintf(actual_buf,
                     sizeof(actual_buf),
                     "len=%zu is_negative=%d",
                     bn.len,
                     bn.is_negative);
            bn_report_fail(r,
                           seed,
                           desc,
                           "len=0 is_negative=false",
                           actual_buf);
        }
        else
        {
            bn_report_pass(r);
        }

        // Known issue: bn_reset() frees bstr but does not NULL it out, leaving
        // a dangling pointer. This matters because callers (and bn_add's own
        // "output ownership policy" check) use `bstr == NULL` to decide
        // whether to allocate fresh memory vs. reuse/free existing memory --
        // a dangling non-NULL bstr can lead to a use-after-free the next time
        // this bn_t is passed as an output placeholder.
        char desc2[160];
        snprintf(desc2,
                 sizeof(desc2),
                 "bn_reset() nulls bstr after free (init(\"%s\"))",
                 bn_edge_magnitudes[i]);
        if (bn.bstr != NULL)
        {
            bn_report_fail(r,
                           seed,
                           desc2,
                           "bstr=NULL",
                           "bstr!=NULL (dangling pointer)");
        }
        else
        {
            bn_report_pass(r);
        }

        // Defensively clear the dangling pointer ourselves so nothing later
        // in this process (including a subsequent bn_reset) double-frees it.
        bn.bstr = NULL;
    }
}

static void run_tostring_tests(bn_test_report_t *r, uint64_t seed)
{
    for (size_t i = 0; i < BN_EDGE_MAGNITUDES_COUNT; i++)
    {
        for (int base = 2; base <= 36; base++)
        {
            bn_t bn = {0};
            bn_init(&bn, bn_edge_magnitudes[i], 10);

            char *str    = NULL;
            size_t len   = 0;
            bn_ret_t ret = bn_tostring(&bn, base, &str, &len);

            char desc[128];
            snprintf(desc,
                     sizeof(desc),
                     "bn_tostring(\"%s\", base=%d)",
                     bn_edge_magnitudes[i],
                     base);

            if (ret != BN_OK)
            {
                char actual_buf[32];
                snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
                bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
            }
            else
            {
                mpz_t m;
                mpz_init(m);
                mpz_set_str(m, bn_edge_magnitudes[i], 10);
                char *expected_str = mpz_get_str(NULL, base, m);

                if (strcmp(str, expected_str) == 0)
                {
                    bn_report_pass(r);
                }
                else
                {
                    bn_report_fail(r, seed, desc, expected_str, str);
                }

                free(expected_str);
                mpz_clear(m);
            }

            free(str);
            bn_reset(&bn);
        }
    }
}

// ==================================================
// bn_add
// ==================================================

static void run_add_basic(bn_test_report_t *r,
                          uint64_t seed,
                          unsigned iterations)
{
    // Edge cases first, positive-only, non-in-place -- the only path bn_add
    // currently implements. Array order already places single-word values
    // (0, 1, 2, 2^32-1) before multi-word values, so a real single-word
    // signal is possible even if multi-word addition is broken.
    for (size_t i = 0; i < BN_EDGE_MAGNITUDES_COUNT; i++)
    {
        for (size_t j = 0; j < BN_EDGE_MAGNITUDES_COUNT; j++)
        {
            bn_t a   = {0};
            bn_t b   = {0};
            bn_t out = {0};
            mpz_t ma, mb, expected;
            mpz_inits(ma, mb, expected, NULL);

            build_pair(bn_edge_magnitudes[i], false, &a, ma);
            build_pair(bn_edge_magnitudes[j], false, &b, mb);
            mpz_add(expected, ma, mb);

            bn_ret_t ret = bn_add(&a, &b, &out);

            char desc[300];
            snprintf(desc,
                     sizeof(desc),
                     "bn_add(%s, %s)",
                     bn_edge_magnitudes[i],
                     bn_edge_magnitudes[j]);

            if (ret != BN_OK)
            {
                char actual_buf[32];
                snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
                bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
            }
            else
            {
                check_bn_eq_mpz(r, seed, desc, &out, expected);
            }

            bn_reset(&a);
            bn_reset(&b);
            bn_reset(&out);
            mpz_clears(ma, mb, expected, NULL);
        }
    }

    // Output ownership policy probe: pre-populate `out` with a stale buffer
    // before a non-in-place call, confirming it doesn't crash and still
    // yields a correct result (the reset+realloc path).
    {
        bn_t a   = {0};
        bn_t b   = {0};
        bn_t out = {0};
        mpz_t ma, mb, expected;
        mpz_inits(ma, mb, expected, NULL);

        build_pair("123456789", false, &a, ma);
        build_pair("987654321", false, &b, mb);
        mpz_add(expected, ma, mb);

        bn_init(&out, "1", 10); // pre-populate with stale, unrelated data

        bn_ret_t ret     = bn_add(&a, &b, &out);
        const char *desc = "bn_add() with pre-populated (stale) out buffer";
        if (ret != BN_OK)
        {
            char actual_buf[32];
            snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
            bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
        }
        else
        {
            check_bn_eq_mpz(r, seed, desc, &out, expected);
        }

        bn_reset(&a);
        bn_reset(&b);
        bn_reset(&out);
        mpz_clears(ma, mb, expected, NULL);
    }

    // Random fuzzing: positive-only, matching the currently implemented path.
    bn_prng_t prng;
    bn_prng_seed(&prng, seed);
    gmp_randstate_t gmp_rng;
    gmp_randinit_default(gmp_rng);
    gmp_randseed_ui(gmp_rng, (unsigned long)seed);

    for (unsigned i = 0; i < iterations; i++)
    {
        mpz_t ma, mb, expected;
        mpz_inits(ma, mb, expected, NULL);
        bn_t a   = {0};
        bn_t b   = {0};
        bn_t out = {0};

        gen_random_value(&prng, gmp_rng, ma, &a);
        gen_random_value(&prng, gmp_rng, mb, &b);
        mpz_abs(ma, ma); // basic scenario is positive-only
        mpz_abs(mb, mb);
        a.is_negative = false;
        b.is_negative = false;

        mpz_add(expected, ma, mb);
        bn_ret_t ret = bn_add(&a, &b, &out);

        char desc[64];
        snprintf(desc, sizeof(desc), "bn_add() random iteration %u", i);

        if (ret != BN_OK)
        {
            char actual_buf[32];
            snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
            bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
        }
        else
        {
            check_bn_eq_mpz(r, seed, desc, &out, expected);
        }

        bn_reset(&a);
        bn_reset(&b);
        bn_reset(&out);
        mpz_clears(ma, mb, expected, NULL);
    }

    gmp_randclear(gmp_rng);
}

static void run_add_negative(bn_test_report_t *r,
                             uint64_t seed,
                             unsigned iterations)
{
    // Full sign-combination coverage on the edge-case table -- exercises the
    // still-TODO negative-support path.
    for (size_t i = 0; i < BN_EDGE_MAGNITUDES_COUNT; i++)
    {
        for (size_t j = 0; j < BN_EDGE_MAGNITUDES_COUNT; j++)
        {
            for (size_t c = 0; c < BN_SIGN_COMBOS_COUNT; c++)
            {
                bn_t a   = {0};
                bn_t b   = {0};
                bn_t out = {0};
                mpz_t ma, mb, expected;
                mpz_inits(ma, mb, expected, NULL);

                build_pair(bn_edge_magnitudes[i],
                           bn_sign_combos[c].neg_a,
                           &a,
                           ma);
                build_pair(bn_edge_magnitudes[j],
                           bn_sign_combos[c].neg_b,
                           &b,
                           mb);
                mpz_add(expected, ma, mb);

                bn_ret_t ret = bn_add(&a, &b, &out);

                char desc[300];
                snprintf(desc,
                         sizeof(desc),
                         "bn_add(%s%s, %s%s)",
                         bn_sign_combos[c].neg_a ? "-" : "",
                         bn_edge_magnitudes[i],
                         bn_sign_combos[c].neg_b ? "-" : "",
                         bn_edge_magnitudes[j]);

                if (ret != BN_OK)
                {
                    char actual_buf[32];
                    snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
                    bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
                }
                else
                {
                    check_bn_eq_mpz(r, seed, desc, &out, expected);
                }

                bn_reset(&a);
                bn_reset(&b);
                bn_reset(&out);
                mpz_clears(ma, mb, expected, NULL);
            }
        }
    }

    bn_prng_t prng;
    bn_prng_seed(&prng, seed);
    gmp_randstate_t gmp_rng;
    gmp_randinit_default(gmp_rng);
    gmp_randseed_ui(gmp_rng, (unsigned long)seed);

    for (unsigned i = 0; i < iterations; i++)
    {
        mpz_t ma, mb, expected;
        mpz_inits(ma, mb, expected, NULL);
        bn_t a   = {0};
        bn_t b   = {0};
        bn_t out = {0};

        gen_random_value(&prng,
                         gmp_rng,
                         ma,
                         &a); // signed, per gen_random_value
        gen_random_value(&prng, gmp_rng, mb, &b);

        mpz_add(expected, ma, mb);
        bn_ret_t ret = bn_add(&a, &b, &out);

        char desc[64];
        snprintf(desc, sizeof(desc), "bn_add() signed random iteration %u", i);

        if (ret != BN_OK)
        {
            char actual_buf[32];
            snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
            bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
        }
        else
        {
            check_bn_eq_mpz(r, seed, desc, &out, expected);
        }

        bn_reset(&a);
        bn_reset(&b);
        bn_reset(&out);
        mpz_clears(ma, mb, expected, NULL);
    }

    gmp_randclear(gmp_rng);
}

/* Minimum bn_t capacity (in bytes, rounded up to a whole 4-byte word as
 * bn_init/bn_add do) needed to hold v without overflow. */
static size_t required_capacity_bytes(const mpz_t v)
{
    const size_t bits  = mpz_sgn(v) == 0 ? 1 : mpz_sizeinbase(v, 2);
    const size_t bytes = (bits + 7) / 8;
    return ((bytes + sizeof(uint32_t) - 1) / sizeof(uint32_t)) *
           sizeof(uint32_t);
}

static void check_add_inplace_result(bn_test_report_t *r,
                                     uint64_t seed,
                                     const char *desc,
                                     bn_ret_t ret,
                                     size_t inplace_capacity,
                                     const bn_t *out,
                                     const mpz_t expected)
{
    const bool fits = required_capacity_bytes(expected) <= inplace_capacity;

    if (fits)
    {
        if (ret != BN_OK)
        {
            char actual_buf[32];
            snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
            bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
        }
        else
        {
            check_bn_eq_mpz(r, seed, desc, out, expected);
        }
    }
    else
    {
        check_ret(r, seed, desc, BN_ERR_OVERFLOW, ret);
    }
}

static void run_add_inplace(bn_test_report_t *r, uint64_t seed)
{
    for (size_t i = 0; i < BN_EDGE_MAGNITUDES_COUNT; i++)
    {
        for (size_t j = 0; j < BN_EDGE_MAGNITUDES_COUNT; j++)
        {
            // a == out (in-place on first operand)
            {
                bn_t a = {0};
                bn_t b = {0};
                mpz_t ma, mb, expected;
                mpz_inits(ma, mb, expected, NULL);
                build_pair(bn_edge_magnitudes[i], false, &a, ma);
                build_pair(bn_edge_magnitudes[j], false, &b, mb);
                mpz_add(expected, ma, mb);

                const size_t inplace_capacity = a.len;
                bn_ret_t ret                  = bn_add(&a, &b, &a);

                char desc[256];
                snprintf(desc,
                         sizeof(desc),
                         "bn_add(%s, %s, out=a) [a==out]",
                         bn_edge_magnitudes[i],
                         bn_edge_magnitudes[j]);
                check_add_inplace_result(r,
                                         seed,
                                         desc,
                                         ret,
                                         inplace_capacity,
                                         &a,
                                         expected);

                bn_reset(&a);
                bn_reset(&b);
                mpz_clears(ma, mb, expected, NULL);
            }

            // b == out (in-place on second operand)
            {
                bn_t a = {0};
                bn_t b = {0};
                mpz_t ma, mb, expected;
                mpz_inits(ma, mb, expected, NULL);
                build_pair(bn_edge_magnitudes[i], false, &a, ma);
                build_pair(bn_edge_magnitudes[j], false, &b, mb);
                mpz_add(expected, ma, mb);

                const size_t inplace_capacity = b.len;
                bn_ret_t ret                  = bn_add(&a, &b, &b);

                char desc[256];
                snprintf(desc,
                         sizeof(desc),
                         "bn_add(%s, b, out=b) [b==out]",
                         bn_edge_magnitudes[i]);
                check_add_inplace_result(r,
                                         seed,
                                         desc,
                                         ret,
                                         inplace_capacity,
                                         &b,
                                         expected);

                bn_reset(&a);
                bn_reset(&b);
                mpz_clears(ma, mb, expected, NULL);
            }
        }
    }

    // a == b == out: already guarded in the current implementation, lock it
    // in as a regression test.
    {
        bn_t a = {0};
        bn_init(&a, "42", 10);
        bn_ret_t ret = bn_add(&a, &a, &a);
        check_ret(r,
                  seed,
                  "bn_add(a, a, out=a) [a==b==out]",
                  BN_ERR_BAD_VALUE,
                  ret);
        bn_reset(&a);
    }
}

static void run_add_tests(bn_test_report_t *r,
                          uint64_t seed,
                          unsigned iterations,
                          const char *scenario)
{
    if (scenario == NULL || strcmp(scenario, "basic") == 0)
    {
        run_add_basic(r, seed, iterations);
    }
    else if (strcmp(scenario, "negative") == 0)
    {
        run_add_negative(r, seed, iterations);
    }
    else if (strcmp(scenario, "inplace") == 0)
    {
        run_add_inplace(r, seed);
    }
    else
    {
        fprintf(stderr, "Unknown --scenario '%s' for op 'add'\n", scenario);
        exit(2);
    }
}

// ==================================================
// bn_sub / bn_mul (structurally identical: stubbed binary ops)
// ==================================================

typedef bn_ret_t (*bn_binop_fn_t)(const bn_t *, const bn_t *, bn_t *);
typedef void (*mpz_binop_fn_t)(mpz_t, const mpz_t, const mpz_t);

static void run_generic_binop_tests(bn_test_report_t *r,
                                    uint64_t seed,
                                    unsigned iterations,
                                    const char *op_name,
                                    bn_binop_fn_t bn_fn,
                                    mpz_binop_fn_t mpz_fn)
{
    for (size_t i = 0; i < BN_EDGE_MAGNITUDES_COUNT; i++)
    {
        for (size_t j = 0; j < BN_EDGE_MAGNITUDES_COUNT; j++)
        {
            for (size_t c = 0; c < BN_SIGN_COMBOS_COUNT; c++)
            {
                bn_t a   = {0};
                bn_t b   = {0};
                bn_t out = {0};
                mpz_t ma, mb, expected;
                mpz_inits(ma, mb, expected, NULL);

                build_pair(bn_edge_magnitudes[i],
                           bn_sign_combos[c].neg_a,
                           &a,
                           ma);
                build_pair(bn_edge_magnitudes[j],
                           bn_sign_combos[c].neg_b,
                           &b,
                           mb);
                mpz_fn(expected, ma, mb);

                bn_ret_t ret = bn_fn(&a, &b, &out);

                char desc[300];
                snprintf(desc,
                         sizeof(desc),
                         "%s(%s%s, %s%s)",
                         op_name,
                         bn_sign_combos[c].neg_a ? "-" : "",
                         bn_edge_magnitudes[i],
                         bn_sign_combos[c].neg_b ? "-" : "",
                         bn_edge_magnitudes[j]);

                if (ret != BN_OK)
                {
                    char actual_buf[32];
                    snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
                    bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
                }
                else
                {
                    check_bn_eq_mpz(r, seed, desc, &out, expected);
                }

                bn_reset(&a);
                bn_reset(&b);
                bn_reset(&out);
                mpz_clears(ma, mb, expected, NULL);
            }
        }
    }

    bn_prng_t prng;
    bn_prng_seed(&prng, seed);
    gmp_randstate_t gmp_rng;
    gmp_randinit_default(gmp_rng);
    gmp_randseed_ui(gmp_rng, (unsigned long)seed);

    for (unsigned i = 0; i < iterations; i++)
    {
        mpz_t ma, mb, expected;
        mpz_inits(ma, mb, expected, NULL);
        bn_t a   = {0};
        bn_t b   = {0};
        bn_t out = {0};

        gen_random_value(&prng, gmp_rng, ma, &a);
        gen_random_value(&prng, gmp_rng, mb, &b);
        mpz_fn(expected, ma, mb);

        bn_ret_t ret = bn_fn(&a, &b, &out);

        char desc[64];
        snprintf(desc, sizeof(desc), "%s() random iteration %u", op_name, i);

        if (ret != BN_OK)
        {
            char actual_buf[32];
            snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
            bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
        }
        else
        {
            check_bn_eq_mpz(r, seed, desc, &out, expected);
        }

        bn_reset(&a);
        bn_reset(&b);
        bn_reset(&out);
        mpz_clears(ma, mb, expected, NULL);
    }

    gmp_randclear(gmp_rng);
}

static void run_sub_tests(bn_test_report_t *r,
                          uint64_t seed,
                          unsigned iterations)
{
    run_generic_binop_tests(r, seed, iterations, "bn_sub", bn_sub, mpz_sub);
}

static void run_mul_tests(bn_test_report_t *r,
                          uint64_t seed,
                          unsigned iterations)
{
    run_generic_binop_tests(r, seed, iterations, "bn_mul", bn_mul, mpz_mul);
}

// ==================================================
// bn_div (Euclidean convention: remainder always >= 0)
// ==================================================

static void run_div_tests(bn_test_report_t *r,
                          uint64_t seed,
                          unsigned iterations)
{
    // Division-by-zero: expect BN_ERR_BAD_VALUE, both outputs untouched.
    {
        bn_t a   = {0};
        bn_t b   = {0};
        bn_t q   = {0};
        bn_t rem = {0};
        bn_init(&a, "12345", 10);
        bn_init(&b, "0", 10);
        bn_ret_t ret = bn_div(&a, &b, &q, &rem);
        check_ret(r, seed, "bn_div(12345, 0)", BN_ERR_BAD_VALUE, ret);
        bn_reset(&a);
        bn_reset(&b);
        bn_reset(&q);
        bn_reset(&rem);
    }

    // divisor==1, divisor==dividend, divisor==dividend+1, negative operands.
    struct
    {
        const char *a;
        const char *b;
    } cases[] = {
        {"0", "1"},
        {"12345", "1"},
        {"-12345", "1"},
        {"12345", "12345"},
        {"-12345", "12345"},
        {"12345", "12346"},
        {"-12345", "-6789"},
        {"12345", "-6789"},
        {"4294967296", "4294967295"},
        {"4294967295", "4294967296"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        bn_t a   = {0};
        bn_t b   = {0};
        bn_t q   = {0};
        bn_t rem = {0};
        mpz_t ma, mb, expected_q, expected_r;
        mpz_inits(ma, mb, expected_q, expected_r, NULL);

        bn_init(&a, cases[i].a, 10);
        bn_init(&b, cases[i].b, 10);
        mpz_set_str(ma, cases[i].a, 10);
        mpz_set_str(mb, cases[i].b, 10);
        mpz_euclidean_divmod(expected_q, expected_r, ma, mb);

        bn_ret_t ret = bn_div(&a, &b, &q, &rem);

        char desc[128];
        snprintf(desc,
                 sizeof(desc),
                 "bn_div(%s, %s) quotient",
                 cases[i].a,
                 cases[i].b);
        char desc_r[128];
        snprintf(desc_r,
                 sizeof(desc_r),
                 "bn_div(%s, %s) remainder",
                 cases[i].a,
                 cases[i].b);

        if (ret != BN_OK)
        {
            char actual_buf[32];
            snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
            bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
            bn_report_fail(r, seed, desc_r, "ret=BN_OK", actual_buf);
        }
        else
        {
            check_bn_eq_mpz(r, seed, desc, &q, expected_q);
            check_bn_eq_mpz(r, seed, desc_r, &rem, expected_r);

            // Euclidean convention: remainder must never be negative.
            char desc_sign[160];
            snprintf(desc_sign,
                     sizeof(desc_sign),
                     "bn_div(%s, %s) remainder sign",
                     cases[i].a,
                     cases[i].b);
            if (rem.is_negative && rem.len > 0)
            {
                bn_report_fail(r,
                               seed,
                               desc_sign,
                               "is_negative=false",
                               "is_negative=true");
            }
            else
            {
                bn_report_pass(r);
            }
        }

        bn_reset(&a);
        bn_reset(&b);
        bn_reset(&q);
        bn_reset(&rem);
        mpz_clears(ma, mb, expected_q, expected_r, NULL);
    }

    // Random fuzzing.
    bn_prng_t prng;
    bn_prng_seed(&prng, seed);
    gmp_randstate_t gmp_rng;
    gmp_randinit_default(gmp_rng);
    gmp_randseed_ui(gmp_rng, (unsigned long)seed);

    for (unsigned i = 0; i < iterations; i++)
    {
        mpz_t ma, mb, expected_q, expected_r;
        mpz_inits(ma, mb, expected_q, expected_r, NULL);
        bn_t a   = {0};
        bn_t b   = {0};
        bn_t q   = {0};
        bn_t rem = {0};

        gen_random_value(&prng, gmp_rng, ma, &a);
        do
        {
            gen_random_value(&prng, gmp_rng, mb, &b);
        } while (mpz_sgn(mb) == 0);

        mpz_euclidean_divmod(expected_q, expected_r, ma, mb);
        bn_ret_t ret = bn_div(&a, &b, &q, &rem);

        char desc[64];
        snprintf(desc, sizeof(desc), "bn_div() random iteration %u", i);

        if (ret != BN_OK)
        {
            char actual_buf[32];
            snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
            bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
        }
        else
        {
            check_bn_eq_mpz(r, seed, desc, &q, expected_q);
            check_bn_eq_mpz(r, seed, desc, &rem, expected_r);
        }

        bn_reset(&a);
        bn_reset(&b);
        bn_reset(&q);
        bn_reset(&rem);
        mpz_clears(ma, mb, expected_q, expected_r, NULL);
    }

    gmp_randclear(gmp_rng);
}

// ==================================================
// bn_mod
// ==================================================

static void run_mod_tests(bn_test_report_t *r,
                          uint64_t seed,
                          unsigned iterations)
{
    struct
    {
        const char *a;
        const char *m;
        bn_ret_t expected_ret; // BN_OK unless invalid modulus
    } invalid_cases[] = {
        {"12345", "0", BN_ERR_BAD_VALUE},
        {"12345", "-7", BN_ERR_BAD_VALUE},
    };

    for (size_t i = 0; i < sizeof(invalid_cases) / sizeof(invalid_cases[0]);
         i++)
    {
        bn_t a   = {0};
        bn_t m   = {0};
        bn_t rem = {0};
        bn_init(&a, invalid_cases[i].a, 10);
        bn_init(&m, invalid_cases[i].m, 10);
        bn_ret_t ret = bn_mod(&a, &m, &rem);

        char desc[128];
        snprintf(desc,
                 sizeof(desc),
                 "bn_mod(%s, %s) [invalid modulus]",
                 invalid_cases[i].a,
                 invalid_cases[i].m);
        check_ret(r, seed, desc, invalid_cases[i].expected_ret, ret);

        bn_reset(&a);
        bn_reset(&m);
        bn_reset(&rem);
    }

    for (size_t i = 0; i < BN_EDGE_MAGNITUDES_COUNT; i++)
    {
        for (size_t j = 1; j < BN_EDGE_MAGNITUDES_COUNT;
             j++) // skip index 0 ("0") as modulus
        {
            for (size_t s = 0; s < 2;
                 s++) // dividend sign only; modulus stays positive
            {
                bn_t a   = {0};
                bn_t m   = {0};
                bn_t rem = {0};
                mpz_t ma, mm, expected;
                mpz_inits(ma, mm, expected, NULL);

                build_pair(bn_edge_magnitudes[i], s == 1, &a, ma);
                build_pair(bn_edge_magnitudes[j], false, &m, mm);
                mpz_mod(
                    expected,
                    ma,
                    mm); // GMP's mpz_mod already returns [0, m) for positive m

                bn_ret_t ret = bn_mod(&a, &m, &rem);

                char desc[300];
                snprintf(desc,
                         sizeof(desc),
                         "bn_mod(%s%s, %s)",
                         s == 1 ? "-" : "",
                         bn_edge_magnitudes[i],
                         bn_edge_magnitudes[j]);

                if (ret != BN_OK)
                {
                    char actual_buf[32];
                    snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
                    bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
                }
                else
                {
                    check_bn_eq_mpz(r, seed, desc, &rem, expected);
                }

                bn_reset(&a);
                bn_reset(&m);
                bn_reset(&rem);
                mpz_clears(ma, mm, expected, NULL);
            }
        }
    }

    bn_prng_t prng;
    bn_prng_seed(&prng, seed);
    gmp_randstate_t gmp_rng;
    gmp_randinit_default(gmp_rng);
    gmp_randseed_ui(gmp_rng, (unsigned long)seed);

    for (unsigned i = 0; i < iterations; i++)
    {
        mpz_t ma, mm, expected;
        mpz_inits(ma, mm, expected, NULL);
        bn_t a   = {0};
        bn_t m   = {0};
        bn_t rem = {0};

        gen_random_value(&prng, gmp_rng, ma, &a);
        do
        {
            gen_random_value(&prng, gmp_rng, mm, &m);
        } while (mpz_sgn(mm) <= 0);
        m.is_negative = false; // modulus must be positive per bn_mod's contract

        mpz_mod(expected, ma, mm);
        bn_ret_t ret = bn_mod(&a, &m, &rem);

        char desc[64];
        snprintf(desc, sizeof(desc), "bn_mod() random iteration %u", i);

        if (ret != BN_OK)
        {
            char actual_buf[32];
            snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
            bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
        }
        else
        {
            check_bn_eq_mpz(r, seed, desc, &rem, expected);
        }

        bn_reset(&a);
        bn_reset(&m);
        bn_reset(&rem);
        mpz_clears(ma, mm, expected, NULL);
    }

    gmp_randclear(gmp_rng);
}

// ==================================================
// bn_modexp
// ==================================================

/* Computes base^exp mod m, supporting negative exponents as modular inverse.
 * Returns false if not invertible. */
static bool compute_expected_modexp(mpz_t out,
                                    const mpz_t base,
                                    const mpz_t exp,
                                    const mpz_t mod)
{
    if (mpz_sgn(exp) >= 0)
    {
        mpz_powm(out, base, exp, mod);
        return true;
    }

    mpz_t base_mod, inv, abs_exp;
    mpz_inits(base_mod, inv, abs_exp, NULL);
    mpz_mod(base_mod, base, mod);

    bool invertible = (mpz_invert(inv, base_mod, mod) != 0);
    if (invertible)
    {
        mpz_abs(abs_exp, exp);
        mpz_powm(out, inv, abs_exp, mod);
    }

    mpz_clears(base_mod, inv, abs_exp, NULL);
    return invertible;
}

static void run_modexp_tests(bn_test_report_t *r,
                             uint64_t seed,
                             unsigned iterations)
{
    for (size_t i = 0; i < BN_MODEXP_CASES_COUNT; i++)
    {
        bn_t base = {0};
        bn_t exp  = {0};
        bn_t mod  = {0};
        bn_t out  = {0};
        mpz_t mbase, mexp, mmod, expected;
        mpz_inits(mbase, mexp, mmod, expected, NULL);

        bn_init(&base, bn_modexp_cases[i].base, 10);
        bn_init(&exp, bn_modexp_cases[i].exp, 10);
        bn_init(&mod, bn_modexp_cases[i].mod, 10);
        mpz_set_str(mbase, bn_modexp_cases[i].base, 10);
        mpz_set_str(mexp, bn_modexp_cases[i].exp, 10);
        mpz_set_str(mmod, bn_modexp_cases[i].mod, 10);

        char desc[200];
        snprintf(desc,
                 sizeof(desc),
                 "bn_modexp(%s, %s, %s)",
                 bn_modexp_cases[i].base,
                 bn_modexp_cases[i].exp,
                 bn_modexp_cases[i].mod);

        if (!compute_expected_modexp(expected, mbase, mexp, mmod))
        {
            bn_report_skip(r, desc); // base not invertible mod m -- undefined
                                     // for negative exponent
        }
        else
        {
            bn_ret_t ret = bn_modexp(&base, &exp, &mod, &out);
            if (ret != BN_OK)
            {
                char actual_buf[32];
                snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
                bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
            }
            else
            {
                check_bn_eq_mpz(r, seed, desc, &out, expected);
            }
        }

        bn_reset(&base);
        bn_reset(&exp);
        bn_reset(&mod);
        bn_reset(&out);
        mpz_clears(mbase, mexp, mmod, expected, NULL);
    }

    // Light random fuzzing: non-negative exponent, positive modulus > 1.
    bn_prng_t prng;
    bn_prng_seed(&prng, seed);
    gmp_randstate_t gmp_rng;
    gmp_randinit_default(gmp_rng);
    gmp_randseed_ui(gmp_rng, (unsigned long)seed);

    for (unsigned i = 0; i < iterations; i++)
    {
        mpz_t mbase, mexp, mmod, expected;
        mpz_inits(mbase, mexp, mmod, expected, NULL);
        bn_t base = {0};
        bn_t exp  = {0};
        bn_t mod  = {0};
        bn_t out  = {0};

        gen_random_value(&prng, gmp_rng, mbase, &base);
        mpz_abs(mbase, mbase);
        base.is_negative = false;

        gen_random_value(&prng, gmp_rng, mexp, &exp);
        mpz_abs(mexp, mexp);
        exp.is_negative = false;

        do
        {
            gen_random_value(&prng, gmp_rng, mmod, &mod);
            mpz_abs(mmod, mmod);
        } while (mpz_cmp_ui(mmod, 1) <= 0);
        mod.is_negative = false;

        mpz_powm(expected, mbase, mexp, mmod);
        bn_ret_t ret = bn_modexp(&base, &exp, &mod, &out);

        char desc[64];
        snprintf(desc, sizeof(desc), "bn_modexp() random iteration %u", i);

        if (ret != BN_OK)
        {
            char actual_buf[32];
            snprintf(actual_buf, sizeof(actual_buf), "ret=%d", ret);
            bn_report_fail(r, seed, desc, "ret=BN_OK", actual_buf);
        }
        else
        {
            check_bn_eq_mpz(r, seed, desc, &out, expected);
        }

        bn_reset(&base);
        bn_reset(&exp);
        bn_reset(&mod);
        bn_reset(&out);
        mpz_clears(mbase, mexp, mmod, expected, NULL);
    }

    gmp_randclear(gmp_rng);
}

// ==================================================
// main / CLI dispatch
// ==================================================

static void print_usage(const char *prog)
{
    fprintf(
        stderr,
        "Usage: %s <op> [--seed N] [--iterations N] [--scenario NAME] [-v]\n"
        "  <op>: init|reset|tostring|add|sub|mul|div|mod|modexp|bridge\n",
        prog);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        print_usage(argv[0]);
        return 2;
    }

    const char *op       = argv[1];
    uint64_t seed        = 0;
    bool seed_set        = false;
    unsigned iterations  = 1000;
    const char *scenario = NULL;

    for (int i = 2; i < argc; i++)
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
        else if (strcmp(argv[i], "--scenario") == 0 && i + 1 < argc)
        {
            scenario = argv[++i];
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            // Verbose flag accepted for future use; every failure is
            // already printed unconditionally by bn_report_fail().
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

    printf("[bignum-test] op=%s seed=0x%016llx iterations=%u\n",
           op,
           (unsigned long long)seed,
           iterations);

    if (!bn_test_gmp_bridge_selftest())
    {
        fprintf(stderr,
                "[bignum-test] GMP bridge self-test failed; aborting\n");
        return 1;
    }

    if (strcmp(op, "bridge") == 0)
    {
        printf("[bignum-test] bridge self-test passed\n");
        return 0;
    }

    bn_test_report_t report;
    bn_report_init(&report, op);

    if (strcmp(op, "init") == 0)
    {
        run_init_tests(&report, seed);
    }
    else if (strcmp(op, "reset") == 0)
    {
        run_reset_tests(&report, seed);
    }
    else if (strcmp(op, "tostring") == 0)
    {
        run_tostring_tests(&report, seed);
    }
    else if (strcmp(op, "add") == 0)
    {
        run_add_tests(&report, seed, iterations, scenario);
    }
    else if (strcmp(op, "sub") == 0)
    {
        run_sub_tests(&report, seed, iterations);
    }
    else if (strcmp(op, "mul") == 0)
    {
        run_mul_tests(&report, seed, iterations);
    }
    else if (strcmp(op, "div") == 0)
    {
        run_div_tests(&report, seed, iterations);
    }
    else if (strcmp(op, "mod") == 0)
    {
        run_mod_tests(&report, seed, iterations);
    }
    else if (strcmp(op, "modexp") == 0)
    {
        run_modexp_tests(&report, seed, iterations);
    }
    else
    {
        fprintf(stderr, "Unknown op '%s'\n", op);
        print_usage(argv[0]);
        return 2;
    }

    return bn_report_finish(&report);
}
