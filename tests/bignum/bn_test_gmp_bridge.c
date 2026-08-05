#include "bn_test_gmp_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROUND_TO_MULTIPLE(x, m) ((((x) + ((m) - 1)) / (m)) * (m))

void bn_to_mpz(const bn_t *bn, mpz_t out)
{
    if (bn->bstr == NULL || bn->len == 0)
    {
        mpz_set_ui(out, 0);
        return;
    }

    /* bn_t::bstr is documented as a LSB-first byte string; importing with
     * word size 1 and order -1 (least significant word/byte first) makes the
     * conversion correct regardless of host endianness. */
    mpz_import(out, bn->len, -1, 1, 0, 0, bn->bstr);

    if (bn->is_negative && mpz_sgn(out) != 0)
    {
        mpz_neg(out, out);
    }
}

void mpz_to_bn(const mpz_t in, bn_t *out)
{
    bn_reset(out);

    const bool is_zero           = (mpz_sgn(in) == 0);
    const size_t magnitude_bytes = is_zero ? 0 :
                                             (mpz_sizeinbase(in, 2) + 7) / 8;

    size_t blen_w = ROUND_TO_MULTIPLE(magnitude_bytes, sizeof(uint32_t)) /
                    sizeof(uint32_t);
    if (blen_w == 0)
    {
        blen_w =
            1; // at least one word, matching bn_init's minimum allocation for 0
    }
    const size_t blen = blen_w * sizeof(uint32_t);

    uint8_t *buf = (uint8_t *)calloc(blen_w, sizeof(uint32_t));
    if (buf == NULL)
    {
        return;
    }

    if (!is_zero)
    {
        size_t count = 0;
        mpz_export(buf, &count, -1, 1, 0, 0, in);
    }

    out->bstr        = buf;
    out->len         = blen;
    out->is_negative = (mpz_sgn(in) < 0);
}

bool bn_mpz_equal(const bn_t *bn, const mpz_t expected)
{
    mpz_t tmp;
    mpz_init(tmp);
    bn_to_mpz(bn, tmp);

    /* GMP has no negative zero; bn_t::is_negative could be true on a
     * zero-magnitude result since bignum.h documents no sign-of-zero
     * canonicalization policy. Treat zero as equal regardless of sign. */
    bool eq;
    if (mpz_sgn(tmp) == 0 && mpz_sgn(expected) == 0)
    {
        eq = true;
    }
    else
    {
        eq = (mpz_cmp(tmp, expected) == 0);
    }

    mpz_clear(tmp);
    return eq;
}

void mpz_euclidean_divmod(mpz_t q, mpz_t r, const mpz_t a, const mpz_t b)
{
    /* Euclidean convention: remainder always in [0, |b|). GMP has no direct
     * primitive for this; mpz_fdiv_qr's remainder already lands in [0, b)
     * when b > 0, and mpz_cdiv_qr's remainder lands in [0, -b) when b < 0. */
    if (mpz_sgn(b) > 0)
    {
        mpz_fdiv_qr(q, r, a, b);
    }
    else
    {
        mpz_cdiv_qr(q, r, a, b);
    }
}

void bn_test_copy(const bn_t *src, bn_t *dst)
{
    bn_reset(dst);
    dst->is_negative = src->is_negative;

    if (src->len > 0 && src->bstr != NULL)
    {
        dst->bstr = (uint8_t *)malloc(src->len);
        memcpy(dst->bstr, src->bstr, src->len);
        dst->len = src->len;
    }
}

void bn_render_for_debug(const bn_t *bn, char *buf, size_t buflen)
{
    if (bn == NULL || bn->bstr == NULL || bn->len == 0)
    {
        snprintf(buf, buflen, "<null/empty>");
        return;
    }

    char *str    = NULL;
    size_t slen  = 0;
    bn_ret_t ret = bn_tostring(bn, 10, &str, &slen);
    if (ret != BN_OK)
    {
        snprintf(buf, buflen, "<bn_tostring error %d>", ret);
        return;
    }

    snprintf(buf, buflen, "%s", str);
    free(str);
}

bool bn_test_gmp_bridge_selftest(void)
{
    /* Deliberately independent of bn_init(): this validates only the
     * bn_to_mpz()/mpz_to_bn() conversion logic introduced by this test
     * harness, not bignum.c itself (which has its own dedicated test
     * group). Values are constructed straight from GMP via mpz_set_str. */
    static const char *values[] = {
        "0",
        "1",
        "-1",
        "4294967295",
        "4294967296",
        "18446744073709551615",
        "18446744073709551616",
        "-123456789012345678901234567890",
    };

    bool ok = true;

    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    {
        mpz_t m;
        mpz_init(m);
        mpz_set_str(m, values[i], 10);

        bn_t bn = {0};
        mpz_to_bn(m, &bn);

        if (!bn_mpz_equal(&bn, m))
        {
            fprintf(stderr,
                    "[bridge selftest] mpz_to_bn mismatch for '%s'\n",
                    values[i]);
            ok = false;
        }

        mpz_t roundtrip;
        mpz_init(roundtrip);
        bn_to_mpz(&bn, roundtrip);
        if (mpz_cmp(roundtrip, m) != 0)
        {
            char *expected_str = mpz_get_str(NULL, 10, m);
            char *actual_str   = mpz_get_str(NULL, 10, roundtrip);
            fprintf(stderr,
                    "[bridge selftest] bn_to_mpz(mpz_to_bn(x)) mismatch: "
                    "expected '%s', got '%s'\n",
                    expected_str,
                    actual_str);
            free(expected_str);
            free(actual_str);
            ok = false;
        }

        bn_reset(&bn);
        mpz_clear(m);
        mpz_clear(roundtrip);
    }

    return ok;
}
