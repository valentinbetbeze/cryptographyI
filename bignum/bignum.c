#include "bignum.h"

#include <assert.h>
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BITS_PER_BYTES          (8)
#define BASE_MIN                (2)
#define BASE_MAX                (36)
#define ROUND_TO_MULTIPLE(x, m) ((((x) + ((m) - 1)) / (m)) * (m))

static size_t get_blen_from_slen(size_t slen, int base)
{
    // log2(g^k) == k * log2(g)
    double num_bytes = ((double)slen * log2(base)) / (double)BITS_PER_BYTES;
    double num_bytes_rounded_up = ceil(num_bytes);
    return (size_t)num_bytes_rounded_up;
}

static size_t get_slen_from_blen(size_t blen, int base)
{
    double num_chars            = (double)(blen * BITS_PER_BYTES) / log2(base);
    double num_chars_rounded_up = ceil(num_chars);
    return (size_t)num_chars_rounded_up;
}

static bool is_base_valid(int base)
{
    return (base >= BASE_MIN && base <= BASE_MAX) ? true : false;
}

static unsigned int get_int_from_char(char ch, int base, bool *is_valid)
{
    assert(is_valid);

    int n    = 0;
    bool ret = true;

    // Character MUST be an element of {0-9,a-z,A-Z}
    if (isdigit(ch))
    {
        n = ch - '0';
    }
    else if (isalpha(ch))
    {
        n = 10 + ch - ((isupper(ch)) ? 'A' : 'a');
    }
    else
    {
        ret = false;
    }

    if (n >= base)
    {
        ret = false;
    }

    *is_valid = ret;

    return n;
}

/**
 * @brief Checks if the absolute value of a is greater than or equal to the
 * absolute value of b, e.g., |a| >= |b|
 *
 * @param [in] a Reference operand
 * @param [in] b Operand compared against
 *
 * @return true if |a| >= |b|; else false.
 *
 * @details The absolute value means that the sign of the bignum is not
 * accounted in the comparison.
 */
static bool is_greater_or_equal_abs(const bn_t *a, const bn_t *b)
{
    assert(a);
    assert(b);

    int l = 0; // lesser-than lock
    int g = 0; // greater-than lock

    const size_t len = (a->len > b->len) ? a->len : b->len;

    for (int i = len - 1; i >= 0; i--)
    {
        for (int n = (BITS_PER_BYTES - 1); n >= 0; n--)
        {
            int bit_a = (i < a->len) ? (a->bstr[i] >> n) & 1 : 0;
            int bit_b = (i < b->len) ? (b->bstr[i] >> n) & 1 : 0;

            /* Defined via the following truth tables:

            a b g | l (a<b)   a b l | g (a>b)
            0 0 0 | 0         0 0 0 | 0
            0 1 0 | 1         0 1 0 | 0
            1 0 0 | 0         1 0 0 | 1
            1 1 0 | 0         1 1 0 | 0
            0 0 1 | 0         0 0 1 | 0
            0 1 1 | 0         0 1 1 | 0
            1 0 1 | 0         1 0 1 | 0
            1 1 1 | 0         1 1 1 | 0

            Locks must be sticky, hence the bitwise-OR. */

            l |= ~bit_a & bit_b & ~g;
            g |= bit_a & ~bit_b & ~l;
        }
    }

    return (l == 0);
}

/**
 * @brief Add a value to a bignum word array and propagate the carry.
 *
 * @param [in]  dst         Least signinficant word of the buffer to add into
 * @param [in]  wlen        Number of words in the buffer, starting at dst
 * @param [in]  value       Word value to add
 * @param [out] carry_words (Optional) Number of words affected by the carry
 *
 * @return BN_ERR_OVERFLOW if the addition overflows the bignum array; else
 * BN_OK.
 */
static bn_ret_t add_with_carry(uint32_t *dst,
                               size_t wlen,
                               uint32_t value,
                               int *carry_words)
{
    assert(dst);

    int i              = 0;
    uint32_t old_value = dst[i];

    dst[i] += value;

    while (i < wlen && dst[i] < old_value)
    {
        i++;
        old_value = dst[i];
        dst[i] += 1;
    }

    if (carry_words)
    {
        *carry_words = i;
    }

    return BN_OK;
}

/**
 * @brief Subtract a value to a bignum word array and propagate the carry.
 *
 * @param [in]  dst         Least signinficant word of the buffer to add into
 * @param [in]  wlen        Number of words in the buffer, starting at dst
 * @param [in]  value       Word value to subtract
 * @param [out] carry_words (Optional) Number of words affected by the carry
 *
 * @return BN_ERR_OVERFLOW if the addition overflows the bignum array; else
 * BN_OK.
 */
static bn_ret_t sub_with_carry(uint32_t *dst,
                               size_t wlen,
                               uint32_t value,
                               int *carry_words)
{
    assert(dst);

    int i              = 0;
    uint32_t old_value = dst[i];

    dst[i] -= value;

    while (i < wlen && dst[i] > old_value)
    {
        i++;
        old_value = dst[i];
        dst[i] -= 1;
    }

    if (carry_words)
    {
        *carry_words = i;
    }

    return BN_OK;
}

/**
 * @brief Add two unsigned bignums, with |a|>=|b|.
 *
 * @param [in]  a   First operand
 * @param [in]  b   Second operand
 * @param [out] out Sum result: out = |a|+|b|
 *
 * @return Status code
 *
 * @details This function supports in-place operation.
 */
static bn_ret_t add_unsigned(const bn_t *a, const bn_t *b, bn_t *out)
{
    assert(a);
    assert(a->bstr);
    assert(b);
    assert(b->bstr);
    assert(out);
    assert(!(a == b && a == out));

    uint8_t *dst = out->bstr; // Default destination buffer

    const bool is_inplace = (out == a || out == b);
    const bn_t *max       = a;
    const bn_t *min       = b;

    // Add a word to account for a potential overflow
    const size_t required_capacity = max->len + sizeof(uint32_t);
    const size_t current_capacity  = max->bstr_len;

    /* Allocate memory except for an inplace operation on the largest bignum
     * which has enough capacity to hold the overflow bit. */
    if ((out != max || current_capacity < required_capacity))
    {
        dst = (uint8_t *)calloc(required_capacity, sizeof(uint8_t));
        if (!dst)
        {
            return BN_ERR_NO_MEMORY;
        }
        memcpy(dst, max->bstr, max->len);
    }

    int msw_i             = (max->len - 1) / sizeof(uint32_t);
    const size_t wlen_min = min->len / sizeof(uint32_t);
    const size_t wlen_dst = required_capacity / sizeof(uint32_t);

    for (int i = 0; i < wlen_min; i++)
    {
        int num_carries = 0;
        uint32_t *dst_w = (uint32_t *)dst;
        uint32_t to_add = ((uint32_t *)min->bstr)[i];

        // Cannot overflow as the destination buffer is properly sized.
        (void)add_with_carry(&dst_w[i], wlen_dst - i, to_add, &num_carries);

        // Keep track of the most significant word index
        int last_idx = i + num_carries;
        if (last_idx > msw_i)
        {
            msw_i = last_idx;
        }
    }

    // Package the output
    if (out->bstr && out->bstr != dst)
    {
        free(out->bstr);
    }
    out->bstr     = dst;
    out->bstr_len = required_capacity;
    out->len      = (msw_i + 1) * sizeof(uint32_t);

    return BN_OK;
}

/**
 * @brief Compute the absolute difference of two unsigned bignums, with
 * |a|>=|b|.
 *
 * @param [in]  a   First operand
 * @param [in]  b   Second operand
 * @param [out] out Subtraction result: out = ||a|-|b||
 *
 * @return Status code
 *
 * @details This function supports in-place operation.
 */
static bn_ret_t sub_unsigned(const bn_t *a, const bn_t *b, bn_t *out)
{
    assert(a);
    assert(a->bstr);
    assert(b);
    assert(b->bstr);
    assert(out);
    assert(!(a == b && a == out));

    uint8_t *dst = out->bstr; // Default destination buffer

    const bool is_inplace = (out == a || out == b);
    const bn_t *max       = a;
    const bn_t *min       = b;

    // Allocate memory except for an inplace operation on the largest bignum
    if (out != max)
    {
        dst = (uint8_t *)calloc(max->len, sizeof(uint8_t));
        if (!dst)
        {
            return BN_ERR_NO_MEMORY;
        }
        memcpy(dst, max->bstr, max->len);
    }

    int msw_i             = (max->len - 1) / sizeof(uint32_t);
    const size_t wlen_min = min->len / sizeof(uint32_t);
    const size_t wlen_dst = max->len / sizeof(uint32_t);

    for (int i = 0; i < wlen_min; i++)
    {
        uint32_t *dst_w = (uint32_t *)dst;
        uint32_t to_sub = ((uint32_t *)min->bstr)[i];

        // Cannot underflow as |dst|=|max|>|min|
        (void)sub_with_carry(&dst_w[i], wlen_dst - i, to_sub, NULL);

        // Keep track of the most significant word index
        while (msw_i > 0 && dst_w[msw_i] == 0)
        {
            msw_i--;
        }
    }

    // Package the output
    if (out->bstr && out->bstr != dst)
    {
        free(out->bstr);
    }
    out->bstr     = dst;
    out->bstr_len = max->len;
    out->len      = (msw_i + 1) * sizeof(uint32_t);

    return BN_OK;
}

/**
 * @brief Construct a bignum object from an ASCII-encoded byte string.
 *
 * @param [in] bn   Bignum object placeholder
 * @param [in] str  ASCII-encoded, MSB-first byte string
 * @param [in] base Base of the ASCII-encoded byte string. Supported base
 *                  values range from 2 to 36 inclusive.
 *
 * @return Status code
 *
 * @details The function supports a subset of the GMP-style convention. See
 *          'ASCII encoding policy' for more.
 */
bn_ret_t bn_init(bn_t *bn, const char *str, int base)
{
    if (!bn || !str)
    {
        return BN_ERR_BAD_PTR;
    }

    if (!is_base_valid(base))
    {
        return BN_ERR_BAD_VALUE;
    }

    // Reset the structure
    bn_reset(bn);

    const char sign = *str;
    if (sign == '-' || sign == '+')
    {
        if (sign == '-')
        {
            bn->is_negative = true;
        }
        str++;
    }

    // Number of characters whose encoded value fit in a byte.
    const size_t slen = strlen(str);
    if (slen == 0)
    {
        fprintf(stderr, "Error: String has no digit.\n");
        return BN_ERR_BAD_LENGTH;
    }

    const size_t blen_raw = get_blen_from_slen(slen, base);
    /* Make sure the buffer size is a multiple of 4 bytes as bignum operations
     * are done on 4-byte blocks (uint32_t). */
    const size_t blen = ROUND_TO_MULTIPLE(blen_raw, sizeof(uint32_t));
    // Length in words
    const size_t blen_w = blen / sizeof(uint32_t);

    // Storage for bignum
    uint32_t *buf = (uint32_t *)calloc(blen_w, sizeof(uint32_t));
    if (buf == NULL)
    {
        return BN_ERR_NO_MEMORY;
    }

    /* Index of the most significant word. Initialized with the start index as
     * the bignum is 0 at the beginning. Incremented as the bignum is
     * constructed. */
    int msw_idx = 0;
    char ch     = 0;

    // Convert the string to 2^32 base using mul-add method.
    while ((ch = *str++))
    {
        // Convert the ASCII-encoded digit
        bool is_valid        = false;
        const uint32_t digit = get_int_from_char(ch, base, &is_valid);
        if (is_valid == false)
        {
            fprintf(stderr, "Error: '%c' is invalid in base %i\n", ch, base);
            free(buf);
            return BN_ERR_BAD_ENC;
        }

        // Multiply the bignum array by the base
        for (int i = msw_idx; i >= 0; i--)
        {
            uint64_t tmp = buf[i];
            tmp *= base;

            // Check and carry overflow
            const uint32_t overflow  = tmp >> 32;        // tmp / 2^32
            const uint32_t remainder = tmp & UINT32_MAX; // tmp % 2^32

            buf[i] = remainder;

            /* In the case of an overflow, the quotient must be added to the
             * next word; as tmp = q * (2^32)^1 + r * (2^32)^0 */
            if (overflow > 0)
            {
                int overflow_idx = i + 1;
                int num_carries  = 0;

                bn_ret_t ret = add_with_carry(&buf[overflow_idx],
                                              blen_w - overflow_idx,
                                              overflow,
                                              &num_carries);
                if (ret != BN_OK)
                {
                    free(buf);
                    return ret;
                }

                int last_idx = overflow_idx + num_carries;
                if (last_idx > msw_idx)
                {
                    msw_idx = last_idx;
                }
            }
        }

        // Add the converted digit to the bignum array.
        int num_carries = 0;
        bn_ret_t ret    = add_with_carry(buf, blen_w, digit, &num_carries);
        if (ret != BN_OK)
        {
            free(buf);
            return ret;
        }

        if (num_carries > msw_idx)
        {
            msw_idx = num_carries;
        }
    }

    bn->len      = (msw_idx + 1) * sizeof(uint32_t);
    bn->bstr     = (uint8_t *)buf;
    bn->bstr_len = blen;

    return BN_OK;
}

/**
 * @brief Reset a bignum object; freeing its memory is zeroing its properties.
 *
 * @param [in] bn Bignum object to reset.
 *
 * @return Status code
 *
 * @details Sets the sign field to positive by default.
 */
bn_ret_t bn_reset(bn_t *bn)
{
    if (!bn)
    {
        return BN_ERR_BAD_PTR;
    }

    if (bn->bstr != NULL)
    {
        free(bn->bstr);
    }

    bn->bstr        = NULL;
    bn->len         = 0;
    bn->is_negative = false;
    bn->bstr_len    = 0;

    return BN_OK;
}

/**
 * @brief ASCII-encode a bignum.
 *
 * @param [in]  bn      Bignum
 * @param [in]  base    Base to use for the representation of the bignum.
 *                      Supported base values range from 2 to 36 inclusive.
 * @param [out] pstr    Buffer holding the ASCII-encoded byte string
 * representation of the bignum.
 * @param [out] len     Length in byte of @p str (null terminator included)
 *
 * @return Status code
 *
 * @details The memory pointed to by @p str is allocated by the function. The
 *          user is responsible for freeing it.
 */
bn_ret_t bn_tostring(const bn_t *bn, int base, char **pstr, size_t *len)
{
    if (!bn || !bn->bstr || !pstr || !len)
    {
        return BN_ERR_BAD_PTR;
    }

    if (bn->len == 0)
    {
        return BN_ERR_BAD_LENGTH;
    }

    if (!is_base_valid(base))
    {
        return BN_ERR_BAD_VALUE;
    }

    int last_idx = 0; // index used to iterate over the string array
    int msw_idx  = 0; // index used to keep track of the most significant word
    const size_t blen_w = bn->len / sizeof(uint32_t); // bignum length in words
    const size_t slen   = get_slen_from_blen(bn->len, base) +
                          ((bn->is_negative) ? 1 : 0);

    char *str = (char *)malloc(slen + 1); // + 1 for null terminator
    if (str == NULL)
    {
        return BN_ERR_NO_MEMORY;
    }

    // Create a temporary copy of the bignum for internal operations.
    uint32_t *buf = (uint32_t *)malloc(bn->len);
    if (buf == NULL)
    {
        free(str);
        return BN_ERR_NO_MEMORY;
    }
    memcpy(buf, bn->bstr, bn->len);

    if (bn->is_negative)
    {
        str[last_idx++] = '-';
    }

    // Find the most significant word
    for (int i = blen_w - 1; i >= 0; i--)
    {
        if (buf[i] != 0)
        {
            msw_idx = i;
            break;
        }
    }

    while (msw_idx >= 0)
    {
        uint64_t remainder = 0;
        uint64_t quotient  = 0;

        // Divide the whole array by the base
        for (int i = msw_idx; i >= 0; i--)
        {
            uint64_t tmp = buf[i];

            quotient  = (tmp + (remainder << 32UL)) / base;
            remainder = (tmp + (remainder << 32UL)) % base;

            buf[i] = (uint32_t)quotient;

            if (i == msw_idx && quotient == 0)
            {
                msw_idx--;
            }
        }

        // The final remainder gives the digit value in the target base
        str[last_idx++] = remainder + ((remainder < 10) ? '0' : -10 + 'a');
    }
    str[last_idx] = '\0'; // Append the null terminator

    // Reverse the string (ignore '-' sign if present)
    char *ptr              = (bn->is_negative) ? &str[1] : &str[0];
    const int ptr_last_idx = (bn->is_negative) ? last_idx - 2 : last_idx - 1;
    for (int i = 0; i <= ptr_last_idx / 2; i++)
    {
        const char tmp        = ptr[i];
        ptr[i]                = ptr[ptr_last_idx - i];
        ptr[ptr_last_idx - i] = tmp;
    }

    *pstr = str;
    *len  = slen;

    free(buf);

    return BN_OK;
}

/**
 * @brief Add two bignums, such that a+b = out.
 *
 * @param [in]  a   First operand
 * @param [in]  b   Second operand
 * @param [out] out Sum result
 *
 * @return Status code
 *
 * @details This function supports in-place operation.
 */
bn_ret_t bn_add(const bn_t *a, const bn_t *b, bn_t *out)
{
    if (!a || !a->bstr || !b || !b->bstr || !out)
    {
        return BN_ERR_BAD_PTR;
    }

    if (a == b && a == out)
    {
        return BN_ERR_BAD_VALUE;
    }

    bn_ret_t ret      = BN_OK;
    const bool a_ge_b = is_greater_or_equal_abs(a, b);
    const bn_t *max   = (a_ge_b) ? a : b;
    const bn_t *min   = (a_ge_b) ? b : a;

    /* Let x and y two positive bignums, such that x >= y
       Case 1: (+x)+(+y) = +(x+y) -> add
       Case 2: (-x)+(-y) = -(x+y) -> add
       Case 3: (+x)+(-y) = +(x-y) -> sub
       Case 4: (-x)+(+y) = -(x-y) -> sub */

    ret = (a->is_negative == b->is_negative) ? add_unsigned(max, min, out) :
                                               sub_unsigned(max, min, out);
    if (ret == BN_OK)
    {
        // The largest absolute value determines the sign.
        out->is_negative = max->is_negative;
    }

    return ret;
}

/**
 * @brief Subtract two bignums, such that a-b = out.
 *
 * @param [in]  a   First operand
 * @param [in]  b   Second operand
 * @param [out] out Subtraction result
 *
 * @return Status code
 *
 * @details This function supports in-place operation.
 */
bn_ret_t bn_sub(const bn_t *a, const bn_t *b, bn_t *out)
{
    if (!a || !a->bstr || !b || !b->bstr || !out)
    {
        return BN_ERR_BAD_PTR;
    }

    if (a == b && a == out)
    {
        return BN_ERR_BAD_VALUE;
    }

    bn_ret_t ret      = BN_OK;
    const bool a_ge_b = is_greater_or_equal_abs(a, b);
    const bn_t *max   = (a_ge_b) ? a : b;
    const bn_t *min   = (a_ge_b) ? b : a;

    /* Let x and y two positive bignums, such that x >= y
       Case 1: (+x)-(+y) = +(x-y) -> sub
       Case 2: (-x)-(-y) = -(x-y) -> sub
       Case 3: (+x)-(-y) = +(x+y) -> add
       Case 4: (-x)-(+y) = -(x+y) -> add */

    ret = (a->is_negative == b->is_negative) ? sub_unsigned(max, min, out) :
                                               add_unsigned(max, min, out);
    if (ret == BN_OK)
    {
        /* A: a->is_negative; B: b->is_negative; O: out->is_negative

           A B a>b O  // example
           0 0 0   0	// -2-(-5) = 3
           0 0 1   1	// -5-(-2) =-3
           0 1 0   1	// -2-(+5) =-7
           0 1 1   1	// -5-(+2) =-7
           1 0 0   0	//  2-(-5) = 7
           1 0 1   0	//  5-(-2) = 7
           1 1 0   1	//  2-(+5) =-3
           1 1 1   0	//  5-(+2) = 3 */

        out->is_negative = (a_ge_b) ? a->is_negative : !b->is_negative;
    }

    return ret;
}

/**
 * @brief Multiply two bignums, such that a * b = out.
 *
 * @param [in]  a   First operand
 * @param [in]  b   Second operand
 * @param [out] out Multiplication result
 *
 * @return Status code
 */
bn_ret_t bn_mul(const bn_t *a, const bn_t *b, bn_t *out)
{
    return BN_OK;
}

/**
 * @brief Divide two bignums, such that a = q * b + r
 *
 * @param [in]  a Dividend
 * @param [in]  b Divisor
 * @param [out] q Quotient
 * @param [out] r Remainder
 *
 * @return Status code
 * @retval BN_ERR_BAD_VALUE: division by 0
 *
 * @details Uses the Euclidean convention where the remainder is always
 *          positive.
 * @details If only the remainder is of interest, it is advised to use bn_mod
 *          for performance gains.
 */
bn_ret_t bn_div(const bn_t *a, const bn_t *b, bn_t *q, bn_t *r)
{
    return BN_OK;
}

/**
 * @brief Reduce a bignum modulo a bignum, such that a mod m = r.
 *
 * @param [in]  a Bignum to reduce
 * @param [in]  m Modulus
 * @param [out] r Remainder
 *
 * @return Status code
 *
 * @details If only the remainder is of interest, it is advised to use this
 *          function over bn_div() for performance gains.
 * @retval BN_ERR_BAD_VALUE: modulo zero or a negative modulus
 */
bn_ret_t bn_mod(const bn_t *a, const bn_t *m, bn_t *r)
{
    return BN_OK;
}

/**
 * @brief Compute the modular exponentiation of a bignum, such that
 *        b**e mod m = out.
 *
 * @param [in]  b   Base
 * @param [in]  e   Exponent
 * @param [in]  m   Modulus
 * @param [out] out Modular exponentiation result
 *
 * @return Status code
 * @retval BN_ERR_BAD_VALUE: modulo zero or a negative modulus
 *
 * @details Negative exponents (inverse modular exponentiation) is supported.
 */
bn_ret_t bn_modexp(const bn_t *b, const bn_t *e, const bn_t *m, bn_t *out)
{
    return BN_OK;
}
