#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Bignum library.
 *
 * How to use
 *
 *      1. Construct a bignum object with bn_init().
 *      2. Perform bignum operations such as bn_add(), bn_mul(), etc.
 *      3. Destroy the bignum object by calling bn_reset().
 *
 * ASCII encoding policy
 *
 *      The library uses the following subset of the GMP-style convention:
 *
 *      - Optional leading + or - signs are supported.
 *      - Digits above 9 are processed as case-insensitive.
 *      - No leading and trailing whitespace
 *      - No base prefix (e.g., 0x for hex, 0b for binary, etc.)
 *      - No empty string (considered invalid)
 *
 * Output ownership policy
 *
 *      The caller must provide a bn_t placeholder for the library to store the
 *      output. If the placeholder does not point to valid memory (e.g.,
 *      bn_t::bstr is NULL) or has insufficient amount of it, the library will
 *      dynamically (re)allocate the required memory; otherwise it will reuse
 *      the existing memory buffer.
 *
 * In-place operation policy
 *
 *      Some bignum functions support in-place operation (mentioned in the
 *      function comment header). For such functions, if in-place is used, the
 *      library will not perform memory reallocation on the in-place buffer
 *      (that is the buffer used as both input and output) and will instead
 *      return a bn_ret_t::BN_ERR_OVERFLOW error.
 *
 * Reentrancy and thread safety
 *
 *      All functions provided by this library are reentrant, however they are
 *      not thread-safe.
 */

/**
 * @brief Return codes.
 */
typedef enum
{
    BN_OK = 0,          // Operation completed successfully
    BN_ERR_BAD_PTR,     // Null input pointers
    BN_ERR_BAD_LENGTH,  // Invalid length (e.g., 0)
    BN_ERR_BAD_ENC,     // Invalid ASCII encoding
    BN_ERR_BAD_VALUE,   // Invalid input value (function specific)
    BN_ERR_NO_MEMORY,   // Memory allocation failure
    BN_ERR_OVERFLOW,    // Result overflowed (in-place usage only)
} bn_ret_t;

/**
 * @brief Bignum descriptor.
 */
typedef struct
{
    uint8_t *bstr;    // Byte string, LSB-first
    size_t len;       // Byte string length
    bool is_negative; // True if the bignum is negative
} bn_t;

// ==================================================
// Lifecycle functions
// ==================================================

bn_ret_t bn_init(bn_t *bn, const char *str, int base);
bn_ret_t bn_reset(bn_t *bn);
bn_ret_t bn_tostring(const bn_t *bn, int base, char **str, size_t *len);

// ==================================================
// Operation functions
// ==================================================

bn_ret_t bn_add(const bn_t *a, const bn_t *b, bn_t *out);
bn_ret_t bn_sub(const bn_t *a, const bn_t *b, bn_t *out);
bn_ret_t bn_mul(const bn_t *a, const bn_t *b, bn_t *out);
bn_ret_t bn_div(const bn_t *a, const bn_t *b, bn_t *q, bn_t *r);
bn_ret_t bn_mod(const bn_t *a, const bn_t *m, bn_t *r);
bn_ret_t bn_modexp(const bn_t *b, const bn_t *e, const bn_t *m, bn_t *out);

#endif // BIGNUM_H
