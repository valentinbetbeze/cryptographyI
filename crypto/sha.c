#include "sha.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#define SHA256_w (32U)  // Word size in bits for SHA-256
#define SHA256_m (512U) // Message block size in bits for SHA-256

#define SHA256_WRD_SZ (SHA256_w / 8U) // Word size in bytes for SHA-256
#define SHA256_BLK_SZ (SHA256_m / 8U) // Message block size in bytes for SHA-256

/**
 * @brief Check if a SHA256 block can hold the padding structure.
 *
 * @param[in] b Number of message bytes in the SHA256 block.
 */
#define SHA256_CAN_LAST_BLK_HOLD_PADDING(b)                                    \
    (((b) > 0U) && ((b) * 8U + 1U <= SHA256_m - sizeof(uint64_t) * 8U))

/**
 * @brief Sequence of sixty-four constant 32-bit words. These words represent
 * the first thirty-two bits of the fractional parts of the cube roots of the
 * first sixty-four prime numbers.
 */
static const uint32_t sha256_K[64U] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/**
 * @brief Initial intermediate hash value.
 */
static const uint32_t H_0[8U] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
};

/**
 * @brief Addition modulo 2^32.
 *
 * @param[in] a 32-bit word
 * @param[in] b 32-bit word
 *
 * @return 32-bit word sum of a and b.
 */
static inline uint32_t sha256_add(uint32_t a, uint32_t b)
{
    return (uint32_t)(a + b);
}

/**
 * @brief Shift left 32-bit word x by n.
 */
static inline uint32_t sha256_SHL(uint32_t x, uint32_t n)
{
    assert(n < SHA256_w);
    return (uint32_t)(x << n);
}

/**
 * @brief Shift right 32-bit word x by n.
 */
static inline uint32_t sha256_SHR(uint32_t x, uint32_t n)
{
    assert(n < SHA256_w);
    return x >> n;
}

/**
 * @brief Rotate left 32-bit word x by n.
 */
static inline uint32_t sha256_ROTL(uint32_t x, uint32_t n)
{
    return sha256_SHL(x, n) | sha256_SHR(x, SHA256_w - n);
}

/**
 * @brief Rotate right 32-bit word x by n.
 */
static inline uint32_t sha256_ROTR(uint32_t x, uint32_t n)
{
    return sha256_SHR(x, n) | sha256_SHL(x, SHA256_w - n);
}

static inline uint32_t sha256_Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

static inline uint32_t sha256_Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sha256_eps0(uint32_t x)
{
    return sha256_ROTR(x, 2) ^ sha256_ROTR(x, 13) ^ sha256_ROTR(x, 22);
}

static inline uint32_t sha256_eps1(uint32_t x)
{
    return sha256_ROTR(x, 6) ^ sha256_ROTR(x, 11) ^ sha256_ROTR(x, 25);
}

static inline uint32_t sha256_sig0(uint32_t x)
{
    return sha256_ROTR(x, 7) ^ sha256_ROTR(x, 18) ^ sha256_SHR(x, 3);
}

static inline uint32_t sha256_sig1(uint32_t x)
{
    return sha256_ROTR(x, 17) ^ sha256_ROTR(x, 19) ^ sha256_SHR(x, 10);
}

/**
 * @brief SHA-256 function
 *
 * @param[in]  msg Message to hash
 * @param[in]  len Message length in bytes
 * @param[out] md Message digest
 *
 * @retval 0 if successful; else 1
 */
int sha256(const uint8_t *msg, size_t len, uint8_t *md)
{
    if (!msg || !md || len > (SIZE_MAX / 8U))
    {
        return 1;
    }

    size_t N               = len / SHA256_BLK_SZ; // Number of message blocks
    size_t N_non_padded    = N;
    size_t remaining_bytes = len % SHA256_BLK_SZ;
    uint64_t len_bits      = len * 8U;

    // Pointer to keep track of the current message block in memory.
    const uint8_t *M = msg;

    // ==================================================
    // Padding the message (section 5.1)
    // ==================================================

    // Placeholder for message padding construction.
    uint8_t block_padding[SHA256_BLK_SZ * 2];
    memset(block_padding, 0, sizeof(block_padding));

    size_t padding_end_pos = 0;
    if (remaining_bytes == 0U ||
        SHA256_CAN_LAST_BLK_HOLD_PADDING(remaining_bytes) == true)
    {
        // One block is sufficient for padding.
        padding_end_pos = SHA256_BLK_SZ - 1U;
        N += 1U;
    }
    else
    {
        /* The last block of the message does not have enough space to add the
         * length value. A new block must be used. */
        padding_end_pos = SHA256_BLK_SZ * 2U - 1U;
        N += 2U;
    }

    // Construct the padding
    memcpy(block_padding, msg + len - remaining_bytes, remaining_bytes);

    block_padding[remaining_bytes] = 1U << 7;

    block_padding[padding_end_pos - 7U] |= (len_bits >> 56) & 0xff;
    block_padding[padding_end_pos - 6U] = (len_bits >> 48) & 0xff;
    block_padding[padding_end_pos - 5U] = (len_bits >> 40) & 0xff;
    block_padding[padding_end_pos - 4U] = (len_bits >> 32) & 0xff;
    block_padding[padding_end_pos - 3U] = (len_bits >> 24) & 0xff;
    block_padding[padding_end_pos - 2U] = (len_bits >> 16) & 0xff;
    block_padding[padding_end_pos - 1U] = (len_bits >> 8) & 0xff;
    block_padding[padding_end_pos - 0U] = (len_bits >> 0) & 0xff;

    // ==================================================
    // Setting the initial hash value H (section 5.3)
    // ==================================================

    uint32_t H[sizeof(H_0) / sizeof(H_0[0])];
    memcpy(H, H_0, sizeof(H));

    // ==================================================
    // Main algorithm (section 5.3)
    // ==================================================

    for (size_t i = 1U; i <= N; i++)
    {
        // Get the start of the current message block.
        if (i <= N_non_padded)
        {
            M = msg + (i - 1U) * SHA256_BLK_SZ;
        }
        else
        {
            M = block_padding + (i - N_non_padded - 1U) * SHA256_BLK_SZ;
        }

        // 1. Prepare the message schedule, {W_t}
        uint32_t W[64];
        for (size_t t = 0U; t < 64U; t++)
        {
            if (t < 16U)
            {
                W[t] = ((uint32_t)M[t * SHA256_WRD_SZ + 0] << 24) |
                       ((uint32_t)M[t * SHA256_WRD_SZ + 1] << 16) |
                       ((uint32_t)M[t * SHA256_WRD_SZ + 2] << 8) |
                       ((uint32_t)M[t * SHA256_WRD_SZ + 3] << 0);
            }
            else
            {
                uint32_t x1 = sha256_sig1(W[t - 2]);
                uint32_t x2 = W[t - 7];
                uint32_t x3 = sha256_sig0(W[t - 15]);
                uint32_t x4 = W[t - 16];

                W[t] = sha256_add(x1, sha256_add(x2, sha256_add(x3, x4)));
            }
        }

        /* 2. Initialize the eight working variables, a..h with the (i-1)th hash
         * value. */
        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        uint32_t f = H[5];
        uint32_t g = H[6];
        uint32_t h = H[7];

        // 3.
        for (size_t t = 0U; t < 64U; t++)
        {
            uint32_t T1 = sha256_add(
                h,
                sha256_add(sha256_eps1(e),
                           sha256_add(sha256_Ch(e, f, g),
                                      sha256_add(sha256_K[t], W[t]))));
            uint32_t T2 = sha256_add(sha256_eps0(a), sha256_Maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = sha256_add(d, T1);
            d = c;
            c = b;
            b = a;
            a = sha256_add(T1, T2);
        }

        // 4. Compute the ith intermediate hash value H
        H[0] = sha256_add(a, H[0]);
        H[1] = sha256_add(b, H[1]);
        H[2] = sha256_add(c, H[2]);
        H[3] = sha256_add(d, H[3]);
        H[4] = sha256_add(e, H[4]);
        H[5] = sha256_add(f, H[5]);
        H[6] = sha256_add(g, H[6]);
        H[7] = sha256_add(h, H[7]);
    }

    // Output the last hash value
    for (size_t i = 0U; i < (sizeof(H) / sizeof(H[0])); i++)
    {
        md[i * SHA256_WRD_SZ + 0] = (H[i] >> 24) & 0xff;
        md[i * SHA256_WRD_SZ + 1] = (H[i] >> 16) & 0xff;
        md[i * SHA256_WRD_SZ + 2] = (H[i] >> 8) & 0xff;
        md[i * SHA256_WRD_SZ + 3] = (H[i] >> 0) & 0xff;
    }

    return 0;
}
