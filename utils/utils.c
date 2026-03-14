#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Helper to convert hex string to bytes.
 *
 * @param[in]  hex   ASCII hex string.
 * @param[out] bytes Byte buffer.
 * @param[in]  sz    Size of the bytes buffer in bytes.
 */
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t sz)
{
    assert(hex);
    assert(bytes);
    assert(sz);

    for (size_t i = 0; i < sz; i++)
    {
        if (sscanf(hex + 2 * i, "%2hhx", &bytes[i]) != 1)
        {
            return -1;
        }
    }
    return 0;
}

/**
 * @brief Helper to convert bytes to hex string
 *
 * @param[in]  bytes Byte buffer.
 * @param[in]  sz    Size of the byte buffer in bytes.
 * @param[out] hex   Buffer to store ASCII-converted bytes. Size must be twice
 * the size of @p bytes.
 */
void bytes_to_hex(const uint8_t *bytes, size_t sz, char *hex)
{
    assert(bytes);
    assert(sz);
    assert(hex);

    for (size_t i = 0; i < sz; i++)
    {
        sprintf(hex + 2 * i, "%02x", bytes[i]);
    }
}

/**
 * @brief Convert 8 bytes to uint64_t (big-endian)
 *
 * @param[in] bytes 8-bit array
 *
 * @return 64-bit value to convert to 8-bit array
 */
uint64_t bytes_to_u64(const uint8_t *bytes)
{
    assert(bytes);

    uint64_t result = 0;
    for (int i = 0; i < 8; i++)
    {
        result = (result << 8) | bytes[i];
    }
    return result;
}

/**
 * @brief Convert uint64_t to 8 bytes (big-endian)
 *
 * @param[in]  value 64-bit value to convert to 8-bit array
 * @param[out] bytes 8-bit array
 */
void u64_to_bytes(uint64_t value, uint8_t *bytes)
{
    assert(bytes);

    for (int i = 7; i >= 0; i--)
    {
        bytes[i] = value & 0xFF;
        value >>= 8;
    }
}

/**
 * @brief Convert bytes to uint32_t array (big-endian)
 */
void bytes_to_words(const uint8_t *bytes, uint32_t *words, size_t num_bytes)
{
    assert(bytes);
    assert(words);

    for (size_t i = 0; i < num_bytes / 4; i++)
    {
        words[i] = ((uint32_t)bytes[i * 4 + 0] << 24) |
                   ((uint32_t)bytes[i * 4 + 1] << 16) |
                   ((uint32_t)bytes[i * 4 + 2] << 8) |
                   ((uint32_t)bytes[i * 4 + 3]);
    }
}

/**
 * @brief Convert uint32_t array to bytes (big-endian)
 */
void words_to_bytes(const uint32_t *words, uint8_t *bytes, size_t num_bytes)
{
    assert(words);
    assert(bytes);

    for (size_t i = 0; i < num_bytes / 4; i++)
    {
        bytes[i * 4 + 0] = (words[i] >> 24) & 0xFF;
        bytes[i * 4 + 1] = (words[i] >> 16) & 0xFF;
        bytes[i * 4 + 2] = (words[i] >> 8) & 0xFF;
        bytes[i * 4 + 3] = words[i] & 0xFF;
    }
}
