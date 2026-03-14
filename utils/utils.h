#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdlib.h>

// Get the number of element of an array
#define N_ARR(arr) (sizeof((arr)) / sizeof((arr)[0]))

int hex_to_bytes(const char *hex, uint8_t *bytes, size_t sz);
void bytes_to_hex(const uint8_t *bytes, size_t sz, char *hex);
void u64_to_bytes(uint64_t value, uint8_t *bytes);
uint64_t bytes_to_u64(const uint8_t *bytes);
void bytes_to_words(const uint8_t *bytes, uint32_t *words, size_t num_bytes);
void words_to_bytes(const uint32_t *words, uint8_t *bytes, size_t num_bytes);

#endif // UTILS_H
