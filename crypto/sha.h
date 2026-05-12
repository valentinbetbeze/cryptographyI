#ifndef SHA_H
#define SHA_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_SZ (32U) // in bytes

int sha256(uint8_t *msg, size_t len, uint8_t *md);

#endif // SHA_H
