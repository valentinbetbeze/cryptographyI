#ifndef SHA_H
#define SHA_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_MD_SZ (256U / 8U) // Message digest size in bytes for SHA-256

int sha256(const uint8_t *msg, uint64_t len, uint8_t *md);

#endif // SHA_H
