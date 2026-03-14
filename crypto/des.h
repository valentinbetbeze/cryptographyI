#ifndef DES_H
#define DES_H

#include <stdbool.h>
#include <stdint.h>

uint64_t des(uint64_t key, uint64_t block, bool encrypt);

#define des_encrypt(key, block) (des(key, block, true))
#define des_decrypt(key, block) (des(key, block, false))

#endif // DES_H
