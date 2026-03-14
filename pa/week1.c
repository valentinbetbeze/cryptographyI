#include "utils.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Helper structure to use statically defined strings safely.
 */
typedef struct string_t
{
    const char *str;
    size_t len;

} string_t;

typedef struct bytes_t
{
    uint8_t *b;
    size_t sz;

} bytes_t;

int main(void)
{
    /* Cryptography I - Week 1 Programming Assignment:

       Let us see what goes wrong when a stream cipher key is used more than
       once. Below are eleven hex-encoded ciphertexts that are the result of
       encrypting eleven plaintexts with a stream cipher, all with the same
       stream cipher key.  Your goal is to decrypt the last ciphertext, and
       submit the secret message within it as solution. */

    // ciphertext 1
    const char c1[] =
        "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146"
        "fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7"
        "bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e87743"
        "01fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e";
    // ciphertext 2
    const char c2[] =
        "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44"
        "ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0"
        "bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab2417"
        "1ab3cdadb8356f";
    // ciphertext 3
    const char c3[] =
        "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44"
        "ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5"
        "f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb";
    // ciphertext 4
    const char c4[] =
        "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056"
        "f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4"
        "ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb7752"
        "00b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229b"
        "e6636aaa";
    // ciphertext 5
    const char c5[] =
        "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213"
        "f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5"
        "ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a"
        "0bb5dcaba43722130f042f8ec85b7c2070";
    // ciphertext 6
    const char c6[] =
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84a"
        "ba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3"
        "f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e43643"
        "4eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9"
        "f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4";
    // ciphertext 7
    const char c7[] =
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909"
        "ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5"
        "e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b17"
        "0fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287"
        "ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1e"
        "fff71ea313c8661dd9a4ce";
    // ciphertext 8
    const char c8[] =
        "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943"
        "ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5"
        "fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac3259"
        "18b2daada43d6712150441c2e04f6565517f317da9d3";
    // ciphertext 9
    const char c9[] =
        "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513"
        "e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0"
        "f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e93342"
        "1cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9"
        "ed6d76e48b63ab15d0208573a7eef027";
    // ciphertext 10
    const char c10[] =
        "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005"
        "b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7"
        "f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83";
    // ciphertext 11 (target)
    const char c11[] =
        "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052"
        "ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8"
        "f3315f4b52e301d16e9f52f904";

    // Convenient way to store and use the ciphertexts
    const string_t ct[] = {
        {.str = c1, .len = sizeof(c1)},
        {.str = c2, .len = sizeof(c2)},
        {.str = c3, .len = sizeof(c3)},
        {.str = c4, .len = sizeof(c4)},
        {.str = c5, .len = sizeof(c5)},
        {.str = c6, .len = sizeof(c6)},
        {.str = c7, .len = sizeof(c7)},
        {.str = c8, .len = sizeof(c8)},
        {.str = c9, .len = sizeof(c9)},
        {.str = c10, .len = sizeof(c10)},
        {.str = c11, .len = sizeof(c11)},
    };

    // Convert hex strings to bytes
    bytes_t ct_bytes[N_ARR(ct)] = {0};
    for (size_t i = 0U; i < N_ARR(ct_bytes); i++)
    {
        const size_t num_bytes = (ct[i].len - 1U) / 2;
        uint8_t *p             = (uint8_t *)malloc(num_bytes);
        if (!p)
        {
            fprintf(stderr, "Out of memory\n");
            return ENOMEM;
        }

        if (hex_to_bytes(ct[i].str, p, num_bytes) != 0)
        {
            fprintf(stderr, "Hex conversion failed\n");
            return 1;
        }

        ct_bytes[i].b  = p;
        ct_bytes[i].sz = num_bytes;
    }

    // Mark the 11th ciphertext as the target
    const bytes_t *const ct_target = &ct_bytes[10U];

    // Recover the target plaintext one byte at a time.
    int scores[0x7f] = {0};
    for (size_t byte_idx = 0U; byte_idx < ct_target->sz; byte_idx++)
    {
        int space_votes[N_ARR(ct_bytes)] = {0};

        /* For each ciphertext, detect where spaces are the most likely to
           exist using the fact that xoring a space with a letter gives a
           letter of the opposite case. */
        for (size_t i = 0; i < N_ARR(ct_bytes); i++)
        {
            if (ct_bytes[i].sz <= byte_idx)
            {
                continue;
            }
            for (size_t j = 0; j < N_ARR(ct_bytes); j++)
            {
                if (i != j && byte_idx < ct_bytes[j].sz)
                {
                    uint8_t x = ct_bytes[i].b[byte_idx] ^
                                ct_bytes[j].b[byte_idx];
                    if (isalpha(x))
                    {
                        space_votes[i]++;
                    }
                }
            }
        }

        // This stage computes a score for each candidate character.
        for (int candidate = 0x20; candidate < 0x7f; candidate++)
        {
            int score = 0;

            // Score computation removed for security

            scores[candidate] = score;
        }

        // Print the winning candidate
        char winner = ' ';
        for (char candidate = 0x20; candidate < 0x7f; candidate++)
        {
            if (scores[candidate] > scores[winner])
            {
                winner = candidate;
            }
        }

        putchar(winner);
    }

    putchar('\n');

    /* Output of the full program:

       The secuet message is: Whtn using a stream cipher, never use the key
       more than once

       False positives: 2 out of 83 characters
       Accuracy: 97.5%
       */

    for (size_t i = 0U; i < N_ARR(ct_bytes); i++)
    {
        free(ct_bytes[i].b);
    }

    return 0;
}
