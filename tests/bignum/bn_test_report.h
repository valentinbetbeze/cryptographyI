#ifndef BN_TEST_REPORT_H
#define BN_TEST_REPORT_H

#include <stdint.h>

typedef struct
{
    const char *op_name;
    unsigned long pass;
    unsigned long fail;
    unsigned long skip;
} bn_test_report_t;

void bn_report_init(bn_test_report_t *r, const char *op_name);
void bn_report_pass(bn_test_report_t *r);
void bn_report_skip(bn_test_report_t *r, const char *reason);

/**
 * Records a failure and prints the seed, case description, and both sides of
 * the mismatch, then keeps going (does not abort) so a single run surfaces
 * every distinct failure instead of stopping at the first.
 */
void bn_report_fail(bn_test_report_t *r,
                    uint64_t seed,
                    const char *case_desc,
                    const char *expected_str,
                    const char *actual_str);

/* Prints the pass/fail/skip summary and returns a process exit code (0 iff no
 * failures). */
int bn_report_finish(const bn_test_report_t *r);

#endif // BN_TEST_REPORT_H
