#include "bn_test_report.h"

#include <stdio.h>

void bn_report_init(bn_test_report_t *r, const char *op_name)
{
    r->op_name = op_name;
    r->pass    = 0;
    r->fail    = 0;
    r->skip    = 0;
}

void bn_report_pass(bn_test_report_t *r)
{
    r->pass++;
}

void bn_report_skip(bn_test_report_t *r, const char *reason)
{
    r->skip++;
    fprintf(stderr, "[%s] SKIP: %s\n", r->op_name, reason);
}

void bn_report_fail(bn_test_report_t *r,
                    uint64_t seed,
                    const char *case_desc,
                    const char *expected_str,
                    const char *actual_str)
{
    r->fail++;
    fprintf(stderr,
            "[%s] FAIL (seed=0x%016llx): %s\n"
            "    expected: %s\n"
            "    actual:   %s\n",
            r->op_name,
            (unsigned long long)seed,
            case_desc,
            expected_str,
            actual_str);
}

int bn_report_finish(const bn_test_report_t *r)
{
    printf("[%s] PASS: %lu  FAIL: %lu  SKIP: %lu\n",
           r->op_name,
           r->pass,
           r->fail,
           r->skip);
    return (r->fail == 0) ? 0 : 1;
}
