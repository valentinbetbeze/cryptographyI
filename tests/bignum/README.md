# bignum test suite

Differential + property-based tests for `bignum/`, checked against GMP as
the correctness oracle. There's no NIST/FIPS vector file for arbitrary-
precision arithmetic, so this doesn't follow the `.rsp` + `run_fips_tests.py`
pattern used elsewhere in `tests/` — it's a single C harness that links
directly against both `bignum` and `libgmp`.

## How it works

`test_bignum <op> [--seed N] [--iterations N] [--scenario NAME]` runs one
operation's test group and exits non-zero on any failure.

Each group does two things, in order:

1. **Edge-case table** (`bn_test_edgecases.h`) — deterministic, always runs
   first. Covers `0`, `1`, exact `2^32`/`2^64` boundaries (where limb-carry
   bugs cluster), all four sign combinations, aliasing (`a==b`, `a==out`,
   `b==out`), and the "output ownership" buffer-reuse policy from
   `bignum.h`.
2. **Random fuzzing** — `--iterations` random operand pairs (default 1000),
   generated on the GMP side first via a seeded PRNG (`bn_test_prng.h`,
   splitmix64 — not libc `rand()`, whose sequence isn't portable across
   platforms) and mirrored into a `bn_t`. Bit-length is weighted toward
   small values and boundary-adjacent values (`2^k`, `2^k±1`) rather than
   sampled uniformly, since that's where bugs actually live.

The seed is always printed at the start of a run, so any CTest failure can
be reproduced exactly with `--seed <printed-value>`.

**Comparison oracle**: `bn_test_gmp_bridge.c` converts both sides to `mpz_t`
(via `mpz_import`/`mpz_export` on the raw `bn_t::bstr`, not through
`bn_tostring`) and compares with `mpz_cmp`. This keeps the pass/fail
decision for e.g. `bn_add` independent of any bug in `bn_tostring` — the
bridge has its own self-test (`bn_test_gmp_bridge_selftest`, run before any
op group) so it's trusted before anything else relies on it.

## CTest wiring

One `add_test(BIGNUM_<op> ...)` per operation in `CMakeLists.txt`. Ops that
are still stubs in `bignum.c` (`return BN_OK;` with no logic) are marked
`WILL_FAIL TRUE` — they show as passing today *because* failure is
expected. The moment a stub gets a real implementation, remove its
`WILL_FAIL` marker in the same change, or CTest will start reporting a
spurious failure.

`BIGNUM_SEED` and `BIGNUM_ITERATIONS` are CMake cache variables if you want
to tune reproducibility/depth for CI without touching the harness.

## Extending it

**Add a random/edge case to an existing op**: edit that op's `run_*_tests`
function in `test_bignum.c`, or add a value/combo to `bn_test_edgecases.h`
if it should apply across multiple ops (it's shared, cross-producted with
signs by each binary-op test group).

**Add a new operation**: for a simple binary op with no special sign/domain
rules, reuse `run_generic_binop_tests` (see `run_sub_tests`/`run_mul_tests`)
— just pass the `bn_*` function and its `mpz_*` equivalent. For anything
with its own contract (like `bn_div`'s Euclidean remainder convention, or
`bn_modexp`'s negative-exponent-as-inverse), write a dedicated `run_*_tests`
following the pattern of `run_div_tests`/`run_modexp_tests`: edge cases via
`check_bn_eq_mpz`/`check_ret`, then a random loop using `gen_random_value`.
Wire it into `main()`'s dispatch and add its `add_test` entry in
`CMakeLists.txt`.

**Debugging a failure**: rerun the specific op with the printed seed and
`-v`, e.g. `./test_bignum add --scenario basic --seed 0x1234...`. On
mismatch, the harness prints both the GMP-side expected value and the
`bn_tostring()` rendering of the actual value.
