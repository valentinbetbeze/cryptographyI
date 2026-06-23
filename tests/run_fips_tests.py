#!/usr/bin/python3

import sys
import subprocess
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable

class Vector(StrEnum):
    KAT = 'Known Answer Test'
    MCT = 'Monte Carlo Test'

class Family(StrEnum):
    BLOCK = 'block cipher'
    HASH = 'hash'
    MAC = 'message authentication code'

@dataclass
class TestConfig:
    """Class for holding the configuration of a FIPS CAVP test."""
    vector: Vector
    family: Family
    scheme: str
    components: dict[str, int|str]
    tests: list[dict[str, str]]

# ============================================
# Block cipher tests
# ============================================

def parse_rsp_block_cipher(rsp_filepath: str, rsp_filename: str) -> TestConfig:
    """
    Parse FIPS .rsp file and extract test vectors for block ciphers (des, aes).
    Returns list of test cases with their parameters.
    """
    if any(token in rsp_filename for token in {'Monte', 'MCT'}):
        vector = Vector.MCT
    else:
        vector = Vector.KAT

    # TODO Rework logic as assuming the cipher from the mode of operation is weak.
    #      Idea: use the information in the file's comment header.
    if rsp_filename.startswith('TECB'):
        cipher = 'des'
        mode = 'ecb'
    elif rsp_filename.startswith('ECB'):
        cipher = 'aes'
        mode = 'ecb'
    elif rsp_filename.startswith('CBC'):
        cipher = 'aes'
        mode = 'cbc'
    elif rsp_filename.startswith('CTR'):
        cipher = 'aes'
        mode = 'ctr'
    else:
        raise ValueError(f"Unknown block cipher response file format: {rsp_filename}")

    if cipher == 'aes':
        key_bits = extract_key_size(rsp_filename)
        if not key_bits:
            print(f"Could not determine key size from filename: {rsp_filename}")
            sys.exit(1)
    else:
        # DES key size is 56 bits + 8 bits for parity check
        key_bits = 64

    cfg = TestConfig(
        vector = vector,
        family = Family.BLOCK,
        scheme = cipher + '_' + mode,
        components = {
            'cipher': cipher,
            'mode': mode,
            'key_bits': key_bits
        },
        tests = []
    )

    current_test: dict[str, str] = {}
    
    with open(rsp_filepath, 'r') as f:
        for line in f:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Track if we're in ENCRYPT or DECRYPT section
            if line.startswith('[ENCRYPT]'):
                current_section = 'ENCRYPT'
                continue
            elif line.startswith('[DECRYPT]'):
                current_section = 'DECRYPT'
                continue

            # Parse key = value pairs
            if '=' in line:
                key, value = (part.strip() for part in line.split('=', 1))

                if key == 'COUNT':
                    # New test case
                    if current_test:
                        cfg.tests.append(current_test)
                    current_test = {'COUNT': value, 'SECTION': current_section}
                else:
                    current_test[key] = value.lower()  # Lowercase for consistency

        # Add last test
        if current_test:
            cfg.tests.append(current_test)
    
    return cfg

def extract_key_size(rsp_filename: str):
    """Extract key size (128, 192, 256) from filename."""
    match = re.search(r'(\d+)', rsp_filename)
    return int(match.group(1)) if match else None

def run_test_aes_ecb(test_exec, operation, key_bits, key_hex, data_hex):
    """
    Run AES ECB test executable.
    Usage: test_aes_ecb <encrypt|decrypt> <key_bits> <key_hex> <data_hex>
    """
    try:
        result = subprocess.run(
            [test_exec, operation, str(key_bits), key_hex, data_hex],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().lower()
    except subprocess.CalledProcessError as e:
        print(f"Error running test: {e.stderr}")
        return None

def run_test_aes_cbc(test_exec, operation, key_bits, key_hex, iv_hex, data_hex):
    """
    Run AES CBC test executable.
    Usage: test_aes_cbc <decrypt> <key_bits> <key_hex> <iv_hex> <data_hex>
    """
    try:
        result = subprocess.run(
            [test_exec, operation, str(key_bits), key_hex, iv_hex, data_hex],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().lower()
    except subprocess.CalledProcessError as e:
        print(f"Error running test: {e.stderr}")
        return None

def run_test_aes_ctr(test_exec, operation, key_bits, key_hex, nonce_hex, data_hex):
    """
    Run AES CTR test executable.
    Usage: test_aes_ctr <decrypt> <key_bits> <key_hex> <nonce_hex> <data_hex>
    """
    try:
        result = subprocess.run(
            [test_exec, operation, str(key_bits), key_hex, nonce_hex, data_hex],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().lower()
    except subprocess.CalledProcessError as e:
        print(f"Error running test: {e.stderr}")
        return None

def run_test_des(test_exec, operation, key_hex, data_hex):
    """
    Run DES test executable (no key_bits parameter needed).
    Usage: test_des_ecb <encrypt|decrypt> <key_hex> <data_hex>
    """
    try:
        result = subprocess.run(
            [test_exec, operation, key_hex, data_hex],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().lower()
    except subprocess.CalledProcessError as e:
        print(f"Error running test: {e.stderr}")
        return None

def run_test_block_cipher(cfg: TestConfig, test_exec: str) -> tuple[int, int, int]:
    """
    Run a sequence of block cipher FIPS CAVP test cases.
    Returns test output: (passed, failed, skipped)
    """
    passed = 0
    failed = 0
    skipped = 0

    for test in cfg.tests:
        count = test['COUNT']
        section = test.get('SECTION', 'DECRYPT')
        key = test['KEY']
        key_bits = cfg.components['key_bits']

        # Skip encryption tests for CBC/CTR (not implemented yet)
        if section == 'ENCRYPT' and cfg.scheme in {'aes_cbc', 'aes_ctr'}:
            skipped += 1
            print(f"  Test {count} (encrypt): SKIP (encryption not implemented)")
            continue

        # Determine plaintext/ciphertext based on section
        if section == 'ENCRYPT':
            operation = 'encrypt'
            input_data = test['PLAINTEXT']
            expected_output = test['CIPHERTEXT']
        else:  # DECRYPT
            operation = 'decrypt'
            input_data = test['CIPHERTEXT']
            expected_output = test['PLAINTEXT']

        # Get IV/nonce for CBC/CTR modes
        iv = test.get('IV', None)

        # Validate required fields
        if cfg.scheme in {'aes_cbc', 'aes_ctr'} and iv is None:
            print(f"  Test {count}: SKIP (missing IV/nonce)")
            skipped += 1
            continue

        # Run test
        match cfg.scheme:
            case 'des_ecb':
                actual_output = run_test_des(test_exec, operation, key, input_data)
            case 'aes_ecb':
                actual_output = run_test_aes_ecb(test_exec, operation, key_bits, key, input_data)
            case 'aes_cbc':
                actual_output = run_test_aes_cbc(test_exec, operation, key_bits, key, iv, input_data)
            case 'aes_ctr':
                actual_output = run_test_aes_ctr(test_exec, operation, key_bits, key, iv, input_data)
            case _:
                print(f"Unsupported block cipher: {cfg.scheme}")
                sys.exit(1)

        if actual_output == expected_output:
            passed += 1
            print(f"  Test {count} ({operation}): PASS")
        else:
            failed += 1
            print(f"  Test {count} ({operation}): FAIL")
            print(f"    Key:      {key}")
            if iv:
                print(f"    IV:       {iv}")
            print(f"    Input:    {input_data}")
            print(f"    Expected: {expected_output}")
            print(f"    Got:      {actual_output}")

    return (passed, failed, skipped)

# ============================================
# Secure hash test functions
# ============================================

def parse_rsp_hash(rsp_filepath: str, rsp_filename: str) -> TestConfig:
    """
    Parse FIPS .rsp file and extract test vectors for secure hashing algs.
    Returns list of test cases with their parameters.
    """
    if any(token in rsp_filename for token in {'Monte', 'MCT'}):
        vector = Vector.MCT
    else:
        vector = Vector.KAT

    if rsp_filename.startswith('SHA'):
        scheme = 'sha'
    else:
        raise ValueError(f"Unknown block cipher response file format: {rsp_filename}")

    cfg = TestConfig(
        vector = vector,
        family = Family.HASH,
        scheme = scheme,
        components = {},
        tests = []
    )

    count = 0
    current_test: dict[str, str] = {}

    with open(rsp_filepath, 'r') as f:
        for line in f:
            line = line.strip()

            # Skip comments, empty lines, and digest length
            if not line or line.startswith('#') or line.startswith('['):
                continue

            if '=' in line:
                key, value = (part.strip() for part in line.split('=', 1))

                if key in {'Len', 'COUNT'}:
                    if current_test:
                        cfg.tests.append(current_test)

                    current_test = {key: value}

                    if key == 'Len':
                        current_test['COUNT'] = str(count)
                        count += 1
                else:
                    current_test[key] = value.lower()  # Lowercase for consistency

        # Add last test
        if current_test:
            cfg.tests.append(current_test)
    
    return cfg

def run_test_sha(test_exec: str, msg_hex: str, msg_len: str):
    """
    Run SHA test executable.
    Usage: test_sha <msg_hex> <msg_len>
    """
    try:
        result = subprocess.run(
            [test_exec, msg_hex, msg_len],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().lower()
    except subprocess.CalledProcessError as e:
        print(f"Error running test: {e.stderr}")
        return None

def run_test_hash(cfg: TestConfig, test_exec: str) -> tuple[int, int, int]:
    """
    Run a sequence of secure hash FIPS CAVP test cases.
    Returns test output: (passed, failed, skipped)
    """
    passed = 0
    failed = 0
    skipped = 0

    if cfg.vector == Vector.MCT:
        seed = cfg.tests.pop(0)['Seed']

    for test in cfg.tests:
        count = int(test['COUNT'])
        expected_output = test['MD']

        if cfg.vector == Vector.MCT:
            len_bytes = str(len(seed) // 2)
            msg = seed
        else:
            len_bytes = str(int(test['Len']) // 8)
            msg = test['Msg']

        md = run_test_sha(test_exec, msg, len_bytes)

        if md is not None and md == expected_output:
            passed += 1
            print(f"  Test {count} : PASS")

            if cfg.vector == Vector.MCT:
                seed = md
        else:
            failed += 1
            print(f"  Test {count} : FAIL")
            print(f"    Input:    {msg}")
            print(f"    Expected: {expected_output}")
            print(f"    Got:      {md}")

            if cfg.vector == Vector.MCT:
                break

    return passed, failed, skipped

# ============================================
# Message authentication code test functions
# ============================================

def parse_rsp_mac(rsp_filepath: str, rsp_filename: str) -> TestConfig:
    """
    Parse a FIPS .rsp file and extract HMAC test vectors. KAT only.
    Returns list of test cases with their parameters.
    """
    if rsp_filename.upper().startswith('HMAC'):
        scheme = 'hmac'
    else:
        raise ValueError(f"Unknown MAC response file format: {rsp_filename}")

    cfg = TestConfig(
        vector = Vector.KAT,
        family = Family.MAC,
        scheme = scheme,
        components = {'hash': 'sha256', 'md_bytes': 32},  # [L=32] => SHA-256
        tests = []
    )

    current_test: dict[str, str] = {}

    with open(rsp_filepath, 'r') as f:
        for line in f:
            line = line.strip()

            # Skip comments, empty lines, and digest length
            if not line or line.startswith('#') or line.startswith('['):
                continue

            if '=' in line:
                key, value = (part.strip() for part in line.split('=', 1))

                if key == 'Count':
                    if current_test:
                        cfg.tests.append(current_test)
                    current_test = {'COUNT': value}
                else:
                    current_test[key] = value.lower()  # Lowercase for consistency

        # Add last test
        if current_test:
            cfg.tests.append(current_test)

    return cfg

def run_test_hmac(test_exec, key_hex, klen, msg_hex, msglen, tlen):
    """
    Run HMAC test executable.
    Usage: test_hmac <key_hex> <klen> <msg_hex> <msglen> <tlen>
    """
    try:
        result = subprocess.run(
            [test_exec, key_hex, str(klen), msg_hex, str(msglen), str(tlen)],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().lower()
    except subprocess.CalledProcessError as e:
        print(f"Error running test: {e.stderr}")
        return None

def run_test_mac(cfg: TestConfig, test_exec: str) -> tuple[int, int, int]:
    """
    Run a sequence of HMAC FIPS CAVP test cases.
    Returns test output: (passed, failed, skipped)
    """
    passed = 0
    failed = 0
    skipped = 0

    for test in cfg.tests:
        count    = int(test['COUNT'])
        klen     = int(test['klen'])
        tlen     = int(test['tlen'])
        key_hex  = test['key']
        msg_hex  = test['msg']
        msglen   = len(msg_hex) // 2          # message length in bytes
        expected = test['mac']                # already truncated to tlen bytes

        tag = run_test_hmac(test_exec, key_hex, klen, msg_hex, msglen, tlen)

        if tag is not None and tag == expected:
            passed += 1
            print(f"  Test {count} : PASS")
        else:
            failed += 1
            print(f"  Test {count} : FAIL")
            print(f"    Key:      {key_hex}")
            print(f"    Msg:      {msg_hex}")
            print(f"    Expected: {expected}")
            print(f"    Got:      {tag}")

    return passed, failed, skipped

# ============================================
# Main logic
# ============================================

PARSERS: dict[str, Callable[[str, str], TestConfig]] = {
    'TECB': parse_rsp_block_cipher,
    'ECB':  parse_rsp_block_cipher,
    'CBC':  parse_rsp_block_cipher,
    'CTR':  parse_rsp_block_cipher,
    'SHA':  parse_rsp_hash,
    'HMAC': parse_rsp_mac
}

RUNNERS = {
    Family.BLOCK: run_test_block_cipher,
    Family.HASH: run_test_hash,
    Family.MAC: run_test_mac
}

def parse_test(rsp_filepath: str) -> TestConfig | None:
    """
    Parse a FIPS .rsp test file.
    Return a TestConfig object holding the parsed data, or None if the .rsp
    test file is not supported.
    """
    rsp_filename = Path(rsp_filepath).name
    filename_upper = rsp_filename.upper()

    for key, parser in PARSERS.items():
        if filename_upper.startswith(key):
            return parser(rsp_filepath, rsp_filename)

    return None

def run_test(cfg: TestConfig, test_exec: str) -> tuple[int, int, int]:
    """
    Run a FIPS test by selecting the appropriate test runner from RUNNERS.
    """
    for family, cb in RUNNERS.items():
        if cfg.family == family:
            return cb(cfg, test_exec)

    raise ValueError(f"Failed to find test function for {cfg.family}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <test_exec> <rsp_file>")
        sys.exit(1)

    test_exec = sys.argv[1]
    rsp_filepath = sys.argv[2]

    cfg = parse_test(rsp_filepath)
    if cfg is None:
        print(f"Unsupported file")
        sys.exit(1)

    if cfg.vector == Vector.MCT and cfg.scheme in {'des_ecb', 'aes_ctr'}:
        print(f"Monte Carlo Test no implemented for {cfg.scheme}")
        sys.exit(1)

    print(f"Found {len(cfg.tests)} test cases")
    print(f"Running {cfg.scheme.upper()} tests from: {rsp_filepath}")

    passed, failed, skipped = run_test(cfg, test_exec)

    # Summary
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
    print(f"{'='*50}")

    sys.exit(0 if failed == 0 else 1)

if __name__ == '__main__':
    main()
