#!/usr/bin/env python3

import sys
import subprocess
import re
from pathlib import Path

def parse_rsp_file(filepath):
    """
    Parse FIPS .rsp file and extract test vectors.
    Returns list of test cases with their parameters.
    """
    tests = []
    current_test: dict[str, int | str ] = {}
    
    with open(filepath, 'r') as f:
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
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'COUNT':
                    # New test case
                    if current_test:
                        tests.append(current_test)
                    current_test = {'COUNT': int(value), 'SECTION': current_section}
                else:
                    current_test[key] = value.lower()  # Lowercase for consistency
        
        # Add last test
        if current_test:
            tests.append(current_test)
    
    return tests

def run_test_aes_ecb(test_executable, operation, key_bits, key_hex, data_hex):
    """
    Run AES ECB test executable.
    Usage: test_aes_ecb <encrypt|decrypt> <key_bits> <key_hex> <data_hex>
    """
    try:
        result = subprocess.run(
            [test_executable, operation, str(key_bits), key_hex, data_hex],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().lower()
    except subprocess.CalledProcessError as e:
        print(f"Error running test: {e.stderr}")
        return None

def run_test_aes_cbc(test_executable, operation, key_bits, key_hex, iv_hex, data_hex):
    """
    Run AES CBC test executable.
    Usage: test_aes_cbc <decrypt> <key_bits> <key_hex> <iv_hex> <data_hex>
    """
    try:
        result = subprocess.run(
            [test_executable, operation, str(key_bits), key_hex, iv_hex, data_hex],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().lower()
    except subprocess.CalledProcessError as e:
        print(f"Error running test: {e.stderr}")
        return None

def run_test_aes_ctr(test_executable, operation, key_bits, key_hex, nonce_hex, data_hex):
    """
    Run AES CTR test executable.
    Usage: test_aes_ctr <decrypt> <key_bits> <key_hex> <nonce_hex> <data_hex>
    """
    try:
        result = subprocess.run(
            [test_executable, operation, str(key_bits), key_hex, nonce_hex, data_hex],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().lower()
    except subprocess.CalledProcessError as e:
        print(f"Error running test: {e.stderr}")
        return None

def run_test_des(test_executable, operation, key_hex, data_hex):
    """
    Run DES test executable (no key_bits parameter needed).
    Usage: test_des_ecb <encrypt|decrypt> <key_hex> <data_hex>
    """
    try:
        result = subprocess.run(
            [test_executable, operation, key_hex, data_hex],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().lower()
    except subprocess.CalledProcessError as e:
        print(f"Error running test: {e.stderr}")
        return None

def extract_key_size(filename):
    """Extract key size (128, 192, 256) from filename."""
    match = re.search(r'(\d+)', filename)
    return int(match.group(1)) if match else None

def get_test_type(filename):
    """
    Determine test type from filename.
    Returns: 'des_ecb', 'aes_ecb', 'aes_cbc', or 'aes_ctr'
    """
    filename_upper = filename.upper()
    
    if filename_upper.startswith('TECB'):
        return 'des_ecb'
    elif filename_upper.startswith('ECB'):
        return 'aes_ecb'
    elif filename_upper.startswith('CBC'):
        return 'aes_cbc'
    elif filename_upper.startswith('CTR'):
        return 'aes_ctr'
    else:
        return None

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <test_executable> <rsp_file>")
        sys.exit(1)
    
    test_executable = sys.argv[1]
    rsp_file = sys.argv[2]
    
    filename = Path(rsp_file).name
    test_type = get_test_type(filename)
    
    if not test_type:
        print(f"Could not determine test type from filename: {filename}")
        print("Expected prefix: ECB*, CBC*, CTR*, or TECB*")
        sys.exit(1)
    
    # Extract key size for AES tests
    if test_type.startswith('aes'):
        key_bits = extract_key_size(filename)
        if not key_bits:
            print(f"Could not determine key size from filename: {rsp_file}")
            sys.exit(1)
        print(f"Running {test_type.upper()} tests from: {rsp_file} (AES-{key_bits})")
    else:
        key_bits = None
        print(f"Running DES ECB tests from: {rsp_file}")
    
    # Parse test vectors
    tests = parse_rsp_file(rsp_file)
    print(f"Found {len(tests)} test cases")
    
    # Run tests
    passed = 0
    failed = 0
    skipped = 0
    
    for test in tests:
        count = test['COUNT']
        section = test.get('SECTION', 'DECRYPT')
        key = test['KEY']
        
        # Skip encryption tests for CBC/CTR (not implemented yet)
        if section == 'ENCRYPT' and test_type in ['aes_cbc', 'aes_ctr']:
            skipped += 1
            print(f"  Test {count} (encrypt): SKIP (encryption not implemented)")
            continue
        
        # Determine plaintext/ciphertext based on section
        if section == 'ENCRYPT':
            plaintext = test['PLAINTEXT']
            expected_ciphertext = test['CIPHERTEXT']
            operation = 'encrypt'
            input_data = plaintext
            expected_output = expected_ciphertext
        else:  # DECRYPT
            plaintext = test['PLAINTEXT']
            expected_ciphertext = test['CIPHERTEXT']
            operation = 'decrypt'
            input_data = expected_ciphertext
            expected_output = plaintext
        
        # Get IV/nonce for CBC/CTR modes
        iv = test.get('IV', None)
        
        # Validate required fields
        if test_type in ['aes_cbc', 'aes_ctr'] and not iv:
            print(f"  Test {count}: SKIP (missing IV/nonce)")
            skipped += 1
            continue
        
        # Run test
        if test_type == 'des_ecb':
            actual_output = run_test_des(test_executable, operation, key, input_data)
        elif test_type == 'aes_ecb':
            actual_output = run_test_aes_ecb(test_executable, operation, key_bits, key, input_data)
        elif test_type == 'aes_cbc':
            actual_output = run_test_aes_cbc(test_executable, operation, key_bits, key, iv, input_data)
        elif test_type == 'aes_ctr':
            actual_output = run_test_aes_ctr(test_executable, operation, key_bits, key, iv, input_data)
        
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
    
    # Summary
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
    print(f"{'='*50}")
    
    sys.exit(0 if failed == 0 else 1)

if __name__ == '__main__':
    main()
