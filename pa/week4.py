import urllib3
import sys
from urllib.parse import quote

TARGET = 'http://crypto-class.appspot.com/po?er='
AES_BLOCK_SZ = 16 # in bytes

http = urllib3.PoolManager()

# Target ciphertext to decrypt (pass as arg from cli):
# f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4

#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------

def query(q: str):
    target = TARGET + quote(q)              # URL-encode the query and build the full URL
    response = http.request('GET', target)  # Send HTTP GET request and wait for response

    if response.status == 404:
        return True   # good padding
    return False      # bad padding

def decrypt_block(ct, pt):
    """
    Decrypt a ciphertext block via a padding oracle attack. The decrypted ciphertext block is
    the second block given through ct, i.e., ct[AES_BLOCK_SZ : 2 * AES_BLOCK_SZ].
    The decrypted data is returned in the user-supplied pt buffer view.
    """
    for pad in range(1, AES_BLOCK_SZ + 1):
        ct_cpy = bytearray(ct)
        pos = AES_BLOCK_SZ - pad                # Get the correspond byte position
                                                #                                    vv pos
        for i in range(pos, AES_BLOCK_SZ):      # Construct the padding, e.g., xxxxxx0202
            ct_cpy[i] ^= pt[i] ^ pad            # pt[i] holds either zeroes or the valid guess

        for guess in range(0, 256):
            ct_cpy[pos] ^= guess
            found = query(ct_cpy.hex())
            if found:                           # Padding is valid: the guess is the pt byte
                pt[pos] = guess
                print(f"Found byte {pos} with guess {guess} ({chr(guess)})")
                if guess != pad:
                    # Guessing the same value as the current pad leaves the ciphertext
                    # unmodified. This is fine for all blocks except for the last one which
                    # may have a valid PKCS#7 padding, leading the guess to be incorrectly
                    # considered valid. To avoid such false positive, subsequent guesses
                    # must be evaluated and given precedence.
                    break
            ct_cpy[pos] ^= guess                # Undo the wrong guess

if __name__ == "__main__":
    ct = bytearray.fromhex(sys.argv[1])
    pt = bytearray(len(ct) - AES_BLOCK_SZ)      # All bytes are init to 0x00 by default

    # Decrypt the full ciphertext one block at a time.
    for i in range(0, len(pt) - AES_BLOCK_SZ + 1, AES_BLOCK_SZ):
        print(f"Working on plaintext block {i // AES_BLOCK_SZ}")
        decrypt_block(memoryview(ct)[i : i + 2 * AES_BLOCK_SZ],
                      memoryview(pt)[i : i + AES_BLOCK_SZ])
    print(pt.decode('ascii', errors='replace'))
