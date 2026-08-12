import gmpy2
import hashlib

def hash_bignum(x: gmpy2.mpz) -> int:
    """Reduce a large gmpy2.mpz to a 256-bit int digest."""
    # to_bytes needs a byte length; compute minimal bytes needed for x
    nbytes = (x.bit_length() + 7) // 8 or 1
    x_bytes = int(x).to_bytes(nbytes, byteorder="big", signed=False)
    digest = hashlib.sha256(x_bytes).digest()
    return int.from_bytes(digest, byteorder="big")

# key: hash(h/g^x1)
# val: x1
table: dict[int, int] = {}

def insert(x: int, y: gmpy2.mpz) -> None:
    table[hash_bignum(y)] = x

def lookup(y: gmpy2.mpz) -> int | None:
    """Return the corresponding x if present; else None"""
    return table.get(hash_bignum(y))

p = gmpy2.mpz(13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171)
g = gmpy2.mpz(11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568)
h = gmpy2.mpz(3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333)

B = 2**20
gB = gmpy2.powmod(g, B, p)

# Build the hash table for the left-hand side of h/g^x1 = (g^B)^x0 mod p
for x1 in range(B):
    y1 = gmpy2.divm(h, gmpy2.powmod(g, x1, p), p)
    insert(x1, y1)

# Find x1 for y0 = (g^B)^x0 = y1 = h/g^x1 mod p
y0 = gmpy2.mpz(1)
for x0 in range(B):
    x1 = lookup(y0)
    if x1 is not None:
        x = x0*B + x1
        print(f"Found: {x} = {x0}B+{x1}")
        break
    y0 = (y0 * gB) % p

assert gmpy2.powmod(g, x, p) == h, "Verification failed"
