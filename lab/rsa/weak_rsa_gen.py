# weak_rsa_gen.py
import secrets
from math import gcd

def gen_prime(bits):
    assert bits >= 8
    while True:
        p = secrets.randbits(bits) | 1
        # quick primality with pow (Miller-Rabin would be nicer)
        if pow(2, p-1, p) == 1:
            return p

def gen_weak_rsa(bits=32, closeness=4):
    """
    Generate RSA where p and q are close: q = p + small_delta
    bits: bits for p (total N ~ 2*bits)
    closeness: max delta for q (small integer)
    WARNING: bits <= 32 or 64 is enforced by caller
    """
    #assert bits <= 32, "For lab only: set bits <= 32"
    p = gen_prime(bits)
    for delta in range(1, closeness+1):
        q = p + delta
        if pow(2, q-1, q) == 1 and gcd(p,q) == 1:
            n = p*q
            phi = (p-1)*(q-1)
            e = 65537
            # ensure invertible
            if gcd(e, phi) == 1:
                # compute d
                # extended gcd for inverse
                def egcd(a,b):
                    if b==0: return (1,0,a)
                    x,y,g = egcd(b,a%b)
                    return (y, x-(a//b)*y, g)
                x,y,g = egcd(e, phi)
                d = x % phi
                return {'p':p,'q':q,'n':n,'e':e,'d':d}
    raise RuntimeError("couldn't find nearby prime q; try new p or bigger closeness")

# ---- add below in weak_rsa_gen.py -------------------------------------------
# Deterministic Miller–Rabin good for 64-bit integers
# Ref: bases {2,3,5,7,11,13,17} are sufficient for n < 2^64
def _is_probable_prime_64(n: int) -> bool:
    if n < 2:
        return False
    # small primes
    small = [2,3,5,7,11,13,17,19,23,29]
    for p in small:
        if n == p:
            return True
        if n % p == 0:
            return n == p
    # write n-1 = d*2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2,3,5,7,11,13,17):
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def _rand_odd_with_bits(bits: int) -> int:
    x = secrets.randbits(bits)
    x |= (1 << (bits - 1))   # force top bit -> exact bit length
    x |= 1                   # make odd
    return x

def gen_prime_mr(bits: int) -> int:
    """Generate a (≤64-bit) probable prime using deterministic MR."""
    assert 8 <= bits <= 64
    while True:
        cand = _rand_odd_with_bits(bits)
        if _is_probable_prime_64(cand):
            return cand

def _inv_mod(a: int, m: int) -> int:
    # Python 3.8+: pow(a, -1, m) works; fall back to EGCD for clarity
    try:
        return pow(a, -1, m)
    except ValueError:
        def egcd(x, y):
            if y == 0:
                return (1, 0, x)
            u, v, g = egcd(y, x % y)
            return (v, u - (x // y) * v, g)
        u, v, g = egcd(a, m)
        if g != 1:
            raise ValueError("inverse does not exist")
        return u % m

def gen_strong_rsa(bits: int = 32, min_gap: int = 1 << 12, e: int = 65537, max_tries: int = 100000):
    """
    Generate a 'strong' toy RSA key where |p - q| >= min_gap (to defeat Fermat on purpose).

    Args:
        bits: bit-length for p and q individually (N ~ 2*bits). Keep ≤ 64 in this lab.
        min_gap: minimum absolute difference |p - q| required.
        e: public exponent (default 65537).
        max_tries: safety cap to avoid infinite loops.

    Returns:
        dict with {'p','q','n','e','d'}

    Notes:
        - Uses deterministic MR for ≤64-bit primes.
        - Ensures gcd(e, p-1) = gcd(e, q-1) = 1 and gcd(e, phi) = 1.
        - If not found within max_tries, raises RuntimeError.
    """
    assert 8 <= bits <= 64, "This lab generator is intended for ≤64-bit primes."
    if min_gap < 1:
        raise ValueError("min_gap must be >= 1")

    tries = 0
    while tries < max_tries:
        tries += 1
        p = gen_prime_mr(bits)   # or use your original gen_prime(bits)
        q = gen_prime_mr(bits)
        if p == q:
            continue
        if abs(p - q) < min_gap:
            continue
        phi = (p - 1) * (q - 1)
        n = p * q
        if gcd(e, p - 1) != 1 or gcd(e, q - 1) != 1 or gcd(e, phi) != 1:
            continue
        d = _inv_mod(e, phi)
        return {'p': p, 'q': q, 'n': n, 'e': e, 'd': d}

    raise RuntimeError(f"couldn't find primes meeting min_gap={min_gap} after {max_tries} tries")

# ---- quick manual test ------------------------------------------------------
if __name__ == "__main__":
    # Existing weak example
    key = gen_weak_rsa(bits=16, closeness=16)
    print("[weak] p=", key['p'], "q=", key['q'], "gap=", abs(key['p']-key['q']))

    # New strong example with enforced distance
    strong = gen_strong_rsa(bits=16, min_gap=1<<8)  # require |p-q| >= 256
    print("[strong] p=", strong['p'], "q=", strong['q'],
          "gap=", abs(strong['p']-strong['q']), "n=", strong['n'])
