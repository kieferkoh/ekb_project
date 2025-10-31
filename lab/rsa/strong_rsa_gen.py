# strong_rsa_gen.py
# Generate strong RSA keys with independent, well-spaced primes.
# - Uses secrets for randomness
# - Miller–Rabin + small-prime trial division
# - Optional "safe prime" mode (p = 2r + 1 with r prime)
# - Enforces a minimum p-q gap to avoid Fermat-style closeness
# - Returns CRT parameters

import secrets
from math import gcd

# Small primes for quick sieving before MR
_SMALL_PRIMES = [
    3,5,7,11,13,17,19,23,29,31,37,41,43,47,
    53,59,61,67,71,73,79,83,89,97,101,103,107,109,113
]

def _rand_odd_bits(bits: int) -> int:
    # ensure exact bit-length and odd
    n = secrets.randbits(bits)
    n |= (1 << (bits - 1))   # set top bit
    n |= 1                   # make odd
    return n

def _trial_division(n: int) -> bool:
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    return True

def _miller_rabin(n: int, rounds: int = 64) -> bool:
    """Probabilistic MR test (good with 64 rounds for large n)."""
    if n < 2:
        return False
    # handle small primes quickly
    for p in (2,):
        if n == p:
            return True
        if n % p == 0:
            return False
    if not _trial_division(n):
        return False

    # write n-1 = d*2^s with d odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        skip_to_next_n = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                skip_to_next_n = False
                break
        if skip_to_next_n:
            return False
    return True

def _gen_prime(bits: int, rounds: int = 64) -> int:
    while True:
        cand = _rand_odd_bits(bits)
        if _miller_rabin(cand, rounds):
            return cand

def _gen_safe_prime(bits: int, rounds: int = 64) -> int:
    """Generate a safe prime p = 2r + 1 with r prime (both ~bits-1)."""
    if bits < 3:
        raise ValueError("bits too small for safe prime")
    while True:
        r = _gen_prime(bits - 1, rounds)
        p = 2 * r + 1
        # p will have either bits or bits+1; ensure target bit-length
        if p.bit_length() != bits:
            continue
        if _miller_rabin(p, rounds):
            return p

def _inv_mod(a: int, m: int) -> int:
    # Python 3.8+: pow(a, -1, m) works; fallback to EGCD for portability
    try:
        return pow(a, -1, m)
    except ValueError:
        # classic EGCD
        def egcd(x, y):
            if y == 0:
                return (1, 0, x)
            u, v, g = egcd(y, x % y)
            return (v, u - (x // y) * v, g)
        x, y, g = egcd(a, m)
        if g != 1:
            raise ValueError("inverse does not exist")
        return x % m

def gen_strong_rsa(
    modulus_bits: int = 2048,
    e: int = 65537,
    strong_prime: bool = False,
    min_gap_bits: int | None = 128,
    mr_rounds: int = 64
) -> dict:
    """
    Generate an RSA key with strong properties.

    Args:
      modulus_bits: total bits of n (even number recommended).
      e: public exponent (65537 recommended).
      strong_prime: if True, generate "safe primes" p,q (p=2r+1).
      min_gap_bits: enforce |p - q| >= 2^(min_gap_bits). If None, skip check.
      mr_rounds: Miller–Rabin rounds per primality test.

    Returns:
      dict: {'p','q','n','e','d','phi','dp','dq','qinv'}

    Notes:
      - Generation time grows with bits and strong_prime=True.
      - Ensures gcd(e, p-1)=gcd(e, q-1)=1 and gcd(e, phi)=1.
      - Ensures p != q and optional wide p-q gap (to defeat Fermat).
    """
    if modulus_bits % 2 != 0:
        raise ValueError("modulus_bits should be even (e.g., 2048, 3072)")
    half = modulus_bits // 2

    gen = _gen_safe_prime if strong_prime else _gen_prime

    while True:
        p = gen(half, mr_rounds)
        q = gen(half, mr_rounds)
        if p == q:
            continue

        # ensure well spaced to avoid Fermat (optional)
        if min_gap_bits is not None:
            gap = abs(p - q)
            if gap.bit_length() < min_gap_bits:
                # too close; try again
                continue

        # ensure e coprime to p-1 and q-1
        if gcd(e, p - 1) != 1 or gcd(e, q - 1) != 1:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) != 1:
            continue

        d = _inv_mod(e, phi)
        dp = d % (p - 1)
        dq = d % (q - 1)
        # qinv = q^{-1} mod p (common convention), keep both if you like
        qinv = _inv_mod(q, p)

        return {
            'p': p, 'q': q, 'n': n, 'e': e, 'd': d, 'phi': phi,
            'dp': dp, 'dq': dq, 'qinv': qinv,
            'min_gap_bits_enforced': min_gap_bits is not None
        }

# -------- CLI quick test --------
if __name__ == "__main__":
    import argparse, time

    ap = argparse.ArgumentParser(description="Generate strong RSA keys.")
    ap.add_argument("--modulus-bits", type=int, default=2048, help="Total bits of n (even).")
    ap.add_argument("--e", type=int, default=65537, help="Public exponent (65537 recommended).")
    ap.add_argument("--strong-prime", action="store_true", help="Use safe primes p=2r+1.")
    ap.add_argument("--min-gap-bits", type=int, default=128, help="Require |p-q| >= 2^(min_gap_bits). Use 0 to disable.")
    args = ap.parse_args()

    min_gap_bits = None if args.min_gap_bits == 0 else args.min_gap_bits

    t0 = time.perf_counter()
    key = gen_strong_rsa(
        modulus_bits=args.modulus_bits,
        e=args.e,
        strong_prime=args.strong_prime,
        min_gap_bits=min_gap_bits
    )
    dt = time.perf_counter() - t0

    print(f"Generated RSA key in {dt:.3f}s")
    print(f"n bits: {key['n'].bit_length()}")
    gap_bits = abs(key['p'] - key['q']).bit_length()
    print(f"|p-q| bits: {gap_bits} (enforced min {min_gap_bits})")
    print(f"e={key['e']}")
    print(f"dp,dq set; qinv computed.")
