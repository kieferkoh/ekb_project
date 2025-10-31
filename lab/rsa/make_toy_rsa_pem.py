#!/usr/bin/env python3
# make_toy_rsa_pem.py
"""
Generate a toy RSA public key (PEM) for demo:
- mode 'weak' : uses gen_weak_rsa (close primes)
- mode 'strong': uses gen_strong_rsa (enforces min_gap)

This prints:
 - PEM public key (SubjectPublicKeyInfo)
 - Debug comments: p, q, |p-q|, n bits
"""

import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod

# Import your project generators (run from project root or as module)
try:
    from lab.rsa.weak_rsa_gen import gen_weak_rsa, gen_strong_rsa
except Exception:
    # If not running as package, try local import (useful when running directly inside lab/rsa/)
    try:
        from weak_rsa_gen import gen_weak_rsa, gen_strong_rsa
    except Exception as e:
        raise ImportError("Could not import gen_weak_rsa/gen_strong_rsa. "
                          "Ensure this script is run from project root and weak_rsa_gen.py contains both functions.") from e

def build_public_pem(n: int, e: int = 65537) -> bytes:
    pubnums = rsa_mod.RSAPublicNumbers(e, n)
    pubkey = pubnums.public_key()
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def main():
    ap = argparse.ArgumentParser(description="Generate toy RSA public PEM (weak or slightly stronger toy key).")
    ap.add_argument("--mode", choices=("weak","strong"), default="strong", help="Which generator to use (weak=close primes, strong=enforce gap).")
    ap.add_argument("--bits", type=int, default=32, help="Bit length of each prime (p and q). Keep <=64 for lab/demo.")
    ap.add_argument("--closeness", type=int, default=16, help="For weak mode: closeness (max delta to try).")
    ap.add_argument("--min-gap", type=int, default=1<<12, help="For strong mode: require |p-q| >= min_gap (absolute integer).")
    ap.add_argument("--e", type=int, default=65537, help="Public exponent.")
    ap.add_argument("--print-private", action="store_true", help="Also print private (PKCS#8) PEM -- WARNING: toy private keys.")
    args = ap.parse_args()

    if args.bits < 8 or args.bits > 64:
        print("[!] Warning: this script is intended for toy/demo keys (bits between 8 and 64).")
        # still allow, but warn

    if args.mode == "weak":
        key = gen_weak_rsa(bits=args.bits, closeness=args.closeness)
    else:
        # strong: uses gen_strong_rsa(bits, min_gap, e)
        key = gen_strong_rsa(bits=args.bits, min_gap=args.min_gap, e=args.e)

    n = int(key["n"])
    e = int(key["e"])
    p = int(key["p"])
    q = int(key["q"])
    gap = abs(p - q)
    nbits = n.bit_length()

    pub_pem = build_public_pem(n, e)
    print(pub_pem.decode().strip())
    # Helpful debug comments for the demo
    print(f"\n# p = {p}")
    print(f"# q = {q}")
    print(f"# |p-q| = {gap}")
    print(f"# n bit-length = {nbits}")
    print(f"# mode = {args.mode}")

    if args.print_private:
        # Build private PEM (PKCS#8) using cryptography from the numbers
        # Note: constructing a private key from components; cryptography's RSAPrivateNumbers expects dp/dq/iqmp.
        # We may not have dp/dq/iqmp in the weak generator return; compute them if possible.
        try:
            # compute phi and d if not present
            if "d" not in key:
                from math import gcd
                phi = (p-1)*(q-1)
                # compute d via pow inverse
                d = pow(e, -1, phi)
                key["d"] = d
            d = int(key["d"])
            dp = d % (p - 1)
            dq = d % (q - 1)
            iqmp = pow(q, -1, p)
            from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod2
            privnums = rsa_mod2.RSAPrivateNumbers(
                p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=iqmp,
                public_numbers=rsa_mod2.RSAPublicNumbers(e=e, n=n)
            )
            privkey = privnums.private_key()
            priv_pem = privkey.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
            print("\n# ----- PRIVATE KEY (PKCS#8 PEM) -----")
            print(priv_pem.decode().strip())
        except Exception as exc:
            print("# Could not export private key PEM:", exc)

if __name__ == "__main__":
    main()
