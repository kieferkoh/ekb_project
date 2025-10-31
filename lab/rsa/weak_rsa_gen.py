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
    assert bits <= 32, "For lab only: set bits <= 32"
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

if __name__ == "__main__":
    key = gen_weak_rsa(bits=16, closeness=16)  # toy
    print("p=", key['p'], "q=", key['q'], "n=", key['n'])
