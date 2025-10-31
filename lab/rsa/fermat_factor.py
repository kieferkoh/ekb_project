# fermat_factor.py
import math
import time

def is_square(n):
    r = int(math.isqrt(n))
    return r*r == n

def fermat_factor(n, max_steps=1_000_000):
    # Safety: refuse large N
    if n.bit_length() > 64:
        raise ValueError("Refusing to factor N > 64 bits in lab tool")
    a = math.isqrt(n)
    if a*a < n:
        a += 1
    steps = 0
    start = time.time()
    while steps < max_steps:
        b2 = a*a - n
        if b2 >= 0 and is_square(b2):
            b = math.isqrt(b2)
            p = a - b
            q = a + b
            if p*q == n:
                return (p, q, steps, time.time()-start)
        a += 1
        steps += 1
    return None

if __name__ == "__main__":
    from weak_rsa_gen import gen_weak_rsa
    key = gen_weak_rsa(bits=16, closeness=32)
    n = key['n']
    print("N=", n)
    res = fermat_factor(n, max_steps=500000)
    print(res)
