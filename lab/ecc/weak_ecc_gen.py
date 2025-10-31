# weak_ecc_gen.py - toy ECC
from ecdsa import ellipticcurve, numbertheory, curves
from ecdsa.ecdsa import Public_key, Private_key, generator_secp256k1

# Create tiny curve over small prime p (toy!)
p = 233
a = 1
b = 1
curve = ellipticcurve.CurveFp(p, a, b)

# pick a small-order point G (you may need to search)
# For demo, pick a known small-order point (x,y)
G = ellipticcurve.Point(curve, 4, 5, 13)  # cofactor=??; order=13 example (toy)
# Private key d chosen
d = 7  # secret
Q = d * G

print("G order approx 13 (toy). Public Q:", Q)

# Attack: brute-force d mod r (r=13)
r = 13
for k in range(r):
    if k*G == Q:
        print("Found d mod r:", k)
        break
