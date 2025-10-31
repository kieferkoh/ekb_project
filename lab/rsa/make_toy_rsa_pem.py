# make_toy_rsa_pem.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# WARNING: toy key only (small)
p = 65537  # using safe e baseline; we will create small key by specifying small public exponent? instead generate small key size
# create a tiny private key (for demo only) - 512 bits or smaller (the web UI will refuse >64 bits),
# so instead we create very tiny RSA using low-level primes: but easiest path: generate a small RSA with cryptography (512)
# But the web UI will refuse >64 bits; so we will generate via the weak generator in the project.

# Use project's weak_rsa_gen to create small primes and create PEM:
from lab.rsa.weak_rsa_gen import gen_weak_rsa  # run this from project root with package mode

key = gen_weak_rsa(bits=16, closeness=16)  # returns dict with p,q,e,d,n
n = key['n']
e = key['e']

# Construct RSAPublicNumbers -> public key object and serialize
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
public_numbers = rsa_mod.RSAPublicNumbers(e, n)
public_key = public_numbers.public_key()
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(pem.decode())
print("# p=", key['p'], " q=", key['q'])
