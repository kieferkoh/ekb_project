# make_strong_rsa_pem.py
# Generate a strong (secure) RSA keypair and print the PEMs.
# Use this for demonstrations where you want a realistic, secure key
# instead of a toy one. Uses 2048-bit modulus by default.

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ======== CONFIGURABLE PARAMETERS ========
KEY_SIZE = 2048  # use 2048 or 4096 for real security
PUBLIC_EXPONENT = 65537
PASSPHRASE = None  # e.g. "mySecretPass" if you want to encrypt private PEM
# ========================================

# Generate a strong RSA keypair (cryptography handles random primes securely)
private_key = rsa.generate_private_key(
    public_exponent=PUBLIC_EXPONENT,
    key_size=KEY_SIZE
)

# Serialize private key to PEM (PKCS#8)
if PASSPHRASE:
    encryption = serialization.BestAvailableEncryption(PASSPHRASE.encode("utf-8"))
else:
    encryption = serialization.NoEncryption()

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=encryption
)

# Serialize public key to PEM (SubjectPublicKeyInfo)
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Print PEMs
print("-----BEGIN PUBLIC KEY PEM-----")
print(public_pem.decode())
print("-----END PUBLIC KEY PEM-----")

# Optional: print internal key parameters (for debugging)
numbers = private_key.private_numbers()
print("\n# p =", numbers.p)
print("# q =", numbers.q)
print("# n =", numbers.public_numbers.n)
print("# e =", numbers.public_numbers.e)
print("# d =", numbers.d)
