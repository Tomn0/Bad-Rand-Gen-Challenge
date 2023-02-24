from Crypto.Util.number import getPrime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize the private key to PEM format
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# Serialize the public key to PEM format
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

print(private_key_pem.decode())
print(public_key_pem)

p = private_key.private_numbers().p
q = private_key.private_numbers().q
print()
print(p)
print(q)



def calculate_keys(p,q):
    e = 65537
    n = p * q # here calculate public modulus
    public_numbers = rsa.RSAPublicNumbers(e,n)

    # TODO: use utility functions to calculate iqmp,dmp1,dmq1
    res = rsa.RSAPrivateNumbers(p,q,0,0,0,0,public_numbers)
    print(res.private_key())

calculate_keys(p,q)