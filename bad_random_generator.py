# from Crypto.Util.number import getPrime
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
    phi = (p-1)*(q-1)
    d = pow(e,-1,phi)
    public_numbers = rsa.RSAPublicNumbers(e,n)

    private_exponent = d
    iqmp = rsa.rsa_crt_iqmp(p,q)
    dmp1 = rsa.rsa_crt_dmp1(private_exponent, p)
    dmq1 = rsa.rsa_crt_dmq1(private_exponent, q)
    res = rsa.RSAPrivateNumbers(p,q,d,dmp1=dmp1,dmq1=dmq1,iqmp=iqmp,public_numbers=public_numbers)
    
    priv = res.private_key()
    public_key = priv.public_key()

    
    # Serialize the private key to PEM format
    private_key_pem = priv.private_bytes(
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
    
    return private_key_pem.decode(), public_key_pem

priv, publ = calculate_keys(p,q)

print(private_key_pem.decode() == priv)
print(public_key_pem == publ)
