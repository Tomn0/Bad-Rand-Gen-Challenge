from subprocess import call

cmd = "openssl prime -generate -bits 2048 -hex 1>&2"
decrypted = call(cmd, shell=True)
print (decrypted)


############################################################
#  an example Python code that generates an RSA key pair, 
# saves the private and public keys in PEM format to files, 
# and also saves the prime factors p and q to variables
############################################################

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

# Generate RSA key pair
key_size = 2048
private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

# Save private key to file
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

# Save public key to file
public_key = private_key.public_key()
with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

# Save prime factors p and q to variables
p = private_key.private_numbers().p
q = private_key.private_numbers().q
print("p:", p)
print("q:", q)
