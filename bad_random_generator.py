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

print(p)
print(q)



def chatpgt_method():
  # Generate two 2048-bit prime numbers
  p = getPrime(2048)
  q = getPrime(2048)

  # Calculate n and phi(n)
  n = p * q
  phi_n = (p - 1) * (q - 1)

  # Choose a public exponent
  e = 65537

  # Calculate the private exponent
  d = pow(e, -1, phi_n)

  # Create an RSAPublicNumbers object
  public_numbers = rsa.RSAPublicNumbers(e, n)

  # Calculate the other private key parameters
  dmp1 = d % (p - 1)
  dmq1 = d % (q - 1)
  iqmp = pow(q, -1, p)

  # Create an RSA private key
  private_key = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, None).private_key(default_backend())

  # Serialize the private key to PEM format
  private_key_pem = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption(),
  )

  # Get the public key
  public_key = private_key.public_key()

  # Serialize the public key to PEM format
  public_key_pem = public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo,
  )

  # Print the private and public keys
  print(private_key_pem.decode())
  print(public_key_pem.decode())

  # Print the prime factors used to create the private key
  print("p: ", p)
  print("q: ", q)