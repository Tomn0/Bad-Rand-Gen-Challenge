from bad_random_generator import load_priv_key, load_publ_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends.openssl.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from math import gcd
import os

# a constant to set the number of keypairs used 
KEYPAIRS = 5
CERTS_PATH = "certs"


def exploit_weak_keys(id, p, q, publ_key: RSAPublicKey):
  '''
  Util function used to recreate the private key and read the secret corresponding to that key
  id: int - indicates the id of the private key and the secret message
  p, q: int - primes factorized from the public key - this permits to recreate the private key and thus break the RSA encryption
  publ_key: RSAPublicKey - the public key: cryptography.hazmat.backends.openssl.rsa._RSAPublicKey
  '''
  ############################
  # Recreate the private key #
  ############################
  public_numbers = rsa.RSAPublicNumbers(publ_key.public_numbers().e,publ_key.public_numbers().n)

  phi = (p-1)*(q-1)
  d = __builtins__.pow(publ_key.public_numbers().e,-1,phi)
  private_exponent = d

  iqmp = rsa.rsa_crt_iqmp(p,q)
  dmp1 = rsa.rsa_crt_dmp1(private_exponent, p)
  dmq1 = rsa.rsa_crt_dmq1(private_exponent, q)

  private_key = rsa.RSAPrivateNumbers(p,q,d,dmp1=dmp1,dmq1=dmq1,iqmp=iqmp,public_numbers=public_numbers).private_key()


  # open the secret
  with open(f"secrets/secret{id}", "rb") as f:
    ciphertext = f.read()

  # decrypt
  plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
      )
  )

  return plaintext


#####################
# Load certificates #
#####################

for first in range(KEYPAIRS):
  # load the public key from the certificate
  with open(f"{CERTS_PATH}/certificate{first}.pem", "rb") as f:   
    pem_data = f.read()
    first_cert = x509.load_pem_x509_certificate(pem_data)
    first_publ_key = first_cert.public_key()
  
  n1 = first_publ_key.public_numbers().n

  for second in range(KEYPAIRS):
    if first == second:
      print(f"Breaking as {first} == {second}")
      continue
    print(f"Trying public key {first} vs public key {second}...")
    
    with open(f"{CERTS_PATH}/certificate{second}.pem", "rb") as f:   
      pem_data = f.read()
      second_cert = x509.load_pem_x509_certificate(pem_data)
      second_publ_key = second_cert.public_key()
    
    n2 = second_publ_key.public_numbers().n

    p = gcd(n1, n2)
    if p == 1:
      print("GCD == 1, breaking..")
      print()
      continue
    else:
      q = n2 // p
      print("Found common value p")
      print("GCD = ", p)

      plaintext = exploit_weak_keys(second, p, q, second_publ_key)
      print("The flag is: ", plaintext)
    #   break
    # break

