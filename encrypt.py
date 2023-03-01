from bad_random_generator import load_publ_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
# a constant to set the number of keypairs used 
KEYPAIRS = 5

# Loaded secret message
with open("flag.txt", "rb") as f:
  secret = f.readline()[:-1]

# create 5 ciphertext for each public key 
for i in range(KEYPAIRS):
  public_key = load_publ_key(name=i)
  # encrypt the secret
  ciphertext = public_key.encrypt(
    secret,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
  )

  # write the ciphertext to a separate file
  with open(f"secret{i}", "wb") as f:
    f.write(ciphertext)

