from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh, utils

# Generate a Diffie-Hellman parameters object
parameters = dh.generate_parameters(generator=2, key_size=2048)

# Generate a private key and a corresponding public key
private_key = parameters.generate_private_key()
public_key = private_key.public_key()

# Get the serialized representation of the public key
serialized_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Generate a large prime number using the Diffie-Hellman parameters
prime_number = parameters.parameter_numbers().p

print(prime_number)