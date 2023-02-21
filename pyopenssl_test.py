from OpenSSL import SSL, crypto

print(SSL._CERTIFICATE_PATH_LOCATIONS)\

type = crypto.TYPE_RSA
bits = 2048

keypair = crypto.PKey()
keypair.generate_key(type, bits)
print(keypair)
print(keypair.type())

secret = crypto.dump_privatekey(crypto.FILETYPE_PEM, keypair)
print(secret)
buff = crypto.dump_publickey(crypto.FILETYPE_PEM, keypair)
print(buff)

prime_number = crypto.get_random_prime(2048)
print(prime_number)


# Task 1: generate public and private key pairs using openssl
