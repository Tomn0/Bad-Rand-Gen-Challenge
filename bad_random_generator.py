from OpenSSL import SSL, crypto

print(SSL._CERTIFICATE_PATH_LOCATIONS)\

type = crypto.TYPE_RSA
bits = 2048

keypair = crypto.PKey()
keypair.generate_key(type, bits)
print(keypair)