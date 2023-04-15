from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
from bad_random_generator import load_priv_key
import os

# Generate a private key
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
#     backend=default_backend()
# )

CERTS_PATH = "certs"

if not os.path.exists(CERTS_PATH):
    os.makedirs(CERTS_PATH)

def self_sign_cert(keypair_id):
    private_key = load_priv_key(keypair_id)

    # Create a certificate signing request (CSR)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"ctf.sfi.pl")
    ])).sign(private_key, hashes.SHA256(), default_backend())

    # Generate a self-signed certificate
    certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"ctf.sfi.pl")
    ])).issuer_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"ctf.sfi.pl")
    ])).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(
        private_key, hashes.SHA256(), default_backend()
    )

    # print(certificate.fingerprint(hashes.SHA256()))
    # print(certificate.public_bytes(serialization.Encoding.PEM).decode())

    # Write our certificate out to disk.
    with open(f"{CERTS_PATH}/certificate{keypair_id}.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))



if __name__ == "__main__":
    # generate all 5 self-signed certificates
    for i in range(5):
        self_sign_cert(i)

