from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Generate a private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Create a certificate signing request (CSR)
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(x509.NameOID.COMMON_NAME, u"example.com")
])).sign(private_key, hashes.SHA256(), default_backend())

# Generate a self-signed certificate
certificate = x509.CertificateBuilder().subject_name(x509.Name([
    x509.NameAttribute(x509.NameOID.COMMON_NAME, u"example.com")
])).issuer_name(x509.Name([
    x509.NameAttribute(x509.NameOID.COMMON_NAME, u"example.com")
])).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
    datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)
).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(
    private_key, hashes.SHA256(), default_backend()
)

print(certificate.public_bytes(serialization.Encoding.PEM))