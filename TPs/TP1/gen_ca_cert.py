import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

with open("data/MSG_CA.key", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"1234"),
    ))

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, 'PT'),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Minho'),
    x509.NameAttribute(NameOID.LOCALITY_NAME, 'Braga'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Universidade do Minho'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'SSI MSG RELAY SERVICE'),
    x509.NameAttribute(NameOID.COMMON_NAME, 'MSG RELAY SERVICE CA'),
    x509.NameAttribute(NameOID.PSEUDONYM, 'MSG_CA')
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None),
    critical=True,
).add_extension(
    x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False
    ),
    critical=True,
).sign(key, hashes.SHA256())

with open("data/MSG_CA.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))