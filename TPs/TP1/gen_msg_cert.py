import sys
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12


with open("data/MSG_CA.key", "rb") as f:    
    ca_key = serialization.load_pem_private_key(
        f.read(), 
        password = b"1234"
    )

with open(f"data/MSG_CA.crt", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, 'PT'),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Minho'),
    x509.NameAttribute(NameOID.LOCALITY_NAME, 'Braga'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Universidade do Minho'),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'SSI MSG RELAY SERVICE'),
    x509.NameAttribute(NameOID.COMMON_NAME, sys.argv[1]),
    x509.NameAttribute(NameOID.PSEUDONYM, sys.argv[2]) 
])

issuer = x509.Name([
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
    x509.BasicConstraints(ca=False, path_length=None),
    critical=True,
).add_extension(
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    ),
    critical=True,
).add_extension(
    x509.ExtendedKeyUsage([
        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH # SERVER_AUTH para gerar o certificado do servidor
    ]),
    critical=False,
).sign(ca_key, hashes.SHA256())

with open(f"data/{sys.argv[2]}.p12", "wb") as f:
    f.write(serialization.pkcs12.serialize_key_and_certificates(
        sys.argv[2].encode(),
        key,
        cert,
        [ca_cert],
        serialization.BestAvailableEncryption(b"1234")
        )
    )