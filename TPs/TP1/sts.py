import datetime
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def load_dh_parameters(p, g):
    pn = dh.DHParameterNumbers(p, g)
    return pn.parameters()

def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def serialize_certificate(certificate):
    pem = certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    )
    return pem

def generate_signature(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def cert_validtime(cert, now=None):
    """valida que 'now' se encontra no período
    de validade do certificado."""
    if now is None:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise x509.verification.VerificationError(
            "Certificate is not valid at this time"
        )

def cert_validsubject(cert, attrs=[]):
    """verifica atributos do campo 'subject'. 'attrs'
    é uma lista de pares '(attr,value)' que condiciona
    os valores de 'attr' a 'value'."""
    #print(cert.subject)
    for attr in attrs:
        if cert.subject.get_attributes_for_oid(attr[0])[0].value != attr[1]:
            raise x509.verification.VerificationError(
                "Certificate subject does not match expected value"
            )

def cert_validexts(cert, policy=[]):
    """valida extensões do certificado.
    'policy' é uma lista de pares '(ext,pred)' onde 'ext' é o OID de uma extensão e 'pred'
    o predicado responsável por verificar o conteúdo dessa extensão."""
    for check in policy:
        ext = cert.extensions.get_extension_for_oid(check[0]).value
        if not check[1](ext):
            raise x509.verification.VerificationError(
                "Certificate extensions does not match expected value"
            )

def validate_certificate(cert, ca_cert, attrs=[], policy=[]):
    try:
        cert.verify_directly_issued_by(ca_cert)
        cert_validtime(cert)
        cert_validsubject(cert, attrs)
        cert_validexts(cert, policy)
        return True, None
    except x509.verification.VerificationError as error:
        return False, error

def validate_signature(public_key, signature, data):
    try:    
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True, None
    except InvalidSignature:
        return False, 'MSG RELAY SERVICE: Invalid Signature!'

def derive_shared_key(private_key, public_key):
    shared_key = private_key.exchange(public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=None, 
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key