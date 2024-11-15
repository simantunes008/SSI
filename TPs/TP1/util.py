import os
import datetime
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509


def load_public_keys():
    public_keys = {}
    data_dir = 'data'
    p12_files = [os.path.join(data_dir, f) for f in os.listdir(data_dir) if f.startswith('MSG_CLI') and f.endswith('.p12')]
    
    for p12_file in p12_files:
        user_data = get_userdata(p12_file)
        user_cert = user_data[1]
        
        for attr in user_cert.subject:
            if attr.oid == x509.NameOID.PSEUDONYM:
                user_id = attr.value
        
        public_keys[user_id] = user_cert.public_key()
    
    return public_keys

def print_info():
    print("-user <FNAME> : User data file. (default: userdata.p12)")
    print("send <UID> <SUBJECT> : Sends a message with a specified subject to the user.")
    print("askqueue : Requests unread messages from the user's queue.")
    print("getmsg <NUM> : Requests a specific message from the user's queue.")
    print("help : Prints usage instructions.")

def get_userdata(p12_fname):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    password = b"1234" # p12 está protgeido 
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password)
    return (private_key, user_cert, ca_cert)

def mkpair(x, y):
    """produz uma byte-string contendo o tuplo '(x,y)' ('x' e 'y' são byte-strings)"""
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def unpair(xy):
    """extrai componentes de um par codificado com 'mkpair'"""
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

def cert_load(fname):
    """lê certificado de ficheiro"""
    with open(fname, "rb") as fcert:
        cert = x509.load_pem_x509_certificate(fcert.read())
    return cert
