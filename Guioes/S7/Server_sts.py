# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import os
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from util import *

conn_cnt = 0
conn_port = 8443
max_msg_size = 9999
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
pn = dh.DHParameterNumbers(p, g)
parameters = pn.parameters()
with open("MSG_SERVER.key", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(), 
        password = b'1234'
    )

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.peer_public_key = None
        self.aesgcm = None
    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        #
        # ALTERAR AQUI COMPORTAMENTO DO SERVIDOR
        #        
        #
        
        if self.msg_cnt == 1:
            self.peer_public_key = load_pem_public_key(msg)
            
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            signature = private_key.sign(
                mkpair(pem, msg),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            with open("MSG_SERVER.crt", "rb") as cert_file:
                cert = cert_file.read()
            
            return mkpair(mkpair(pem, signature), cert)
        
        if self.msg_cnt == 2:
            signature, pem_data = unpair(msg)
            
            cert = x509.load_pem_x509_certificate(pem_data)
            
            # Validação do certificado
            try:
                ca_cert = cert_load("MSG_CA.crt")
                cert.verify_directly_issued_by(ca_cert)
                cert_validtime(cert)
                cert_validsubject(cert, [(x509.NameOID.COMMON_NAME, "User 1 (SSI MSG Relay Client 1)")])
                cert_validexts(
                    cert,
                    [
                        (
                            x509.ExtensionOID.EXTENDED_KEY_USAGE,
                            lambda e: x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in e,
                        )
                    ],
                )
            except x509.verification.VerificationError as e:
                print(e)
                return b''
            
            public_key = cert.public_key()
            
            message = mkpair(
                self.peer_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo), 
                self.public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            )
            
            # Validação da assinatura
            try:    
                public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except InvalidSignature:
                print('Invalid signature')
                return b''
            
            # Derivação da chave
            shared_key = self.private_key.exchange(self.peer_public_key)
            derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',).derive(shared_key)
            self.aesgcm = AESGCM(derived_key)
            
            new_msg = ''.encode()
            
            nonce = os.urandom(12)
            ciphertext = self.aesgcm.encrypt(nonce, new_msg, None)
            return nonce + ciphertext
        
        nonce = msg[:12]
        ciphertext = msg[12:]
        msg = self.aesgcm.decrypt(nonce, ciphertext, None)
        
        txt = msg.decode()
        print('%d : %r' % (self.id, txt))
        new_msg = txt.upper().encode()
        
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, new_msg, None)
        new_msg = (nonce + ciphertext)
        
        #
        
        return new_msg if len(new_msg)>0 else None


#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = await reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        await writer.drain()
        data = await reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.new_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()