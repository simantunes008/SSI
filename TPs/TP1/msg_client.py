# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import os
import sys
import bson
import asyncio
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from util import *
from sts import *


conn_port = 8443
max_msg_size = 9999
parameters = load_dh_parameters(
    0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
    2
)
if len(sys.argv) > 1:
    if sys.argv[1] == '-user':
        try:
            private_key, user_cert, ca_cert = get_userdata(f'data/{sys.argv[2]}')
        except Exception as e:
            sys.stderr.write('MSG RELAY SERVICE: ' + str(e) + '!\n')
            sys.exit(1)
else:
    private_key, user_cert, ca_cert = get_userdata('data/userdata.p12')
public_key = user_cert.public_key()
public_keys = load_public_keys()

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.aesgcm = None
    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt +=1
        
        #! ÍNICIO DO PROTOCOLO STATION-TO-STATION
        if self.msg_cnt == 1:
            return serialize_public_key(self.public_key)
        
        if self.msg_cnt == 2:
            pair, cert = unpair(msg)
            serialized_key, signature = unpair(pair)
            
            server_public_key = load_pem_public_key(serialized_key)
            server_cert = x509.load_pem_x509_certificate(cert)
            
            success, error = validate_certificate(server_cert, ca_cert, [(x509.NameOID.PSEUDONYM, "MSG_SERVER")], [(x509.ExtensionOID.EXTENDED_KEY_USAGE, lambda e: x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in e)])
            if not success:
                sys.stderr.write('MSG RELAY SERVICE: ' + str(error) + '!\n')
                return b''
            
            cert_public_key = server_cert.public_key()
            
            success, error = validate_signature(cert_public_key, signature, mkpair(serialized_key, serialize_public_key(self.public_key)))
            if not success:
                sys.stderr.write('MSG RELAY SERVICE: ' + str(error) + '!\n')
                return b''
            
            self.aesgcm = AESGCM(derive_shared_key(self.private_key, server_public_key))
            
            signature = generate_signature(private_key, mkpair(serialize_public_key(self.public_key), serialized_key))
            cert = serialize_certificate(user_cert)
            
            return mkpair(signature, cert)
        #! FIM DO PROTOCOLO STATION-TO-STATION
        
        if msg != b'':
            nonce = msg[:12]
            ciphertext = msg[12:]
            msg = self.aesgcm.decrypt(nonce, ciphertext, None)
            txt = bson.loads(msg)
        
        if txt['command'] == 'send':
            print('Received (%d): %r' % (self.msg_cnt - 2, txt['content']))
        elif txt['command'] == 'askqueue':
            print('Received (%d): %r' % (self.msg_cnt - 2, txt['content']))
        elif txt['command'] == 'getmsg':
            content = txt['content']
            
            if content:
                sender = txt['sender']
                signature = txt['signature']
                
                success, error = validate_signature(public_keys[sender], signature, content)
                if not success:
                    sys.stderr.write('MSG RELAY SERVICE: ' + str(error) + '!\n')
                    return b''
                
                content = private_key.decrypt(
                    content,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode()
                
                print('Received (%d): %r' % (self.msg_cnt - 2, content))
            else:
                sys.stderr.write('MSG RELAY SERVICE: unknown message!\n')
        else:
            print('Received (%d): %r' % (self.msg_cnt - 2, ''))
        
        print('Input command (empty to finish)')
        
        flag = False
        new_msg = b''
        
        while not flag:
            user_input = input()   
            if not user_input:
                break 
            
            if user_input.startswith('send'):
                tokens = user_input.split(' ')
                
                if len(tokens) < 3:
                    sys.stderr.write('MSG RELAY SERVICE: command error!\n')
                    print_info()
                    continue
                
                uid = tokens[1]
                subject = tokens[2]
                content = input().encode()   
                
                if len(content) > 1000:
                    sys.stderr.write('MSG RELAY SERVICE: command error!\n')
                    print_info()
                    continue
                
                enc_content = public_keys[uid].encrypt(
                    content,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                signature = generate_signature(private_key, enc_content)
                
                new_msg = bson.dumps({
                    "command"   : 'send',
                    "uid"       : uid,
                    "subject"   : subject,
                    "content"   : enc_content,
                    "signature" : signature
                })
                
                flag = True
                
            elif user_input == 'askqueue':
                new_msg = bson.dumps({
                    "command" : 'askqueue',
                })
                
                flag = True
                
            elif user_input.startswith('getmsg'):
                tokens = user_input.split(' ')
                
                if len(tokens) < 2:
                    sys.stderr.write('MSG RELAY SERVICE: command error!\n')
                    print_info()
                    continue
                
                num = int(tokens[1])
                
                new_msg = bson.dumps({
                    "command" : 'getmsg',
                    "num"     : num
                })
                
                flag = True
                
            elif user_input == 'help':
                print_info()
                
            else:
                sys.stderr.write('MSG RELAY SERVICE: command error!\n')
                print_info()
        
        if new_msg != b'':
            nonce = os.urandom(12)
            ciphertext = self.aesgcm.encrypt(nonce, new_msg, None )
            new_msg = (nonce + ciphertext)
        #
        return new_msg if len(new_msg)>0 else None






#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg :
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()