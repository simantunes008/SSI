# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import os
import bson
import datetime
import logging
import asyncio
from queue import Queue
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


conn_cnt = 0
conn_port = 8443
max_msg_size = 9999
parameters = load_dh_parameters(
    0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
    2
)
private_key, server_cert, ca_cert = get_userdata('data/MSG_SERVER.p12')
db = {}
logging.basicConfig(filename=f'logs/server_log_{datetime.datetime.now().strftime("%Y-%m-%d")}.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.user_public_key = None
        self.aesgcm = None
        self.user_id = None
    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        
        #! ÍNICIO DO PROTOCOLO STATION-TO-STATION
        if self.msg_cnt == 1:
            self.user_public_key = load_pem_public_key(msg)
            
            key = serialize_public_key(self.public_key)
            signature = generate_signature(private_key, mkpair(key, msg))
            cert = serialize_certificate(server_cert)
            
            return mkpair(mkpair(key, signature), cert)
        
        if self.msg_cnt == 2:
            signature, pem_data = unpair(msg)
            user_cert = x509.load_pem_x509_certificate(pem_data)
            
            success, error = validate_certificate(user_cert, ca_cert, [(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI MSG RELAY SERVICE")], [(x509.ExtensionOID.EXTENDED_KEY_USAGE, lambda e: x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in e)])
            if not success:
                logging.info(f"Transaction from user {self.user_id}: {str(error)}")
                return b''
            
            for attr in user_cert.subject:
                if attr.oid == x509.NameOID.PSEUDONYM:
                    self.user_id = attr.value
            
            cert_public_key = user_cert.public_key()
            
            success, error = validate_signature(cert_public_key, signature, mkpair(serialize_public_key(self.user_public_key), serialize_public_key(self.public_key)))
            if not success:
                logging.info(f"Transaction from user {self.user_id}: {str(error)}")
                return b''
            
            self.aesgcm = AESGCM(derive_shared_key(self.private_key, self.user_public_key))
            
            if self.user_id not in db:
                db[self.user_id] = Queue()
            
            logging.info(f"Transaction from user {self.user_id}: started")
            
            new_msg = bson.dumps({
                'command' : None
            })
            
            nonce = os.urandom(12)
            ciphertext = self.aesgcm.encrypt(nonce, new_msg, None)
            return nonce + ciphertext
        #! FIM DO PROTOCOLO STATION-TO-STATION
        
        nonce = msg[:12]
        ciphertext = msg[12:]
        msg = self.aesgcm.decrypt(nonce, ciphertext, None)
        txt = bson.loads(msg)
        
        if txt['command'] == 'send':
            uid = txt["uid"]
            subject = txt["subject"]
            content = txt["content"]
            signature = txt['signature']
            now = datetime.datetime.now(tz=datetime.timezone.utc)
            
            if uid not in db:
                db[uid] = Queue()
            
            db[uid].put({
                'num'       : db[uid].qsize() + 1,
                'sender'    : self.user_id,
                'time'      : now.strftime("%Y-%m-%d %H:%M:%S"),
                'subject'   : subject,
                'content'   : content,
                'signature' : signature,
                'read'      : False
            })
            
            new_msg = bson.dumps({
                "command" : 'send',
                "content" : f'Message sent to {uid}'
            })
            
            logging.info(f"Transaction from user {self.user_id}: {txt['command']}")
            
        elif txt['command'] == 'askqueue':
            queue_messages = db[self.user_id].queue
            content = []
            
            for message in queue_messages:
                if not message['read']:
                    num = message['num']
                    sender = message['sender']  
                    time = message['time']
                    subject = message['subject']
                    content.append(f"{num}:{sender}:{time}:{subject}")
            
            new_msg = bson.dumps({
                "command" : 'askqueue',
                "content" : content
            })
            
            logging.info(f"Transaction from user {self.user_id}: {txt['command']}")
            
        elif txt['command'] == 'getmsg':
            num = txt['num']
            
            queue_messages = list(db[self.user_id].queue)
            
            if 1 <= num <= len(queue_messages):
                message = queue_messages[num - 1]
                
                message['read'] = True
                
                new_msg = bson.dumps({
                    "command"   : 'getmsg',
                    "sender"    : message['sender'],
                    "content"   : message['content'],
                    'signature' : message['signature'],
                })
            else:
                new_msg = bson.dumps({
                    "command" : 'getmsg',
                    "content" : None
                })
            
            logging.info(f"Transaction from user {self.user_id}: {txt['command']}")
        
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
    logging.info(f"Transaction from user {srvwrk.user_id}: finished")
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