import sys, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

def setup(fkey):
    key = os.urandom(32)
    with open(fkey, 'wb') as file:
        file.write(key)

def enc(fich, fkey):
    with open(fich, 'rb') as file:
        plaintext = file.read()
    
    with open(fkey, 'rb') as file:
        key = file.read()
    
    nonce = os.urandom(16)
    
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode = None)
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(plaintext)
    
    with open(fich + '.enc', 'wb') as file:
        file.write(nonce + ciphertext)

def dec(fich, fkey):
    with open(fich, 'rb') as file:
        nonce = file.read(16)
        ciphertext = file.read()
    
    with open(fkey, 'rb') as file:
        key = file.read()
    
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode = None)
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(ciphertext)
    
    with open(fich + '.dec', 'wb') as file:
        file.write(plaintext)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cfich_chacha20.py [steup|enc|dec] [fkey|fich] fkey.")
        return
    
    operation = sys.argv[1]
    
    if operation == 'setup':
        fkey = sys.argv[2]
        setup(fkey)
    elif operation == 'enc':
        fich = sys.argv[2]
        fkey = sys.argv[3]
        enc(fich, fkey)
    elif operation == 'dec':
        fich = sys.argv[2]
        fkey = sys.argv[3]
        dec(fich, fkey)
    else:
        print("Error: Invalid operation. Use 'setup', 'enc' or 'dec'.")

if __name__ == '__main__':
    main()