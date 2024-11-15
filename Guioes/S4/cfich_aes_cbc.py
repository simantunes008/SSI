from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os, sys

def setup(fkey):
    key = os.urandom(32)
    with open(fkey, 'wb') as file:
        file.write(key)


def enc(fich, fkey):
    with open(fich, 'rb') as file:
        plaintext = file.read()
    
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    with open(fkey, 'rb') as file:
        key = file.read()
    
    iv = os.urandom(16)  # CBC mode pede um vetor de inicialização
    algorithm = algorithms.AES(key)
    mode = modes.CBC(iv)
    cipher = Cipher(algorithm, mode)
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    with open(fich + '.enc', 'wb') as file:
        file.write(iv + ciphertext)  

def dec(fich, fkey):
    with open(fich, 'rb') as file:
        iv_ciphertext = file.read()
    
    iv = iv_ciphertext[:16] 
    ciphertext = iv_ciphertext[16:]
    
    with open(fkey, 'rb') as file:
        key = file.read()
    
    algorithm = algorithms.AES(key)
    mode = modes.CBC(iv)
    cipher = Cipher(algorithm, mode)
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
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
        print("Error: Invalid operation. Use 'enc' or 'dec'.")

if __name__ == '__main__':
    main()        