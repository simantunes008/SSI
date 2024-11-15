import sys, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(), #Hashes - comprimento fixo para um bloco de dados
        length = 32,
        salt = salt, #Garante que os hashes gerados são diferentes
        iterations = 100000,
    )
    key = kdf.derive(passphrase.encode())
    return key

def enc(fich, passphrase):
    with open(fich, 'rb') as file:
        plaintext = file.read()

    salt = os.urandom(16)  # Random salt
    key = derive_key(passphrase, salt)
    nonce = os.urandom(16)

    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext)

    with open(fich + '.enc', 'wb') as file:
        file.write(salt + nonce + ciphertext)

def dec(fich, passphrase):
    with open(fich, 'rb') as file:
        data = file.read()

    salt = data[:16]
    nonce = data[16:32]
    ciphertext = data[32:]

    key = derive_key(passphrase, salt)

    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(fich + '.dec', 'wb') as file:
        file.write(plaintext)

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 pbenc_chacha20.py [enc|dec] [fich]")
        return

    operation = sys.argv[1]
    fich = sys.argv[2]
    passphrase = input("Enter passphrase: ")

    if operation == 'enc':
        enc(fich, passphrase)
    elif operation == 'dec':
        dec(fich, passphrase)
    else:
        print("Error: Invalid operation. Use 'enc' or 'dec'.")

if __name__ == '__main__':
    main()
