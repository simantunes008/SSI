import sys
import random
import os

def bad_prng(n):
    """ an INSECURE pseudo-random number generator """
    random.seed(os.urandom(2))
    return os.urandom(n)

def xor_bytes(byte_data1, byte_data2):
    return bytes(a ^ b for a, b in zip(byte_data1, byte_data2))

def read_bytes_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

def main():
    if len(sys.argv) < 3:
        print("Usage: python bad_otp_attack.py [encrypted_file] [word1] [word2] ...")
        return

    encrypted_file = sys.argv[1]
    words = sys.argv[2:]

    encrypted_bytes = read_bytes_from_file(encrypted_file)

    for i in range(2**16):
        random.seed(i.to_bytes(2, 'big'))
        key = bad_prng(len(encrypted_bytes))
        decrypted_bytes = xor_bytes(encrypted_bytes, key)
        decrypted_text = decrypted_bytes.decode(errors='ignore')

        if any(word in decrypted_text for word in words):
            print(f"Found plaintext: {decrypted_text}")
            break

if __name__ == "__main__":
    main()
