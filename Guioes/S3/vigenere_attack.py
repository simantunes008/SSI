import sys
from collections import Counter
from itertools import product

def preproc(str):
    l = []
    for c in str:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def dec(message, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    decrypted_message = ''
    for i in range(len(message)):
        original_position = alphabet.index(message[i])
        key_position = alphabet.index(key[i % len(key)])
        shift = (original_position - key_position) % 26
        decrypted_message += alphabet[shift]
    return decrypted_message

def attack(key_length, message, words):
    most_frequent = []
    
    for i in range(key_length):
        slice = message[i::key_length]
        char_count = Counter(slice)
        most_common = char_count.most_common(len(slice))
        most_frequent.append([char for char, _ in most_common])
    
    for key_candidate in product(*most_frequent):
        key = ''.join(key_candidate)
        decrypted_message = dec(message, key)
        if any(word in decrypted_message for word in words):
            return key, decrypted_message
    return '', ''

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 vigenere_attack.py lenght message word1 word2 ...")
        return
    
    key_lenght = int(sys.argv[1])
    message = preproc(sys.argv[2])
    words = [preproc(word) for word in sys.argv[3:]]
    
    key, decrypted_message = attack(key_lenght, message, words)
    
    if key:
        print(key)
        print(decrypted_message)

if __name__ == '__main__':
    main()
