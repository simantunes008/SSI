import sys

def preproc(str):
    l = []
    for c in str:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def enc(message, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    encrypted_message = ''
    for i in range(len(message)):
        original_position = alphabet.index(message[i])
        key_position = alphabet.index(key[i % len(key)])
        shift = (original_position + key_position) % 26
        encrypted_message += alphabet[shift]
    return encrypted_message

def dec(message, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    decrypted_message = ''
    for i in range(len(message)):
        original_position = alphabet.index(message[i])
        key_position = alphabet.index(key[i % len(key)])
        shift = (original_position - key_position) % 26
        decrypted_message += alphabet[shift]
    return decrypted_message

def main():
    if len(sys.argv) != 4:
        print("Usage: python vigenere.py [enc|dec] key message")
        return
    
    operation = sys.argv[1]
    key = sys.argv[2]
    message = preproc(sys.argv[3])
    
    if operation == 'enc':
        result = enc(message, key)
    elif operation == 'dec':
        result = dec(message, key)
    else:
        print("Error: Invalid operation. Use 'enc' for encryption or 'dec' for decryption.")
    
    print(result)

if __name__ == '__main__':
    main()
