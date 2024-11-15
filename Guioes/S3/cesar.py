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
    shift = alphabet.index(key)
    for char in message:
        original_position = alphabet.index(char)
        new_position = (original_position + shift) % 26
        encrypted_message += alphabet[new_position]
    return encrypted_message

def dec(message, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    decrypted_message = ''
    shift = alphabet.index(key)
    for char in message:
        original_position = alphabet.index(char)
        new_position = (original_position - shift) % 26
        decrypted_message += alphabet[new_position]
    return decrypted_message

def main():
    if len(sys.argv) != 4:
        print("Usage: python cesar.py [enc|dec] key message")
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
