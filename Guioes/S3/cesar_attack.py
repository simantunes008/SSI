import sys

def preproc(str):
    l = []
    for c in str:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def dec(message, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    decrypted_message = ''
    shift = alphabet.index(key)
    for char in message:
        original_position = alphabet.index(char)
        new_position = (original_position - shift) % 26
        decrypted_message += alphabet[new_position]
    return decrypted_message

def attack(message, words):
    for key in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        decryted_message = dec(message, key)
        if any(word in decryted_message for word in words):
            return key, decryted_message
    return '',''

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 cesar_attack.py message word1 word2 ...")
        return
    
    message = preproc(sys.argv[1])
    words = [preproc(word) for word in sys.argv[2:]]
    
    key, decrypted_message = attack(message, words)
    
    if key:
        print(key)
        print(decrypted_message)

if __name__ == '__main__':
    main()
