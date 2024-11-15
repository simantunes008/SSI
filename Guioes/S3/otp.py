import sys
import os

def generate_random_bytes(num_bytes):
    return os.urandom(num_bytes)

def write_bytes_to_file(bytes_data, filename):
    with open(filename, 'wb') as file:
        file.write(bytes_data)

def read_bytes_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

def setup(num_bytes, filename):
    random_bytes = generate_random_bytes(num_bytes)
    write_bytes_to_file(random_bytes, filename)

def xor_bytes(byte_data1, byte_data2):
    return bytes(a ^ b for a, b in zip(byte_data1, byte_data2))

def enc(message_filename, key_filename):
    message_bytes = read_bytes_from_file(message_filename)
    key_bytes = read_bytes_from_file(key_filename)
    encrypted_bytes = xor_bytes(message_bytes, key_bytes)
    encrypted_message_filename = message_filename + '.enc'
    write_bytes_to_file(encrypted_bytes, encrypted_message_filename)

def dec(message_filename, key_filename):
    message_bytes = read_bytes_from_file(message_filename)
    key_bytes = read_bytes_from_file(key_filename)
    decrypted_bytes = xor_bytes(message_bytes, key_bytes)
    decrypted_message_filename = message_filename + '.dec'
    write_bytes_to_file(decrypted_bytes, decrypted_message_filename)

def main():
    if len(sys.argv) != 4:
        print("Usage: python opt.py [setup|enc|dec] [nbytes|message] key")
        return
    
    operation = sys.argv[1]
    
    if operation == 'setup':
        setup(int(sys.argv[2]), sys.argv[3])
    elif operation == 'enc':
        enc(sys.argv[2], sys.argv[3])
    elif operation == 'dec':
        dec(sys.argv[2], sys.argv[3])
    else:
        print("Error: Invalid operation. Use 'setup', 'enc' or 'dec'.")

if __name__ == '__main__':
    main()
