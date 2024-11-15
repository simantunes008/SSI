import sys

def attack(fctxt, pos, ptxtAtPos, newPtxtAtPos):
    with open(fctxt, 'rb') as file:
        nonce = file.read(16)
        ciphertext = file.read()
    
    segment = ciphertext[pos:pos+len(ptxtAtPos)]
    
    xor_bytes = bytes([a ^ b for a, b in zip(segment, ptxtAtPos)])
    xor_bytes = bytes([a ^ b for a, b in zip(newPtxtAtPos, xor_bytes)])
    
    modified_ciphertext = ciphertext[:pos] + xor_bytes + ciphertext[pos+len(newPtxtAtPos):]
    
    with open(fctxt + '.attack', 'wb') as file:
        file.write(nonce + modified_ciphertext)

def main():
    if len(sys.argv) != 5:
        print("Usage: python3 chacha20_int_attck.py fctxt pos ptxtAtPos newPtxtAtPos")
        return
    
    fctxt = sys.argv[1]
    pos = int(sys.argv[2])
    ptxtAtPos = sys.argv[3].encode('utf-8')
    newPtxtAtPos = sys.argv[4].encode('utf-8')
    
    attack(fctxt, pos, ptxtAtPos, newPtxtAtPos)

if __name__ == '__main__':
    main()
