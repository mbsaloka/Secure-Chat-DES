# Constants Table
INITIAL_PERMUTATION = [
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
]
FINAL_PERMUTATION = [
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
]
EXPANSION_PERM = [
    32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
    12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1
]
S_BOXES = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]
PERMUTATION_P = [
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
]
KEY_INITIAL_PERM = [
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,21,13,5,28,20,12,4
]
KEY_FINAL_PERM = [
    14,17,11,24,1,5,3,28,15,6,21,10,23,19,
    12,4,26,8,16,7,27,20,13,2,41,52,31,37,
    47,55,30,40,51,45,33,48,44,49,39,56,
    34,53,46,42,50,36,29,32
]
SHIFT_SCHEDULE = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# Utility Functions
def str_to_bits(s):
    return ''.join(f"{ord(c):08b}" for c in s)

def bits_to_str(b):
    chars = [chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)]
    return ''.join(chars)

def permute(block, table):
    return ''.join(block[i-1] for i in table)

def xor(a, b):
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def pad_bits(b):
    while len(b) % 64 != 0:
        b += '0'
    return b

def split_blocks(bits, size=64):
    return [bits[i:i+size] for i in range(0, len(bits), size)]

# Subkey Generation
def generate_subkeys(key_64bit):
    key = permute(key_64bit, KEY_INITIAL_PERM)
    C, D = key[:28], key[28:]
    subkeys = []
    for shift in SHIFT_SCHEDULE:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        subkeys.append(permute(C + D, KEY_FINAL_PERM))
    return subkeys

# Feistel Function
def sbox_substitution(bits):
    out = ''
    for i in range(8):
        block = bits[i*6:(i+1)*6]
        row = int(block[0] + block[-1], 2)
        col = int(block[1:5], 2)
        out += f"{S_BOXES[i][row][col]:04b}"
    return out

def feistel(right, subkey):
    expanded = permute(right, EXPANSION_PERM)
    xored = xor(expanded, subkey)
    sboxed = sbox_substitution(xored)
    return permute(sboxed, PERMUTATION_P)

# DES Block Processing
def des_block(block, subkeys, encrypt=True):
    block = permute(block, INITIAL_PERMUTATION)
    L, R = block[:32], block[32:]
    keys = subkeys if encrypt else reversed(subkeys)
    for k in keys:
        L, R = R, xor(L, feistel(R, k))
    return permute(R + L, FINAL_PERMUTATION)

# String Encoding
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def bits_to_safe_string(bits):
    result = ''
    for i in range(0, len(bits), 6):
        chunk = bits[i:i+6]
        if len(chunk) < 6:
            chunk = chunk.ljust(6, '0')
        val = int(chunk, 2)
        result += CHARSET[val]
    return result

def safe_string_to_bits(s):
    bits = ''
    for c in s:
        val = CHARSET.index(c)
        bits += f"{val:06b}"
    return bits

# DES Encrypt/Decrypt Implementation
def des_encrypt(plaintext, key, mode="single"):
    key_bits = pad_bits(str_to_bits(key)[:64])
    subkeys = generate_subkeys(key_bits)
    plain_bits = pad_bits(str_to_bits(plaintext))
    blocks = split_blocks(plain_bits)

    ciphertext_bits = ''
    prev = '0' * 64
    for block in blocks:
        if mode == "multiple":
            block = xor(block, prev)
        enc_block = des_block(block, subkeys, True)
        ciphertext_bits += enc_block
        prev = enc_block if mode == "multiple" else prev

    return bits_to_safe_string(ciphertext_bits)

def des_decrypt(ciphertext, key, mode="single"):
    key_bits = pad_bits(str_to_bits(key)[:64])
    subkeys = generate_subkeys(key_bits)

    ciphertext_bits = safe_string_to_bits(ciphertext)
    ciphertext_bits = ciphertext_bits[:len(ciphertext_bits)//64*64]
    blocks = split_blocks(ciphertext_bits)

    plaintext_bits = ''
    prev = '0' * 64
    for block in blocks:
        dec_block = des_block(block, subkeys, False)
        if mode == "multiple":
            dec_block = xor(dec_block, prev)
            prev = block
        plaintext_bits += dec_block

    return bits_to_str(plaintext_bits).rstrip('\x00')

if __name__ == "__main__":
    text = input("Text : ")
    key = input("Key : ")

    enc_single = des_encrypt(text, key, mode="single")
    dec_single = des_decrypt(enc_single, key, mode="single")

    print("\n[Single Mode]")
    print("Ciphertext :", enc_single)
    print("Decrypted  :", dec_single)

    enc_multi = des_encrypt(text, key, mode="multiple")
    dec_multi = des_decrypt(enc_multi, key, mode="multiple")

    print("\n[Multiple Mode]")
    print("Ciphertext :", enc_multi)
    print("Decrypted  :", dec_multi)
