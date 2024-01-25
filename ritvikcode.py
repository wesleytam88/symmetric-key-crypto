from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes
from urllib.parse import quote

BLOCK_SIZE = 16
HEADER_SIZE = 54

def pad(data):
    padding_size = BLOCK_SIZE - len(data)
    padding = bytes([padding_size]) * padding_size
    return data + padding

def ecb(key, plaintext):
    ciphertext = b""
    cipher = AES.new(key, AES.MODE_ECB)

    for i in range(0, len(plaintext), BLOCK_SIZE):
        curr_block = plaintext[i:(i+BLOCK_SIZE)]
        padded = pad(curr_block)
        ciphertext += cipher.encrypt(padded)

    return ciphertext

def cbc(key, iv, plaintext):
    ciphertext = b""
    cipher = AES.new(key, AES.MODE_ECB)

    prev_block = iv

    for i in range(0, len(plaintext), BLOCK_SIZE):
        curr_block = plaintext[i:(i+BLOCK_SIZE)]
        padded = pad(curr_block)

        temp = bytes([x ^ y for (x, y) in zip(padded, prev_block)])

        prev_block = cipher.encrypt(temp)
        ciphertext += prev_block

    return ciphertext

def cbc_decrypt(key, iv, ciphertext):
    plaintext = b""
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = iv

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        curr_block = ciphertext[i:(i+BLOCK_SIZE)]
        block = cipher.decrypt(curr_block)

        temp = bytes([x ^ y for (x, y) in zip(block, prev_block)])

        prev_block = curr_block
        plaintext += temp
    
    # only last block is padded
    padding_size = plaintext[-1]
    plaintext += plaintext[:-padding_size]

    return plaintext

def submit(key, iv):
    prepend_string = "userid=456;userdata="
    append_string = ";session-id=31337"

    user_string = input("Enter Your Data:")
    user_string = quote(user_string)

    # My cbc encryption method takes care of padding so it doesn't have to be done here
    complete_string = prepend_string + user_string + append_string
    complete_string = bytes(complete_string.encode())
    
    return cbc(key, iv, complete_string)

def tamper(ciphertext: bytes) -> bytes:
    nine_ascii = 0x39
    semicolon_ascii = 0x3b
    equals_ascii = 0x3d
    ciphertext = list(ciphertext)

    # user_string = 9admin9true

    # the i (ciphertext[4]) in userid
    # is mapped to same byte as 1st 9 in 9admin9true in CBC encryption
    first_block_byte = ciphertext[4]
    decrypted_byte = first_block_byte ^ nine_ascii
    byte_needed = decrypted_byte ^ semicolon_ascii
    ciphertext[4] = byte_needed

    # the ; (ciphertext[10]) in ...id=456;user...
    # is mapped to the same byte as the 2nd 9 in 9admin9true in CBC encryption
    first_block_byte = ciphertext[10]
    decrypted_byte = first_block_byte ^ nine_ascii
    byte_needed = decrypted_byte ^ equals_ascii
    ciphertext[10] = byte_needed

    return bytes(ciphertext)

def verify(key, iv, ciphertext):
    plaintext = cbc_decrypt(key, iv, ciphertext)

    if b";admin=true" in plaintext:
        return True
    else:
        return False


def part1():
    key = get_random_bytes(BLOCK_SIZE)
    iv = get_random_bytes(BLOCK_SIZE)   

    with open("mustang.bmp", 'rb') as file:
        header = file.read(HEADER_SIZE)
        body = file.read()


    ebc_ciphertext = ecb(key, body)
    with open("ebc_output.bmp", 'wb') as file:
        file.write(header)
        file.write(ebc_ciphertext)

    cbc_ciphertext = cbc(key, iv, body)
    with open("cbc_output_test.bmp", 'wb') as file:
         file.write(header)
         file.write(cbc_ciphertext)

    
    with open("cbc_output_test.bmp", 'rb') as file:
        decrypt_header = file.read(HEADER_SIZE)
     
        decrypt_body = file.read()
        cbc_plaintext = cbc_decrypt(key, iv, decrypt_body)

        with open("cbc_decrypted.bmp", "wb") as f:
            f.write(decrypt_header)
            f.write(cbc_plaintext)

def part2():
    part2_key = get_random_bytes(BLOCK_SIZE)
    part2_iv = get_random_bytes(BLOCK_SIZE)

    ciphertext = submit(part2_key, part2_iv)
    tampered = tamper(ciphertext)
    print(verify(part2_key, part2_iv, tampered))

def main():
    part2()

if __name__ == "__main__":
    main()