from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes

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

    
    plaintext = plaintext[:-padding_size]

    return plaintext



def main():

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

    


if __name__ == "__main__":
    main()