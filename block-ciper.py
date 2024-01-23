import typing
import random
from Crypto.Cipher import AES
import urllib.parse

SIZE_HEADER = 54
SIZE_BLOCK = 128

def generate_key() -> bytearray:
    key = bytearray(16)
    for i, byte in enumerate(key):
        key[i] = random.randrange(0, 255)
    return key

def generate_IV() -> bytes:
    iv = bytearray(SIZE_BLOCK)
    for i, byte in enumerate(iv):
        iv[i] = random.randrange(0, 255)
    return bytes(iv)

def xor(x: bytes, y: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(x, y))

def file_len(f: typing.BinaryIO) -> int:
    currentPos = f.tell()
    f.seek(0, 2)            # move to end of file
    length = f.tell()       # get current pos
    f.seek(currentPos, 0)   # go back to original position
    return length

def encrypt_ECB(block: bytes, key: bytearray) -> bytes:
    '''Given a block of 128 bytes or less, encrypts the block in ECB mode
    using AES and PKCS#7 padding'''
    cipher = AES.new(key, mode=AES.MODE_ECB)


    # check if block needs padding
    if len(block) < SIZE_BLOCK:
        padding_length = SIZE_BLOCK - len(block)
        block = block.ljust(SIZE_BLOCK, bytes([padding_length]))
   
    # encrypt block
    encrypted_block = cipher.encrypt(block)
    return encrypted_block

def encrypt_file_CBC(filename: str, key: bytearray, iv: bytes):
    cipher = AES.new(key=key, mode=AES.MODE_CBC)
    filename_encrypted = filename.split('.')[0] + '_encrypted_CBC.bmp'
   
    with open(filename_encrypted, 'wb') as encrypted_file:
        with open(filename, 'rb') as f:
            length = file_len(f)
            header = f.read(SIZE_HEADER)
            encrypted_file.write(header)

            # loop until not enougb bytes to make a full block
            while length - f.tell() >= SIZE_BLOCK:
                block = f.read(SIZE_BLOCK)
                block_xor = xor(block, iv)
                encrypted_block = cipher.encrypt(block_xor)
                encrypted_file.write(encrypted_block)
                iv = encrypted_block

            # check if need padding
            bytes_left = length - f.tell()
            if bytes_left > 0:
                padding_length = SIZE_BLOCK - bytes_left
                remaining = f.read(bytes_left)
                remaining_padded = remaining.ljust(SIZE_BLOCK, bytes([padding_length]))
                remaining_padded_xor = xor(remaining_padded, iv)
                remaining_encrypted = cipher.encrypt(remaining_padded_xor)
                encrypted_file.write(remaining_encrypted)

def encrypt_CBC(block: bytes, key: bytearray, iv: bytes) -> bytes:
    '''Given a block of 128 bytes or less, encrypts the block in CBC mode
    using AES and PKCS#7 padding'''
    cipher = AES.new(key, mode=AES.MODE_CBC)

    # check if block needs padding
    if len(block) < SIZE_BLOCK:
        padding_char = SIZE_BLOCK - len(block)
        block = block.ljust(SIZE_BLOCK, bytes([padding_char]))

    block_xor = xor(block, iv)
    print(block_xor.hex())
    block_encrypted = cipher.encrypt(block_xor)
    print(block_encrypted.hex())
    return block_encrypted

def decrypt_file_CBC(filename: str, key: bytearray, iv: bytes):
    cipher = AES.new(key=key, mode=AES.MODE_CBC)
    filename_decrypted = filename.split('.')[0] + '_decrypted.bmp'

    with open(filename_decrypted, 'wb') as decrypted_file:
        with open(filename, 'rb') as f:
            length = file_len(f)
            header = f.read(SIZE_HEADER)
            decrypted_file.write(header)

            while length - f.tell() > SIZE_BLOCK:
                block = f.read(SIZE_BLOCK)
                block_decrypted = cipher.decrypt(block)
                block_decrypted_xor = xor(block_decrypted, iv)
                decrypted_file.write(block_decrypted_xor)
                iv = block

            # last block, deal with padding
            block = f.read(SIZE_BLOCK)
            block_decrypted = cipher.decrypt(block)
            block_decrypted_xor = xor(block_decrypted, iv)
            padding_char = bytes(block_decrypted_xor[-1])      # Assumes the last byte is a padding byte
            block_decrypted_no_pad = block_decrypted_xor.rstrip(padding_char)
            decrypted_file.write(block_decrypted_no_pad)

def decrypt_CBC(block_encrypted: bytes,
                key: bytearray,
                iv: bytes,
                isLast=False) -> bytes:
    '''Given a block of 128 bytes, decrypts the block in CBC mode
    using AES and PKCS#7 padding'''
    cipher = AES.new(key, mode=AES.MODE_CBC)

    print(block_encrypted.hex())
    block_decrypted = cipher.decrypt(block_encrypted)
    print(block_decrypted.hex())
    block_decrypted_xor = xor(block_decrypted, iv)
    if isLast:
        # Strip padding off before returning block
        # Assumes last byte is a padding byte
        padding_char = bytes(block_decrypted_xor[-1])
        block_decrypted_xor = block_decrypted_xor.rstrip(padding_char)
    return block_decrypted_xor

def task1():
    filename = "mustang.bmp"

    key = generate_key()
    iv = generate_IV()

    # encrypt_CBC(filename, key, iv)

    # decrypt_CBC("mustang_encrypted_CBC.bmp", key, iv)

    # encrypt using ECB
    filename_encrypted = filename.split('.')[0] + '_encrypted_ECB.bmp'
    with open(filename_encrypted, 'wb') as encrypted_file:
        with open(filename, 'rb') as f:
            length = file_len(f)
            header = f.read(SIZE_HEADER)        # Don't encrypte/decrypt header
            encrypted_file.write(header)

            # loop until not enough bytes left to make a full block
            while length - f.tell() >= SIZE_BLOCK:
                block = f.read(SIZE_BLOCK)
                encrypted_block = encrypt_ECB(block, key)
                encrypted_file.write(encrypted_block)

            # deal with last chunk of message
            bytes_left = length - f.tell()
            if bytes_left > 0:
                remaining = f.read(bytes_left)
                remaining_encrypted = encrypt_ECB(remaining, key)
                encrypted_file.write(remaining_encrypted)

    # encrypt using CBC
    filename_encrypted = filename.split('.')[0] + '_encrypted_CBC.bmp'
    with open(filename_encrypted, 'wb') as encrypted_file:
        with open(filename, 'rb') as f:
            length = file_len(f)
            header = f.read(SIZE_HEADER)
            encrypted_file.write(header)

            # loop until not enougb bytes to make a full block
            while length - f.tell() >= SIZE_BLOCK:
                block = f.read(SIZE_BLOCK)
                block_encrypted = encrypt_CBC(block, key, iv)
                encrypted_file.write(block_encrypted)
                iv = block_encrypted

            # deal with last chunk of message
            bytes_left = length - f.tell()
            if bytes_left > 0:
                remaining = f.read(bytes_left)
                remaining_encrypted = encrypt_CBC(remaining, key, iv)
                encrypted_file.write(remaining_encrypted)

    # decrypt CBC
    filename_decrypted = filename.split('.')[0] + '_decrypted.bmp'
    with open(filename_decrypted, 'wb') as decrypted_file:
        with open("mustang_encrypted_CBC.bmp", 'rb') as f:
            length = file_len(f)
            header = f.read(SIZE_HEADER)
            decrypted_file.write(header)

            while length - f.tell() > SIZE_BLOCK:
                block = f.read(SIZE_BLOCK)
                block_decrypted = decrypt_CBC(block, key, iv)
                decrypted_file.write(block_decrypted)
                iv = block

            # last block, deal with padding
            block = f.read(SIZE_BLOCK)
            block_decrypted_no_pad = decrypt_CBC(block, key, iv, isLast=True)
            decrypted_file.write(block_decrypted_no_pad)

def submit(key: bytearray, iv: bytearray) -> bytes:
    ciphertext: bytes = b''

    user_str = "test=test;test"
    # url encode the input string
    user_str = urllib.parse.quote(user_str)
    # add data
    user_str = f"userid=456;userdata={user_str};session-id=31337"
    # convert string into bytes
    encoded = user_str.encode()

    remaining_length = len(encoded)
    i = 0
    while remaining_length >= SIZE_BLOCK:
        block = encoded[i:i + SIZE_BLOCK]
        encrypted_block = encrypt_CBC(block, key, iv)
        ciphertext += encrypted_block
        iv = encrypted_block

        i += SIZE_BLOCK
        remaining_length -= SIZE_BLOCK
    # pad remaining plaintext
    block = encoded[i : i + remaining_length]
    ciphertext += encrypt_CBC(block, key, iv)

    return ciphertext

def verify(ciphertext: bytes, key: bytearray, iv: bytearray) -> bytes:
    plaintext: bytes = b''

    # decrypt ciphertext
    remaining_length = len(ciphertext)
    i = 0
    while remaining_length > SIZE_BLOCK:
        block = ciphertext[i:i + SIZE_BLOCK]
        decrypted_block = decrypt_CBC(block, key, iv)
        plaintext += decrypted_block
        iv = block
   
    # deal with last block of ciphertext
    block = ciphertext[i:i + remaining_length]
    plaintext += decrypt_CBC(block, key, iv, isLast=True)

    return plaintext

def task2():
    key = generate_key()
    iv = generate_IV()
    ciphertext = submit(key, iv)
    plaintext = verify(ciphertext, key, iv)
    # print(plaintext)

def main():
    # task1()
    task2()

if __name__ == '__main__':
    main()
