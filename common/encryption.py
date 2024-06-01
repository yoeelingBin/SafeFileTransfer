from Crypto.Cipher import AES
import os

AES_KEY = b'your_32_byte_aes_key_here__12345'

def encrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag

def decrypt_file(nonce, ciphertext, tag):
    cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data