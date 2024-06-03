from Crypto.Cipher import AES
import os
import string
import random

# 使用AES的CBC模式进行加密
class AEScryptor:
    def __init__(self, key: bytes, iv: bytes=None, charset: str="utf-8") -> None:
        '''
        构建一个AES对象
        key: 秘钥，字节型数据
        iv: iv偏移量; 字节型数据
        characterSet: 字符集编码
        '''
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key length must be 16, 24, or 32 bytes.")
        
        self.key = key
        self.iv = iv
        self.charset = charset
        self.data = ""
    
    def __pkcs7_padding(self, data: bytes) -> bytes:
        '''
        对数据进行PKCS#7填充,为16bytes的倍数
        '''
        pad_len = 16 - (len(data) % 16)
        padding = bytes([pad_len] * pad_len)
        return data + padding
    
    def __pkcs7_unpadding(self, data: bytes) -> bytes:
        '''
        移除PKCS#7填充
        '''
        pad_len = data[-1]
        return data[:-pad_len]
    
    def encrypt_from_file(self, file_path: str) -> bytes:
        '''
        从文件加密
        file_path: 需要加密的文件路径, str
        '''
        with open(file_path, 'rb') as f:
            self.data = f.read()
        return self.__encrypt()
    
    def decrypt_from_file(self, ciphertext: bytes, file_path: str) -> bytes:
        '''
        从文件解密
        ciphertext: 密文, bytes
        file_path: 需要解密的文件路径, str
        '''
        self.data = ciphertext
        de_data = self.__decrypt()
        with open(file_path, 'wb') as file:
            file.write(de_data)
        
        return de_data
    
    def __encrypt(self) -> bytes:
        '''
        使用CBC进行加密
        '''
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        data = self.__pkcs7_padding(self.data)
        en_data = aes.encrypt(data)
        return en_data
    
    def __decrypt(self) -> bytes:
        '''
        使用CBC进行解密
        '''
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        de_data = aes.decrypt(self.data)
        de_data = self.__pkcs7_unpadding(de_data)
        return de_data

def genKey() -> bytes:
    source = string.ascii_letters + string.digits
    key = "".join(random.sample(source, 16))
    return key.encode()

# AES_KEY = b'your_32_byte_aes_key_here__12345'

# def encrypt_file(file_path):
#     with open(file_path, 'rb') as f:
#         data = f.read()
#     cipher = AES.new(AES_KEY, AES.MODE_EAX)
#     ciphertext, tag = cipher.encrypt_and_digest(data)
#     return cipher.nonce, ciphertext, tag

# def decrypt_file(nonce, ciphertext, tag):
#     cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=nonce)
#     data = cipher.decrypt_and_verify(ciphertext, tag)
#     return data


if __name__ == "__main__":
    key = genKey()
    iv =  b"0000100000010000"
    enc_file_path = '1.txt' #需要加密的文件
    dec_file_path = '1d.txt'
    aes = AEScryptor(key, iv)

    en_text = aes.encrypt_from_file(enc_file_path) #加密明文
    print("密文：",en_text) #加密明文，bytes类型
    de_text = aes.decrypt_from_file(en_text, dec_file_path) # 解密密文
    print("明文：",de_text)