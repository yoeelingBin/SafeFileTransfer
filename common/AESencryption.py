from Crypto.Cipher import AES
import os
import string
import random
import base64

# 使用AES的CBC模式进行加密
class AESCryptor:
    def __init__(self, key: bytes, iv: bytes = None, charset: str = "utf-8") -> None:
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

    @staticmethod
    def gen_key(length: int = 16) -> bytes:
        '''
        生成一个AES密钥
        length: 密钥长度, 必须是16, 24, 或 32
        '''
        if length not in [16, 24, 32]:
            raise ValueError("Key length must be 16, 24, or 32 bytes.")
        
        source = string.ascii_letters + string.digits
        key = "".join(random.sample(source, length))
        return key.encode()
    
    @staticmethod
    def gen_iv() -> bytes:
        '''
        生成一个随机的IV(初始化向量)
        '''
        return random.getrandbits(128).to_bytes(16, byteorder='big')
    
    def __pkcs7_padding(self, data: str) -> bytes:
        '''
        对数据进行PKCS#7填充,为16bytes的倍数
        '''
        data_bytes = data.encode("utf-8")
        pad_len = 16 - (len(data_bytes) % 16)
        padding = bytes([pad_len] * pad_len)
        return data_bytes + padding
    
    def __pkcs7_unpadding(self, data: str) -> bytes:
        '''
        移除PKCS#7填充
        '''
        return data.rstrip(bytes([data[-1]]))
    
    def encrypt_message(self, data) -> bytes:
        '''
        加密消息
        data: 需要加密的数据
        '''
        if isinstance(data, bytes):
            self.data = base64.b64encode(data).decode('ascii')
        else:
            self.data = base64.b64encode(data.encode('utf-8')).decode('ascii')
        return self.__encrypt()
    
    def decrypt_message(self, ciphertext) -> bytes:
        '''
        解密消息
        ciphertext: 密文
        '''
        if isinstance(ciphertext, str):
            self.data = base64.decodebytes(ciphertext.encode(encoding='utf-8'))
        else:
            self.data = base64.decodebytes(ciphertext)
            
        return self.__decrypt()
    
    def __encrypt(self) -> str:
        '''
        使用CBC进行加密
        '''
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        data = self.__pkcs7_padding(self.data)
        en_data = aes.encrypt(data)
        encrypted_text = base64.b64encode(en_data).decode("utf-8")
        return encrypted_text
    
    def __decrypt(self) -> bytes:
        '''
        使用CBC进行解密
        '''
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        de_data = aes.decrypt(self.data)
        de_data = self.__pkcs7_unpadding(de_data)
        decrypted_text = base64.b64decode(de_data)
        return decrypted_text

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
    key = AESCryptor.gen_key(16)
    iv =  AESCryptor.gen_iv()
    aes = AESCryptor(key, iv)
    data = "哈哈哈哈"
    bdata = b"0xdeadbeaf"

    print("原始：", bdata)
    en_text = aes.encrypt_message(bdata) #加密明文
    print("密文：", en_text) #加密明文，bytes类型
    de_text = aes.decrypt_message(en_text) # 解密密文
    print("明文：", de_text)