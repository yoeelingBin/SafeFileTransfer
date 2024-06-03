from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP

class RSACryptor:
    def __init__(self, key_size=2048) -> None:
        self.key_size = key_size
        self.private_key = None
        self.public_key = None

    def gen_rsa_key_pairs(self):
        # 生成RSA密钥对
        key = RSA.generate(self.key_size)
        self.private_key = key.export_key("PEM")
        self.public_key = key.publickey().export_key()

    def save_keys(self, dir: str):
        '''
        保存公私钥
        dir: 保存的目录
        '''
        if self.private_key and self.public_key:
            with open(dir + "private.pem", "wb") as f:
                f.write(self.private_key)
            with open(dir + "public.pem", "wb") as f:
                f.write(self.public_key)
        else:
            raise ValueError("Keys have not been generated yet.")
        
    def load_keys(self, dir: str):
        '''
        加载密钥
        dir: 密钥保存的目录
        '''
        with open(dir + "private.pem", "rb") as f:
            self.private_key = RSA.import_key(f.read())
        with open(dir + "public.pem", "rb") as f:
            self.public_key = RSA.import_key(f.read())

    def encrypt_message(self, message, public_key_path: str=None) -> bytes:
        '''
        加密消息
        message: 消息或者文件 str or bytes
        public_key_path: 公钥路径
        '''
        if public_key_path:
            with open(public_key_path, "rb") as f:
                public_key = RSA.import_key(f.read())
        else:
            public_key = self.public_key
        
        if not public_key:
            raise ValueError("Public key is not available.")
        
        if isinstance(message,str):
            message = message.encode('utf-8')
        
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_message = cipher_rsa.encrypt(message)
        return encrypted_message
    
    def decrypt_message(self, encrypted_message, private_key_path: str=None) -> str:
        '''
        解密消息
        encrypted_message: 加密后的消息
        private_key_path: 私钥路径
        '''
        if private_key_path:
            with open(private_key_path, "rb") as f:
                private_key = RSA.import_key(f.read())
        else:
            private_key = self.private_key
        
        if not private_key:
            raise ValueError("Private key is not available.")
        
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher_rsa.decrypt(encrypted_message)
        return decrypted_message.decode()
    
    def sign_message(self, message, private_key_path: str=None) -> bytes:
        '''
        进行签名
        message: 需要签名的消息
        private_key_path: 私钥路径
        '''
        if private_key_path:
            with open(private_key_path, "rb") as f:
                private_key = RSA.import_key(f.read())
        else:
            private_key = self.private_key
        
        if not private_key:
            raise ValueError("Private key is not available.")
        
        if isinstance(message,str):
            message=message.encode()
        
        h = SHA256.new(message)
        signature = pkcs1_15.new(private_key).sign(h)
        return signature
    
    def verify_signature(self, message, signature: bytes, public_key_path: str=None) -> bool:
        '''
        验证签名
        message: 需要签名的消息
        signature: 消息签名
        public_key_path: 公钥路径
        '''
        if public_key_path:
            with open(public_key_path, "rb") as f:
                public_key = RSA.import_key(f.read())
        else:
            public_key = self.public_key
        
        if not public_key:
            raise ValueError("Public key is not available.")
        
        h = SHA256.new(message.encode())
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
# 示例使用
if __name__ == "__main__":
    rsa_encryption = RSACryptor()
    rsa_encryption.gen_rsa_key_pairs()
    rsa_encryption.save_keys("keys/client/client")

    message = "这是一个需要加密的消息。"
    print("原始消息:", message)
    
    # 加密消息
    encrypted_message = rsa_encryption.encrypt_message(message, public_key_path="keys/client/clientpublic.pem")
    print("加密后的消息:", encrypted_message)
    
    # 解密消息
    decrypted_message = rsa_encryption.decrypt_message(encrypted_message, private_key_path="keys/client/clientprivate.pem")
    print("解密后的消息:", decrypted_message)

    # 签名消息
    signature = rsa_encryption.sign_message(message, private_key_path="keys/client/clientprivate.pem")
    print("签名:", signature)
    
    # 验证签名
    is_valid = rsa_encryption.verify_signature(message, signature, public_key_path="keys/client/clientpublic.pem")
    print("签名验证结果:", is_valid)