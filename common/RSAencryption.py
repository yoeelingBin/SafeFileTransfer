from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
import base64

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

    def encrypt_message(self, message: bytes | str, public_key) -> bytes:
        '''
        加密消息
        message: 消息或者文件 str or bytes
        public_key: 公钥
        '''
        self.rsa_key = RSA.import_key(public_key)
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
        encrypted_message = base64.b64encode(cipher_rsa.encrypt(message))
        return encrypted_message
    
    def decrypt_message(self, encrypted_message: bytes | str, private_key) -> bytes:
        '''
        解密消息
        encrypted_message: 加密后的消息
        private_key: 私钥
        '''
        self.rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
        decrypted_message = cipher_rsa.decrypt(base64.b64decode(encrypted_message))
        return decrypted_message
    
    def sign_message(self, message: bytes | str, private_key) -> bytes:
        '''
        进行签名
        message: 需要签名的消息
        private_key: 私钥
        '''
        self.rsa_key = RSA.import_key(private_key)
        
        if isinstance(message,str):
            message = message.encode()
        
        # h = SHA256.new(message)
        # signature = pkcs1_15.new(self.rsa_key).sign(h)
        digest = SHA256.new()
        digest.update(message)
        signer = pkcs1_15.new(self.rsa_key)
        signature = signer.sign(digest)
        signature = base64.b64encode(signature)
        return signature
    
    def verify_signature(self, message: bytes | str, signature: bytes, public_key) -> bool:
        '''
        验证签名
        message: 需要签名的消息
        signature: 消息签名
        public_key: 公钥
        '''
        self.rsa_key = RSA.import_key(public_key)

        if isinstance(message, str):
            message = message.encode()
        
        verifier = pkcs1_15.new(self.rsa_key)
        digest = SHA256.new()
        digest.update(message)

        try:
            verifier.verify(digest, base64.b64decode(signature))
            return True
        except (ValueError, TypeError):
            return False
# 示例使用
if __name__ == "__main__":
    rsa_encryption = RSACryptor()
    rsa_encryption.gen_rsa_key_pairs()
    rsa_encryption.save_keys("keys/client/client")

    message = "这是一个需要加密的消息。"
    bmessage = b"0xdeadbeaf"
    print("原始消息:", bmessage)

    pubkey = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1FqviXNLDxLrUPPjwqbW
MyFlG2Wnrmmd8GbFg/CVdGXqpiyO5lGMkraMbowL8sM3E/dUu0CvWowsQAZB5syd
6l8uLqdCaOMtj5h18YPk7HSURYc3PBd9Ame+IdfwWD39Fs2QuNmBcCX/VYNLod/9
F7MMx2G1nxnVToSESMQGNfRGdb6M8d/w+/v9dQzUcOVZTcMPcw2dN2AeezLooYMg
yRXooFtRnNRFbmPuD3G16SsC37crhhXdGJaRCnU/zFzMxVdDhQRy0WznpnsZuhOJ
s70I4IywJ4tIPhYlAZTf5hILUNlvFLbl1o31LgQhvVyFQcUKjKIzCrMFecd4iQmx
tQIDAQAB
-----END PUBLIC KEY-----
    '''

    prikey = '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1FqviXNLDxLrUPPjwqbWMyFlG2Wnrmmd8GbFg/CVdGXqpiyO
5lGMkraMbowL8sM3E/dUu0CvWowsQAZB5syd6l8uLqdCaOMtj5h18YPk7HSURYc3
PBd9Ame+IdfwWD39Fs2QuNmBcCX/VYNLod/9F7MMx2G1nxnVToSESMQGNfRGdb6M
8d/w+/v9dQzUcOVZTcMPcw2dN2AeezLooYMgyRXooFtRnNRFbmPuD3G16SsC37cr
hhXdGJaRCnU/zFzMxVdDhQRy0WznpnsZuhOJs70I4IywJ4tIPhYlAZTf5hILUNlv
FLbl1o31LgQhvVyFQcUKjKIzCrMFecd4iQmxtQIDAQABAoIBAAO90BEuIsZXcnSQ
6fbJoZQPC+CdKL+1Z0s2z2pk2tcb8dFxtnWboIdGwwj3SBn+9cGMEh7N3uGuOhwi
DtxE2x7PK+NddzcTktgpE5fVErG4w82OHOBVA8QmY+/le95dOdobFAXsg3JRtWBd
VLEeI+ENtbU8rvHUwnWYO/hvoArZmDNp6iF3Gt6fcoCFiI8itht99xRVHj+e52gQ
bPQjgtHOnG4SxiePPKnr93MBH73m1M48lS+Tm0cup2S3OyFtAjoEj2DPw6grl6oY
w0dbFEJryFouOMaJ7ySEK9z/2SnAn6CF840S0NvxVa0sHbDLCndNT04x37TZkx/y
GcowOjUCgYEA49/UuypdYC+CcT65ReLhkmX2EZxyr1eieqgaX+bS5hPS7OahmDzs
yIN8BGoWVdg5uX4iwGNHj3TWSZLqFNU0Vj5w1lswDvSuTUplck/1MpwgW8qxWqnh
gdtqfy3MrV7YLVEyJnphVmgYtmOFIl0fhSH3GuI7xrajLoQZMZllu3cCgYEA7pB2
7JtJmURLl9mcs4iIFJfebj6XfeuPQ34il5PjtUHHGbm7Phn2r1Qgc0MrHfnCHIw7
O+Cuh40eRgDuEJuL3Qz53Zq2sn8YlU/3eFpVESlfhNze9YvMFx9OH7Wo/ID/VqQu
4b5kAMaaIfE87RAXk84y5gmbmlVhhIYdFeAZrzMCgYEAs9CVqpf0lQkIctpfEvHE
tGR291CwAwMxOH7cSR74/wtXnw8jJuG0q0luHIGmXFlCu8f4Hj55Yo985RPkWUog
gYnGOrA8TSDxRhZV1Q2ZXDVtJ2Hb78IsK+97qx317Dzyc1gmLczWcHu2PH5tuT8o
t0KlHna1WsoWHIeq5cO5TmMCgYAE+PHhoKL6FNhWg+ymOVRMyZWTSq6xqzVDPN/P
tP9sCcDyolJqyvO/V8uNW3sMluYa3jll2BsLLD/TSbWslvFlXB3hJpZkRg3nHtGT
qp5XSzt4c3oaOB265aYlNw4cpTutPKLVhbhj47/WsUaJ0moLZKLe9JhPsTPlJT55
9D/UzQKBgQDLiUBG/EOjsLQB/75FWjNa+9KeEapzBzxKVg3+iIrF3WOMIlJwDgXQ
Hn8P0R2Z3CKSsrwMROYrZL1eM7i4YDq8KdTH3PypWs88qB0I1qnynFSg3Adg7dwz
s6XcJwnfPYYUYlhWXbrWPqXKvzYKVL7nt0NveACwX+fCKiHeBYbhcA==
-----END RSA PRIVATE KEY-----
'''
    
    # 加密消息
    encrypted_message = rsa_encryption.encrypt_message(bmessage, public_key=pubkey)
    print("加密后的消息:", encrypted_message)
    
    # 解密消息
    decrypted_message = rsa_encryption.decrypt_message(encrypted_message, private_key=prikey)
    print("解密后的消息:", decrypted_message)

    # 签名消息
    signature = rsa_encryption.sign_message(bmessage, private_key=prikey)
    print("签名:", signature)
    
    # 验证签名
    is_valid = rsa_encryption.verify_signature(bmessage, signature, public_key=pubkey)
    print("签名验证结果:", is_valid)