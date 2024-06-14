import socket
import ssl
import os
import base64
import pickle
import struct
import time
import json
from common.AESencryption import AESCryptor
from common.RSAencryption import RSACryptor
from common.utils import sha256_hash

CLIENT_PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3KVnjnA2BXxf6leV3EjRSdAHTdEHwmjjiJgFFBJiB+V4RCAE
FDWiRA8tiU+LkAPZwH/XE8dWkO/cCc3f6LHrMC/BosVPLvxMWrkkQkH9eS/eTja9
RpF0RxJozVT7bRJDhKd/dkOKdiqGzuzoR0YIJ+agFImPdauS/tlLK5ja+/RU6yL4
iDs6u191h7vB4wAa2N2c/KSFOYjjbybskN77jyyFEA2miixqJJRAn6bRsa6PKRZ3
X1jkcxUZqigRvxtEGhhYmZroKSJ/9OzuKz6vY9ZtqOR7NNxdYiMbGD/TljRxF+y/
aSpavbPzMpRSLPz5yF4BCVm5r/4YZtII8wKmKwIDAQABAoIBAAf6PPvD59gb7pXY
89Sil1qNWG5CU/797tgV8v0OSxgQ/l+sLqmSZNsEF3fi9d9PnFRe6uZOqz0TRwfd
ty5BHIlB+MTLUHkY6yPOlNaGb0Ut62I1jXNbN/KH4l0mKO8BHYrSyYN7nqp2ECi0
HRPSnuHeb0Q+0v6EpQxsy9B4NtasJiNan2snCEQ7i6OAGNsuIvc79MmIWmdSiRm7
lC3ZpSNyom25Qo4DQbzbZ/oeozJ4N4CppRG0Lmhcvv6/2G43lWaGa7EuSoOUdOgR
Ba7RPlPnGpW147yHleSGet1qmASf818qIOypNHoay1BAZgWmdszQv2/VhLTnZ9dv
oSSviHUCgYEA6PoNAj2VuL/LmZQhU5NxiK99ELzALyFQQvsMaG4eafud5X2P6U/G
lDe9kZNjLBacpeesiPf39S5r3V4YL3nf6emcXcTUIwZbG1fGKxge9Ixh4HgC+1ve
B7NS702SXZmQ6VDCZi0obLKmJweaH7enT5GaLo8PVVsQ5R/B4SmSBI8CgYEA8nNo
UBjKoMynlyAXEfX+KP+8fL9Ba1wFzWxOKyw5hTIhPxuuYYbpBdQU/JBGvu3yGLKt
blbST2s28emMDlgHewWOzywTBmffmGqYt4gjjLFg8ZRxMql5q53PiOEL1zLunkq0
JL/2yXA0KRO51HVj4KK+0zmiOUlM18j747AV6qUCgYBT92sg15lSkK2MmHq6aHWO
0dC9a4nIcrU+rsR2DtofUHRD9dEcQYhMexpzkS85AJ1MngbtBpHzZ9uwWO1WjxJI
d83Hbd0XEn9bh3MArRza/o14HUjV1vJazCKj5M1Ptr0nmde2g6gCJREFGBRQQhym
7M8o4J6iIMQiECQMRrM9uQKBgFGjsthlwLVstHIbCCmwH6lGk/2dmTXBguKtOZUo
CyZivvc1Jv8IIqcnxvlUy722+fJ/GA8zhRXhEFtdPSAHXF18fZ4dRTq+93enTU1f
tjjF8dLnHUbl8mZreVqqDQaly9vZY9eMHFmwQqAiWEzGSp91rbQKkCmiGRIAR3Ff
9cFRAoGBAMIKBnWWMOHSxvxS3XvNCQ+NiYylFGdFS0/VHQiDqvt8zQ3bkHNQ5Hpk
XaY6GW2VVq/cDALzQOw2cb0uvyEFmFe78mYdsQAR4hGmA47QASXT6lqeYUuvnMGJ
V5eKqdttensnCsFam8W6wVklBsO2KiS2xpqY9OfI1efUYz14nYIh
-----END RSA PRIVATE KEY-----
'''
SERVER_PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAv8TQORU+5RHbuXv40mtFCYCmG3ML2a4VkhtLEDRArO0M+Dpb
Blikbw5hPVHwcfSyqayFRFA+VUzSa8jwTwULz2MgCSav57nouwpGqJA8hznezTpl
XMU1Gbjic8N1MDwIaRAtnQrgS+bRrrp/1ry+ygNcJRlt8e0hfJR1arHVqSKW897G
cnGYXwVKZ7AwUHW54PzPegfc8lMGVWPHctdriYcMCynUK8LDGraayg06vy6OwsLI
15m2W+q2eUbrdcHFYV3hmeWNhhvcgMPdYnfWaG//ImhD/rO4zLNZjtrKzsYWeGpv
rmwgg5czU7X3rl2fm9Shhm9iB8c3QmF+tuXMOQIDAQABAoIBAAZbwz+xSaWUwwFS
b/yiG+blwhw041azY/m1N/bwlJhnP7/XR39dXw5jnqvG1L8iiu3/T2fldTuk0XFL
d1RXaX3V3pEPHFQFoQban18lcSxWqeGKJyQ9UbZpn/CQsYkI5Ip/Q9PqMWey3o75
lhWLqpPOKrb8Md4Mq8iSr5X7EYeLFEfcLrxlJvJuAnqjMb8zK9h+/LGa8uUDSlxC
cvSTm26g9IxSMpKC/CKXW8Dhi+y6J/F677G9yu6n//OqK3UXIyPYS9uALNrXSmKq
GzbAcOxkIetFI/fm7L2vFk+vtdoLKgEw1OQ9+UhP3MqdOCkoFNAzcUNQNswxGyB2
UVi3k6UCgYEAxm1dFOUvekxW2Ld5Km/oKNgmnzfIhcHzWsu4q0hxPPmYjM5m/Wcw
v432QGzAaC7Y/VuvfH8dRFSvh6264O27jLia2hRv8uXxGL93nfthN03frI077Z4T
DNY20jhekPfnRaHX/f3/L1sEFBDSJPEotqMk9gbnSvyB88GAFjIzXZ8CgYEA92jh
wYF9kiohb9hPAsSGI6Dyyzns0KexYsjWM/XKM3uBREzQKfnBLeSyaS4kFVRcFhlV
1wud8Rd/NH1OpeQy9jd+2k5wQrzlOvvKjcNBitw8Z9vaFAuzF5GpaiXT0BNOBbFd
EROjEpUtjuN2hcPkr3J4mSYO2dpkF5yDazlO1ycCgYAyR/5BUD4ysGuFaSC0Bz1+
NB+9UuZmNpqTFHKMPMQtHlZwv9DLP73TnIadFrG+9LgZo4UZeCCTcx4ztGtZmgRf
iVv8DRe9JlVs3v/RsaSV3g7i67sW4GqVYybrKEuWUqtxMqzH+PgUKO0kpIqLv+yA
M2EnUuKDVu8bNJpfhYMMowKBgFf8kcTqk0jG+Os4xyiZ0YacN5x0tjaiXKBgAmWq
NMXIV3l9w84Zx0zV92kWgrifLryhN/jpZbsW+yMkqTKwDDuqEs/6c0wYt4EZiLiP
xyBmIIljE5RrcL6iC9j3KPPn2aiGoi1viWATc4dMd5ssxohqsl7svP1XAJ+xBr+8
OsCjAoGAC70z9Js1wiBlAQX5pq59rlsU+76KUSf8QtPxC3KTtsbRXwJjVyzvRMHg
Z9uOhaAKGAVskyes+6yCrajr6OYDYniJnoUKX5AauxT1J0pgasAN4mZ3MrDkEy4r
msT6Tt/GSW50sLrjf1v3M26FJS9dq7v0Tbl34Ka03CzaGD6L4Ho=
-----END RSA PRIVATE KEY-----
'''
CLIENT_PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3KVnjnA2BXxf6leV3EjR
SdAHTdEHwmjjiJgFFBJiB+V4RCAEFDWiRA8tiU+LkAPZwH/XE8dWkO/cCc3f6LHr
MC/BosVPLvxMWrkkQkH9eS/eTja9RpF0RxJozVT7bRJDhKd/dkOKdiqGzuzoR0YI
J+agFImPdauS/tlLK5ja+/RU6yL4iDs6u191h7vB4wAa2N2c/KSFOYjjbybskN77
jyyFEA2miixqJJRAn6bRsa6PKRZ3X1jkcxUZqigRvxtEGhhYmZroKSJ/9OzuKz6v
Y9ZtqOR7NNxdYiMbGD/TljRxF+y/aSpavbPzMpRSLPz5yF4BCVm5r/4YZtII8wKm
KwIDAQAB
-----END PUBLIC KEY-----
'''

class Client:
    '''
    客户端类

    Attributes: None
    '''
    SERVER_ADDRESS = '127.0.0.1'
    SERVER_PORT = 12345
    
    def __init__(self) -> None:
        self.ssock = self._initialize_ssl_connection()
        self.rsa_cipher = RSACryptor()
        self.aes_key = AESCryptor.gen_key()
        self.aes_iv = AESCryptor.gen_iv()
        self.aes_cipher = AESCryptor(self.aes_key, iv=self.aes_iv)
        self.server_public_key = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8TQORU+5RHbuXv40mtF
CYCmG3ML2a4VkhtLEDRArO0M+DpbBlikbw5hPVHwcfSyqayFRFA+VUzSa8jwTwUL
z2MgCSav57nouwpGqJA8hznezTplXMU1Gbjic8N1MDwIaRAtnQrgS+bRrrp/1ry+
ygNcJRlt8e0hfJR1arHVqSKW897GcnGYXwVKZ7AwUHW54PzPegfc8lMGVWPHctdr
iYcMCynUK8LDGraayg06vy6OwsLI15m2W+q2eUbrdcHFYV3hmeWNhhvcgMPdYnfW
aG//ImhD/rO4zLNZjtrKzsYWeGpvrmwgg5czU7X3rl2fm9Shhm9iB8c3QmF+tuXM
OQIDAQAB
-----END PUBLIC KEY-----
'''

    def _initialize_ssl_connection(self):
        context = ssl.create_default_context()
        context.load_verify_locations("certs/server.crt")
        sock = socket.create_connection((self.SERVER_ADDRESS, self.SERVER_PORT))
        return context.wrap_socket(sock, server_hostname=self.SERVER_ADDRESS)
    
    def connect(self):
        '''
        Usage: 与服务端进行连接
        '''
        print("开始交换公钥")
        self.exchange_pubkey("keys/client/clientpublic.pem")
        self.verify_key(self.ssock)

    def exchange_pubkey(self, key_dir: str):
        '''
        Usage: 向服务端发送客户端公钥

        Args:
            key_dir: 存放公钥的目录
        '''
        with open(key_dir, 'rb') as fi:
            public_key = fi.read()
        key_hash = sha256_hash(public_key)
        hash_message = pickle.dumps([public_key, key_hash])
        for _ in range(3):  # 尝试三次
            try:
                self.ssock.send(hash_message)
                print("公钥发送成功")
                return
            except ConnectionRefusedError:
                print("公钥发送失败，尝试重新发送")
        print("公钥发送失败")
    
    def verify_key(self, sock):
        '''
        Usage: 对服务端公钥完整性进行验证

        Args:
            sock: SSLSocket
        '''
        while True:
            message = sock.recv(4096)
            (public_key, key_hash) = pickle.loads(message)
            if key_hash == sha256_hash(public_key):
                print("公钥完整性验证完成，可以开始传输文件\n")
                self.server_public_key = public_key
                print("收到公钥\n" +  self.server_public_key.decode('utf-8') + "\n")
                break
    
    def upload_file(self, file_path: str):
        '''
        客户端上传文件
        
        Args: 
            file_path: 文件路径
        '''
        try:
            if os.path.isfile(file_path):
                self._send_file_header(file_path)
                self._send_file_content(file_path)
            else:
                print(f"文件 {file_path} 不存在")
        except Exception as e:
            print(f"上传文件时发生错误: {e}")
            

    def _send_file_header(self, file_path: str):
        header = {
            'command': 'UPLOAD',
            'fileName': os.path.basename(file_path),
            'fileSize': os.stat(file_path).st_size,
            'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        }
        header_bytes = bytes(json.dumps(header).encode("utf-8"))
        fhead = struct.pack('128s', header_bytes)
        self.ssock.send(fhead)

    def _send_file_content(self, file_path: str):
        with open(file_path, 'rb') as fp:
            while True:
                data = fp.read(1024)
                if not data:
                    print(f'{os.path.basename(file_path)}文件发送完毕...')
                    break
                print("发送的内容:", data)
                tosend = self.encrypt_file(data)
                print("加密后的消息", tosend)
                self.ssock.send(str(len(tosend)).encode('utf-8'))
                self.ssock.send(tosend)

    def encrypt_file(self, data) -> bytes:
        '''
        加密二进制数据
        
        Args: 
            data: 需要加密数据
        Returns:
            加密后的数据
        '''
        print("aes加密密钥:", self.aes_key, "aes初始向量:", self.aes_iv)
        
        digest = self.rsa_cipher.sign_message(data, CLIENT_PRIVATE_KEY)
        print("消息摘要:", digest)
        
        concated_message = {"Message": base64.b64encode(data), "Digest": digest}
        dumpped_message = pickle.dumps(concated_message)
        
        cipher_message = self.aes_cipher.encrypt_message(dumpped_message)
        
        keyiv = {"Key": self.aes_key, "IV": self.aes_iv}
        print("密钥和初始向量", keyiv)
        dumpped_keyiv = pickle.dumps(keyiv)
        print("序列化后的密钥和初始向量", dumpped_keyiv)
        
        cipher_keyiv = self.rsa_cipher.encrypt_message(dumpped_keyiv, self.server_public_key)
        print("加密后的密钥和初始向量", cipher_keyiv)
        
        send_message = pickle.dumps([cipher_message, cipher_keyiv])
        print("序列化前的发送消息", [cipher_message, cipher_keyiv])
        return send_message

    def decrypt_file(self, data) -> bytes:
        '''
        解密二进制数据
        
        Args: 
            data: 需要解密的数据
        Returns:
            解密后的数据(完整性通过),否则返回None
        '''
        cipher_message, cipher_keyiv = pickle.loads(data)
        print(f"密文:{cipher_message}, 类型{type(cipher_message)}\n密钥:{cipher_keyiv}, 类型{type(cipher_keyiv)}")
        decrypted_keyiv = self.rsa_cipher.decrypt_message(cipher_keyiv, SERVER_PRIVATE_KEY)
        keyiv = pickle.loads(decrypted_keyiv)
        key, iv = keyiv["Key"], keyiv["IV"]
        print(f"解密后的密钥{key}和初始向量{iv}:")
        
        aes = AESCryptor(key, iv)
        decrypted_message = aes.decrypt_message(cipher_message)
        plain_message = pickle.loads(decrypted_message)
        content = base64.b64decode(plain_message['Message'])
        print("解密的内容是", content)
        digest = plain_message['Digest']
        print("解密的消息摘要", digest, type(digest))
        
        if self.rsa_cipher.verify_signature(content, digest, CLIENT_PUBLIC_KEY):
            return content
        else:
            print("文件签名不一致!")
            return None
    
    def download_file(self, file_path: str):
        '''
        Usage: 客户端下载文件
        
        Args: 
            file_path: 文件路径
        '''
        # TODO: 


if __name__ == "__main__":
    mes = b"kskskkqqqhfhfh1234"
    file1_path = "test_files/1.txt"
    file2_path = "test_files/2.md"
    file3_path = "test_files/3.jpg"
    client = Client()
    client.upload_file(file2_path)
    # fp = open(file_path, 'rb')
    # data = fp.read(1024)
    # enc_data = encrypt_file(data)
    # dec_data = decrypt_file(enc_data)
    # print(dec_data)
    # fp.close()
