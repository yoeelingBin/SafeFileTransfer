import socket
import ssl
import os
import base64
import pickle
import struct
import time
import json
from common.AESencryption import AESCryptor
from common.utils import sha256_hash
from common.RSAencryption import RSACryptor

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 12345
SERVER_PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8TQORU+5RHbuXv40mtF
CYCmG3ML2a4VkhtLEDRArO0M+DpbBlikbw5hPVHwcfSyqayFRFA+VUzSa8jwTwUL
z2MgCSav57nouwpGqJA8hznezTplXMU1Gbjic8N1MDwIaRAtnQrgS+bRrrp/1ry+
ygNcJRlt8e0hfJR1arHVqSKW897GcnGYXwVKZ7AwUHW54PzPegfc8lMGVWPHctdr
iYcMCynUK8LDGraayg06vy6OwsLI15m2W+q2eUbrdcHFYV3hmeWNhhvcgMPdYnfW
aG//ImhD/rO4zLNZjtrKzsYWeGpvrmwgg5czU7X3rl2fm9Shhm9iB8c3QmF+tuXM
OQIDAQAB
-----END PUBLIC KEY-----
'''
CLIENT_PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAhm9dbOXVREZQnIW4k6kPkNeUkVm/13VX1npIch/z5YXb04OK
nTTjQYZznbsJZLk3kUqz5UV/i5zGxmlI45K+thK6qN59SpN7EXxRQ3YULNQGIxX6
3xY3TVfUKVRzyEtODL0foP1fF8U7X2pDTuGaNyckJnOLSlj3KEiRnKyARBr6qlfS
OPpA88jT0leQmHKtaa785/oD1Oe8oAHSCgZGK1tGT+AhERnoagpEkbSGx06UVnnX
++tipzBcLiPRzOXzQSNdzvylPXuYs8TBnZ8SaHDId64f8rxW71lEaeD64p7iDQOj
EV6excQcjcTu2fZZ+fuTV6TsrjzzsBy+5ztxEQIDAQABAoIBABJ2mL1cOB+h4UVg
pNp8JXFOTQ8aD/EpTRCIXTXLXKXBGNFiZ2Gy7KPzBs2lbU4CQCGkwbNIib1ky/Sz
wLknTikBxoAV2ohTsVspQ0dBdYDjTRp5f38vH8DwFz6ROjuf2A7Y1KS5gltokQBy
6YlGY8s/sBqAfk4ON5e2lm+5o1N3BtDFob1GEBZn4ekxoiol/FCfD1V7n7cazLIy
SqROelB2zC4OQZVyysH/OYCu7bHl5xZLkycpvMMuzTAZV2t6+PtjzksYurYjrEHH
gvRTCmUxTZ2vJ4uN2OUpsA/8JGWT+omLYzwP+gwOLItFZM8lbkRn+hk0ytd1EZTd
gFFcNt8CgYEAt6gSUXCwkujwKso8Zom1nSucI8HsYTmvot76c6NPkeXpgz628DtA
dbuhx+qGyPf9hExqCcggsYMf9Z9Itp5cWeHT9SHY8EZ4H3UoBbJqBO1K7wH2VXfW
wb4f7cFdj/Alb/j4eCX06Xh+f8Xh4Y+zK91q2gdiwsDf26vCo2S7SXcCgYEAu2PL
k9J2HVmsdRqunYrSNgKZwi0JdA4HYXXu6wsOehcoKinNhNKsFQh73rpOyOlsZ7cM
ucsU5N6LtEwMyyH0fnX17P2LOLmunZ0QiahDzFjvqeyonFdtnd3jGezi6h0cug3r
2ZsZ+STlsIkDaWNl7dLReLZTMvW5LYVY80rQu7cCgYAlz9e9prrj9EuGM88NuWqH
6nOiNQnq1oqfuNLNviDiw/g4yk+11C0oUDI1y8ZmWBB9DZKDYw3AHmQVGO9Kkf4n
j0QpYwecKJYQu/k6ewoy63wTC09hN2QizXcbZ0VRHjtG+3aEniP3cZRx0Bb6brCP
5m1aaEzgFf/A5XMUWufobwKBgQC7Na4y1nZOSEJ1E90TY5czglGenmPtX/6brbit
dXRXIT9tMCo04kwtDzbBg5wmOJ2m2EeMbolHRdaIn9nALwIWPT8eLweh+k+rAzl8
bXCefNOjDd49o1LN/tleEz136vHCJxpTYhMGx4f5YEjaRwWUHaRMVsq0BK2l/qyp
EzuJ7QKBgEhVwgSqUA213Ei8hUb9XEo6JKK/l5qyv+2RcY3HpTLdS2eZd0VwtQmt
OdWeNtIDT9gar0AUhg7eEx6hu/ZHjpNYYHgQ/CmSgEegpAc9Jnkp2/oHtZ0ETxlD
g1U5DpBKWxwGNHgxnctv9Y9oGJHOJG7HQLPbThIkLoA2Z+JfDNGH
-----END RSA PRIVATE KEY-----
'''

class client:
    def __init__(self) -> None:
        context = ssl.create_default_context()
        # 信任自签名证书
        context.load_verify_locations("certs/server.crt") 
        # 连接服务端
        self.sock = socket.create_connection((SERVER_ADDRESS, SERVER_PORT))
        # 将socket打包成SSL socket
        self.ssock = context.wrap_socket(self.sock, server_hostname=SERVER_ADDRESS)
    
    def upload_file(self, filepath: str):
        if os.path.isfile(filepath):
            # 定义打包规则
            fileinfo_size = struct.calcsize('128sl')
            # 定义文件头信息，包含文件名和文件大小
            header = {
                'command': 'UPLOAD',
                'fileName': os.path.basename(filepath),
                'fileSize': os.stat(filepath).st_size,
                'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            }
            header_bytes = bytes(json.dumps(header).encode("utf-8"))
            fhead = struct.pack('128s', header_bytes)
            # 发送文件名称与文件大小
            print(fhead)
            self.ssock.send(fhead)
            # 将传输文件以二进制的形式分多次上传至服务器
            fp = open(filepath, 'rb')
            while True:
                data = fp.read(1024)
                if not data:
                    print('{}文件发送完毕...'.format(os.path.basename(filepath)))
                    break
                print("发送的内容:", data)
                tosend = encrypt_file(data)
                print("加密后的消息:", tosend)
                self.ssock.send(str(len(tosend)).encode('utf-8'))
                self.ssock.send(tosend)

            # fp.close()
            self.ssock.close()


def encrypt_file(data) -> bytes:
    # RSA初始化
    rsa_cipher = RSACryptor()
    # AES初始化
    aes_key = AESCryptor.gen_key()
    aes_iv = AESCryptor.gen_iv()
    aes_cipher = AESCryptor(aes_key, iv=aes_iv)
    print("aes加密密钥:", aes_key, "aes初始向量:", aes_iv)
    # 消息摘要
    digest = rsa_cipher.sign_message(data, CLIENT_PRIVATE_KEY)
    # 将摘要和消息打包
    concated_message = {"Message": base64.b64encode(data), "Digest": digest.decode("utf-8")}
    dumpped_message = pickle.dumps(concated_message)
    # 对称加密消息
    cipher_message = aes_cipher.encrypt_message(dumpped_message)
    # 密钥和初始向量
    keyiv = {"Key": aes_key, "IV": aes_iv}
    print("密钥和初始向量", keyiv)
    dumpped_keyiv = pickle.dumps(keyiv)
    print("序列化后的密钥和初始向量", dumpped_keyiv)
    # 非对称加密密钥
    cipher_keyiv = rsa_cipher.encrypt_message(dumpped_keyiv, SERVER_PUBLIC_KEY)
    print("加密后的密钥和初始向量", cipher_keyiv)
    # 发送消息
    print("序列化前的发送消息", [cipher_message, cipher_keyiv])
    send_message = pickle.dumps([cipher_message, cipher_keyiv])
    print("发送的消息:", send_message)
    return send_message



# def upload_file(file_path):
#     nonce, ciphertext, tag = encrypt_file(file_path)
#     file_hash = sha256_hash(file_path)
#     filename = file_path.split('\\')[-1]
#     filename_bytes = filename.encode()
    
#     context = ssl.create_default_context()
#     context.load_verify_locations("certs/server.crt") # 信任自签名证书
#     with socket.create_connection((SERVER_ADDRESS, SERVER_PORT)) as sock:
#         with context.wrap_socket(sock, server_hostname=SERVER_ADDRESS) as ssock:
#             header = b'UPLOAD' + f'{len(filename_bytes):016d}'.encode()
#             ssock.sendall(header)
#             ssock.sendall(filename_bytes)
#             data = nonce + ciphertext + tag + file_hash.encode()
#             ssock.sendall(f'{len(data):016d}'.encode())  # 发送数据长度
#             ssock.sendall(data)
#             response = ssock.recv(4096)
#             print(response.decode())

#     print("File send success")

def download_file(file_name, save_path):
    context = ssl.create_default_context()
    context.load_verify_locations("certs/server.crt")
    with socket.create_connection((SERVER_ADDRESS, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_ADDRESS) as ssock:
            header = b'DOWNLOAD' + f'{len(file_name):016d}'.encode()
            ssock.sendall(header)
            ssock.sendall(file_name.encode())

            response = ssock.recv(4096)
            if response.startswith(b'File not found'):
                print("File not found on server")
                return
            
            data_length = int(response[:16].decode())
            data = response[16:]
            while len(data) < data_length:
                data += ssock.recv(4096)
                
            nonce, ciphertext, tag, file_hash = data[:16], data[16:-48], data[-48:-32], data[-32:].decode()
            decrypted_data = decrypt_file(nonce, ciphertext, tag)

            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            
            if sha256_hash(save_path) != file_hash:
                print("File integrity check failed")
            else:
                print("File downloaded successfully")

# Example usage:
# upload_file('path_to_your_file')
# download_file('file_name_on_server', 'path_to_save_file')
if __name__ == "__main__":
    mes = b"kskskkqqqhfhfh1234"
    file_path = "1.txt"
    # client = client()
    # client.upload_file(file_path)
    fp = open(file_path, 'rb')
    data = fp.read(1024)
    encrypt_file(data)
    fp.close()