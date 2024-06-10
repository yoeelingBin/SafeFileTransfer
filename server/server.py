import socket
import ssl
import sys
import threading
import struct
import json
import pickle
import base64
from common.RSAencryption import RSACryptor
from common.AESencryption import AESCryptor

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 12345
UPLOAD_DIR = 'uploaded_files'
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

def init_key():
    '''
    Usage: 生成公私钥
    '''
    global SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY
    rsa = RSACryptor()
    rsa.gen_rsa_key_pairs()
    SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY = rsa.public_key, rsa.private_key


class Server:
    '''
    Description: 服务端类
    '''
    def listen(self) -> None:
        '''
        Usage: 开启监听
        '''
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            try:
                sock.bind((SERVER_ADDRESS, SERVER_PORT))
                sock.listen(5)
                print("Server Listening...")
                # 打包成ssl socket
                with context.wrap_socket(sock, server_side=True) as ssock:
                    while True:
                        # 接收客户端连接
                        connection, client_address = ssock.accept()
                        print('Connected by: ', client_address)
                        #开启多线程,这里arg后面一定要跟逗号，否则报错
                        thread = threading.Thread(target = self.handle_conn, args=(connection,))
                        thread.start()
            except socket.error as msg:
                print(msg)
                sys.exit(1)

    def handle_conn(self, conn):
        '''
        Usage: 处理连接

        Args:
            conn: SSL Socket连接
        '''
        # 收到请求后的处理
        while True:
            # 申请相同大小的空间存放发送过来的文件名与文件大小信息
            fileinfo_size = struct.calcsize('128sl')
            # 接收文件名与文件大小信息
            buf = conn.recv(fileinfo_size)
            # 判断是否接收到文件头信息
            if buf:
                header_json = str(struct.unpack('128s', buf)[0], encoding='utf-8').strip('\00')
                print(header_json)
                header = json.loads(header_json)
                command = header['command']

                if command == "UPLOAD":
                    self.handle_upload(conn, header)
                    break
                elif command == "DOWNLOAD":
                    self.handle_download(conn, header)

    def handle_upload(self, conn, header):
        '''
        Usage: 处理文件上传

        Args:
            conn: SSL Socket连接
            header: 文件头信息
        '''
        file_name, file_size = header["fileName"], header["fileSize"]
        print(f'Upload: file new name is {file_name}, filesize is {file_size}')
        # 定义接收了的文件大小
        recvd_size = 0
        # 存储在uploaded_files目录中
        fp = open("uploaded_files/" + str(file_name), "wb")
        print("Start receiving")  
        while not recvd_size == file_size:
            if file_size - recvd_size > 1024:
                # 由于经过加密，实际发送的文件长度和原本不一致
                recv_len = int(conn.recv(1024).decode("utf-8"))
                print("该段发送长度: ", recv_len)
                rdata = conn.recv(recv_len)
                decrypted_data = decrypt_file(rdata)
                recvd_size += len(decrypted_data)
            else:
                recv_len = int(conn.recv(1024).decode("utf-8"))
                print("该段发送长度: ", recv_len)
                rdata = conn.recv(recv_len)
                # print(rdata)
                decrypted_data = decrypt_file(rdata)
                recvd_size = file_size
            fp.write(decrypted_data)
        fp.close()
        print('receive done')
        conn.close()

    def handle_download(self, conn, header):
        '''
        Usage: 处理文件下载

        Args:
            conn: SSL Socket连接
            header: 文件头信息
        '''
        #TODO
    


def decrypt_file(data):
    '''
    Usage: 解密二进制数据
        
    Args: 
        data: 需要解密的数据
    Returns:
        解密后的数据(完整性通过),否则返回None
    '''
    rsa = RSACryptor()
    cipher_message, cipher_keyiv = pickle.loads(data)
    print(f"密文:{cipher_message}, 类型{type(cipher_message)}\n密钥:{cipher_keyiv}, 类型{type(cipher_keyiv)}")
    decrypted_keyiv = rsa.decrypt_message(cipher_keyiv, SERVER_PRIVATE_KEY)
    # print("接收到的密钥和初始向量:", decrypted_keyiv)
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
    if rsa.verify_signature(content, digest, CLIENT_PUBLIC_KEY):
        print("完整性验证通过!")
        return content
    else:
        print("文件签名不一致!")
        return None


if __name__ == "__main__":
    # init_key()
    server = Server()
    server.listen()
    



# Example usage:
# Start the server: python server/server.py
