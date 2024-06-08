import socket
import ssl
import sys
import os
import threading
import struct
import json
import pickle
import base64
from common.utils import sha256_hash
from common.RSAencryption import RSACryptor
from common.AESencryption import AESCryptor

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 12345
UPLOAD_DIR = 'uploaded_files'
CLIENT_PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqxKcgrLBuvIzR575zEd+
11ZewWBF/lO+B5GdecNlRGbJ7HOoWDWe9o7dV5pqmArliALFN/7RvwYMTtaUMidJ
YGsDG9OJxq8/lLcKsx34fdzZEel1bb60RyMfNXGpCA7P69auK8ljeaEU2WxoMtkZ
bz2RcP/+zwDj05a6edhXqAdZjqx2Pu0a8SSdS19eeIbkRzEQ9Gm8MDuJVfLU9QAs
LzWI7YrpRnw9XqaRzZas0MCfIsakm88pOcWuQ4qpl0X2/AjPrQmiyPbNLnw/3baL
r8kyLApo6Ivt6gCVpkmRREH4aecU4TY3Ce5rPJQcJbxrp4M0EvyS0Q7hvKW9SY3s
0wIDAQAB
-----END PUBLIC KEY-----
'''

def init_key():
    global SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY
    rsa = RSACryptor()
    rsa.gen_rsa_key_pairs()
    SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY = rsa.public_key, rsa.private_key

def handle_client(connection):
    header = connection.recv(22)  # 6 bytes for command and 16 bytes for filename length
    command = header[:6]
    filename_len = int(header[6:22].decode())
    filename = connection.recv(filename_len).decode()

    if command == b'UPLOAD':
        handle_upload(connection, filename)
    elif command == b'DOWNLOAD':
        handle_download(connection, filename)

def handle_upload(connection, filename):
    data_length = int(connection.recv(16).decode())
    data = connection.recv(data_length)
    while len(data) < data_length:
        data += connection.recv(4096)
        
    nonce, ciphertext, tag, file_hash = data[:16], data[16:-48], data[-48:-32], data[-32:].decode()
    
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    with open(file_path, 'wb') as f:
        f.write(nonce + ciphertext + tag)
    
    if sha256_hash(file_path) != file_hash:
        connection.sendall(b'File integrity check failed')
    else:
        connection.sendall(b'File received successfully')

def handle_download(connection, filename):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        connection.sendall(b'File not found')
        return
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    nonce, ciphertext, tag = data[:16], data[16:-32], data[-32:]
    file_hash = sha256_hash(file_path)
    
    data = nonce + ciphertext + tag + file_hash.encode()
    connection.sendall(f'{len(data):016d}'.encode())  # 发送数据长度
    connection.sendall(data)


def run_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")
    # 确保上传目录存在
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((SERVER_ADDRESS, SERVER_PORT))
        sock.listen(5)
        print("Server Listening...")
        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                connection, client_address = ssock.accept()
                handle_client(connection)
                connection.close()


class server:
    def listen(self) -> None:
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
        # 收到请求后的处理
        while True:
            # 申请相同大小的空间存放发送过来的文件名与文件大小信息
            fileinfo_size = struct.calcsize('128sl')
            # 接收文件名与文件大小信息
            buf = conn.recv(fileinfo_size)
            print(len(buf))
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
        file_name, file_size = header["fileName"], header["fileSize"]
        print('Upload: file new name is %s, filesize is %s' % (file_name, file_size))
        # 定义接收了的文件大小
        recvd_size = 0
        # 存储在uploaded_files目录中
        fp = open("/uploaded_files" + str(file_name), "wb")
        print("Start receiving")  
        while not recvd_size == file_size:
            if file_size - recvd_size > 1024:
                # 由于经过加密，实际发送的文件长度和原本不一致
                len = int(conn.recv(1024).decode("utf-8"))
                print("该段发送长度: ", len)
                rdata = conn.recv(len)
                decrypted_data = decrypt_file(rdata)
                recvd_size += len(decrypted_data)
            else:
                len = int(conn.recv(1024).decode("utf-8"))
                print("该段发送长度: ", len)
                rdata = conn.recv(len)
                decrypted_data = decrypt_file(rdata)
                recvd_size = file_size
            fp.write(rdata)
        fp.close()
        print('receive done')
        conn.close()

    def handle_download(self, conn, header):
        pass
    
def decrypt_file(data):
    rsa = RSACryptor()
    cipher_message, cipher_keyiv = pickle.loads(data)
    print("密文:{}(类型{}) \n 密钥:{}(类型{})".format(cipher_message, type(cipher_message), cipher_keyiv, type(cipher_keyiv)))
    # decrypted_keyiv = rsa.decrypt_message(cipher_keyiv, SERVER_PRIVATE_KEY)
    # print("接收到的密钥和初始向量:", decrypted_keyiv)
    # keyiv = pickle.loads(decrypted_keyiv)
    # key, iv = keyiv["Key"], keyiv["IV"]
    # aes = AESCryptor(key, iv)
    # decrypted_message = aes.decrypt_message(cipher_message)
    # plain_message = pickle.loads(decrypted_message)
    # content = base64.b64decode(plain_message['Message'])
    # print('传送的内容是', content)
    # digest = plain_message['digest']
    # if RSACryptor.verify_signature(content, digest, CLIENT_PUBLIC_KEY):
    #     return content
    # else:
    #     print("文件签名不一致!")


if __name__ == "__main__":
    # server = server()
    # server.listen()
    # 发送的内容: b'1222222'
    # aes加密密钥: b'JLlTu52jAHXEmw7K' aes初始向量: b"\xc7{'\x0f\xc2}\x1b\xbcV\xac\xb5\xd1\xf5g,\xe6"
    # 加密后的消息: b'\x80\x04\x95A\x04\x00\x00\x00\x00\x00\x00]\x94(X\xd8\x02\x00\x002jDP4bXbVnBMp29wn0SmfoPCrBvyg7WO81VArJ9SGJR6dBmzDrTDc5dR4BKDpW59vMR+tonpWox/nU+5/H9Gk269CG+Xe2+giQ1m4yZ1QGc29c3lXkqvR8C0H5o8UiZhqBLJE7A7XjLPdvwJLwRyNYq7E2PbPTfd6YUedV6icLxWLM7Nmh9xGSqBYLZCl5t2rRx3trwnczopxIoh/vOyHGgcBUMr99LLS/Tj6fcjwUEMBbziquwc2sg77a6JNom31KKbzMBhUH4TLxAnN/V4qJ1PDGRj4UMdeMHu1A0I7wF3WmqZVVOPTltIWfeAj+wm9OVOexT9idkW7RrnQ4RgQt0zoecIapsYA/Db2smtR3BOR0eTG3LhCSnYEaJR5lOlVZw5LgsOOQnP0QJXK4VirfmaI/TqRBhmSUp9b7+RG89xKIYlAyPYdcZlbGtsvSW4Em63SYR/VCHBFRRudlN9yAmRwQwQLecOfmBsFB3ecP/WMhaHxk1mLxnzpS+iNAqEhUQQTxKncCJ+DDYvTeyx9TfkMolT3Juudt+PQQ8XrxjVnqmSSpyXU/ctAJ7N5voCQuw7iFISxmsVBVgcv1CvOIEtwU0CmXpwKFRFU5l59BnjBBtW5V89e2i06UJxFPc30kj0vDZ1LOwBl4jE3MQTfmg2mh1mBGvd+X2VZSxoYrOT3bsEMiYWEuA4FwBugn9mCO4/CzDtIQXsmv1eU0GtLQ==\x94BX\x01\x00\x00suHEiAXZFwBG2EniQcZO8YgRZqagWWN5G4PUz/1Rl1VCeO8fc6QxmKXSebsjKXvoE+QNSZPPzY5zAYsTAvBLabaO4qZnGfNS6FY2lbnBVNnue8buV4x/Z7eNftZ9TisGJanJXPWdm2u07bJwRIoEn41dTPQ+Mlny+5gGUBmaJcsPvOdqZufNd/ZTKtRK2ovRtxtWFyKNkvdH8F9AY5Y+Fp8X7ptUnbFbF11UbFb8bySl8CT4TZxl1u/iGxOKIbQj/2Ev91egW7bNi4/pwL3bSH5CZHYKK5Tm9NaAULoIrDXaPSFriSyBvvRjvvHraM7E/sKeXZUOyq7YMdhQK0GF0w==\x94e.'
    init_key()
    data = b'\x80\x04\x95A\x04\x00\x00\x00\x00\x00\x00]\x94(X\xd8\x02\x00\x002jDP4bXbVnBMp29wn0SmfoPCrBvyg7WO81VArJ9SGJR6dBmzDrTDc5dR4BKDpW59vMR+tonpWox/nU+5/H9Gk269CG+Xe2+giQ1m4yZ1QGc29c3lXkqvR8C0H5o8UiZhqBLJE7A7XjLPdvwJLwRyNYq7E2PbPTfd6YUedV6icLxWLM7Nmh9xGSqBYLZCl5t2rRx3trwnczopxIoh/vOyHGgcBUMr99LLS/Tj6fcjwUEMBbziquwc2sg77a6JNom31KKbzMBhUH4TLxAnN/V4qJ1PDGRj4UMdeMHu1A0I7wF3WmqZVVOPTltIWfeAj+wm9OVOexT9idkW7RrnQ4RgQt0zoecIapsYA/Db2smtR3BOR0eTG3LhCSnYEaJR5lOlVZw5LgsOOQnP0QJXK4VirfmaI/TqRBhmSUp9b7+RG89xKIYlAyPYdcZlbGtsvSW4Em63SYR/VCHBFRRudlN9yAmRwQwQLecOfmBsFB3ecP/WMhaHxk1mLxnzpS+iNAqEhUQQTxKncCJ+DDYvTeyx9TfkMolT3Juudt+PQQ8XrxjVnqmSSpyXU/ctAJ7N5voCQuw7iFISxmsVBVgcv1CvOIEtwU0CmXpwKFRFU5l59BnjBBtW5V89e2i06UJxFPc30kj0vDZ1LOwBl4jE3MQTfmg2mh1mBGvd+X2VZSxoYrOT3bsEMiYWEuA4FwBugn9mCO4/CzDtIQXsmv1eU0GtLQ==\x94BX\x01\x00\x00suHEiAXZFwBG2EniQcZO8YgRZqagWWN5G4PUz/1Rl1VCeO8fc6QxmKXSebsjKXvoE+QNSZPPzY5zAYsTAvBLabaO4qZnGfNS6FY2lbnBVNnue8buV4x/Z7eNftZ9TisGJanJXPWdm2u07bJwRIoEn41dTPQ+Mlny+5gGUBmaJcsPvOdqZufNd/ZTKtRK2ovRtxtWFyKNkvdH8F9AY5Y+Fp8X7ptUnbFbF11UbFb8bySl8CT4TZxl1u/iGxOKIbQj/2Ev91egW7bNi4/pwL3bSH5CZHYKK5Tm9NaAULoIrDXaPSFriSyBvvRjvvHraM7E/sKeXZUOyq7YMdhQK0GF0w==\x94e.'
    decrypt_file(data)



# Example usage:
# Start the server: python server/server.py
