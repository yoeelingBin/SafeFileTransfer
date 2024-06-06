import socket
import ssl
import sys
import os
import threading
import struct
import json
from common.utils import sha256_hash

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 12345
UPLOAD_DIR = 'uploaded_files'

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
            # 判断是否接收到文件头信息
            if buf:
                header_json = str(struct.unpack('128s', buf)[0], encoding='utf-8').strip('\00')
                print(header_json)
                header = json.loads(header_json)
                command = header['command']

                if command == "UPLOAD":
                    self.handle_upload(conn, header)
                elif command == "DOWNLOAD":
                    self.handle_download(conn, header)
            
    def handle_upload(self, conn, header):
        pass

    def handle_download(self, conn, header):
        pass
    



if __name__ == "__main__":
    server = server()
    server.listen()


# Example usage:
# Start the server: python server/server.py
