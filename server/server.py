import socket
import ssl
import sys
import os
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


# def handle_client(connection):
#     data = connection.recv(4096)
#     nonce, ciphertext, tag, file_hash = data[:16], data[16:-64], data[-64:-32], data[-32:].decode()
#     file_name = 'uploaded_file'
    
#     with open(file_name, 'wb') as f:
#         f.write(nonce + ciphertext + tag)
    
#     if sha256_hash(file_name) != file_hash:
#         connection.sendall(b'File integrity check failed')
#     else:
#         connection.sendall(b'File received successfully')

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

if __name__ == "__main__":
    run_server()


# Example usage:
# Start the server: python server/server.py
