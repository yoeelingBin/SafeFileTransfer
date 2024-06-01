import socket
import ssl
import os
from common.encryption import encrypt_file, decrypt_file
from common.utils import sha256_hash

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 12345

def upload_file(file_path):
    nonce, ciphertext, tag = encrypt_file(file_path)
    file_hash = sha256_hash(file_path)
    filename = file_path.split('\\')[-1]
    filename_bytes = filename.encode()
    
    context = ssl.create_default_context()
    context.load_verify_locations("certs/server.crt")
    with socket.create_connection((SERVER_ADDRESS, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_ADDRESS) as ssock:
            header = b'UPLOAD' + f'{len(filename_bytes):016d}'.encode()
            data = nonce + ciphertext + tag + file_hash.encode()
            ssock.sendall(f'{len(data):016d}'.encode())  # 发送数据长度
            ssock.sendall(data)
            response = ssock.recv(4096)
            print(response.decode())

    print("File send success")

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
    upload_file("1.txt")