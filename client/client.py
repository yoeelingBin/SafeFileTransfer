import socket
import ssl
from common.encryption import encrypt_file, decrypt_file
from common.utils import sha256_hash

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 12345

def upload_file(file_path):
    nonce, ciphertext, tag = encrypt_file(file_path)
    file_hash = sha256_hash(file_path)
    
    context = ssl.create_default_context()
    with socket.create_connection((SERVER_ADDRESS, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_ADDRESS) as ssock:
            ssock.sendall(nonce + ciphertext + tag + file_hash.encode())

def download_file(file_name, save_path):
    context = ssl.create_default_context()
    with socket.create_connection((SERVER_ADDRESS, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_ADDRESS) as ssock:
            ssock.sendall(file_name.encode())
            data = ssock.recv(4096)
            nonce, ciphertext, tag, file_hash = data[:16], data[16:-64], data[-64:-32], data[-32:].decode()
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
