import socket
import ssl
import sys
from common.utils import sha256_hash

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 12345

def handle_client(connection):
    data = connection.recv(4096)
    nonce, ciphertext, tag, file_hash = data[:16], data[16:-64], data[-64:-32], data[-32:].decode()
    file_name = 'uploaded_file'
    
    with open(file_name, 'wb') as f:
        f.write(nonce + ciphertext + tag)
    
    if sha256_hash(file_name) != file_hash:
        connection.sendall(b'File integrity check failed')
    else:
        connection.sendall(b'File received successfully')
        
    # Implement file download handling...

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((SERVER_ADDRESS, SERVER_PORT))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                connection, client_address = ssock.accept()
                handle_client(connection)
                connection.close()

if __name__ == "__main__":
    run_server()


# Example usage:
# Start the server: python server/server.py
