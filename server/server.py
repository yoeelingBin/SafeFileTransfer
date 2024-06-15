import socket
import ssl
import sys
import threading
import struct
import json
import pickle
import base64
import pymysql
import bcrypt
import os
from common.RSAencryption import RSACryptor
from common.AESencryption import AESCryptor
from common.utils import sha256_hash

SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 12345
UPLOAD_DIR = 'uploaded_files'

def init_key():
    '''
    Usage: 生成公私钥
    '''
    rsa = RSACryptor()
    rsa.gen_rsa_key_pairs()
    rsa.save_keys("keys/server/server")
    return rsa.public_key, rsa.private_key

def conn_db():
    '''
    Usage: 打开数据库连接
    '''
    #打开数据库连接
    db = pymysql.connect(host='127.0.0.1', port=3306, user='root', passwd='011014', db='file_transfer', charset='utf8mb4')
    #使用cursor方法创建一个游标
    cursor = db.cursor()
    #查询数据库版本
    cursor.execute("select version()")
    data = cursor.fetchone()
    print(f"Database Version:{data}")
    return db, cursor


class Server:
    '''
    Description: 服务端类
    '''
    def __init__(self):
        self.server_public_key, self.server_private_key = init_key()
        self.client_public_key = None
        self.rsa_cipher = RSACryptor()
        self.aes_key = AESCryptor.gen_key()
        self.aes_iv = AESCryptor.gen_iv()
        self.aes_cipher = AESCryptor(self.aes_key, iv=self.aes_iv)
        self.db, self.cursor = conn_db()

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

    def exchange_pubkey(self, key_dir: str, conn):
        '''
        Usage: 向服务端发送客户端公钥

        Args:
            key_dir: 存放公钥的目录
        '''
        with open(key_dir, 'rb') as fi:
            public_key = fi.read()
        print("发送服务端公钥\n" + public_key.decode("utf-8"))
        key_hash = sha256_hash(public_key)
        hash_message = pickle.dumps([public_key, key_hash])
        for _ in range(3):  # 尝试三次
            try:
                conn.send(hash_message)
                print("服务端公钥发送成功")
                return
            except ConnectionRefusedError:
                print("公钥发送失败，尝试重新发送")
        print("公钥发送失败")
    
    def verify_key(self, conn):
        '''
        Usage: 对服务端公钥完整性进行验证

        Args:
            sock: SSLSocket
        '''
        while True:
            message = conn.recv(4096)
            (public_key, key_hash) = pickle.loads(message)
            if key_hash == sha256_hash(public_key):
                print("客户端公钥完整性验证完成，可以开始传输文件\n")
                self.client_public_key = public_key
                print("收到客户端公钥\n" +  self.client_public_key.decode('utf-8') + "\n")
                break

    def handle_conn(self, conn):
        '''
        Usage: 处理连接

        Args:
            conn: SSL Socket连接
        '''
        try:
            self.exchange_pubkey("keys/server/serverpublic.pem", conn)
            self.verify_key(conn)
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
                    elif command == "REGISTER":
                        self.handle_register(conn, header)
                    elif command == "LOGIN":
                        self.handle_login(conn, header)
                    elif command == "LIST":
                        self.handle_list(conn, header)
        except Exception as e:
            print(f"Error during connection handling: {e}")

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
        fp = open(UPLOAD_DIR + "/" + str(file_name), "wb")
        print("Start receiving")  
        while not recvd_size == file_size:
            if file_size - recvd_size > 1024:
                # 由于经过加密，实际发送的文件长度和原本不一致
                recv_len = int(conn.recv(1024).decode("utf-8"))
                print("该段发送长度: ", recv_len)
                rdata = conn.recv(recv_len)
                decrypted_data = self.decrypt_file(rdata)
                recvd_size += len(decrypted_data)
            else:
                recv_len = int(conn.recv(1024).decode("utf-8"))
                print("该段发送长度: ", recv_len)
                rdata = conn.recv(recv_len)
                # print(rdata)
                decrypted_data = self.decrypt_file(rdata)
                recvd_size = file_size
            fp.write(decrypted_data)
        fp.close()
        print('receive done')
        # conn.close()

    def handle_download(self, conn, header):
        '''
        Usage: 处理文件下载

        Args:
            conn: SSL Socket连接
            header: 文件头信息
        '''
        file_name = header['fileName']
        file_path = os.path.join(UPLOAD_DIR+'/', str(file_name))
        try:
            if os.path.isfile(file_path):
                response = {
                    'status': 'OK', 
                    'fileSize': os.stat(file_path).st_size,
                    'message': 'File found'
                }

                res_hex = bytes(json.dumps(response).encode('utf-8'))
                res_pack = struct.pack('128s', res_hex)
                conn.send(res_pack)

                with open(file_path, 'rb') as fp:
                    while True:
                        data = fp.read(1024)
                        if not data:
                            print(f'{os.path.basename(file_path)}文件发送完毕...')
                            break
                        print("发送的内容:", data)
                        tosend = self.encrypt_file(data)
                        print("加密后的消息", tosend)
                        conn.send(str(len(tosend)).encode('utf-8'))
                        conn.send(tosend)
            else:
                response = {
                    'status': 'ERROR', 
                    'message': 'File not found'
                }
                res_hex = bytes(json.dumps(response).encode('utf-8'))
                res_pack = struct.pack('128s', res_hex)
                conn.send(res_pack)
                print(f"文件 {file_path} 不存在")
        except Exception as e:
                response = {
                    'status': 'ERROR', 
                    'message': f'Error {e} occuered while downloading'
                }
                res_hex = bytes(json.dumps(response).encode('utf-8'))
                res_pack = struct.pack('128s', res_hex)
                conn.send(res_pack)
                print(f"下载文件时发生错误: {e}")    

    def handle_register(self, conn, header):
        '''
        Usage: 处理注册

        Args:
            conn: SSL Socket连接
            header: 文件头信息
        '''
        username, password, time = header['username'], header['password'], header['time']
        try:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            sql = "INSERT INTO users (username, password) VALUES (%s, %s)"
            val = (username, hashed_password)
            self.cursor.execute(sql, val)
            self.db.commit()
            response = {'status': 'OK', 'message': 'User registered successfully'}
        except pymysql.IntegrityError:
            response = {'status': 'ERROR', 'message': 'User already exists'}
        except Exception as e:
            response = {'status': 'ERROR', 'message': str(e)}

        res_hex = bytes(json.dumps(response).encode('utf-8'))
        res_pack = struct.pack('128s', res_hex)
        conn.send(res_pack)

    def handle_login(self, conn, header):
        '''
        Usage: 处理登录

        Args:
            conn: SSL Socket连接
            header: 文件头信息
        '''
        username, password, time = header['username'], header['password'], header['time']
        try:
            sql = "SELECT password FROM users WHERE username = %s"
            val = (username,)
            self.cursor.execute(sql, val)
            result = self.cursor.fetchone()
            if result:
                hashed_password = result[0]
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                    response = {'status': 'OK', 'message': 'Login successful'}
                else:
                    response = {'status': 'ERROR', 'message': 'Invalid password'}
            else:
                response = {'status': 'ERROR', 'message': 'User does not exist'}
        except Exception as e:
            response = {'status': 'ERROR', 'message': str(e)}

        res_hex = bytes(json.dumps(response).encode('utf-8'))
        res_pack = struct.pack('128s', res_hex)
        conn.send(res_pack)

    def handle_list(self, conn, header):
        '''
        Usage: 处理列出文件

        Args:
            conn: SSL Socket连接
            header: 文件头信息
        '''
        time = header['time']
        try:
            files = os.listdir(UPLOAD_DIR)
            response = {'status': 'OK', 'files': files}
        except Exception as e:
            response = {'status': 'ERROR', 'message': str(e)}

        res_hex = bytes(json.dumps(response).encode('utf-8'))
        res_pack = struct.pack('128s', res_hex)
        conn.send(res_pack)

    def encrypt_file(self, data) -> bytes:
        '''
        加密二进制数据
        
        Args: 
            data: 需要加密数据
        Returns:
            加密后的数据
        '''
        print("aes加密密钥:", self.aes_key, "aes初始向量:", self.aes_iv)
        
        digest = self.rsa_cipher.sign_message(data, self.server_private_key)
        print("消息摘要:", digest)
        
        concated_message = {"Message": base64.b64encode(data), "Digest": digest}
        dumpped_message = pickle.dumps(concated_message)
        
        cipher_message = self.aes_cipher.encrypt_message(dumpped_message)
        
        keyiv = {"Key": self.aes_key, "IV": self.aes_iv}
        print("密钥和初始向量", keyiv)
        dumpped_keyiv = pickle.dumps(keyiv)
        print("序列化后的密钥和初始向量", dumpped_keyiv)
        
        cipher_keyiv = self.rsa_cipher.encrypt_message(dumpped_keyiv, self.client_public_key)
        print("加密后的密钥和初始向量", cipher_keyiv)
        
        send_message = pickle.dumps([cipher_message, cipher_keyiv])
        print("序列化前的发送消息", [cipher_message, cipher_keyiv])
        return send_message
    
    def decrypt_file(self, data) -> bytes:
        '''
        Usage: 解密二进制数据
            
        Args: 
            data: 需要解密的数据
        Returns:
            解密后的数据(完整性通过),否则返回None
        '''
        cipher_message, cipher_keyiv = pickle.loads(data)
        print(f"密文:{cipher_message}, 类型{type(cipher_message)}\n密钥:{cipher_keyiv}, 类型{type(cipher_keyiv)}")
        decrypted_keyiv = self.rsa_cipher.decrypt_message(cipher_keyiv, self.server_private_key)
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

        if self.rsa_cipher.verify_signature(content, digest, self.client_public_key):
            print("完整性验证通过!")
            return content
        else:
            print("文件签名不一致!")
            return None


if __name__ == "__main__":
    server = Server()
    server.listen()
    

# Example usage:
# Start the server: python server/server.py
