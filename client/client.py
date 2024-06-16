import socket
import ssl
import os
import base64
import pickle
import struct
import time
import json
import tkinter
from common.AESencryption import AESCryptor
from common.RSAencryption import RSACryptor
from common.utils import sha256_hash

DOWNLOAD_DIR = 'download_files'

def init_key():
    '''
    Usage: 生成公私钥
    '''
    rsa = RSACryptor()
    rsa.gen_rsa_key_pairs()
    rsa.save_keys("keys/client/client")
    return rsa.public_key, rsa.private_key

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
        self.server_public_key = None
        self.client_public_key, self.client_private_key = init_key()


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
        print("开始验证对方公钥完整性")
        self.verify_key(self.ssock)

    def exchange_pubkey(self, key_dir: str):
        '''
        Usage: 向服务端发送客户端公钥

        Args:
            key_dir: 存放公钥的目录
        '''
        with open(key_dir, 'rb') as fi:
            public_key = fi.read()
        print("发送客户端公钥\n" + public_key.decode("utf-8"))
        key_hash = sha256_hash(public_key)
        hash_message = pickle.dumps([public_key, key_hash])
        for _ in range(3):  # 尝试三次
            try:
                self.ssock.send(hash_message)
                print("客户端公钥发送成功")
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
                print("服务端公钥完整性验证完成，可以开始传输文件\n")
                self.server_public_key = public_key
                print("收到服务端公钥\n" +  self.server_public_key.decode('utf-8') + "\n")
                break

    def register(self, username, password) -> bool:
        '''
        Usage: 注册

        Args:
            username: 用户名
            password: 密码
        Returns:
            注册成功与否
        '''
        header = {
            'command': 'REGISTER',
            'username': username,
            'password': password,
            'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        }
        header_bytes = bytes(json.dumps(header).encode("utf-8"))
        fhead = struct.pack('128s', header_bytes)
        self.ssock.send(fhead)

        print('注册中...')
        fileinfo_size = struct.calcsize('128s')
        buf = self.ssock.recv(fileinfo_size)
        if buf:
            header_json = str(struct.unpack('128s', buf)[0], encoding='utf-8').strip('\00')
            print(header_json)
            header = json.loads(header_json)
            status = header['status']
            if status == 'OK':
                print("注册成功")
                return True
            elif status == 'ERROR':
                print("注册失败")
                return False
        return False

    def login(self, username, password) -> bool:
        '''
        Usage: 登录

        Args:
            username: 用户名
            password: 密码
        Returns:
            登录成功与否
        '''
        header = {
            'command': 'LOGIN',
            'username': username,
            'password': password,
            'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        }
        header_bytes = bytes(json.dumps(header).encode("utf-8"))
        fhead = struct.pack('128s', header_bytes)
        self.ssock.send(fhead)

        print('登录中...')
        fileinfo_size = struct.calcsize('128s')
        buf = self.ssock.recv(fileinfo_size)
        if buf:
            header_json = str(struct.unpack('128s', buf)[0], encoding='utf-8').strip('\00')
            print(header_json)
            header = json.loads(header_json)
            status = header['status']
            if status == 'OK':
                print("登录成功")
                return True
            elif status == 'ERROR':
                print("登录失败")
                return False
        return False
            
    def list_files(self) -> list[str]:
        '''
        Usage: 列出服务端已上传的文件

        Args:
        Returns:
            文件名列表
        '''
        header = {
            'command': 'LIST',
            'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        }
        header_bytes = bytes(json.dumps(header).encode("utf-8"))
        fhead = struct.pack('128s', header_bytes)
        self.ssock.send(fhead)

        fileinfo_size = struct.calcsize('128s')
        buf = self.ssock.recv(fileinfo_size)
        if buf:
            header_json = str(struct.unpack('128s', buf)[0], encoding='utf-8').strip('\00')
            print(header_json)
            header = json.loads(header_json)
            status = header['status']
            if status == 'OK':
                print("服务器文件列表:")
                for file in header['files']:
                    print(file)
                return header['files']
            else:
                print("获取文件列表失败:", header['message'])
                return None
        return None

    
    def upload_file(self, file_path: str):
        '''
        客户端上传文件
        
        Args: 
            file_path: 上传文件路径
        '''
        try:
            if os.path.isfile(file_path):
                header = {
                    'command': 'UPLOAD',
                    'fileName': os.path.basename(file_path),
                    'fileSize': os.stat(file_path).st_size,
                    'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                }

                header_bytes = bytes(json.dumps(header).encode("utf-8"))
                fhead = struct.pack('128s', header_bytes)
                self.ssock.send(fhead)

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
                tkinter.messagebox.showinfo('提示！', message='上传成功')
            else:
                print(f"文件 {file_path} 不存在")
        except Exception as e:
            print(f"上传文件时发生错误: {e}")    

    def download_file(self, file_name: str):
        '''
        Usage: 客户端下载文件
        
        Args: 
            file_path: 文件路径
        '''
        header = {
            'command': 'DOWNLOAD',
            'fileName': file_name,
            'fileSize': '',
            'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        }

        header_bytes = bytes(json.dumps(header).encode("utf-8"))
        fhead = struct.pack('128s', header_bytes)
        self.ssock.send(fhead)

        fileinfo_size = struct.calcsize('128sl')
        buf = self.ssock.recv(fileinfo_size)
        if buf:
            header_json = str(struct.unpack('128s', buf)[0], encoding='utf-8').strip('\00')
            print(header_json)
            header = json.loads(header_json)
            status = header['status']     

            if status == 'OK':
                file_size = header["fileSize"]
                file_path = os.path.join(DOWNLOAD_DIR + "/", file_name)
                print(f'download file path is {file_path}, filesize is {file_size}')
                recvd_size = 0
                fp = open(file_path, 'wb')
                print("Start receiving")  
                while recvd_size != file_size:
                    if file_size - recvd_size > 1024:
                        # 由于经过加密，实际发送的文件长度和原本不一致
                        recv_len = int(self.ssock.recv(1024).decode("utf-8"))
                        print("该段发送长度: ", recv_len)
                        rdata = self.ssock.recv(recv_len)
                        decrypted_data = self.decrypt_file(rdata)
                        recvd_size += len(decrypted_data)
                    else:
                        recv_len = int(self.ssock.recv(1024).decode("utf-8"))
                        print("该段发送长度: ", recv_len)
                        rdata = self.ssock.recv(recv_len)
                        # print(rdata)
                        decrypted_data = self.decrypt_file(rdata)
                        recvd_size = file_size
                    fp.write(decrypted_data)
                fp.close()
                print('下载完成')
                tkinter.messagebox.showinfo('提示！',message='下载成功：' + file_name)

    def encrypt_file(self, data) -> bytes:
        '''
        加密二进制数据
        
        Args: 
            data: 需要加密数据
        Returns:
            加密后的数据
        '''
        print("aes加密密钥:", self.aes_key, "aes初始向量:", self.aes_iv)
        
        digest = self.rsa_cipher.sign_message(data, self.client_private_key)
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
        decrypted_keyiv = self.rsa_cipher.decrypt_message(cipher_keyiv, self.client_private_key)
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
        
        if self.rsa_cipher.verify_signature(content, digest, self.server_public_key):
            return content
        print("文件签名不一致!")
        return None


if __name__ == "__main__":
    file1_path = "test_files/1.txt"
    file2_path = "test_files/2.md"
    file3_path = "test_files/3.jpg"
    client = Client()
    client.connect()
    # client.upload_file(file2_path)
    # client.upload_file(file1_path)
    # client.register('testuser', 'testpasswd')
    # client.login('testuser', 'testpasswd')
    client.list_files()

