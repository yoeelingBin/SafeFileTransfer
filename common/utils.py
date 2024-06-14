import hashlib

def sha256_hash(data: str):
    '''
    Usage: 进行sha256哈希
    
    Args:
        data: 需要哈希的字符串
    Returns:
        进行哈希和消息摘要后的字符串
    '''
    sha256 = hashlib.sha256()
    sha256.update(data)
    res = sha256.hexdigest()
    return res

if __name__ == '__main__':
    e = sha256_hash('你好'.encode('utf-8'))
    print(e)
    