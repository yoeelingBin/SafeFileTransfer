from Crypto.PublicKey import RSA

def gen_rsa_key_pairs(dir: str) -> tuple[bytes,bytes]:
    # 生成RSA密钥对
    key = RSA.generate(2048)
    private_key = key.export_key("PEM")
    public_key = key.publickey().export_key()

    # 保存密钥到文件
    with open(dir + "private.pem", "wb") as f:
        f.write(private_key)
    with open(dir + "public.pem", "wb") as f:
        f.write(public_key)

    return private_key, public_key