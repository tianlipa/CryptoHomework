import os
import json
from datetime import datetime
from sm4 import encrypt_file, decrypt_file, encrypt_bytes, decrypt_bytes
from sm3 import sm3_hash
import secrets

VAULT_INDEX = "vault_index.json"
VAULT_FOLDER = "vault"

def init_vault(user_key: bytes):
    os.makedirs(VAULT_FOLDER, exist_ok=True)
    if os.path.exists(VAULT_INDEX):
        raise Exception("Vault already initialized.")
    vault = {
        "key_hash": sm3_hash(user_key),
        "files": {}
    }
    with open(VAULT_INDEX, "w") as f:
        json.dump(vault, f, indent=4)

def load_vault(user_key: bytes):
    if not os.path.exists(VAULT_INDEX):
        raise Exception("Vault not initialized.")
    with open(VAULT_INDEX, "r") as f:
        vault = json.load(f)
    if sm3_hash(user_key) != vault["key_hash"]:
        raise Exception("Invalid key.")
    return vault

def save_vault(vault):
    with open(VAULT_INDEX, "w") as f:
        json.dump(vault, f, indent=4)

def encrypt_filename(filename: str, user_key: bytes) -> str:
    enc_bytes = encrypt_bytes(filename.encode('utf-8'), user_key)
    return enc_bytes.hex()

def decrypt_filename(enc_hex: str, user_key: bytes) -> str:
    enc_bytes = bytes.fromhex(enc_hex)
    dec_bytes = decrypt_bytes(enc_bytes, user_key)
    return dec_bytes.decode('utf-8')

def add_file_to_vault(filepath, user_key: bytes):
    vault = load_vault(user_key)
    filename = os.path.basename(filepath)
    enc_name = encrypt_filename(filename, user_key) + ".enc"
    enc_path = os.path.join(VAULT_FOLDER, enc_name)

    # 生成独立文件密钥
    file_key = secrets.token_bytes(16)  # SM4密钥16字节
    # 用主密钥加密文件密钥
    enc_file_key = encrypt_bytes(file_key, user_key)
    enc_file_key_hex = enc_file_key.hex()

    # 用文件密钥加密文件
    encrypt_file(filepath, enc_path, file_key)
    file_hash = sm3_hash(open(filepath, "rb").read())
    vault["files"][enc_name] = {
        # 不再保存 original_name
        "hash": file_hash,
        "timestamp": datetime.now().isoformat(),
        "enc_file_key": enc_file_key_hex
    }
    save_vault(vault)

def remove_file_from_vault(filename, output_path, user_key: bytes):
    vault = load_vault(user_key)
    # 遍历所有密文名，解密比对
    enc_name = None
    for k in vault["files"]:
        enc_filename = k[:-4] if k.endswith(".enc") else k
        try:
            dec_name = decrypt_filename(enc_filename, user_key)
            if dec_name == filename:
                enc_name = k
                break
        except Exception:
            continue
    if not enc_name:
        raise Exception("File not found in vault.")

    enc_path = os.path.join(VAULT_FOLDER, enc_name)
    enc_file_key_hex = vault["files"][enc_name]["enc_file_key"]
    enc_file_key = bytes.fromhex(enc_file_key_hex)
    # 用主密钥解密文件密钥
    file_key = decrypt_bytes(enc_file_key, user_key)

    decrypt_file(enc_path, output_path, file_key)
    del vault["files"][enc_name]
    os.remove(enc_path)
    save_vault(vault)

def list_vault(user_key: bytes):
    vault = load_vault(user_key)
    for enc_name, meta in vault["files"].items():
        enc_filename = enc_name[:-4] if enc_name.endswith(".enc") else enc_name
        try:
            dec_name = decrypt_filename(enc_filename, user_key)
        except Exception:
            dec_name = "<解密失败>"
        print(f"[{meta['timestamp']}] {dec_name} → {enc_name} (hash: {meta['hash'][:8]}...)")

if __name__ == "__main__":
    print("欢迎使用SM4文件保险箱")
    print("可用操作：init, add, remove, list, exit")
    while True:
        action = input("请输入操作类型: ").strip().lower()
        if action == "exit":
            print("已退出。")
            break
        key_hex = input("请输入用户密钥（十六进制）: ").strip()
        try:
            user_key = bytes.fromhex(key_hex)
        except Exception:
            print("密钥格式错误，请输入十六进制字符串。")
            continue

        try:
            if action == "init":
                init_vault(user_key)
                print("保险箱已初始化。")
            elif action == "add":
                filepath = input("请输入要添加的文件路径: ").strip()
                add_file_to_vault(filepath, user_key)
                print(f"文件 {filepath} 已加密并加入保险箱。")
            elif action == "remove":
                filename = input("请输入原始文件名（如 xxx.txt）: ").strip()
                output_path = input("请输入解密输出路径: ").strip()
                remove_file_from_vault(filename, output_path, user_key)
                print(f"文件 {filename} 已解密并移除保险箱。")
            elif action == "list":
                list_vault(user_key)
            else:
                print("未知操作，请重新输入。")
        except Exception as e:
            print("错误:", e)