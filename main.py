import os
import json
from datetime import datetime
from sm4 import encrypt_file, decrypt_file  # 你已有的实现
from sm3 import sm3_hash  # 你已有的实现

VAULT_INDEX = "vault_index.json"
VAULT_FOLDER = "vault"

# 初始化文件库
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

# 加载文件库并验证密钥
def load_vault(user_key: bytes):
    if not os.path.exists(VAULT_INDEX):
        raise Exception("Vault not initialized.")
    with open(VAULT_INDEX, "r") as f:
        vault = json.load(f)
    if sm3_hash(user_key) != vault["key_hash"]:
        raise Exception("Invalid key.")
    return vault

# 保存 vault 状态
def save_vault(vault):
    with open(VAULT_INDEX, "w") as f:
        json.dump(vault, f, indent=4)

# 添加文件到文件库（加密）
def add_file_to_vault(filepath, user_key: bytes):
    vault = load_vault(user_key)
    filename = os.path.basename(filepath)
    enc_name = filename + ".enc"
    enc_path = os.path.join(VAULT_FOLDER, enc_name)
    encrypt_file(filepath, enc_path, user_key)
    file_hash = sm3_hash(open(filepath, "rb").read())
    vault["files"][enc_name] = {
        "original_name": filename,
        "hash": file_hash,
        "timestamp": datetime.now().isoformat()
    }
    save_vault(vault)

# 移除文件（解密）
def remove_file_from_vault(enc_name, output_path, user_key: bytes):
    vault = load_vault(user_key)
    enc_path = os.path.join(VAULT_FOLDER, enc_name)
    if enc_name not in vault["files"]:
        raise Exception("File not found in vault.")
    decrypt_file(enc_path, output_path, user_key)
    del vault["files"][enc_name]
    os.remove(enc_path)
    save_vault(vault)

# 浏览文件库
def list_vault(user_key: bytes):
    vault = load_vault(user_key)
    for enc_name, meta in vault["files"].items():
        print(f"[{meta['timestamp']}] {meta['original_name']} → {enc_name} (hash: {meta['hash'][:8]}...)")

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
                enc_name = input("请输入加密文件名（如 xxx.txt.enc）: ").strip()
                output_path = input("请输入解密输出路径: ").strip()
                remove_file_from_vault(enc_name, output_path, user_key)
                print(f"文件 {enc_name} 已解密并移除保险箱。")
            elif action == "list":
                list_vault(user_key)
            else:
                print("未知操作，请重新输入。")
        except Exception as e:
            print("错误:", e)