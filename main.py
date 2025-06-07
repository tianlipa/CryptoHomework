import os
import json
from datetime import datetime
from sm4 import encrypt_file, decrypt_file, encrypt_bytes, decrypt_bytes
from sm3 import sm3_hash
import secrets
import time
# ...existing code...

import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, scrolledtext

VAULT_INDEX = "vault_index.json"
VAULT_FOLDER = "vault"

def init_vault(user_key: bytes):
    os.makedirs(VAULT_FOLDER, exist_ok=True)
    if os.path.exists(VAULT_INDEX):
        raise Exception("保险箱已存在，请删除保险箱后重试。")
    vault = {
        "key_hash": sm3_hash(user_key),
        "files": {}
    }
    with open(VAULT_INDEX, "w") as f:
        json.dump(vault, f, indent=4)

def load_vault(user_key: bytes):
    if not os.path.exists(VAULT_INDEX):
        raise Exception("初始化失败。")
    with open(VAULT_INDEX, "r") as f:
        vault = json.load(f)
    if sm3_hash(user_key) != vault["key_hash"]:
        raise Exception("密码错误。")
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

        # 检查是否已存在同名文件
    if enc_name in vault["files"]:
        raise Exception(f"保险箱内已存在同名文件。")

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
        raise Exception("文件不存在。")

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




def gui_main():
    def get_key():
        key_hex = key_entry.get().strip()
        if not key_hex:
            messagebox.showerror("错误", "请输入密钥。")
            return None
        try:
            # 支持任意长度密钥，先转字节再哈希
            raw_bytes = key_hex.encode("utf-8")
            hash_hex = sm3_hash(raw_bytes)
            # 取前16字节作为SM4密钥
            return bytes.fromhex(hash_hex[:32])
        except Exception:
            messagebox.showerror("错误", "密钥处理失败。")
            return None

    def do_init():
        user_key = get_key()
        if not user_key:
            return
        try:
            init_vault(user_key)
            messagebox.showinfo("成功", "保险箱已初始化。")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def do_add():
        user_key = get_key()
        if not user_key:
            return
        filepath = filedialog.askopenfilename(title="选择要添加的文件")
        if not filepath:
            return
        try:
            start_time = time.time()
            add_file_to_vault(filepath, user_key)
            elapsed_time = time.time() - start_time
            messagebox.showinfo("成功", f"文件 {filepath} 已加密并加入保险箱，用时 {elapsed_time:.4f} 秒")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def do_remove():
        user_key = get_key()
        if not user_key:
            return
        filename = simpledialog.askstring("输入", "请输入原始文件名（如 xxx.txt）:")
        if not filename:
            return
        output_path = filedialog.asksaveasfilename(title="选择解密输出路径", initialfile=filename)
        if not output_path:
            return
        try:
            start_time = time.time()
            remove_file_from_vault(filename, output_path, user_key)
            elapsed_time = time.time() - start_time
            messagebox.showinfo("成功", f"文件 {filename} 已解密并移除保险箱，用时 {elapsed_time:.4f} 秒")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def do_list():
        user_key = get_key()
        if not user_key:
            return
        try:
            vault = load_vault(user_key)
            output.delete(1.0, tk.END)
            for enc_name, meta in vault["files"].items():
                enc_filename = enc_name[:-4] if enc_name.endswith(".enc") else enc_name
                try:
                    dec_name = decrypt_filename(enc_filename, user_key)
                except Exception:
                    dec_name = "<解密失败>"
                output.insert(tk.END, f"[{meta['timestamp']}] {dec_name} → {enc_name}\n")
                output.insert(tk.END, f"hash: {meta['hash']}\n\n")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    root = tk.Tk()
    root.title("SM4 文件保险箱 by tianlipa")

    tk.Label(root, text="用户密钥：").grid(row=0, column=0, sticky="e")
    key_entry = tk.Entry(root, width=40, show="*")
    key_entry.grid(row=0, column=1, columnspan=4, padx=5, pady=5)

    tk.Button(root, text="初始化保险箱", command=do_init).grid(row=1, column=0, padx=5, pady=5)
    tk.Button(root, text="添加文件", command=do_add).grid(row=1, column=1, padx=5, pady=5)
    tk.Button(root, text="移除文件", command=do_remove).grid(row=1, column=2, padx=5, pady=5)
    tk.Button(root, text="列出文件", command=do_list).grid(row=1, column=3, padx=5, pady=5)
    tk.Button(root, text="退出", command=root.quit).grid(row=1, column=4, padx=5, pady=5)

    output = scrolledtext.ScrolledText(root, width=80, height=20)
    output.grid(row=2, column=0, columnspan=5, padx=5, pady=5)

    root.mainloop()


if __name__ == "__main__":
    gui_main()
    # print("欢迎使用SM4文件保险箱")
    # print("可用操作：init, add, remove, list, exit")
    # while True:
    #     action = input("请输入操作类型: ").strip().lower()
    #     if action == "exit":
    #         print("已退出。")
    #         break
    #     key_hex = input("请输入用户密钥（十六进制）: ").strip()
    #     try:
    #         user_key = bytes.fromhex(key_hex)
    #     except Exception:
    #         print("密钥格式错误，请输入十六进制字符串。")
    #         continue

    #     try:
    #         if action == "init":
    #             init_vault(user_key)
    #             print("保险箱已初始化。")
    #         elif action == "add":
    #             filepath = input("请输入要添加的文件路径: ").strip()
    #             add_file_to_vault(filepath, user_key)
    #             print(f"文件 {filepath} 已加密并加入保险箱。")
    #         elif action == "remove":
    #             filename = input("请输入原始文件名（如 xxx.txt）: ").strip()
    #             output_path = input("请输入解密输出路径: ").strip()
    #             remove_file_from_vault(filename, output_path, user_key)
    #             print(f"文件 {filename} 已解密并移除保险箱。")
    #         elif action == "list":
    #             list_vault(user_key)
    #         else:
    #             print("未知操作，请重新输入。")
    #     except Exception as e:
    #         print("错误:", e)