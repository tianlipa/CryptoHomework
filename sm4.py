# -*- coding: utf-8 -*-

"""
SM4算法实现示例（ECB模式）
-------------------------------------
注意：
1. 该代码实现了 SM4 的基本加解密功能，并增加了 PKCS7 填充处理。
2. 为了简化示例，SBOX 和 CK 表未在代码中给出，请按 SM4 标准补充完整（SBOX 为 256 个字节，CK 为 32 个 32 位常量）。
3. 该代码仅供参考，实际生产环境下建议使用安全、经过验证的库。
"""

import time

# ---------------------
# 固定常量（部分）
# ---------------------

# SBOX: 256 字节替代表（应填充完整）
SBOX = [
    0xD6,0x90,0xE9,0xFE,0xCC,0xE1,0x3D,0xB7,0x16,0xB6,0x14,0xC2,0x28,0xFB,0x2C,0x05,
	0x2B,0x67,0x9A,0x76,0x2A,0xBE,0x04,0xC3,0xAA,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
	0x9C,0x42,0x50,0xF4,0x91,0xEF,0x98,0x7A,0x33,0x54,0x0B,0x43,0xED,0xCF,0xAC,0x62,
	0xE4,0xB3,0x1C,0xA9,0xC9,0x08,0xe8,0x95,0x80,0xDF,0x94,0xFA,0x75,0x8F,0x3F,0xA6,
	0x47,0x07,0xA7,0xFC,0xF3,0x73,0x17,0xBA,0x83,0x59,0x3C,0x19,0xE6,0x85,0x4F,0xA8,
	0x68,0x6B,0x81,0xB2,0x71,0x64,0xDA,0x8B,0xF8,0xEB,0x0F,0x4B,0x70,0x56,0x9d,0x35,
	0x1E,0x24,0x0E,0x5E,0x63,0x58,0xD1,0xA2,0x25,0x22,0x7C,0x3B,0x01,0x21,0x78,0x87,
	0xD4,0x00,0x46,0x57,0x9F,0xD3,0x27,0x52,0x4C,0x36,0x02,0xE7,0xA0,0xc4,0xC8,0x9E,
	0xEA,0xBF,0x8A,0xD2,0x40,0xc7,0x38,0xB5,0xA3,0xF7,0xF2,0xCE,0xF9,0x61,0x15,0xA1,
	0xE0,0xAE,0x5D,0xA4,0x9B,0x34,0x1A,0x55,0xAD,0x93,0x32,0x30,0xF5,0x8C,0xB1,0xE3,
	0x1D,0xF6,0xE2,0x2E,0x82,0x66,0xCA,0x60,0xC0,0x29,0x23,0xAB,0x0D,0x53,0x4E,0x6F,
	0xD5,0xDB,0x37,0x45,0xDE,0xFD,0x8E,0x2F,0x03,0xFF,0x6A,0x72,0x6D,0x6C,0x5B,0x51,
	0x8D,0x1b,0xAF,0x92,0xBB,0xDD,0xBC,0x7F,0x11,0xD9,0x5C,0x41,0x1F,0x10,0x5A,0xD8,
	0x0A,0xC1,0x31,0x88,0xA5,0xCD,0x7B,0xBD,0x2D,0x74,0xD0,0x12,0xB8,0xE5,0xB4,0xB0,
	0x89,0x69,0x97,0x4A,0x0C,0x96,0x77,0x7E,0x65,0xB9,0xF1,0x09,0xC5,0x6E,0xC6,0x84,
	0x18,0xF0,0x7D,0xEC,0x3A,0xDC,0x4D,0x20,0x79,0xEE,0x5F,0x3E,0xD7,0xCB,0x39,0x48
]

# CK 表：32个 32 位常量（应填充完整）
CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C838AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
]

# FK 常量
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

# ---------------------
# 工具函数
# ---------------------
def left_rotate(x, n):
    """对 32 位整数 x 左移 n 位（循环移位）"""
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def byte_substitution(a):
    """
    对32位整数 a 的每个字节进行 SBOX 替换，返回替换后的 32 位整数。
    SBOX 数组必须包含 256 个元素。
    """
    return ((SBOX[(a >> 24) & 0xFF] << 24) |
            (SBOX[(a >> 16) & 0xFF] << 16) |
            (SBOX[(a >> 8) & 0xFF] << 8)  |
             SBOX[a & 0xFF])

def L1(b):
    """线性变换 L1，用于数据加密过程"""
    return b ^ left_rotate(b, 2) ^ left_rotate(b, 10) ^ left_rotate(b, 18) ^ left_rotate(b, 24)

def L2(b):
    """线性变换 L2，用于密钥扩展过程"""
    return b ^ left_rotate(b, 13) ^ left_rotate(b, 23)

def T(b):
    """非线性变换函数 T (包含 SBOX 替换及线性变换 L1)"""
    return L1(byte_substitution(b))

def T_key(b):
    """密钥扩展中的非线性变换 T_key (包含 SBOX 替换及线性变换 L2)"""
    return L2(byte_substitution(b))

# ---------------------
# SM4 密钥扩展
# ---------------------
def key_expansion(key):
    """
    密钥扩展函数：
      参数 key 为 16 字节密钥，返回 32 个轮密钥 rk（每个为 32 位整数）
    """
    if len(key) != 16:
        raise ValueError("Key 长度必须为 16 字节")
    # 将 128 位密钥分为 4 个 32 位整数
    MK = [int.from_bytes(key[i:i+4], byteorder='big') for i in range(0, 16, 4)]
    # 初始化中间变量 K[0..3]
    K = [MK[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        # 注意：CK 必须提供第 i 个常量
        temp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]
        temp = T_key(temp)
        new_key = K[i] ^ temp
        rk.append(new_key)
        K.append(new_key)
    return rk

# ---------------------
# 单分组加解密
# ---------------------
def sm4_encrypt_block(block, rk):
    """
    单分组加密，参数 block 为 16 字节，rk 为 32 个轮密钥列表
    返回加密后 16 字节的密文
    """
    if len(block) != 16:
        raise ValueError("SM4 加密输入 block 必须为 16 字节")
    # 将 16 字节分解为 4 个 32 位整数
    X = [int.from_bytes(block[i:i+4], byteorder='big') for i in range(0, 16, 4)]
    for i in range(32):
        tmp = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]
        t = T(tmp)
        new_word = X[i] ^ t
        X.append(new_word)
    # 最终结果为 X35, X34, X33, X32 逆序拼接
    result = b''.join(x.to_bytes(4, byteorder='big') for x in X[-4:][::-1])
    return result

def sm4_decrypt_block(block, rk):
    """
    单分组解密，注意解密时轮密钥序列需逆序使用。
    """
    return sm4_encrypt_block(block, rk[::-1])

# ---------------------
# PKCS7 填充与去填充
# ---------------------
def pkcs7_padding(data):
    """
    PKCS7 填充：SM4 的分组大小为 16 字节
    """
    block_size = 16
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpadding(data):
    """
    去除 PKCS7 填充，返回去除填充的原始数据。
    """
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("无效填充")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("填充错误")
    return data[:-pad_len]

# ---------------------
# ECB模式加解密（支持任意长度数据）
# ---------------------
def sm4_encrypt_ecb(plaintext, key):
    """
    ECB 模式加密：
      - 对明文先使用 PKCS7 填充至 16 字节的整数倍，
      - 逐分组进行 SM4 加密，
      - 最后拼接密文返回。
    """
    rk = key_expansion(key)
    padded = pkcs7_padding(plaintext)
    ciphertext = b''
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        ciphertext += sm4_encrypt_block(block, rk)
    return ciphertext

def sm4_decrypt_ecb(ciphertext, key):
    """
    ECB 模式解密：
      - 分组进行 SM4 解密，
      - 去除 PKCS7 填充，
      - 返回明文。
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("密文长度必须为 16 的倍数")
    rk = key_expansion(key)
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        plaintext += sm4_decrypt_block(block, rk)
    return pkcs7_unpadding(plaintext)

def sm4_encrypt_file(input_path, output_path, key):
    """
    使用SM4 ECB模式加密文件，结果写入output_path
    """
    with open(input_path, 'rb') as fin:
        data = fin.read()
    ciphertext = sm4_encrypt_ecb(data, key)
    with open(output_path, 'wb') as fout:
        fout.write(ciphertext)

def sm4_decrypt_file(input_path, output_path, key):
    """
    使用SM4 ECB模式解密文件，结果写入output_path
    """
    with open(input_path, 'rb') as fin:
        data = fin.read()
    plaintext = sm4_decrypt_ecb(data, key)
    with open(output_path, 'wb') as fout:
        fout.write(plaintext)

# ---------------------
# 示例用法
# ---------------------
if __name__ == '__main__':
    # 示例密钥（16字节）和明文
    key = b'0123456789abcdeF'  # 128-bit 密钥
    # plaintext = b"Hello, this is a test message for SM4 encryption. 1234567890"
    
    # print("原始明文:", plaintext)
    # # 加密
    # ciphertext = sm4_encrypt_ecb(plaintext, key)
    # print("加密后密文 (hex):", ciphertext.hex())
    
    # # 解密
    # decrypted = sm4_decrypt_ecb(ciphertext, key)
    # print("解密后明文:", decrypted)

    # 文件加解密
    start = time.time()
    sm4_encrypt_file('test.txt', 'testENC.txt', key)
    end = time.time()
    print(f"加密文件耗时: {end - start:.4f} 秒")

    start = time.time()
    sm4_decrypt_file('testENC.txt', 'testDEC.txt', key)
    end = time.time()
    print(f"解密文件耗时: {end - start:.4f} 秒")

