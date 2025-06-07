import ctypes
import time
from ctypes import c_ubyte, c_uint, c_int, POINTER, byref

sm4 = ctypes.CDLL('./sm4.dll')

sm4.SM4_ECB_Encrypt.argtypes = [
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte), c_uint,
    POINTER(c_ubyte), POINTER(c_uint)
]
sm4.SM4_ECB_Encrypt.restype = c_int

sm4.SM4_ECB_Decrypt.argtypes = sm4.SM4_ECB_Encrypt.argtypes
sm4.SM4_ECB_Decrypt.restype = c_int

def to_c_buffer(py_bytes):
    return (c_ubyte * len(py_bytes))(*py_bytes)

# PKCS7 padding
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("无效的填充")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("填充内容不正确")
    return data[:-pad_len]

def encrypt_file(input_path, output_path, key):
    with open(input_path, 'rb') as f:
        data = f.read()
    padded = pkcs7_pad(data, 16)
    key_buf = to_c_buffer(key)
    plain_buf = to_c_buffer(padded)
    enc_buf = (c_ubyte * (len(padded) + 16))()
    enc_len = c_uint(0)
    ret = sm4.SM4_ECB_Encrypt(
        key_buf, len(key),
        plain_buf, len(padded),
        enc_buf, byref(enc_len)
    )
    assert ret == 0, f"加密失败: {ret}"
    with open(output_path, 'wb') as f:
        f.write(bytes(enc_buf[:enc_len.value]))

def decrypt_file(input_path, output_path, key):
    with open(input_path, 'rb') as f:
        data = f.read()
    key_buf = to_c_buffer(key)
    dec_buf = (c_ubyte * (len(data) + 16))()
    dec_len = c_uint(0)
    ret = sm4.SM4_ECB_Decrypt(
        key_buf, len(key),
        to_c_buffer(data), len(data),
        dec_buf, byref(dec_len)
    )
    assert ret == 0, f"解密失败: {ret}"
    decrypted = pkcs7_unpad(bytes(dec_buf[:dec_len.value]))
    with open(output_path, 'wb') as f:
        f.write(decrypted)


if __name__ == "__main__":
    print("SM4加密测试")
    key = bytes.fromhex('0123456789abcdeffedcba9876543210')
    # plaintext = b"恐龙抗狼哈基米, 恐龙抗狼胖宝宝"  # 任意长度

    # padded_plaintext = pkcs7_pad(plaintext, 16)

    # key_buf = to_c_buffer(key)
    # plain_buf = to_c_buffer(padded_plaintext)
    # out_buf_len = c_uint(1024)
    # enc_buf = (c_ubyte * out_buf_len.value)()
    # enc_len = c_uint(0)

    # ret = sm4.SM4_ECB_Encrypt(
    #     key_buf, len(key),
    #     plain_buf, len(padded_plaintext),
    #     enc_buf, byref(enc_len)
    # )
    # assert ret == 0, f"加密失败: {ret}"

    # ciphertext = bytes(enc_buf[:enc_len.value])
    # print("密文:", ciphertext.hex())

    # dec_buf = (c_ubyte * 1024)()
    # dec_len = c_uint(0)

    # ret = sm4.SM4_ECB_Decrypt(
    #     key_buf, len(key),
    #     to_c_buffer(ciphertext), len(ciphertext),
    #     dec_buf, byref(dec_len)
    # )
    # assert ret == 0, f"解密失败: {ret}"

    # decrypted_padded = bytes(dec_buf[:dec_len.value])
    # decrypted = pkcs7_unpad(decrypted_padded)
    # print("解密结果:", decrypted.decode())

    start = time.time()
    encrypt_file('test.txt', 'CIPHER.bin', key)
    end = time.time()
    print(f"加密文件耗时: {end - start:.4f} 秒")

    start = time.time()
    decrypt_file('CIPHER.bin', 'PLAINTEXT.txt', key)
    end = time.time()
    print(f"解密文件耗时: {end - start:.4f} 秒")