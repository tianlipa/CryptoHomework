import struct
import sys

def left_rotate(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def int_to_bytes(x, length):
    return x.to_bytes(length, 'big')

def bytes_to_int(b):
    return int.from_bytes(b, 'big')


# 填充函数
def padding(message: bytes):
    m_len = len(message) * 8
    message += b'\x80'
    while ((len(message) * 8 + 64) % 512) != 0:
        message += b'\x00'
    message += struct.pack('>Q', m_len)
    return message


def T(j):   # T常量生成函数
    if j < 16:
        return 0x79CC4519 
    else:
        return 0x7A879D8A

def FF(X, Y, Z, j):
    if j < 16:
        return (X ^ Y ^ Z)
    else:
        return ((X & Y) | (X & Z) | (Y & Z))

def GG(X, Y, Z, j):
    if j < 16:
        return (X ^ Y ^ Z)
    else:
        return ((X & Y) | (~X & Z))

def P0(X):
    return X ^ left_rotate(X, 9) ^ left_rotate(X, 17)

def P1(X):
    return X ^ left_rotate(X, 15) ^ left_rotate(X, 23)

# 消息扩展
def message_expand(B):
    W = []
    for i in range(16):
        W.append(int.from_bytes(B[i*4:(i+1)*4], 'big'))
    for i in range(16, 68):
        term = P1(W[i-16] ^ W[i-9] ^ left_rotate(W[i-3], 15)) ^ left_rotate(W[i-13], 7) ^ W[i-6]
        W.append(term & 0xFFFFFFFF)
    W_prime = [W[i] ^ W[i+4] for i in range(64)]
    return W, W_prime

# 压缩函数
def CF(V_i, B_i):
    A, B, C, D, E, F, G, H = V_i
    W, W_prime = message_expand(B_i)

    for j in range(64):
        SS1 = left_rotate((left_rotate(A, 12) + E + left_rotate(T(j), j % 32)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ left_rotate(A, 12)
        TT1 = (FF(A, B, C, j) + D + SS2 + W_prime[j]) & 0xFFFFFFFF
        TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = left_rotate(B, 9)
        B = A
        A = TT1
        H = G
        G = left_rotate(F, 19)
        F = E
        E = P0(TT2)
    
    return [a ^ b for a, b in zip(V_i, [A, B, C, D, E, F, G, H])]

# SM3主函数
def sm3_hash(msg: bytes) -> str:
    IV = [
        0x7380166F,
        0x4914B2B9,
        0x172442D7,
        0xDA8A0600,
        0xA96F30BC,
        0x163138AA,
        0xE38DEE4D,
        0xB0FB0E4E,
    ]                   # 标准规定的IV初始值

    msg = padding(msg)
    n = len(msg) // 64

    V = IV
    for i in range(n):
        B = msg[i*64:(i+1)*64]
        V = CF(V, B)

    return ''.join(f'{x:08x}' for x in V)

print("1.加密输入文本（UTF-8编码）\n2.加密输入文本（自定义编码）\n3.加密指定文件")
operation = input("请选择操作(1/2): ")
if operation == '1':
    print("请输入待加密文本，按回车-Ctrl+Z-回车结束输入:")
    data = sys.stdin.read()
    data = data.rstrip()  # 去除末尾换行符
    data = bytes(data, 'utf-8')
    digest = sm3_hash(data)
    print("SM3:", digest)
elif operation == '2':
    encoding = input("请输入文本编码（如utf-8、gbk等）: ")
    print("请输入待加密文本，按回车-Ctrl+Z-回车结束输入:")
    data = sys.stdin.read()
    data = data.rstrip()
    try:
        data = bytes(data, encoding)
    except (LookupError, UnicodeEncodeError):
        print("编码不合法或内容无法用该编码编码。")
        sys.exit(1)
    digest = sm3_hash(data)
    print("SM3:", digest)
elif operation == '3':
    file_path = input("请输入待加密文件路径: ")
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        digest = sm3_hash(data)
        print("SM3:", digest)
    except FileNotFoundError:
        print("文件未找到，请检查路径是否正确。")
else:
    print("无效操作。")