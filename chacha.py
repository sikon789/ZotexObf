# -*- coding: utf-8 -*-
"""
ChaCha20 流密码（IETF 变体，RFC 8439）
替换原 LCG/减法流，解决：
  - LCG 状态只有 8 bit（%256）→ ChaCha20 密钥空间 256 bit
  - 重复密钥流 = many-time pad → 每段随机 nonce
"""
import struct
import os

MASK = 0xFFFFFFFF


def _rotl(v, c):
    return ((v << c) & MASK) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK
    s[d] ^= s[a]; s[d] = _rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & MASK
    s[b] ^= s[c]; s[b] = _rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & MASK
    s[d] ^= s[a]; s[d] = _rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & MASK
    s[b] ^= s[c]; s[b] = _rotl(s[b], 7)


def _block(key32, counter, nonce12):
    const = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = list(struct.unpack('<8I', key32))
    n = list(struct.unpack('<3I', nonce12))
    st = const + k + [counter & MASK] + n
    w = st[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    out = [(w[i] + st[i]) & MASK for i in range(16)]
    return struct.pack('<16I', *out)


def chacha20_xor(key32, nonce12, data: bytes) -> bytes:
    """加密/解密（异或自反）。"""
    if len(key32) != 32 or len(nonce12) != 12:
        raise ValueError('key 必须 32 字节，nonce 必须 12 字节')
    out = bytearray()
    ctr = 0
    for i in range(0, len(data), 64):
        ks = _block(key32, ctr, nonce12)
        chunk = data[i:i + 64]
        for j, b in enumerate(chunk):
            out.append(b ^ ks[j])
        ctr = (ctr + 1) & MASK
    return bytes(out)


def derive_key32(secret: str, salt: str = '') -> bytes:
    """SHA-256 KDF：任意长度输入 → 均匀 32 字节（不截断、不补零）。
    Python / PHP / Lua 三端必须一致：sha256(secret + "|" + salt)。"""
    import hashlib
    return hashlib.sha256((secret + '|' + salt).encode('utf-8')).digest()


def encrypt_with_nonce(key32: bytes, data: bytes) -> bytes:
    """随机 nonce + 加密，返回 nonce(12) || ciphertext。"""
    nonce = os.urandom(12)
    return nonce + chacha20_xor(key32, nonce, data)


def decrypt_with_nonce(key32: bytes, blob: bytes) -> bytes:
    """拆出 nonce 并解密。"""
    nonce, cipher = blob[:12], blob[12:]
    return chacha20_xor(key32, nonce, cipher)


if __name__ == '__main__':
    # RFC 8439 测试向量
    key = bytes(range(32))
    nonce = bytes([0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0])
    plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
                 b"only one tip for the future, sunscreen would be it.")
    # counter=1 的用例，这里手工验证第 1 块
    ks = _block(key, 1, nonce)
    expected_ks = bytes.fromhex(
        '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e'
        'd2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e')
    print('ChaCha20 标准向量:', 'OK' if ks == expected_ks else 'FAIL')
    # 自反测试
    enc = chacha20_xor(key, nonce, plaintext)
    dec = chacha20_xor(key, nonce, enc)
    print('加解密自反:', 'OK' if dec == plaintext else 'FAIL')
    # nonce 封装
    blob = encrypt_with_nonce(key, plaintext)
    print('nonce 封装往返:', 'OK' if decrypt_with_nonce(key, blob) == plaintext else 'FAIL')
