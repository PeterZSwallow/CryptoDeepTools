#!/usr/bin/env python3
"""
breakECDSA.py  –  Python 3, все зависимости встроены внутрь файла.
Оригинал: https://github.com/PeterZSwallow/CryptoDeepTools/tree/main/02BreakECDSAcryptography

Принимает Raw TX (hex) как аргумент командной строки и выводит R, S, Z, PUBKEY.

Единственная внешняя зависимость: pip install ecdsa
Использование:
    python3 breakECDSA.py <raw_tx_hex>
"""

import sys
import hashlib
import struct

# ── внешняя зависимость ──────────────────────────────────────────────────────
try:
    import ecdsa
    import ecdsa.der
    import ecdsa.util
except ImportError:
    sys.exit("Установите ecdsa:  pip install ecdsa")
# ─────────────────────────────────────────────────────────────────────────────


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  utils.py  (встроено, портировано на Python 3)                            ║
# ║  Оригинал: shirriff/bitcoin-code                                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def _varint(n: int) -> bytes:
    """Кодирует целое число в Bitcoin varint (bytes)."""
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n < 0xffff:
        return struct.pack('<BH', 0xfd, n)
    elif n < 0xffffffff:
        return struct.pack('<BL', 0xfe, n)
    else:
        return struct.pack('<BQ', 0xff, n)


def _varstr(s: bytes) -> bytes:
    """Prefixes bytes with varint length."""
    return _varint(len(s)) + s


def _process_varint(payload: bytes):
    """Возвращает [значение, длина_поля]."""
    n0 = payload[0]
    if n0 < 0xfd:
        return [n0, 1]
    elif n0 == 0xfd:
        return [struct.unpack('<H', payload[1:3])[0], 3]
    elif n0 == 0xfe:
        return [struct.unpack('<L', payload[1:5])[0], 5]
    else:
        return [struct.unpack('<Q', payload[1:9])[0], 9]


def _base58encode(n: int) -> str:
    result = ''
    while n > 0:
        result = _B58_ALPHABET[n % 58] + result
        n //= 58
    return result


def _base58decode(s: str) -> int:
    result = 0
    for ch in s:
        result = result * 58 + _B58_ALPHABET.index(ch)
    return result


def _base256encode(n: int) -> bytes:
    result = b''
    while n > 0:
        result = bytes([n % 256]) + result
        n //= 256
    return result


def _base256decode(s: bytes) -> int:
    result = 0
    for byte in s:
        result = result * 256 + (byte if isinstance(byte, int) else ord(byte))
    return result


def _count_leading(s, ch) -> int:
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count


def _base58check_encode(version: int, payload: bytes) -> str:
    """Кодирует (version || payload) в Base58Check строку."""
    s = bytes([version]) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[:4]
    result = s + checksum
    leading_zeros = _count_leading(result, 0)          # итерация по bytes → int
    return '1' * leading_zeros + _base58encode(_base256decode(result))


def _base58check_decode(s: str) -> bytes:
    """Декодирует Base58Check строку, возвращает payload без version-байта."""
    leading_ones = _count_leading(s, '1')              # итерация по str → chr
    decoded_int   = _base58decode(s)
    decoded_bytes = _base256encode(decoded_int)
    payload   = b'\x00' * leading_ones + decoded_bytes[:-4]
    chk       = decoded_bytes[-4:]
    checksum  = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if chk != checksum:
        raise ValueError("Неверная контрольная сумма Base58Check")
    return payload[1:]          # убираем version-байт


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  keyUtils.py  (встроено, портировано на Python 3)                         ║
# ║  Оригинал: shirriff/bitcoin-code                                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def _der_sig_to_hex_sig(s: str) -> str:
    """
    Вход:  hex-строка DER-кодированной подписи (без последнего байта hashtype).
    Выход: 64-байтовая hex-строка (R || S).
    """
    raw = bytes.fromhex(s)
    raw, junk = ecdsa.der.remove_sequence(raw)
    if junk:
        print(f"[предупреждение] JUNK после последовательности: {junk.hex()}", file=sys.stderr)
    assert not junk, "Лишние байты после DER-последовательности"
    x, raw = ecdsa.der.remove_integer(raw)
    y, _   = ecdsa.der.remove_integer(raw)
    return '%064x%064x' % (x, y)


def _pub_key_to_addr(s: str) -> str:
    """Вход: hex-строка публичного ключа → Bitcoin-адрес (Base58Check)."""
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(bytes.fromhex(s)).digest())
    return _base58check_encode(0, ripemd160.digest())


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  txnUtils.py  (встроено, портировано на Python 3)                         ║
# ║  Оригинал: shirriff/bitcoin-code                                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def _parse_txn(txn: str):
    """
    Разбирает Raw TX (hex-строка) на составляющие.
    Возвращает [first, sig, pub, rest]  — всё hex-строки.
    """
    first     = txn[0:41 * 2]
    script_len = int(txn[41 * 2:42 * 2], 16)
    script    = txn[42 * 2: 42 * 2 + 2 * script_len]

    sig_len   = int(script[0:2], 16)
    sig       = script[2: 2 + sig_len * 2]

    pub_offset = 2 + sig_len * 2
    pub_len    = int(script[pub_offset: pub_offset + 2], 16)
    pub        = script[pub_offset + 2:]

    assert len(pub) == pub_len * 2, (
        f"Длина публичного ключа не совпадает: ожидалось {pub_len * 2}, "
        f"получено {len(pub)}"
    )

    rest = txn[42 * 2 + 2 * script_len:]
    return [first, sig, pub, rest]


def _get_signable_txn(parsed) -> str:
    """
    Подставляет scriptPubKey в транзакцию и добавляет SIGHASH_ALL.
    Возвращает hex-строку, которую нужно хэшировать для получения Z.
    """
    first, sig, pub, rest = parsed
    input_addr = _base58check_decode(_pub_key_to_addr(pub))   # bytes
    return first + "1976a914" + input_addr.hex() + "88ac" + rest + "01000000"


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  breakECDSA.py  — основная логика                                         ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def main():
    if len(sys.argv) < 2:
        print("Использование: python3 breakECDSA.py <raw_tx_hex>")
        sys.exit(1)

    tx = sys.argv[1].strip()

    # 1. Разобрать транзакцию
    m = _parse_txn(tx)

    # 2. Построить версию транзакции для подписи
    e = _get_signable_txn(m)

    # 3. Двойной SHA-256 → Z
    e_bytes = bytes.fromhex(e)
    hash1   = hashlib.sha256(e_bytes).digest()
    hash2   = hashlib.sha256(hash1).digest()
    z       = hash2.hex()

    # 4. Извлечь R и S из DER-подписи (убираем последний байт hashtype)
    s    = _der_sig_to_hex_sig(m[1][:-2])
    pub  = m[2]
    sigR = s[:64]
    sigS = s[64:]
    sigZ = z

    # 5. Вывод
    print("R = 0x" + sigR)
    print("S = 0x" + sigS)
    print("Z = 0x" + sigZ)
    print()
    print("PUBKEY = " + pub)
    print()
    print("=" * 70)
    print()


if __name__ == '__main__':
    main()
