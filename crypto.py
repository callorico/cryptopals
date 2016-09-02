import os
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from bitops import xor


class PaddingError(Exception):
    pass


def pkcs_7(rawbytes, block_size):
    padding_bytes = block_size - (len(rawbytes) % block_size)
    return rawbytes + (chr(padding_bytes) * padding_bytes)

def strip_pkcs_7(rawbytes):
    padding_bytes = ord(rawbytes[-1])
    if not all(ord(b) == padding_bytes for b in rawbytes[-padding_bytes:]):
        raise PaddingError('Invalid padding')

    return rawbytes[:-padding_bytes]

def ecb_encrypt(plaintext, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    padded = pkcs_7(plaintext, len(key))
    ciphertext = ''
    for start in range(0, len(padded), len(key)):
        end = start + len(key)
        ciphertext += encryptor.update(padded[start:end])

    return ciphertext

def ecb_decrypt(ciphertext, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    plaintext = ''
    for start in range(0, len(ciphertext), len(key)):
        end = start + len(key)
        plaintext += decryptor.update(ciphertext[start:end])

    return strip_pkcs_7(plaintext)

def cbc_encrypt(plaintext, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    padded = pkcs_7(plaintext, len(iv))
    ciphertext = ''
    for start in range(0, len(padded), len(iv)):
        end = start + len(iv)
        scrambled = xor(iv, padded[start:end])
        ciphertext_block = encryptor.update(scrambled)
        ciphertext += ciphertext_block
        iv = ciphertext_block

    return ciphertext

def cbc_decrypt(ciphertext, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    plaintext = ''
    block_size = len(iv)
    for start in range(0, len(ciphertext), block_size):
        end = start + block_size
        ciphertext_block = ciphertext[start:end]
        plaintext += xor(iv, decryptor.update(ciphertext_block))
        iv = ciphertext_block

    return strip_pkcs_7(plaintext)

def encryption_key():
    return os.urandom(16)

def iv():
    return os.urandom(16)

def random_padding(min=5, max=10):
    length = random.randint(min, max)
    return os.urandom(length)