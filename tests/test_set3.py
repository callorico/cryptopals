import unittest
import random
from collections import OrderedDict
from convert import base64_to_bytes
from crypto import (cbc_decrypt, cbc_encrypt, encryption_key, iv, PaddingError,
                    strip_pkcs_7, ctr_decrypt, ctr_encrypt)

secret_messages = [
    base64_to_bytes(c)
    for c in [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
    ]
]

def encrypt_random_choice(key):
    selection = secret_messages[random.randint(0, len(secret_messages) - 1)]
    init_vector = iv()
    return (
        cbc_encrypt(selection, key, init_vector),
        init_vector,
    )


def is_padding_valid(ciphertext, key, iv):
    try:
        cbc_decrypt(ciphertext, key, iv)
        return True
    except PaddingError:
        return False


class TestSet3(unittest.TestCase):

    def test_challenge17(self):
        key = encryption_key()
        ciphertext, init_vector = encrypt_random_choice(key)

        block_size = len(init_vector)
        blocks = (
            ciphertext[i:(i+block_size)]
            for i in range(0, len(ciphertext), block_size)
        )

        prev_block = init_vector
        plaintext = ''
        for block in blocks:
            plaintext_block = [0] * block_size

            for i in reversed(range(block_size)):
                padding_value = block_size - i

                # Generate a tampered_iv that will produce a plaintext block
                # that is properly pkcs7-padded with padding_value
                tampered_iv = [0] * block_size

                for j in range(i + 1, block_size):
                    tampered_iv[j] = (
                        ord(prev_block[j]) ^ plaintext_block[j] ^ padding_value
                    )

                # Use the oracle to find the tampered iv value for block
                # position i that will produce padding_value in the plaintext
                for modified in range(256):
                    tampered_iv[i] = modified
                    if is_padding_valid(block, key, ''.join(chr(c) for c in tampered_iv)):
                        break

                # Now the plaintext for index i can be calculated:
                # Pi = prev_block[i] ^ modified ^ padding_value
                plaintext_block[i] = (
                    ord(prev_block[i]) ^ modified ^ padding_value
                )

            plaintext += ''.join(chr(c) for c in plaintext_block)
            prev_block = block

        plaintext = strip_pkcs_7(plaintext)
        # print plaintext
        self.assertIn(plaintext, secret_messages)

    def test_challenge18(self):
        ciphertext = base64_to_bytes('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
        nonce = '\x00' * 8
        plaintext = ctr_decrypt(ciphertext, 'YELLOW SUBMARINE', nonce)
        self.assertEqual(
            'Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ',
            plaintext
        )

        plaintext = 'the quick brown fox jumped over the lazy dog.'
        key = encryption_key()
        ciphertext = ctr_encrypt(plaintext, key, nonce)
        self.assertEqual(plaintext, ctr_decrypt(ciphertext, key, nonce))
