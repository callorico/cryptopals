import unittest
import random
import crack
import bitops
import itertools
import utils
from collections import OrderedDict, Counter, defaultdict
from convert import base64_to_bytes, bytes_to_hex
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

    def test_challenge19(self):
        plaintexts = [
            base64_to_bytes(m)
            for m in [
                'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
                'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
                'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
                'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
                'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
                'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
                'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
                'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
                'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
                'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
                'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
                'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
                'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
                'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
                'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
                'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
                'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
                'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
                'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
                'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
                'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
                'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
                'U2hlIHJvZGUgdG8gaGFycmllcnM/',
                'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
                'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
                'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
                'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
                'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
                'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
                'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
                'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
                'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
                'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
                'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
                'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
                'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
                'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
                'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
                'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
                'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
            ]
        ]

        key = encryption_key()
        nonce = '\x00' * 8
        ciphertexts = [
            ctr_encrypt(m, key, nonce)
            for m in plaintexts
        ]

        self.fail('TODO: Implement this...')

    def test_challenge20(self):
        plaintexts = [
            base64_to_bytes(line)
            for line in utils.readlines('20.txt')
        ]

        key = encryption_key()
        nonce = '\0' * 8
        ciphertexts = [
            ctr_encrypt(m, key, nonce)
            for m in plaintexts
        ]

        # Because of the fixed-nonce, the encrypted keystream bytes are
        # repeated for every plaintext message.
        #
        # ciphertext[i] ^ keystream[i] = plaintext[i]
        #
        # We can create a transposed ciphertext message by concatenating
        # ciphertext[i] from every encrypted message and then xor'ing that
        # against a guessed keystream byte. Then we can test whether the
        # resulting plaintext looks like english based on character
        # distributions. If so, then we've figured out the keystream byte.

        keystream = ''
        for index in itertools.count():
            transposed = ''.join(m[index:index+1] for m in ciphertexts)
            if not transposed:
                break

            score, _, key = crack.find_best_single_byte_key(
                transposed,
            )
            # print 'Best score for index {}: {}'.format(index, score)
            keystream += key[0]

        for m in ciphertexts:
            print bitops.xor(m, keystream)
