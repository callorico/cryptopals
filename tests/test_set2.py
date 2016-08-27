import unittest
import os
import itertools
import random
import urllib
import urlparse
from collections import OrderedDict
from convert import base64_to_bytes
from crypto import (pkcs_7, cbc_decrypt, cbc_encrypt, ecb_encrypt, ecb_decrypt,
                    encryption_key, iv, random_padding, strip_pkcs_7,
                    PaddingError)
from crack import is_ecb, discover_block_size
from utils import read

def multimode_oracle(plaintext, mode):
    tampered = random_padding() + plaintext + random_padding()

    key = encryption_key()

    if mode == 'ecb':
        return ecb_encrypt(tampered, key)
    elif mode == 'cbc':
        return cbc_encrypt(tampered, key, iv())

    raise ValueError('Unknown mode')

def ecb_oracle(plaintext, key='YELLOW SUBMARINE'):
    secret = base64_to_bytes('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    full = plaintext + secret
    return ecb_encrypt(full, key)

def decrypt_ecb_with_oracle(oracle, block_size):
    plaintext = 'A' * block_size

    for block_index in itertools.count():
        for offset in range(1, block_size + 1):
            prefix = plaintext[-(block_size - 1):]

            # Use the oracle to build a map between the encrypted block and all
            # possible answers for the byte in position pos
            lookup = {}
            for i in range(256):
                block = prefix + chr(i)
                result = oracle(block)
                lookup[result[:block_size]] = chr(i)

            # Offset the real data by the desired amount. The first
            # block_size - 1 characters in the target block should be the
            # same as prefix
            padding = plaintext[:(block_size - offset)]
            result = oracle(padding)

            # Compare the final byte against the lookup data.
            start = block_index * block_size
            end = start + block_size
            val = lookup[result[start:end]]
            if ord(val) == 1 and end == len(result):
                # If this is the last block of the cipher text and the
                # decrypted value is 1, then this is the padding byte and we
                # are done.
                #
                # Strip off the leading A's
                return plaintext[block_size:]
            plaintext += val

def profile_for(email):
    user_dict = OrderedDict()
    user_dict['email'] = email
    user_dict['uid'] = 10
    user_dict['role'] = 'user'

    return urllib.urlencode(user_dict)

def encrypt_profile(email, key):
    qs = profile_for(email)
    return ecb_encrypt(qs, key)

def decrypt_profile(ciphertext, key):
    qs = ecb_decrypt(ciphertext, key)
    return urlparse.parse_qs(qs)

class TestSet2(unittest.TestCase):

    def test_challenge9(self):
        self.assertEquals(
            'YELLOW SUBMARINE\x04\x04\x04\x04',
            pkcs_7('YELLOW SUBMARINE', 20)
        )

    def test_challenge10(self):
        ciphertext = base64_to_bytes(read('10.txt'))

        key = 'YELLOW SUBMARINE'
        iv = '\x00' * 16
        plaintext = cbc_decrypt(ciphertext, key, iv)
        ciphertext = cbc_encrypt(plaintext, key, iv)

        plaintext2 = cbc_decrypt(ciphertext, key, iv)
        self.assertEquals(plaintext, plaintext2)

    def test_challenge11(self):
        sample = 'the quick brown fox jumped over the lazy dog'
        key = 'YELLOW SUBMARINE'
        ciphertext = ecb_encrypt(sample, key)
        plaintext = ecb_decrypt(ciphertext, key)
        self.assertEquals(sample, plaintext)

        ciphertext2 = ecb_encrypt(plaintext, key)
        self.assertEquals(ciphertext, ciphertext2)

        for _ in range(100):
            if random.random() < 0.5:
                mode = 'cbc'
            else:
                mode = 'ecb'

            oracle = lambda p: multimode_oracle(p, mode)
            self.assertEqual(
                mode == 'ecb',
                is_ecb(oracle, 16)
            )

    def test_challenge12(self):
        block_size = discover_block_size(ecb_oracle)
        self.assertEqual(16, block_size)
        self.assertTrue(is_ecb(ecb_oracle, block_size))

        plaintext = decrypt_ecb_with_oracle(ecb_oracle, block_size)
        # print plaintezt
        self.assertIn(
            'No, I just drove by',
            plaintext
        )

    def test_challenge13(self):
        # email=ryan%40rescale.com&uid=10&role=user

        # Generate some ciphertext where the 2nd block starts with admin
        # 0               1               2               3
        # email=AAAAAAAAAAadmin&uid=10&role=user
        key = encryption_key()
        ciphertext = encrypt_profile('AAAAAAAAAAadmin', key)
        admin_block = ciphertext[16:]

        # print ecb_decrypt(admin_block, key)
        # Provide an email address that causes a cipher block to end with role=
        # 0               1               2               3
        # email=ryan%2BAAAAAAAAAA%40gmail.com&uid=10&role=user
        ciphertext = encrypt_profile('ryan+AAAAAAAAAA@gmail.com', key)
        prefix = ciphertext[:(16 * 3)]

        # Then paste the admin block to the end of that
        manipulated = prefix + admin_block

        profile = decrypt_profile(manipulated, key)
        self.assertIn('admin', profile['role'])

    def test_challenge15(self):
        self.assertEquals(
            'ICE ICE BABY',
            strip_pkcs_7('ICE ICE BABY\x04\x04\x04\x04')
        )

        with self.assertRaises(PaddingError):
            strip_pkcs_7('ICE ICE BABY\x05\x05\x05\x05')

        with self.assertRaises(PaddingError):
            strip_pkcs_7('ICE ICE BABY\x01\x02\x03\x04')
