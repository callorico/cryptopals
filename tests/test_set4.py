import unittest
import utils
import convert
import crypto
import bitops
import urllib
import string


def edit(ciphertext, key, nonce, offset, plaintext):
    orig_plaintext = crypto.ctr_decrypt(ciphertext, key, nonce)
    new_plaintext = (orig_plaintext[:offset]
        + plaintext
        + orig_plaintext[offset + len(plaintext):]
    )
    return crypto.ctr_encrypt(new_plaintext, key, nonce)

def encrypt_url(content, key):
    return crypto.cbc_encrypt(full_content, key, key)

def encrypt_kvps(content, key, nonce):
    full_content = (
        'comment1=cooking%20MCs;userdata='
        + urllib.quote(content)
        + ';comment2=%20like%20a%20pound%20of%20bacon'
    )

    return crypto.ctr_encrypt(full_content, key, nonce)

def is_admin(ciphertext, key, nonce):
    decrypted = crypto.ctr_decrypt(ciphertext, key, nonce)
    return ';admin=true;' in decrypted

def encrypt_kvps(content, key, nonce):
    full_content = (
        'comment1=cooking%20MCs;userdata='
        + urllib.quote(content)
        + ';comment2=%20like%20a%20pound%20of%20bacon'
    )

    return crypto.ctr_encrypt(full_content, key, nonce)

def encrypt_kvps_cbc(content, key):
    full_content = (
        'comment1=cooking%20MCs;userdata='
        + urllib.quote(content)
        + ';comment2=%20like%20a%20pound%20of%20bacon'
    )

    return crypto.cbc_encrypt(full_content, key, key)

def is_admin_cbc(ciphertext, key):
    decrypted = crypto.cbc_decrypt(ciphertext, key, key)
    if not all(ord(c) < 128 for c in decrypted):
        raise ValueError('Invalid message ' + decrypted)

    return ';admin=true;' in decrypted

class TestSet4(unittest.TestCase):

    def test_challenge25(self):
        ciphertext = convert.base64_to_bytes(utils.read('25.txt'))
        plaintext = crypto.ecb_decrypt(ciphertext, 'YELLOW SUBMARINE')

        key = crypto.encryption_key()
        nonce = '\x00' * 8
        ciphertext = crypto.ctr_encrypt(plaintext, key, nonce)

        # The edit function lets us recover the original keystream because
        # in CTR mode: plaintext ^ keystream = ciphertext and then through
        # the magic of xor:
        #
        # plaintext ^ ciphertext = keystream
        #
        # Through the edit function, we know the plaintext and ciphertext
        # for every index in the byte stream.

        keystream = ''
        for offset in range(len(ciphertext)):
            new_ciphertext = edit(ciphertext, key, nonce, offset, 'A')
            keystream += bitops.xor(new_ciphertext[offset], 'A')

        recovered_plaintext = bitops.xor(ciphertext, keystream)
        self.assertEquals(plaintext, recovered_plaintext)

    def test_challenge26(self):
        key = crypto.encryption_key()
        nonce = '\x00' * 8
        ciphertext = encrypt_kvps('admin=true', key, nonce)
        self.assertFalse(
            is_admin(ciphertext, key, nonce),
            'Should have escaped the ='
        )

        # 0               1               2               3               4
        # comment1=cooking%20MCs;userdata=true;comment2=%20like%20a%20pound%20of%20bacon
        # comment1=cooking%20MCs;us;admin=true;comment2=%20like%20a%20pound%20of%20bacon
        ciphertext = encrypt_kvps('true', key, nonce)
        self.assertFalse(is_admin(ciphertext, key, nonce))

        # ciphertext ^ orig plaintext = keystream
        # keystream ^ (desired plaintext) = new ciphertext to splice in
        start = 25
        orig_plaintext = 'erdata'
        keystream = bitops.xor(
            ciphertext[start:start + len(orig_plaintext)],
            orig_plaintext
        )

        tampered_chunk = bitops.xor(keystream, ';admin')

        tampered_ciphertext = (ciphertext[:start]
            + tampered_chunk
            + ciphertext[start + len(tampered_chunk):]
        )

        self.assertTrue(is_admin(tampered_ciphertext, key, nonce))

    def test_challenge27(self):
        key = crypto.encryption_key()
        ciphertext = encrypt_kvps_cbc('hello', key)

        tampered = (
            ciphertext[:16]
            + ('\x00' * 16)
            + ciphertext[:16]
            + ciphertext[16:]
        )

        try:
            is_admin_cbc(tampered, key)
        except ValueError as e:
            expected_prefix = 'Invalid message '
            plaintext = e.message[len(expected_prefix):]

        # C1 = 0
        # P2 = D(E(P0 ^ IV)) ^ C1
        # P2 = P0 ^ IV ^ 0
        # P2 = P0 ^ IV
        # The first block in the recovered plaintext is P0 and iv = key so:
        # P0 ^ P2 = IV = KEY
        #
        # The 3rd plaintext block is
        # D(E(P0 ^ IV)) ^ 0
        recovered_key = bitops.xor(plaintext[:16], plaintext[32:48])
        self.assertEqual(key, recovered_key)
