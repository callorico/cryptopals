import unittest
import utils
import convert
import crypto
import bitops
import urllib


def edit(ciphertext, key, nonce, offset, plaintext):
    orig_plaintext = crypto.ctr_decrypt(ciphertext, key, nonce)
    new_plaintext = (orig_plaintext[:offset]
        + plaintext
        + orig_plaintext[offset + len(plaintext):]
    )
    return crypto.ctr_encrypt(new_plaintext, key, nonce)

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
