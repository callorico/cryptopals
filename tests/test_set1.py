import unittest
from collections import Counter
from convert import hex_to_bytes, bytes_to_hex, bytes_to_base64, base64_to_bytes
from bitops import xor, repeating_key_xor, hamming_distance, block_distance
from crack import find_best_single_byte_key, test_keysize
from utils import readlines, read
from crypto import ecb_decrypt

class TestSet1(unittest.TestCase):

    def test_challenge1(self):
        hex_input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        rawbytes = hex_to_bytes(hex_input)
        b64 = bytes_to_base64(rawbytes)
        self.assertEqual(
            'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t',
            b64
        )

    def test_challenge2(self):
        hex_input1 = '1c0111001f010100061a024b53535009181c'
        hex_input2 = '686974207468652062756c6c277320657965'

        xor_result = xor(hex_to_bytes(hex_input1), hex_to_bytes(hex_input2))
        self.assertEquals(
            '746865206b696420646f6e277420706c6179',
            bytes_to_hex(xor_result)
        )

    def test_challenge3(self):
        hex_input1 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        rawbytes = hex_to_bytes(hex_input1)

        score, translation, _ = find_best_single_byte_key(rawbytes)
        self.assertEquals(
            'Cooking MC\'s like a pound of bacon',
            translation
        )

    def test_challenge4(self):
        best_score = -1.0
        best_translation = None
        best_encrypted = None
        for encrypted in readlines('4.txt'):
            rawbytes = hex_to_bytes(encrypted)
            score, translation, _ = find_best_single_byte_key(rawbytes)
            if score > best_score:
                best_score = score
                best_encrypted = encrypted
                best_translation = translation

        # print 'Best score is: {}. Original cipher text: {}'.format(
        #     best_score,
        #     best_encrypted
        # )

        self.assertEquals(
            'Now that the party is jumping\n',
            best_translation
        )

    def test_challenge5(self):
        source_text = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
        key = 'ICE'

        cipher = repeating_key_xor(source_text, key)
        encoded = bytes_to_hex(cipher)
        self.assertEquals(
            '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f',
            encoded
        )

    def test_challenge6(self):
        self.assertEquals(
            37,
            hamming_distance('this is a test', 'wokka wokka!!!')
        )

        b64_encoded = read('6.txt')
        ciphertext = base64_to_bytes(b64_encoded)

        distances = [block_distance(k, ciphertext) for k in range(2, 41)]
        distances.sort(key=lambda t: t[0])

        dist, keysize = distances[0]
        # print 'dist: {}, key_size: {}'.format(dist, keysize)
        key = test_keysize(keysize, ciphertext)
        # print 'Testing key size: {}. Key: {}'.format(keysize, bytes_to_hex(key))

        plaintext = repeating_key_xor(ciphertext, key)
        # print 'Decrypted:\n{}'.format(plaintext)
        self.assertIn(
            'Play that funky music',
            plaintext
        )

    def test_challenge7(self):
        b64_encoded = read('7.txt')
        ciphertext = base64_to_bytes(b64_encoded)

        key = 'YELLOW SUBMARINE'

        plaintext = ecb_decrypt(ciphertext, key)

        # print plaintext
        self.assertIn('Play that funky music', plaintext)

    def test_challenge8(self):
        ecb_line_number = -1
        for line_number, line in enumerate(readlines('8.txt')):
            ciphertext = hex_to_bytes(line)
            blocks = [ciphertext[s:s+16] for s in range(0, len(ciphertext), 16)]
            counts = Counter(blocks)
            histogram = [c for _, c in counts.most_common()]
            if any(c > 2 for c in histogram):
                ecb_line_number = line_number
                # print counts
                # print ciphertext
                break

        self.assertEqual(132, ecb_line_number)
