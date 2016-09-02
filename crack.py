import string
import math
from bitops import xor
from collections import Counter


english_freq_vector = {
    ' ': 18.28846265,
    'E': 10.26665037,
    'T': 7.51699827,
    'A': 6.53216702,
    'O': 6.15957725,
    'N': 5.71201113,
    'I': 5.66844326,
    'S': 5.31700534,
    'R': 4.98790855,
    'H': 4.97856396,
    'L': 3.31754796,
    'D': 3.28292310,
    'U': 2.27579536,
    'C': 2.23367596,
    'M': 2.02656783,
    'F': 1.98306716,
    'W': 1.70389377,
    'G': 1.62490441,
    'P': 1.50432428,
    'Y': 1.42766662,
    'B': 1.25888074,
    'V': 0.79611644,
    'K': 0.56096272,
    'X': 0.14092016,
    'J': 0.09752181,
    'Q': 0.08367550,
    'Z': 0.05128469,
}

def vector_length(count_dict):
    return math.sqrt(sum([v * v for v in count_dict.values()]))

english_freq_vector_length = vector_length(english_freq_vector)


def single_byte_keys(length):
    for x in range(256):
        yield chr(x) * length

def english_score(rawbytes):
    if not all(c in string.printable for c in rawbytes):
        return 0.0

    canonical = [
        c.upper() for c in rawbytes if c.upper() in english_freq_vector
    ]

    counts = Counter(canonical)
    for letter in counts:
        counts[letter] /= float(len(canonical))

    # Calculate cosine against canonical english frequency vector
    numerator = 0.0
    for letter, freq in counts.iteritems():
        numerator += freq * english_freq_vector[letter]

    return numerator / (english_freq_vector_length * vector_length(counts))

def find_best_single_byte_key(rawbytes):
    best_key = None
    best_translation = None
    best_score = -1.0
    for key in single_byte_keys(len(rawbytes)):
        translation = xor(rawbytes, key)
        score = english_score(translation)
        if score > best_score:
            best_score = score
            best_key = key
            best_translation = translation

    return (best_score, best_translation, best_key)

def test_keysize(keysize, ciphertext):
    key = ''
    for offset in range(keysize):
        transposed = ''
        for start in range(0, len(ciphertext), keysize):
            if start + offset < len(ciphertext):
                transposed += ciphertext[start + offset]

        _, _, best_key = find_best_single_byte_key(transposed)
        key += best_key[0]

    return key

def is_ecb(oracle, block_size):
    plaintext = 'a' * 1000
    ciphertext = oracle(plaintext)
    repeated_blocks = len(plaintext) / block_size

    # With ECB mode there should be a lot of repeated blocks since the cipher
    # text doesn't change if the same plaintext is used. We'll just use 90% as
    # a rule of thumb.
    blocks = block_histogram(ciphertext, block_size)
    _, count = blocks.most_common(1)[0]
    return count >= (repeated_blocks * 0.9)

def block_histogram(ciphertext, block_size):
    blocks = [
        ciphertext[s:s+block_size]
        for s in range(0, len(ciphertext), block_size)
    ]
    return Counter(blocks)

def find_prefix_length(oracle, block_size):
    """Return a tuple where the first element is the block-aligned length of
    the oracle's random prefix and the second element is the number of padding
    bytes that need to be added to the last block in the random prefix to block
    align it.
    """

    # Pass N repeated blocks of the same content to the oracle and look for
    # N consecutive repeated blocks in the ciphertext. First prefix the N
    # blocks with 0-bytes, if N matches are not found, then try prefixing with
    # 1-byte, and so on until all N-1 possible padding bytes are tried.
    repeated_blocks = 5
    for padding in range(0, block_size):
        content_length = padding + (block_size * repeated_blocks)
        result = oracle('A' * content_length)
        repeats = 0
        start_position = 0
        prev_block = None
        for start in range(0, len(result), block_size):
            block = result[start:start + block_size]
            if block == prev_block:
                repeats += 1
                if repeats == repeated_blocks:
                    break
            else:
                start_position = start
                repeats = 1

            prev_block = block

        if repeats == repeated_blocks:
            return start_position, padding

    raise ValueError('Unable to determine prefix length')

def discover_block_size(oracle):
    original_length = len(oracle(''))
    for i in range(1, 256):
        new_length = len(oracle('A' * i))
        if new_length > original_length:
            diff = new_length - original_length
            return diff