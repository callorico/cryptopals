import string
import math
import itertools
from bitops import xor, to_bytes_be
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

first_letter_english_freq_vector = {
    'A': 11.602,
    'B': 4.702,
    'C': 3.511,
    'D': 2.670,
    'E': 2.007,
    'F': 3.779,
    'G': 1.950,
    'H': 7.232,
    'I': 6.286,
    'J': 0.597,
    'K': 0.590,
    'L': 2.705,
    'M': 4.383,
    'N': 2.365,
    'O': 6.264,
    'P': 2.545,
    'Q': 0.173,
    'R': 1.653,
    'S': 7.755,
    'T': 16.671,
    'U': 1.487,
    'V': 0.649,
    'W': 6.753,
    'X': 0.017,
    'Y': 1.620,
    'Z': 0.034,
}

def vector_length(count_dict):
    return math.sqrt(sum([v * v for v in count_dict.values()]))

def single_byte_keys(length):
    for x in range(256):
        yield chr(x) * length

def english_score(rawbytes, freq_vector=None, allowed_chars=None):
    if allowed_chars is None:
        allowed_chars = string.printable

    if not all(c in allowed_chars for c in rawbytes):
        return 0.0

    canonical = [c.upper() for c in rawbytes]
    if not canonical:
        return 0.0

    if freq_vector is None:
        freq_vector = english_freq_vector

    counts = Counter(canonical)

    # Calculate cosine against the specified english frequency vector
    numerator = 0.0
    for letter, freq in counts.iteritems():
        numerator += freq * freq_vector.get(letter, 0.0)

    return numerator / (vector_length(freq_vector) * vector_length(counts))

def find_best_single_byte_key(rawbytes, freq_vector=None, allowed_chars=None):
    best_key = None
    best_translation = None
    best_score = -1.0
    for key in single_byte_keys(len(rawbytes)):
        translation = xor(rawbytes, key)
        score = english_score(
            translation,
            freq_vector=freq_vector,
            allowed_chars=allowed_chars
        )
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

def untemper(v):
    # Undo each of the Mersenne Twister tempering operations in reverse order

    # y ^ (y >> 18)
    v = invert_right_shift(v, 18)

    # # y = y ^ ((y << 15) & 0xefc60000)
    v = invert_left_shift(v, 15, 0xefc60000)

    # y = y ^ ((y << 7) & 0x9d2c5680)
    v = invert_left_shift(v, 7, 0x9d2c5680)

    # y = y ^ ((y >> 11) & 0xffffffff)
    v = invert_right_shift(v, 11)

    return v

def invert_right_shift(v, bits):
    # Recover the untempered bits (u) in chunks of len(bits) marching from
    # left to right.
    # The right shift sets the leftmost len(bits) to 0. This is xor'ed
    # against the untempered value and since u ^ 0 = u, we have the leftmost
    # len(bits). Chunk n of the untempered value can be recovered by
    # xor'ing chunk n of the tempered value against chunk n-1 of the
    # untempered value.

    u = 0
    max_shift = 32 - bits
    for offset in itertools.chain(range(max_shift, 0, -bits), [0]):
        mask = ((1 << bits) - 1) << offset
        u |= (v ^ (u >> bits)) & mask

    return u

def invert_left_shift(v, bits, magic):
    # Recover the untempered bits in chunks of len(bits) marching from
    # right to left.
    # The left shift sets the rightmost len(bits) to 0. Since we know the
    # magic value, we can xor this against the tempered value to recover the
    # rightmost chunk of the untempered value. Now, chunk n of the untempered
    # value can be recovered by xor'ing chunk n of the tempered value against
    # chunk n-1 of the untempered value AND'ed with chunk n-1 of the magic
    # value.
    u = 0
    max_shift = 32 - bits
    for offset in itertools.chain(range(0, max_shift, bits), [max_shift]):
        mask = ((1 << bits) - 1) << offset
        u |= (v ^ ((u << bits) & magic)) & mask

    return u

def sha1_padding(message_length_bytes):
    padding = '\x80'

    padding_length = ((56 - (message_length_bytes + 1) % 64) % 64)
    padding += '\x00' * padding_length

    message_length_bits = message_length_bytes * 8
    padding += to_bytes_be(message_length_bits, 8)

    return padding