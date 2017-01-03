import itertools

def xor(rawbytes, rawbytes2):
    return ''.join([chr(ord(i) ^ ord(j)) for i, j in zip(rawbytes, rawbytes2)])

def repeating_key_xor(rawbytes, key):
    return xor(rawbytes, itertools.cycle(key))

def bits_set(single_byte):
    return sum([(single_byte >> i) & 0x01 for i in range(8)])

def hamming_distance(rawbytes1, rawbytes2):
    return sum([bits_set(ord(r) ^ ord(r2)) for r, r2 in zip(rawbytes1, rawbytes2)])

def block_distance(size, ciphertext):
    blocks_to_compare = 4

    blocks = []
    for start in range(0, size * blocks_to_compare, size):
        blocks.append(ciphertext[start:start+size])

    # Calculate hamming distance between each pair of blocks
    distances = [
        hamming_distance(i, j)
        for i, j in itertools.combinations(blocks, 2)
    ]

    average_distance = sum(distances) / float(len(distances))
    normalized_distance = average_distance / size

    return (normalized_distance, size)

def twiddle_bits(mask, actual_char, target_char):
    """Flips the corresponding bit in the mask whenever the actual and target
    bits differ
    """
    differing_bits = ord(actual_char) ^ ord(target_char)

    mask_bits_to_keep = (ord(mask) & ~differing_bits)
    mask_bits_to_flip = (~ord(mask) & differing_bits)

    return chr(mask_bits_to_keep | mask_bits_to_flip)

def to_bytes_le(number, length=0):
    """Returns a bytestring with the little-endian representation of the
    specified number that is zero-padded to the desired length.
    """
    bytestring = ''
    quotient = number
    while quotient:
        quotient, remainder = divmod(quotient, 256)
        bytestring += chr(remainder)

    bytestring += '\x00' * (length - (len(bytestring)))

    return bytestring

def to_bytes_be(number, length=0):
    """Returns a bytestring with the big-endian representation of the
    specified number that is zero-padded to the desired length.
    """
    return ''.join(reversed(to_bytes_le(number, length)))

def from_bytes_be(be_str):
    num = 0
    for c in be_str:
        num = (num << 8) | ord(c)

    return num

def from_bytes_le(le_str):
    return from_bytes_be(''.join(reversed(le_str)))
