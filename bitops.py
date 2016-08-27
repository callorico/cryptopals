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
