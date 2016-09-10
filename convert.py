hex_alphabet = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
b64_alphabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/']

def hex_to_bytes(hexchars):
    encoded = ''
    for i in range(0, len(hexchars), 2):
        upper = hex_alphabet.index(hexchars[i])
        lower = hex_alphabet.index(hexchars[i + 1])
        encoded += chr((upper << 4) | lower)

    return encoded

def bytes_to_hex(rawbytes):
    encoded = ''
    mask = 0b00001111
    for i in rawbytes:
        encoded += hex_alphabet[(ord(i) >> 4 & mask)]
        encoded += hex_alphabet[(ord(i) & mask)]

    return encoded

def bytes_to_base64(rawbytes):
    encoded = ''
    mask = 0b000000000000000000111111
    for i in range(0, len(rawbytes), 3):
        numeric = (ord(rawbytes[i]) << 16)
        if (i + 1) < len(rawbytes):
            numeric |= (ord(rawbytes[i + 1]) << 8)

        if (i + 2) < len(rawbytes):
            numeric |= ord(rawbytes[i + 2])

        encoded += b64_alphabet[(numeric >> 18 & mask)]
        encoded += b64_alphabet[(numeric >> 12 & mask)]

        if (i + 1) < len(rawbytes):
            encoded += b64_alphabet[(numeric >> 6 & mask)]

        if (i + 2) < len(rawbytes):
            encoded += b64_alphabet[(numeric & mask)]

    remainder = len(rawbytes) % 3
    if remainder:
        padding = '=' * (3 - remainder)
    else:
        padding = ''

    return encoded + padding

def base64_to_bytes(b64chars):
    encoded = ''
    for i in range(0, len(b64chars), 4):
        first = base64_to_int(b64chars[i])
        second = base64_to_int(b64chars[i + 1])
        third = base64_to_int(b64chars[i + 2], allow_padding_char=True)
        fourth = base64_to_int(b64chars[i + 3], allow_padding_char=True)

        numeric = (first << 18) | (second << 12) | (third << 6) | fourth

        encoded += chr((numeric >> 16) & 0xff)
        encoded += chr((numeric >> 8) & 0xff)
        encoded += chr(numeric & 0xff)

    if b64chars.endswith('=='):
        return encoded[:-2]
    elif b64chars.endswith('='):
        return encoded[:-1]
    else:
        return encoded

def base64_to_int(b64char, allow_padding_char=False):
    if allow_padding_char and b64char == '=':
        return 0

    return b64_alphabet.index(b64char)
