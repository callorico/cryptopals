import unittest
import random
import crypto
import convert
from sha1 import Sha1Hash
from bitops import to_bytes_le


class Alice(object):
    def __init__(self, p, g):
        self.r = random.SystemRandom()
        self.p = p
        self.g = g

        self.a = self.r.randrange(self.p)
        self.A = pow(self.g, self.a, self.p)
        self.messages = []

    def send(self, receiver, message):
        self.messages.append(message)

        B = receiver.handshake(self.p, self.g, self.A)
        s = pow(B, self.a, self.p)

        key = Sha1Hash().update(to_bytes_le(s)).digest()[:16]

        iv = crypto.iv()
        ciphertext = crypto.cbc_encrypt(message, key, iv) + iv
        returned_message = receiver.echo(ciphertext)

        returned_ciphertext = returned_message[:-16]
        returned_iv = returned_message[-16:]

        decrypted = crypto.cbc_decrypt(
            returned_ciphertext,
            key,
            returned_iv
        )

        return decrypted

class Bob(object):
    def __init__(self):
        self.r = random.SystemRandom()
        self.messages = []

    def handshake(self, p, g, A):
        self.b = self.r.randrange(p)
        self.p = p
        self.A = A
        B = pow(g, self.b, p)

        return B

    def echo(self, message):
        s = pow(self.A, self.b, self.p)
        key = Sha1Hash().update(to_bytes_le(s)).digest()[:16]

        ciphertext = message[:-16]
        iv = message[-16:]
        plaintext = crypto.cbc_decrypt(ciphertext, key, iv)

        self.messages.append(plaintext)
        iv = crypto.iv()
        return crypto.cbc_encrypt(plaintext, key, iv) + iv


class Mort(object):
    def __init__(self, receiver):
        self.receiver = receiver
        self.messages = []

    def handshake(self, p, g, A):
        self.p = p
        self.g = g
        self.A = A
        self.B = self.receiver.handshake(p, g, p)

        return p

    def echo(self, message):
        response = self.receiver.echo(message)

        # Our malicious middleman has returned p to Alice.
        # Alice uses this value as B.
        # Alice generates her key with: (B ** a) % p
        # Because B == p, p ** a will always be an exact multiple of p so the
        # mod value will be 0 regardless of the value of a.

        key = Sha1Hash().digest()[:16]

        ciphertext = message[:-16]
        iv = message[-16:]

        plaintext = crypto.cbc_decrypt(ciphertext, key, iv)

        self.messages.append(plaintext)
        return response


class TestSet5(unittest.TestCase):

    def setUp(self):
        self.p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
        self.g = 2

    def test_challenge33(self):
        r = random.SystemRandom()

        p = self.p
        g = self.g

        a = r.randrange(p)
        A = pow(g, a, p)

        b = r.randrange(p)
        B = pow(g, b, p)

        s = pow(B, a, p)
        s2 = pow(A, b, p)

        self.assertEqual(s, s2)

    def test_challenge34(self):
        a = Alice(p=self.p, g=self.g)
        b = Bob()
        message = a.send(b, 'yellow submarine')
        self.assertEquals('yellow submarine', message)
        self.assertEquals('yellow submarine', b.messages[-1])

        m = Mort(b)
        message = a.send(m, 'hello world 2')
        self.assertEquals('hello world 2', message)
        self.assertEquals('hello world 2', m.messages[-1])
