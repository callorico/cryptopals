import unittest
import crack
import bitops
import convert

class TestCrack(unittest.TestCase):

    def test_sha1_padding_length(self):
        for i in xrange(10000):
            padding = crack.sha1_padding(i)
            total_message_length = len(padding) + i
            self.assertTrue(
                total_message_length % 64 == 0,
                'Invalid padding length for message '
                'size {}: {}'.format(i, len(padding))
            )

            self.assertEquals('\x80', padding[0])
            message_length = bitops.from_bytes_be(padding[-8:])

            self.assertEquals(
                i * 8,
                message_length,
                'Invalid message bit length for message '
                'size {}: {}'.format(i, message_length))

            self.assertTrue(
                all(c == '\x00' for c in padding[1:-8]),
                'Unexpected padding NUL values for message size {}'.format(i)
            )
