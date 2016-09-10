import unittest
import bitops

class TestBitops(unittest.TestCase):

    def test_to_bytes_uses_little_endian_representation(self):
        self.assertEqual(
            '\x01\x00\x00\x00\x00\x00\x00\x00',
            bitops.to_bytes(1, 8)
        )

        self.assertEqual(
            '\x02\x00\x00\x00\x00\x00\x00\x00',
            bitops.to_bytes(2, 8)
        )

        self.assertEqual(
            '\xff\x00\x00\x00\x00\x00\x00\x00',
            bitops.to_bytes(255, 8)
        )

        self.assertEqual(
            '\x00\x01\x00\x00\x00\x00\x00\x00',
            bitops.to_bytes(256, 8)
        )

        self.assertEqual(
            '\x01\x01\x00\x00\x00\x00\x00\x00',
            bitops.to_bytes(257, 8)
        )

    def test_xor_trim_to_shortest(self):
        self.assertEqual(
            '\x00',
            bitops.xor('\x01', '\x01\x02')
        )