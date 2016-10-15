import unittest
import bitops

class TestBitops(unittest.TestCase):

    def test_to_bytes_le_uses_little_endian_representation(self):
        self.assertEqual(
            '\x01\x00\x00\x00\x00\x00\x00\x00',
            bitops.to_bytes_le(1, 8)
        )

        self.assertEqual(
            '\x02\x00\x00\x00\x00\x00\x00\x00',
            bitops.to_bytes_le(2, 8)
        )

        self.assertEqual(
            '\xff\x00\x00\x00\x00\x00\x00\x00',
            bitops.to_bytes_le(255, 8)
        )

        self.assertEqual(
            '\x00\x01\x00\x00\x00\x00\x00\x00',
            bitops.to_bytes_le(256, 8)
        )

        self.assertEqual(
            '\x01\x01\x00\x00\x00\x00\x00\x00',
            bitops.to_bytes_le(257, 8)
        )

    def test_to_bytes_be_uses_big_endian_representation(self):
        self.assertEqual(
            '\x0A\x0B\x0C\x0D',
            bitops.to_bytes_be(0x0A0B0C0D, 4)
        )

    def test_from_bytes_be(self):
        self.assertEqual(
            0x0A0B0C0D0A0B0C0D,
            bitops.from_bytes_be('\x0A\x0B\x0C\x0D\x0A\x0B\x0C\x0D')
        )

    def test_xor_trim_to_shortest(self):
        self.assertEqual(
            '\x00',
            bitops.xor('\x01', '\x01\x02')
        )