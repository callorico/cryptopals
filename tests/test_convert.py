import unittest
import convert

class TestConvert(unittest.TestCase):

    def test_base64_to_bytes_with_padding(self):
        self.assertEquals('M', convert.base64_to_bytes('TQ=='))
        self.assertEquals('Ma', convert.base64_to_bytes('TWE='))

    def test_bytes_to_base64_with_padding(self):
        self.assertEquals('TQ==', convert.bytes_to_base64('M'))
        self.assertEquals('TWE=', convert.bytes_to_base64('Ma'))
