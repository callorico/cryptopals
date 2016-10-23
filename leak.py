import web
import time
import crypto
import convert

urls = (
    '/test', 'TimingLeak'
)
app = web.application(urls, globals())
# key = crypto.encryption_key()
key = 'YELLOW SUBMARINE'

class TimingLeak(object):

    def GET(self):
        qs = web.input()

        with open(qs.file, 'r') as f:
            contents = f.read()
        expected = crypto.hmac(key, contents)
        # print 'expected: {}'.format(convert.bytes_to_hex(expected))

        actual = convert.hex_to_bytes(qs.signature)

        is_mac_valid = self._insecure_compare(expected, actual)
        if not is_mac_valid:
            raise web.InternalError('Invalid MAC')

        return 'Valid MAC'

    def _insecure_compare(self, expected, actual):
        if len(expected) != len(actual):
            return False

        for e, a in zip(expected, actual):
            if e != a:
                return False
            time.sleep(50.0 / 1000.0)

        return True

if __name__ == '__main__':
    app.run()
