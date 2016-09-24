

class MT19937(object):
    n = 624
    lower_mask = (1 << 31) - 1
    upper_mask = ~lower_mask & 0xffffffff

    def __init__(self, seed):
        self._mt = [seed]
        self._index = self.n
        for i in range(1, self.n):
            prev = self._mt[i - 1]
            val = 1812433253 * (prev ^ (prev >> 30)) + 1
            self._mt.append(val & 0xffffffff)

    def next(self):
        if self._index >= self.n:
            self._twist()

        y = self._mt[self._index]
        y = y ^ ((y >> 11) & 0xffffffff)
        y = y ^ ((y << 7) & 0x9d2c5680)
        y = y ^ ((y << 15) & 0xefc60000)
        y = y ^ (y >> 18)

        self._index += 1
        return y & 0xffffffff

    def _twist(self):
        for i in range(self.n):
            x = (
                (self._mt[i] & self.upper_mask)
                + self._mt[(i + 1) % self.n] & self.lower_mask
            )
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ 0x9908b0df

            self._mt[i] = self._mt[(i + 397) % self.n] ^ xA
        self._index = 0