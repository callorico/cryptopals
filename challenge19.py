import curses
import string
from convert import base64_to_bytes
from crypto import encryption_key, ctr_encrypt
from bitops import xor


class Translations(object):
    def __init__(self, ciphertexts):
        self.ciphertexts = ciphertexts
        max_length = max(len(c) for c in self.ciphertexts)
        self.keystream = [None] * max_length

    def __len__(self):
        return len(self.ciphertexts)

    def set_plaintext_char(self, index, pos, plaintext_val):
        if plaintext_val is None:
            self.keystream[pos] = None
        else:
            self.keystream[pos] = xor(
                self.ciphertexts[index][pos],
                plaintext_val
            )

    @property
    def plaintexts(self):
        for ciphertext in self.ciphertexts:
            yield [self._decrypt_char(i, c) for i, c in enumerate(ciphertext)]

    def _decrypt_char(self, index, ciphertext_val):
        if self.keystream[index] is None:
            return None
        else:
            return xor(self.keystream[index], ciphertext_val)


class TranslationsView(object):
    def __init__(self, translations):
        self.translations = translations
        self.x_pos = 0
        self.y_pos = 0

    def move_cursor(self, x_delta, y_delta):
        self.y_pos = self._clamp(
            self.y_pos + y_delta,
            0,
            len(self.translations)
        )

        self.x_pos = self._clamp(
            self.x_pos + x_delta,
            0,
            len(self.translations.ciphertexts[self.y_pos])
        )

    def set_plaintext_char(self, ch):
        self.translations.set_plaintext_char(self.y_pos, self.x_pos, ch)

    def event_loop(self, stdscr, *args, **kwargs):
        curses.init_pair(1, curses.COLOR_RED, curses.COLOR_RED)
        self.render(stdscr)

        while True:
            c = stdscr.getch()
            if c == 27:
                break
            elif c == curses.KEY_RIGHT:
                self.move_cursor(1, 0)
            elif c == curses.KEY_LEFT:
                self.move_cursor(-1, 0)
            elif c == curses.KEY_DOWN:
                self.move_cursor(0, 1)
            elif c == curses.KEY_UP:
                self.move_cursor(0, -1)
            elif c == curses.KEY_BACKSPACE:
                self.set_plaintext_char(None)
            elif c < 256 and chr(c) in string.printable:
                self.set_plaintext_char(chr(c))

            self.render(stdscr)
            stdscr.move(self.y_pos, self.x_pos)

    def render(self, stdscr):
        for line, plaintext in enumerate(translations.plaintexts):
            for pos, c in enumerate(plaintext):
                render_ch, attribs = self._render_char(c)
                stdscr.addch(line, pos, render_ch, attribs)

    def _render_char(self, ch):
        if ch is None:
            return '*', 0
        elif ch not in string.printable:
            return ' ', curses.color_pair(1)
        else:
            return ch, 0

    def _clamp(self, val, min, max):
        if val < min:
            return min
        elif val >= max:
            return max - 1
        else:
            return val


if __name__ == '__main__':
    plaintexts = [
        base64_to_bytes(m)
        for m in [
            'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
            'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
            'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
            'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
            'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
            'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
            'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
            'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
            'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
            'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
            'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
            'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
            'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
            'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
            'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
            'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
            'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
            'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
            'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
            'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
            'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
            'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
            'U2hlIHJvZGUgdG8gaGFycmllcnM/',
            'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
            'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
            'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
            'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
            'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
            'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
            'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
            'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
            'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
            'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
            'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
            'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
            'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
            'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
            'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
            'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
            'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
        ]
    ]

    key = encryption_key()
    nonce = '\x00' * 8
    ciphertexts = [
        ctr_encrypt(m, key, nonce)
        for m in plaintexts
    ]

    translations = Translations(ciphertexts)
    view = TranslationsView(translations)
    curses.wrapper(view.event_loop)

    # Answer: Easter 1916 by Yeats
    # Set the line third from the bottom to:
    #
    # He, too, has been changed in his turn,
    #
    # To generate the complete keystream