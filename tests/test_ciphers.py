import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ciphers import caesar, feistel, lfsr_stream, super_cipher, vigenere  # noqa: E402
from ciphers.utils import from_hex  # noqa: E402


class TestVigenere(unittest.TestCase):
    def test_known_vector(self):
        out, _ = vigenere.encrypt("ATTACKATDAWN", "LEMON")
        self.assertEqual(out, "LXFOPVEFRNHR")

    def test_roundtrip_mixed(self):
        text = "Halo, Kriptografi 2026! Ini Uji Coba."
        enc, _ = vigenere.encrypt(text, "Kripto")
        dec, _ = vigenere.decrypt(enc, "Kripto")
        self.assertEqual(dec, text)

    def test_bad_key(self):
        with self.assertRaises(ValueError):
            vigenere.encrypt("abc", "123")


class TestCaesar(unittest.TestCase):
    def test_known(self):
        out, _ = caesar.encrypt("Hello, World!", "3")
        self.assertEqual(out, "Khoor, Zruog!")

    def test_roundtrip_and_wrap(self):
        text = "Kriptografi XYZ xyz 2026\n\u00e9"
        for k in (0, 3, 25, 26, -5, 100):
            enc, _ = caesar.encrypt(text, k)
            dec, _ = caesar.decrypt(enc, k)
            self.assertEqual(dec, text)

    def test_bad_key(self):
        with self.assertRaises(ValueError):
            caesar.encrypt("abc", "x")


class TestLFSR(unittest.TestCase):
    def test_materi_example(self):
        bits = "".join(map(str, lfsr_stream.keystream("1111", 15)))
        self.assertEqual(bits, "111101011001000")

    def test_max_period(self):
        """Periode harus tepat 2^n - 1 (tidak ada periode yang lebih pendek)."""
        for n, seed in ((4, "1111"), (8, "10110001"), (16, "1010110011100001")):
            period = 2 ** n - 1
            ks = lfsr_stream.keystream(seed, 2 * period)
            self.assertEqual(ks[:period], ks[period:2 * period])
            for p in range(1, period):
                if period % p == 0:
                    self.assertNotEqual(ks[:period], ks[p:p + period])

    def test_roundtrip_unicode(self):
        text = "Halo Kriptografi, ini uji 123 dan é ü 你好"
        for seed in ("1111", "10110001", "1010110011100001"):
            enc, _ = lfsr_stream.encrypt(text, seed)
            dec, _ = lfsr_stream.decrypt(enc, seed)
            self.assertEqual(dec, text)

    def test_bad_seed(self):
        for s in ("0000", "101", "abcd"):
            with self.assertRaises(ValueError):
                lfsr_stream.encrypt("x", s)


class TestFeistel(unittest.TestCase):
    def test_roundtrip_ecb_cbc(self):
        for mode in ("ECB", "CBC"):
            for n in range(0, 41):
                data = bytes((i * 7 + 3) % 256 for i in range(n))
                enc, _ = feistel.encrypt_bytes(data, "KUNCI123", mode)
                dec, _ = feistel.decrypt_bytes(enc, "KUNCI123", mode)
                self.assertEqual(dec, data)

    def test_key_lengths(self):
        for key in ("A", "abc", "12345678", "kunci yang sangat panjang sekali"):
            enc, _ = feistel.encrypt("Tes panjang kunci", key, "ECB")
            dec, _ = feistel.decrypt(enc, key, "ECB")
            self.assertEqual(dec, "Tes panjang kunci")

    def test_ecb_deterministic_and_padding_size(self):
        enc1, _ = feistel.encrypt("ABCDEFGH", "kunci", "ECB")
        enc2, _ = feistel.encrypt("ABCDEFGH", "kunci", "ECB")
        self.assertEqual(enc1, enc2)
        self.assertEqual(len(from_hex(enc1)), 16)  # 8 byte + 1 blok padding penuh

    def test_wrong_key_detected_or_garbled(self):
        enc, _ = feistel.encrypt("Rahasia penting sekali", "KUNCI123", "ECB")
        try:
            dec, _ = feistel.decrypt(enc, "SALAHKEY", "ECB")
            self.assertNotEqual(dec, "Rahasia penting sekali")
        except ValueError:
            pass

    def test_bad_ciphertext(self):
        with self.assertRaises(ValueError):
            feistel.decrypt("ABC", "k", "ECB")
        with self.assertRaises(ValueError):
            feistel.decrypt("0011", "k", "ECB")


class TestSuper(unittest.TestCase):
    def test_roundtrip(self):
        text = "Halo Kriptografi, ini super enkripsi! 2026\nBaris kedua é"
        for mode in ("ECB", "CBC"):
            enc, steps = super_cipher.encrypt(text, "KRIPTO", "3", "1010110011100001", "KUNCI123", mode)
            self.assertTrue(len(steps) > 10)
            dec, _ = super_cipher.decrypt(enc, "KRIPTO", "3", "1010110011100001", "KUNCI123", mode)
            self.assertEqual(dec, text)

    def test_wrong_lfsr_seed_errors_or_garbles(self):
        enc, _ = super_cipher.encrypt("Tes", "KRIPTO", "3", "1010110011100001", "KUNCI123", "ECB")
        try:
            dec, _ = super_cipher.decrypt(enc, "KRIPTO", "3", "1111", "KUNCI123", "ECB")
            self.assertNotEqual(dec, "Tes")
        except ValueError:
            pass


if __name__ == "__main__":
    unittest.main()
