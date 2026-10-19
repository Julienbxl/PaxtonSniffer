# SPDX-License-Identifier: GPL-3.0-only
"""Host tests of the published C decoder and acceptance rules, with synthetic data."""

import ctypes
from pathlib import Path
import random
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


class Decode(ctypes.Structure):
    _fields_ = [("word", ctypes.c_uint32), ("onset_q8", ctypes.c_int32),
                ("half_q8", ctypes.c_int32), ("peak_count", ctypes.c_uint16),
                ("threshold", ctypes.c_uint16), ("sof_error_q8", ctypes.c_uint16),
                ("errors", ctypes.c_uint8), ("status", ctypes.c_uint8)]


def encode_digits(digits):
    bits = ""
    for char in digits:
        value = int(char, 16)
        parity = 1 ^ (value.bit_count() & 1)
        bits += str(parity) + f"{value:04b}"
    return int(bits.ljust(32, "0"), 2)


def synthetic_mad(word, half_us=128, count=749):
    values = [2] * count
    bits = [1] * 5 + [(word >> bit) & 1 for bit in range(31, -1, -1)]
    previous = False
    edges = []
    for index, bit in enumerate(bits):
        for half, level in enumerate((bool(bit), not bool(bit))):
            if level != previous:
                center = round((1759 + (2 * index + half) * half_us - 815) / 16)
                if 1 <= center < count - 1:
                    values[center - 1:center + 2] = [10, 40, 10]
                    edges.append(center)
            previous = level
    return values, edges


class ReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="paxton-host-")
        temporary = Path(cls.temporary.name)
        # Compile the actual application functions, not a Python reimplementation.
        protocol = (ROOT / "app/hitag2_protocol.c").read_text()
        consensus = protocol[protocol.index("#define DIRECT_CONFIRMATIONS"):
                             protocol.index("/*\n * Passive compact")]
        start = protocol.rindex("static bool paxton_digits_from_bits(")
        parity = protocol[start:protocol.index("static bool classify_reader_pair(", start)]
        host = """
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
""" + consensus + parity + """
void test_reset(void) {
    memset(direct_pages, 0, sizeof(direct_pages));
    memset(captured_digits, 0, sizeof(captured_digits));
    capture_ready = false;
    capture_active = false;
    captured_id = 0;
}
bool test_observe(const char* label, uint32_t word, uint32_t reader_us,
                  uint32_t count, uint32_t errors, bool locked) {
    uint8_t bits[32];
    for(uint32_t i = 0; i < 32; i++) bits[i] = (word >> (31 - i)) & 1;
    char digits[9];
    uint32_t n;
    bool parity_ok = paxton_digits_from_bits(bits, 32, digits, sizeof(digits), &n);
    return observe_direct_page(label, bits, count, errors, locked, reader_us, parity_ok, digits);
}
uint32_t test_id(void) { return captured_id; }
const char* test_digits(void) { return captured_digits; }
bool test_ready(void) { return capture_ready; }
uint32_t test_count(uint32_t page) { return best_direct_candidate(page)->count; }
"""
        source = temporary / "acceptance.c"
        source.write_text(host)
        library = temporary / "receiver.so"
        subprocess.run(["cc", "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror",
                        "-shared", "-fPIC", str(ROOT / "app/hitag2_edge_decode.c"),
                        str(source), "-o", str(library)], check=True)
        cls.library = ctypes.CDLL(str(library))
        cls.decoder = cls.library.hitag2_edge_decode
        cls.decoder.argtypes = [ctypes.POINTER(ctypes.c_uint16), ctypes.c_size_t,
                               ctypes.c_uint16, ctypes.c_uint16, ctypes.POINTER(Decode)]
        cls.decoder.restype = ctypes.c_bool
        cls.observe = cls.library.test_observe
        cls.observe.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32,
                               ctypes.c_uint32, ctypes.c_uint32, ctypes.c_bool]
        cls.observe.restype = ctypes.c_bool
        cls.library.test_id.restype = ctypes.c_uint32
        cls.library.test_digits.restype = ctypes.c_char_p
        cls.library.test_ready.restype = ctypes.c_bool
        cls.library.test_count.argtypes = [ctypes.c_uint32]
        cls.library.test_count.restype = ctypes.c_uint32

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.library.test_reset()

    def decode(self, values, step=16):
        samples = (ctypes.c_uint16 * len(values))(*values)
        result = Decode()
        return self.decoder(samples, len(samples), step, 800, ctypes.byref(result)), result

    def submit(self, page, digits, time, count=32, errors=0, locked=True):
        return self.observe(page.encode(), encode_digits(digits), time, count, errors, locked)

    def test_complete_frames_have_exact_payload(self):
        randomizer = random.Random(20261016)
        words = [0, 0xFFFFFFFF, 0xAAAAAAAA, 0x55555555]
        words += [randomizer.getrandbits(32) for _ in range(30)]
        for word in words:
            with self.subTest(word=f"{word:08X}"):
                ok, result = self.decode(synthetic_mad(word)[0])
                self.assertTrue(ok)
                self.assertEqual(result.word, word)
                self.assertEqual(result.errors, 0)
                self.assertEqual(result.half_q8, 128 * 256)

    def test_sof_clock_range(self):
        for half in (124, 128, 132):
            with self.subTest(half=half):
                ok, result = self.decode(synthetic_mad(0x13579BDF, half)[0])
                self.assertTrue(ok)
                self.assertEqual(result.word, 0x13579BDF)
        for half in (100, 160):
            self.assertFalse(self.decode(synthetic_mad(0x13579BDF, half)[0])[0])

    def test_flat_wrong_grid_and_short_window_rejected(self):
        self.assertFalse(self.decode([2] * 749)[0])
        self.assertFalse(self.decode(synthetic_mad(0x13579BDF)[0], step=8)[0])
        self.assertFalse(self.decode(synthetic_mad(0x13579BDF, count=200)[0])[0])

    def test_missing_payload_transition_rejected(self):
        values, edges = synthetic_mad(0x13579BDF)
        center = edges[15]
        values[center - 1:center + 2] = [2, 2, 2]
        self.assertFalse(self.decode(values)[0])

    def test_two_distinct_commands_per_page_required(self):
        self.assertFalse(self.submit("E0", "123456", 1000))
        self.assertFalse(self.submit("E0", "123456", 2000))
        self.assertFalse(self.submit("E8", "78F", 3000))
        self.assertTrue(self.submit("E8", "78F", 4000))
        self.assertEqual(self.library.test_digits(), b"12345678")
        self.assertEqual(self.library.test_id(), 12345678)
        self.assertEqual(f"{self.library.test_id():010X}", "0000BC614E")

    def test_same_command_cannot_vote_twice(self):
        self.submit("E0", "123456", 1000)
        self.submit("E0", "123456", 1000)
        self.submit("E0", "123456", 900)
        self.assertEqual(self.library.test_count(0), 1)
        self.submit("E8", "78F", 2000)
        self.submit("E8", "78F", 3000)
        self.assertFalse(self.library.test_ready())

    def test_tied_page_blocks_export(self):
        self.submit("E0", "123456", 1000)
        self.submit("E0", "123456", 2000)
        self.submit("E0", "654321", 3000)
        self.submit("E0", "654321", 4000)
        self.submit("E8", "78F", 5000)
        self.assertFalse(self.submit("E8", "78F", 6000))
        self.assertFalse(self.library.test_ready())
        self.assertTrue(self.submit("E0", "123456", 7000))

    def test_invalid_parity_partial_unlocked_and_wrong_page_rejected(self):
        word = encode_digits("123456")
        self.assertFalse(self.observe(b"E0", word ^ (1 << 31), 1000, 32, 0, True))
        self.assertFalse(self.submit("E0", "123456", 2000, count=17))
        self.assertFalse(self.submit("E0", "123456", 3000, errors=1))
        self.assertFalse(self.submit("E0", "123456", 4000, locked=False))
        self.assertFalse(self.submit("F0", "123456", 5000))
        self.assertFalse(self.submit("E8", "123456", 6000))
        self.assertFalse(self.submit("E0", "78F", 7000))
        self.assertEqual(self.library.test_count(0), 0)
        self.assertEqual(self.library.test_count(1), 0)


if __name__ == "__main__":
    unittest.main()
