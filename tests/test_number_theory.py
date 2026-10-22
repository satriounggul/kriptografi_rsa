"""
Unit Tests for Number Theory Primitives (P1 / QA).
Implements R-25: modinv, Miller-Rabin (including Carmichael numbers), modexp vs pow.
"""

import unittest
from core.number_theory import gcd, extended_gcd, modinv, modexp, miller_rabin, generate_prime


class TestNumberTheory(unittest.TestCase):

    def test_gcd(self):
        self.assertEqual(gcd(54, 24), 6)
        self.assertEqual(gcd(101, 103), 1)
        self.assertEqual(gcd(0, 5), 5)
        self.assertEqual(gcd(5, 0), 5)
        self.assertEqual(gcd(0, 0), 0)

    def test_extended_gcd(self):
        cases = [(54, 24), (101, 103), (123456, 7890), (35, 15)]
        for a, b in cases:
            g, x, y = extended_gcd(a, b)
            self.assertEqual(g, gcd(a, b))
            self.assertEqual(a * x + b * y, g)

    def test_modinv(self):
        test_pairs = [(3, 11), (7, 40), (17, 3120), (65537, 1000000007)]
        for a, m in test_pairs:
            inv = modinv(a, m)
            self.assertEqual((a * inv) % m, 1)

        # Test non-coprime raises ValueError
        with self.assertRaises(ValueError):
            modinv(6, 9)

    def test_modexp_vs_builtin_pow(self):
        """R-23 / R-25: Test custom square-and-multiply modexp against built-in pow."""
        test_cases = [
            (2, 10, 1000),
            (12345, 6789, 1000000007),
            (7, 0, 13),
            (0, 5, 19),
            (999, 1, 1000),
            (2**64 + 13, 2**32 + 5, 2**64 - 59)
        ]
        for b, e, m in test_cases:
            expected = pow(b, e, m)  # Permitted only in tests as comparator (R-23)
            actual = modexp(b, e, m)
            self.assertEqual(actual, expected)

    def test_miller_rabin_known_primes(self):
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 97, 101, 104729, 2147483647]
        for p in primes:
            self.assertTrue(miller_rabin(p, rounds=20), f"Expected {p} to be prime")

    def test_miller_rabin_known_composites(self):
        composites = [4, 6, 8, 9, 15, 21, 25, 27, 35, 49, 91, 100, 561, 1105, 1729, 2465, 2821, 6601]
        for c in composites:
            self.assertFalse(miller_rabin(c, rounds=20), f"Expected {c} to be composite (including Carmichael numbers)")

    def test_generate_prime(self):
        for bits in [16, 32, 64, 128]:
            p = generate_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(miller_rabin(p, rounds=30))


if __name__ == "__main__":
    unittest.main()
