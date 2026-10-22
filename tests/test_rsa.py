"""
Cross-Testing and Edge-Case Tests for RSA (P2 / QA).
Implements R-22, R-24, R-26.
"""

import unittest
from core.keygen import generate_keys, validate_keys
from core.codec import text_to_blocks, blocks_to_text
from core.rsa import encrypt, decrypt_standard, decrypt_crt_garner, decrypt_crt_gauss


class TestRSA(unittest.TestCase):

    def test_validation_rejects_invalid_params(self):
        """R-26: generate_keys must reject invalid k and too small bit sizes."""
        with self.assertRaises(ValueError):
            generate_keys(bits=64, k=1)  # k must be >= 2

        with self.assertRaises(ValueError):
            generate_keys(bits=8, k=2)   # bit size too small

        with self.assertRaises(ValueError):
            generate_keys(bits=32, k=10) # each prime would be < 4 bits

    def test_key_generation_and_validation(self):
        """Tests key generation for k=2, 3, 4."""
        for k in [2, 3, 4]:
            keys = generate_keys(bits=128, k=k)
            pub = keys["public_key"]
            priv = keys["private_key"]
            self.assertTrue(validate_keys(pub, priv))
            self.assertEqual(priv["k"], k)
            self.assertEqual(len(priv["primes"]), k)
            self.assertEqual(len(priv["d_primes"]), k)
            self.assertEqual(len(priv["t_coeffs"]), k - 1)

    def test_cross_methods_random_messages(self):
        """
        R-22: Cross-test. All methods must yield identical plaintexts across
        random keys and messages for various values of k.
        """
        for k in [2, 3, 4]:
            keys = generate_keys(bits=128, k=k)
            pub = keys["public_key"]
            priv = keys["private_key"]
            n, e, d = pub["n"], pub["e"], priv["d"]

            test_messages = [42, 1337, n // 3, n // 2, n - 42]
            for m in test_messages:
                c = encrypt(m, e, n)

                m_std, _ = decrypt_standard(c, d, n)
                m_garner, _ = decrypt_crt_garner(c, priv)
                m_gauss, _ = decrypt_crt_gauss(c, priv)

                self.assertEqual(m_std, m, f"Standard decryption failed for k={k}, m={m}")
                self.assertEqual(m_garner, m, f"CRT Garner failed for k={k}, m={m}")
                self.assertEqual(m_gauss, m, f"CRT Gauss failed for k={k}, m={m}")

    def test_edge_cases(self):
        """
        R-24: Edge cases:
        1. Message 0
        2. Message 1
        3. Message n - 1
        4. Message multiple of one of p_i (gcd(c, p_i) != 1)
        """
        for k in [2, 3]:
            keys = generate_keys(bits=128, k=k)
            pub = keys["public_key"]
            priv = keys["private_key"]
            n, e, d = pub["n"], pub["e"], priv["d"]
            primes = priv["primes"]

            # Edge Case 1: Message 0
            c0 = encrypt(0, e, n)
            m0_std, _ = decrypt_standard(c0, d, n)
            m0_garner, _ = decrypt_crt_garner(c0, priv)
            m0_gauss, _ = decrypt_crt_gauss(c0, priv)
            self.assertEqual(m0_std, 0)
            self.assertEqual(m0_garner, 0)
            self.assertEqual(m0_gauss, 0)

            # Edge Case 2: Message 1
            c1 = encrypt(1, e, n)
            m1_std, _ = decrypt_standard(c1, d, n)
            m1_garner, _ = decrypt_crt_garner(c1, priv)
            m1_gauss, _ = decrypt_crt_gauss(c1, priv)
            self.assertEqual(m1_std, 1)
            self.assertEqual(m1_garner, 1)
            self.assertEqual(m1_gauss, 1)

            # Edge Case 3: Message n - 1
            c_last = encrypt(n - 1, e, n)
            mlast_std, _ = decrypt_standard(c_last, d, n)
            mlast_garner, _ = decrypt_crt_garner(c_last, priv)
            mlast_gauss, _ = decrypt_crt_gauss(c_last, priv)
            self.assertEqual(mlast_std, n - 1)
            self.assertEqual(mlast_garner, n - 1)
            self.assertEqual(mlast_gauss, n - 1)

            # Edge Case 4: Message multiple of one of p_i
            # Choose m = 2 * p_1 (as long as 2 * p_1 < n)
            target_p = primes[0]
            m_mult = target_p * 2
            if m_mult < n:
                c_mult = encrypt(m_mult, e, n)
                mmult_std, _ = decrypt_standard(c_mult, d, n)
                mmult_garner, _ = decrypt_crt_garner(c_mult, priv)
                mmult_gauss, _ = decrypt_crt_gauss(c_mult, priv)
                self.assertEqual(mmult_std, m_mult)
                self.assertEqual(mmult_garner, m_mult)
                self.assertEqual(mmult_gauss, m_mult)

    def test_codec_roundtrip(self):
        """R-14: text_to_blocks and blocks_to_text round trip test."""
        keys = generate_keys(bits=256, k=2)
        n = keys["public_key"]["n"]

        sample_texts = [
            "Halo Dunia!",
            "Kriptografi RSA Multi-Prime dengan CRT dan Teorema Fermat Kecil",
            "Special characters: !@#$%^&*()_+~`|}{[]:;?><,./'\"",
            "Testing 1234567890..."
        ]

        for text in sample_texts:
            blocks = text_to_blocks(text, n)
            for b in blocks:
                self.assertLess(b, n)
            recovered = blocks_to_text(blocks, n)
            self.assertEqual(recovered, text)


if __name__ == "__main__":
    unittest.main()
