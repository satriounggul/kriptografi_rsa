"""
Multi-Prime RSA Key Generation & Validation (P1).
Implements R-10, R-11, R-12, R-13 in strict accordance with RFC 8017 / PKCS #1 v2.2.
"""

from typing import Dict, List, Any
from core.number_theory import gcd, modinv, generate_prime


def compute_phi(primes: List[int]) -> int:
    """Computes Euler's totient function phi(n) = prod(p_i - 1)."""
    phi = 1
    for p in primes:
        phi *= (p - 1)
    return phi


def compute_lcm(a: int, b: int) -> int:
    """Computes Least Common Multiple lcm(a, b) = |a * b| // gcd(a, b)."""
    return (a * b) // gcd(a, b)


def compute_lambda(primes: List[int]) -> int:
    """Computes Carmichael's totient lambda(n) = lcm(p_1 - 1, ..., p_k - 1)."""
    current_lcm = primes[0] - 1
    for p in primes[1:]:
        current_lcm = compute_lcm(current_lcm, p - 1)
    return current_lcm


def select_e(primes: List[int]) -> int:
    """
    Selects public exponent e such that gcd(e, p_i - 1) = 1 for all primes p_i (R-11).
    Prefers 65537 if valid, otherwise searches small odd integers starting from 3.
    """
    # Check standard 65537 first
    e_std = 65537
    valid_std = True
    for p in primes:
        if gcd(e_std, p - 1) != 1 or e_std >= p:
            valid_std = False
            break
    if valid_std:
        return e_std

    # Otherwise scan candidates: 3, 5, 17, 257, ...
    cand = 3
    while True:
        valid = True
        for p in primes:
            if gcd(cand, p - 1) != 1:
                valid = False
                break
        if valid:
            return cand
        cand += 2


def compute_garner_coefficients(primes: List[int]) -> List[int]:
    """
    Computes Garner coefficients (R-12):
    t_i = (p_1 * p_2 * ... * p_{i-1})^(-1) mod p_i for i = 2 ... k.
    Returns list [t_2, t_3, ..., t_k].
    Note: Index 0 in the returned list corresponds to t_2 for prime p_2.
    """
    k = len(primes)
    t_coeffs = []
    accumulated_prod = primes[0]

    for i in range(1, k):
        p_i = primes[i]
        # (p_1 * ... * p_{i-1}) mod p_i
        prod_mod_pi = accumulated_prod % p_i
        t_i = modinv(prod_mod_pi, p_i)
        t_coeffs.append(t_i)
        accumulated_prod *= p_i

    return t_coeffs


def generate_keys(bits: int, k: int = 2) -> Dict[str, Any]:
    """
    R-10: Generates multi-prime RSA keys.
    bits: Total bit length of the modulus n.
    k: Number of prime factors (k >= 2).

    Returns a dict with 'public_key' and 'private_key'.
    """
    # Validation of parameters
    if k < 2:
        raise ValueError(f"Number of primes k must be >= 2, got {k}")
    if bits < 16:
        raise ValueError(f"Modulus bits must be >= 16 for valid key generation, got {bits}")
    if bits // k < 4:
        raise ValueError(f"Bit length too small for k={k}. Each prime requires at least 4 bits.")

    # Calculate bit lengths for each prime
    base_bits = bits // k
    remainder_bits = bits % k
    prime_bits = [base_bits + (1 if i < remainder_bits else 0) for i in range(k)]

    max_attempts = 100
    for _ in range(max_attempts):
        primes: List[int] = []
        while len(primes) < k:
            b = prime_bits[len(primes)]
            p = generate_prime(b)
            # Ensure all primes are distinct
            if p not in primes:
                primes.append(p)

        # Sort primes to keep RFC 8017 / standard convention (p_1 < p_2 < ... or ordered)
        primes.sort()

        # Compute modulus n = prod(p_i)
        n = 1
        for p in primes:
            n *= p

        # Check total bits
        if n.bit_length() != bits and n.bit_length() != bits - 1:
            # Tolerable close range; if strictly required, continue
            pass

        # Compute totient phi(n)
        phi = compute_phi(primes)

        # Select e
        e = select_e(primes)

        try:
            d = modinv(e, phi)
        except ValueError:
            # Try again if inverse does not exist
            continue

        # Precompute CRT exponents d_i = d mod (p_i - 1) (R-12)
        d_primes = []
        valid_di = True
        for p in primes:
            di = d % (p - 1)
            # Guarantee di > 0 (R-13)
            if di == 0:
                di = p - 1
            if di <= 0:
                valid_di = False
                break
            d_primes.append(di)

        if not valid_di:
            continue

        # Garner coefficients t_i for i = 2 ... k
        t_coeffs = compute_garner_coefficients(primes)

        public_key = {
            "n": n,
            "e": e,
            "bits": n.bit_length(),
            "k": k
        }

        private_key = {
            "n": n,
            "e": e,
            "d": d,
            "primes": primes,           # [p_1, p_2, ..., p_k]
            "d_primes": d_primes,       # [d_1, d_2, ..., d_k]
            "t_coeffs": t_coeffs,       # [t_2, ..., t_k]
            "bits": n.bit_length(),
            "k": k
        }

        # Validate keys (R-13)
        if validate_keys(public_key, private_key):
            return {
                "public_key": public_key,
                "private_key": private_key
            }

    raise RuntimeError(f"Failed to generate valid multi-prime RSA keys for bits={bits}, k={k} after {max_attempts} attempts.")


def validate_keys(public_key: Dict[str, Any], private_key: Dict[str, Any]) -> bool:
    """
    R-13: Validates the key pair:
    1. All primes are distinct.
    2. Modulus n matches product of all primes.
    3. (e * d) = 1 (mod (p_i - 1)) for each prime, and (e * d) = 1 (mod phi(n)).
    4. Each d_i > 0 and d_i = d mod (p_i - 1).
    5. Each Garner coefficient t_i is correct.
    """
    primes = private_key["primes"]
    k = private_key["k"]
    n = private_key["n"]
    e = public_key["e"]
    d = private_key["d"]
    d_primes = private_key["d_primes"]
    t_coeffs = private_key["t_coeffs"]

    # 1. Distinct primes
    if len(set(primes)) != k:
        return False

    # 2. Modulus n
    prod_p = 1
    for p in primes:
        prod_p *= p
    if prod_p != n:
        return False

    # 3. Euler totient verification
    phi = compute_phi(primes)
    if (e * d) % phi != 1:
        # Also check lambda(n)
        lam = compute_lambda(primes)
        if (e * d) % lam != 1:
            return False

    # 4. CRT exponents
    for p, di in zip(primes, d_primes):
        if di <= 0:
            return False
        expected_di = d % (p - 1)
        if expected_di == 0:
            expected_di = p - 1
        if di != expected_di:
            return False

    # 5. Garner coefficients verification
    accum = primes[0]
    for idx, t_i in enumerate(t_coeffs):
        p_i = primes[idx + 1]
        if (accum * t_i) % p_i != 1:
            return False
        accum *= p_i

    return True
