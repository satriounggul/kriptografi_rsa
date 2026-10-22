"""
Fundamental Number Theory Primitives (P1).
Implemented purely from scratch without forbidden functions (R-05 to R-09).
NO usage of pow(a, b, m), pow(x, -1, m), math.gcd, or crypto libraries.
"""

import secrets
from typing import Tuple, Optional
from core.op_counter import OperationCounter

# First few small primes for fast pre-filtering candidates before Miller-Rabin
_SMALL_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
    149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
    227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293
)


def gcd(a: int, b: int) -> int:
    """
    R-05: Greatest Common Divisor using the Euclidean algorithm.
    Custom implementation, no math.gcd used.
    """
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    R-05: Extended Euclidean Algorithm.
    Computes (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    """
    R-06: Modular Inverse of a modulo m.
    Returns x such that (a * x) % m == 1.
    Raises ValueError if inverse does not exist (gcd(a, m) != 1) or m <= 0.
    """
    if m <= 0:
        raise ValueError(f"Modulus m must be positive, got {m}")

    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {g} != 1")

    return x % m


def modexp(base: int, exponent: int, modulus: int, op_counter: Optional[OperationCounter] = None) -> int:
    """
    R-07: Modular Exponentiation using Square-and-Multiply.
    Computes (base ** exponent) % modulus.
    Strictly forbidden from using pow(base, exponent, modulus).
    Optionally tracks arithmetic operations via op_counter.
    """
    if modulus <= 0:
        raise ValueError(f"Modulus must be positive, got {modulus}")
    if modulus == 1:
        return 0
    if exponent < 0:
        raise ValueError("Negative exponent not supported in modexp without explicit inverse")
    if exponent == 0:
        return 1

    # Reduce base mod modulus initially
    b = base % modulus
    if op_counter is not None:
        op_counter.count_mod()

    result = 1
    e = exponent

    # Square-and-Multiply algorithm (from LSB to MSB)
    while e > 0:
        if op_counter is not None:
            op_counter.count_shift()

        if e & 1:
            result = (result * b) % modulus
            if op_counter is not None:
                op_counter.count_mul()
                op_counter.count_mod()

        b = (b * b) % modulus
        if op_counter is not None:
            op_counter.count_mul()
            op_counter.count_mod()

        e >>= 1

    return result


def miller_rabin(n: int, rounds: int = 40) -> bool:
    """
    R-08: Miller-Rabin Primality Test.
    Returns True if n is probably prime, False if definitely composite.
    Rounds = 40 gives error probability <= 4^(-40) < 10^(-24).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 as 2^s * d with d odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Perform rounds of testing
    for _ in range(rounds):
        # Pick random witness a in [2, n - 2]
        a = secrets.randbelow(n - 3) + 2

        # Compute a^d mod n using custom modexp
        x = modexp(a, d, n)
        if x == 1 or x == n - 1:
            continue

        composite = True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break

        if composite:
            return False

    return True


def generate_prime(bits: int, rounds: int = 40) -> int:
    """
    R-09: Generate a random probable prime of the specified bit length.
    Ensures the number has exactly 'bits' length (MSB is 1) and is odd.
    """
    if bits < 2:
        raise ValueError(f"Prime bit length must be >= 2, got {bits}")
    if bits == 2:
        return secrets.choice([2, 3])
    if bits == 3:
        return secrets.choice([5, 7])

    while True:
        # Generate random number with MSB and LSB set
        cand = secrets.randbits(bits)
        cand |= (1 << (bits - 1)) | 1

        # Quick pre-filter using small primes
        passed_filter = True
        for p in _SMALL_PRIMES:
            if cand % p == 0:
                if cand == p:
                    return p
                passed_filter = False
                break

        if not passed_filter:
            continue

        # Miller-Rabin primality test
        if miller_rabin(cand, rounds=rounds):
            return cand
