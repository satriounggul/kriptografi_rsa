# Teori Bilangan Dasar

import secrets
from typing import Tuple, Optional
from core.op_counter import OperationCounter

# Bilangan prima kecil untuk penyaringan kandidat sebelum Miller-Rabin
_SMALL_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
    149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
    227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293
)

# Fungsi mencari GCD dengan Euclidean Algorithm
def gcd(a: int, b: int) -> int:
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a

# Fungsi mencari GCD dengan Euclidean Algorithm dan mencari Bezout's Coefficient
def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t

# Fungsi mencari invers modulo, x dimana (a * x) % m == 1
def modinv(a: int, m: int) -> int:
    if m <= 0:
        raise ValueError(f"Modulus harus positif, m = {m}")

    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Inverse modulo tidak ditemukan : gcd({a}, {m}) = {g} != 1")

    return x % m

# Fungsi mencari eksponen modulo, (base ** exponent) % modulus
def modexp(base: int, exponent: int, modulus: int, op_counter: Optional[OperationCounter] = None) -> int:
    if modulus <= 0:
        raise ValueError(f"Modulus harus positif, modulus = {modulus}")
    if modulus == 1:
        return 0
    if exponent < 0:
        raise ValueError("Eksponen negatif tidak diperbolehkan.")
    if exponent == 0:
        return 1

    b = base % modulus
    if op_counter is not None:
        op_counter.count_mod()

    result = 1
    e = exponent

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

# Fungsi menguji primalitas Miller-Rabin
def miller_rabin(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
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

# Fungsi pembangkit bilangan prima dengan panjang bit = 'bits'
def generate_prime(bits: int, rounds: int = 40) -> int:
    if bits < 2:
        raise ValueError(f"Panjang bit harus >= 2, panjang = {bits} bit.")
    if bits == 2:
        return secrets.choice([2, 3])
    if bits == 3:
        return secrets.choice([5, 7])

    while True:
        cand = secrets.randbits(bits)
        cand |= (1 << (bits - 1)) | 1

        # Filter awal dengan bilangan prima kecil sebelum Miller-Rabin
        passed_filter = True
        for p in _SMALL_PRIMES:
            if cand % p == 0:
                if cand == p:
                    return p
                passed_filter = False
                break

        if not passed_filter:
            continue

        # Uji primalitas Miller-Rabin
        if miller_rabin(cand, rounds=rounds):
            return cand