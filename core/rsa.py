"""
RSA Encryption and Decryption Algorithms (P2).
Implements R-15 to R-21:
- R-15: encrypt(m, e, n)
- R-16: decrypt_standard (Method A)
- R-17: decrypt_crt (CRT + Fermat: c_i = c mod p_i, m_i = c_i^d_i mod p_i)
- R-18: Garner recombination for k primes
- R-19: Gauss/SRC recombination as comparison
- R-21: Comprehensive intermediate steps recording
"""

import time
from typing import Dict, Any, Optional, Tuple, List
from core.number_theory import modexp, modinv
from core.op_counter import OperationCounter


def encrypt(m: int, e: int, n: int, op_counter: Optional[OperationCounter] = None) -> int:
    """
    R-15: Encrypts plaintext message integer m with public key (e, n).
    Computes c = (m ** e) mod n using square-and-multiply.
    """
    if m < 0 or m >= n:
        raise ValueError(f"Message integer m ({m}) must satisfy 0 <= m < n ({n}).")
    return modexp(m, e, n, op_counter=op_counter)


def decrypt_standard(
    c: int,
    d: int,
    n: int,
    op_counter: Optional[OperationCounter] = None
) -> Tuple[int, Dict[str, Any]]:
    """
    R-16: Standard RSA Decryption (Method A: c^d mod n).
    Returns (m, intermediate_data).
    """
    if c < 0 or c >= n:
        raise ValueError(f"Ciphertext c ({c}) must satisfy 0 <= c < n ({n}).")

    counter = op_counter or OperationCounter()
    start_time = time.perf_counter()

    m = modexp(c, d, n, op_counter=counter)

    elapsed_s = time.perf_counter() - start_time

    steps = {
        "method": "standard",
        "c": c,
        "d": d,
        "n": n,
        "m": m,
        "execution_time_s": elapsed_s,
        "operation_counts": counter.to_dict()
    }

    return m, steps


def decrypt_crt_garner(
    c: int,
    private_key: Dict[str, Any],
    op_counter: Optional[OperationCounter] = None
) -> Tuple[int, Dict[str, Any]]:
    """
    R-17 & R-18: CRT + Little Fermat Decryption with Garner Recombination.
    Applies Little Fermat Theorem to reduce exponent: d_i = d mod (p_i - 1).
    Computes c_i = c mod p_i and m_i = c_i^d_i mod p_i.
    Recombines using Garner's algorithm for k primes.
    """
    primes: List[int] = private_key["primes"]
    d_primes: List[int] = private_key["d_primes"]
    t_coeffs: List[int] = private_key["t_coeffs"]
    n: int = private_key["n"]
    k: int = private_key["k"]

    if c < 0 or c >= n:
        raise ValueError(f"Ciphertext c ({c}) must satisfy 0 <= c < n ({n}).")

    counter = op_counter or OperationCounter()
    start_time = time.perf_counter()

    # Step 1: Compute c_i and m_i for each prime (R-17)
    per_prime_steps: List[Dict[str, Any]] = []
    m_list: List[int] = []

    for i in range(k):
        p_i = primes[i]
        d_i = d_primes[i]

        # c_i = c mod p_i
        c_i = c % p_i
        counter.count_mod()

        # m_i = c_i^d_i mod p_i
        m_i = modexp(c_i, d_i, p_i, op_counter=counter)
        m_list.append(m_i)

        per_prime_steps.append({
            "prime_index": i + 1,
            "p_i": p_i,
            "d_i": d_i,
            "c_i": c_i,
            "m_i": m_i
        })

    # Step 2: Garner's Algorithm Recombination (R-18)
    # 1. Initialize x = m_1
    x = m_list[0]
    p_accum = primes[0]
    garner_steps: List[Dict[str, Any]] = []

    # 2. For i = 2 ... k:
    #    u = (m_i - x) * t_i mod p_i
    #    x = x + u * (p_1 * ... * p_{i-1})
    for i in range(1, k):
        p_i = primes[i]
        t_i = t_coeffs[i - 1]
        m_i = m_list[i]

        diff = (m_i - x) % p_i
        counter.count_mod()
        counter.count_add()

        u = (diff * t_i) % p_i
        counter.count_mul()
        counter.count_mod()

        prod_prev = p_accum
        u_times_prod = u * prod_prev
        counter.count_mul()

        x_prev = x
        x = x_prev + u_times_prod
        counter.count_add()

        garner_steps.append({
            "step": i + 1,
            "p_i": p_i,
            "t_i": t_i,
            "m_i": m_i,
            "x_prev": x_prev,
            "diff": diff,
            "u": u,
            "P_prev": prod_prev,
            "term_added": u_times_prod,
            "x_new": x
        })

        p_accum *= p_i
        counter.count_mul()

    # Final result modulo n (normative guarantees x < n if all m_i < p_i)
    if x >= n:
        x = x % n
        counter.count_mod()

    elapsed_s = time.perf_counter() - start_time

    steps = {
        "method": "crt_garner",
        "k": k,
        "n": n,
        "per_prime": per_prime_steps,
        "garner_steps": garner_steps,
        "plaintext": x,
        "execution_time_s": elapsed_s,
        "operation_counts": counter.to_dict()
    }

    return x, steps


def decrypt_crt_gauss(
    c: int,
    private_key: Dict[str, Any],
    op_counter: Optional[OperationCounter] = None
) -> Tuple[int, Dict[str, Any]]:
    """
    R-19 (Optional): Standard Gauss / Single-Remainder CRT Recombination.
    Used as an explicit baseline to compare number of operations vs Garner.
    Formula: x = sum(m_i * N_i * M_i) mod n, where N_i = n // p_i and M_i = N_i^(-1) mod p_i.
    """
    primes: List[int] = private_key["primes"]
    d_primes: List[int] = private_key["d_primes"]
    n: int = private_key["n"]
    k: int = private_key["k"]

    if c < 0 or c >= n:
        raise ValueError(f"Ciphertext c ({c}) must satisfy 0 <= c < n ({n}).")

    counter = op_counter or OperationCounter()
    start_time = time.perf_counter()

    # Step 1: Compute c_i and m_i per prime
    per_prime_steps: List[Dict[str, Any]] = []
    m_list: List[int] = []

    for i in range(k):
        p_i = primes[i]
        d_i = d_primes[i]

        c_i = c % p_i
        counter.count_mod()

        m_i = modexp(c_i, d_i, p_i, op_counter=counter)
        m_list.append(m_i)

        per_prime_steps.append({
            "prime_index": i + 1,
            "p_i": p_i,
            "d_i": d_i,
            "c_i": c_i,
            "m_i": m_i
        })

    # Step 2: Gauss Recombination
    gauss_steps: List[Dict[str, Any]] = []
    x = 0

    for i in range(k):
        p_i = primes[i]
        m_i = m_list[i]

        # N_i = n // p_i (large bignum)
        N_i = n // p_i
        counter.count_div()

        # M_i = (N_i % p_i)^(-1) mod p_i
        N_i_mod_p = N_i % p_i
        counter.count_mod()
        M_i = modinv(N_i_mod_p, p_i)

        # term = m_i * N_i * M_i
        temp = (m_i * M_i) % p_i
        counter.count_mul()
        counter.count_mod()

        term = temp * N_i
        counter.count_mul()

        x += term
        counter.count_add()

        gauss_steps.append({
            "step": i + 1,
            "p_i": p_i,
            "m_i": m_i,
            "N_i": N_i,
            "M_i": M_i,
            "term": term
        })

    # Final reduction modulo n (on the very large accumulated sum)
    x = x % n
    counter.count_mod()

    elapsed_s = time.perf_counter() - start_time

    steps = {
        "method": "crt_gauss",
        "k": k,
        "n": n,
        "per_prime": per_prime_steps,
        "gauss_steps": gauss_steps,
        "plaintext": x,
        "execution_time_s": elapsed_s,
        "operation_counts": counter.to_dict()
    }

    return x, steps
