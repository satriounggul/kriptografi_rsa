# Enkripsi dan Dekripsi RSA

import time
from typing import Dict, Any, Optional, Tuple, List
from core.number_theory import modexp, modinv
from core.op_counter import OperationCounter

# Fungsi enkripsi, enkripsi dengan public key (e, n)
# c = (m ** e) mod n
def encrypt(m: int, e: int, n: int, op_counter: Optional[OperationCounter] = None) -> int:
    if m < 0 or m >= n:
        raise ValueError(f"Pesan m ({m}) harus memenuhi 0 <= m < n ({n}).")
    return modexp(m, e, n, op_counter=op_counter)

# Fungsi dekripsi standar, dekripsi dengan private key (d, n), untuk pembanding CRT
def decrypt_standard(
    c: int,
    d: int,
    n: int,
    op_counter: Optional[OperationCounter] = None
) -> Tuple[int, Dict[str, Any]]:
    if c < 0 or c >= n:
        raise ValueError(f"Ciphertext c ({c}) harus memenuhi 0 <= c < n ({n}).")

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

# Fungsi dekripsi dengan CRT dan Little Fermat, kemudian rekombinasi dengan Garner
def decrypt_crt_garner(
    c: int,
    private_key: Dict[str, Any],
    op_counter: Optional[OperationCounter] = None
) -> Tuple[int, Dict[str, Any]]:
    primes: List[int] = private_key["primes"]
    d_primes: List[int] = private_key["d_primes"]
    t_coeffs: List[int] = private_key["t_coeffs"]
    n: int = private_key["n"]
    k: int = private_key["k"]

    if c < 0 or c >= n:
        raise ValueError(f"Ciphertext c ({c}) harus memenuhi 0 <= c < n ({n}).")

    counter = op_counter or OperationCounter()
    start_time = time.perf_counter()

    # Langkah 1 : Menghitung dekripsi per bilangan prima
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

    # Langkah 2 : Algoritma rekombinasi Garner
    x = m_list[0]
    p_accum = primes[0]
    garner_steps: List[Dict[str, Any]] = []

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

# Fungsi dekripsi dengan CRT dan rekombinasi Gauss, untuk pembanding Garner
def decrypt_crt_gauss(
    c: int,
    private_key: Dict[str, Any],
    op_counter: Optional[OperationCounter] = None
) -> Tuple[int, Dict[str, Any]]:
    primes: List[int] = private_key["primes"]
    d_primes: List[int] = private_key["d_primes"]
    n: int = private_key["n"]
    k: int = private_key["k"]

    if c < 0 or c >= n:
        raise ValueError(f"Ciphertext c ({c}) harus memenuhi 0 <= c < n ({n}).")

    counter = op_counter or OperationCounter()
    start_time = time.perf_counter()

    # Langkah 1 : Menghitung dekripsi per bilangan prima
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

    # Langkah 2 : Algoritma rekombinasi Gauss
    gauss_steps: List[Dict[str, Any]] = []
    x = 0

    for i in range(k):
        p_i = primes[i]
        m_i = m_list[i]

        N_i = n // p_i
        counter.count_div()

        N_i_mod_p = N_i % p_i
        counter.count_mod()
        M_i = modinv(N_i_mod_p, p_i)

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