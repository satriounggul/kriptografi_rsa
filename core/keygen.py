# Pembangkitan dan Validasi Key Multi-Prime RSA

from typing import Dict, List, Any
from core.number_theory import gcd, modinv, generate_prime

# Membuat fungsi menghitung Euler n = prod(p_i - 1)
def compute_phi(primes: List[int]) -> int:
    phi = 1
    for p in primes:
        phi *= (p - 1)
    return phi

# Membuat fungsi menghitung LCM : lcm(a, b) = |a * b| // gcd(a,b)
def compute_lcm(a: int, b: int) -> int:
    return (a * b) // gcd(a, b)

# Membuat fungsi untuk menghitung Carmichael's Totient agar ukuran private key lebih kecil dibanding Euler's Totient
# Carmichael's Totient : lambda n = lcm(p_1 - 1, ... , p_k - 1)
def compute_lambda(primes: List[int]) -> int:
    current_lcm = primes[0] - 1
    for p in primes[1:]:
        current_lcm = compute_lcm(current_lcm, p - 1)
    return current_lcm

# Membuat fungsi mencari public key e, dimana gcd(e, p_i - 1) = 1, untuk seluruh bilangan prima p_i
def select_e(primes: List[int]) -> int:
    # Mengecek nilai standar 65537 terlebih dahulu
    e_std = 65537
    valid_std = True
    for p in primes:
        if gcd(e_std, p - 1) != 1 or e_std >= p:
            valid_std = False
            break
    if valid_std:
        return e_std

    # Mencari nilai e alternatif dari primes yang memiliki gcd(e, p_i - 1) = 1
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

# Membuat fungsi menghitung Garner Coefficients untuk mempercepat dekripsi dengan CRT
# Garner Coefficients : t_i = (p_1 * p_2 * ... * p_{i-1}) ^ (-1) * mod p_i, untuk i = 2 ... k.
# Hasil : [t_2, t_3, ..., t_k]
def compute_garner_coefficients(primes: List[int]) -> List[int]:
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

# Membuat fungsi generate key multi-prime RSA
# bits : total panjang bit modulus n
# k : jumlah faktor prima (k >= 2
def generate_keys(bits: int, k: int = 2) -> Dict[str, Any]:
    if k < 2:
        raise ValueError(f"Nilai k harus >= 2, k = {k}.")
    if bits < 16:
        raise ValueError(f"Nilai bits harus >= 16, bit = {bits}.")
    if bits // k < 4:
        raise ValueError(f"Panjang bit terlalu kecil untuk k = {k} (Minimal 4 bit).")

    # Menghitung panjang bit untuk setiap bilangan prima
    base_bits = bits // k
    remainder_bits = bits % k
    prime_bits = [base_bits + (1 if i < remainder_bits else 0) for i in range(k)]

    max_attempts = 100
    for _ in range(max_attempts):
        # Membangkitkan k prima yang unik
        primes: List[int] = []
        while len(primes) < k:
            b = prime_bits[len(primes)]
            p = generate_prime(b)
            if p not in primes:
                primes.append(p)

        # Mengurutkan bilangan prima
        primes.sort()

        # Menghitung modulus n = prod(p_i)
        n = 1
        for p in primes:
            n *= p

        # Menghitung total bit
        if n.bit_length() != bits and n.bit_length() != bits - 1:
            pass

        # Menghitung Euler n
        phi = compute_phi(primes)

        # Memilih nilai e
        e = select_e(primes)

        try:
            d = modinv(e, phi)
        except ValueError:
            continue

        # Reduksi eksponen dengan Fermat's Little Theorem
        d_primes = []
        valid_di = True
        for p in primes:
            di = d % (p - 1)

            if di == 0:
                di = p - 1
            if di <= 0:
                valid_di = False
                break
            d_primes.append(di)

        if not valid_di:
            continue

        # Menghitung Garner coefficients
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
            "t_coeffs": t_coeffs,       # [t_2, ..., t_k] - koefisien Garner
            "bits": n.bit_length(),
            "k": k
        }

        if validate_keys(public_key, private_key):
            return {
                "public_key": public_key,
                "private_key": private_key
            }

    raise RuntimeError(f"Gagal membangkitkan kunci RSA bit = {bits}, k = {k} setelah {max_attempts} percobaan.")

# Validasi pasangan key
def validate_keys(public_key: Dict[str, Any], private_key: Dict[str, Any]) -> bool:
    primes = private_key["primes"]
    k = private_key["k"]
    n = private_key["n"]
    e = public_key["e"]
    d = private_key["d"]
    d_primes = private_key["d_primes"]
    t_coeffs = private_key["t_coeffs"]

    # 1. Mengecek semua bilangan prima unik
    if len(set(primes)) != k:
        return False

    # 2. Modulus n adalah hasil perkalian seluruh prima = n = (p_1 * ... * p_k).
    prod_p = 1
    for p in primes:
        prod_p *= p
    if prod_p != n:
        return False

    # 3. Cek relasi eksponen (e * d) kongruensi 1 untuk mod Euler n.
    phi = compute_phi(primes)
    if (e * d) % phi != 1:
        # Jika gagal maka cek terhadap modulus lambda n.
        lam = compute_lambda(primes)
        if (e * d) % lam != 1:
            return False

    # 4. Memastikan setiap d_i sesuai dengan d mod (p_i - 1) dan nilainya > 0
    for p, di in zip(primes, d_primes):
        if di <= 0:
            return False
        expected_di = d % (p - 1)
        if expected_di == 0:
            expected_di = p - 1
        if di != expected_di:
            return False

    # 5. Mengecek koefisien Garner (P_{i-1} * t_i) kongruensi 1 terhadap mod p_i untuk seluruh i = 2 ... k
    accum = primes[0]
    for idx, t_i in enumerate(t_coeffs):
        p_i = primes[idx + 1]
        if (accum * t_i) % p_i != 1:
            return False
        accum *= p_i

    return True