# Multi-Prime RSA Cryptography

Program implementasi algoritma **Multi-Prime RSA** murni (*textbook RSA*) dengan dukungan **Chinese Remainder Theorem (CRT)** dan **Teorema Fermat Kecil**.

Aplikasi ini berfokus pada dua fungsi inti:
1. **Pembangkitan Kunci (Key Generation):** Membuat kunci publik ($n, e$) dan kunci privat ($d, p_i, d_i, t_i$) untuk $k \ge 2$ bilangan prima.
2. **Enkripsi & Dekripsi:** Mengenkripsi teks atau angka, serta mendekripsinya kembali menggunakan metode RSA Standar maupun metode percepatan CRT (Garner dan Gauss).

---

## 1. Cara Menjalankan Aplikasi Web

Aplikasi berjalan secara lokal (*localhost*) tanpa memerlukan instalasi library tambahan (*zero dependencies*, hanya butuh Python bawaan):

```bash
python server/app.py --port 8000
```

Buka peramban di:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## 2. Cara Menjalankan Pengujian

Untuk menjalankan seluruh tes unit (GCD, Extended Euclid, Modular Inversion, Square-and-Multiply, Miller-Rabin, pengujian kasus tepi, dan audit bebas fungsi terlarang):

```bash
python -m unittest discover tests
```

---

## 3. Struktur Berkas

```text
kriptografi_rsa/
├── core/                  # Inti algoritma teori bilangan & RSA
│   ├── number_theory.py   # GCD, modinv, modexp (square-and-multiply), Miller-Rabin
│   ├── keygen.py          # Pembangkitan kunci multi-prime & koefisien Garner
│   ├── codec.py           # Konversi teks ke blok bilangan dan sebaliknya
│   ├── rsa.py             # Algoritma enkripsi & dekripsi (Standar, Garner, Gauss)
│   └── op_counter.py      # Penghitung operasi perkalian & modulo
├── server/
│   └── app.py             # Server HTTP lokal (endpoint /keygen, /encrypt, /decrypt)
├── static/                # Antarmuka web pengguna
│   ├── index.html         # Halaman antarmuka pembangkitan kunci, enkripsi, dan dekripsi
│   ├── style.css          # Tampilan antarmuka
│   └── app.js             # Logika interaksi frontend
└── tests/                 # Rangkaian pengujian otomatis
```
