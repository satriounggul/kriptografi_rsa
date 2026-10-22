"""Core Cryptographic Module for Multi-Prime RSA with CRT."""

from core.number_theory import gcd, extended_gcd, modinv, modexp, miller_rabin, generate_prime
from core.keygen import generate_keys, validate_keys
from core.codec import text_to_blocks, blocks_to_text
from core.rsa import encrypt, decrypt_standard, decrypt_crt_garner, decrypt_crt_gauss
from core.op_counter import OperationCounter

__all__ = [
    "gcd",
    "extended_gcd",
    "modinv",
    "modexp",
    "miller_rabin",
    "generate_prime",
    "generate_keys",
    "validate_keys",
    "text_to_blocks",
    "blocks_to_text",
    "encrypt",
    "decrypt_standard",
    "decrypt_crt_garner",
    "decrypt_crt_gauss",
    "OperationCounter"
]
