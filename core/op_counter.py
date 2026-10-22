"""
Operation Counter for Cryptographic Operations.
Used to measure the exact number of arithmetic operations (multiplications, modulos,
bit shifts, additions) per decryption method, avoiding misleading timing results in Python (R-28).
"""

from typing import Dict


class OperationCounter:
    """Tracks arithmetic operations during modular arithmetic and decryption."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.multiplications: int = 0
        self.modulo_ops: int = 0
        self.bit_shifts: int = 0
        self.additions: int = 0
        self.divisions: int = 0

    def count_mul(self, count: int = 1) -> None:
        self.multiplications += count

    def count_mod(self, count: int = 1) -> None:
        self.modulo_ops += count

    def count_shift(self, count: int = 1) -> None:
        self.bit_shifts += count

    def count_add(self, count: int = 1) -> None:
        self.additions += count

    def count_div(self, count: int = 1) -> None:
        self.divisions += count

    def to_dict(self) -> Dict[str, int]:
        total_arithmetic = self.multiplications + self.modulo_ops + self.bit_shifts + self.additions + self.divisions
        return {
            "multiplications": self.multiplications,
            "modulo_ops": self.modulo_ops,
            "bit_shifts": self.bit_shifts,
            "additions": self.additions,
            "divisions": self.divisions,
            "total_operations": total_arithmetic
        }

    def copy(self) -> "OperationCounter":
        other = OperationCounter()
        other.multiplications = self.multiplications
        other.modulo_ops = self.modulo_ops
        other.bit_shifts = self.bit_shifts
        other.additions = self.additions
        other.divisions = self.divisions
        return other
