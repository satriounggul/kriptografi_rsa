"""
Text and Block Encoding / Decoding (P1).
Implements R-14: text_to_blocks and blocks_to_text.
Toy version without padding, ensuring every block integer < n.
"""

from typing import List


def text_to_blocks(text: str, n: int) -> List[int]:
    """
    R-14: Converts a string of text into a list of integers (blocks) such that
    every block is strictly strictly less than modulus n (block < n).
    """
    if not text:
        return []

    data = text.encode("utf-8")
    modulus_bits = n.bit_length()
    # Number of bytes that are strictly less than n
    # Since 2^(8*b) <= 2^(bits - 1) < n, b = (bits - 1) // 8
    max_block_bytes = (modulus_bits - 1) // 8
    if max_block_bytes < 1:
        raise ValueError(f"Modulus n ({modulus_bits} bits) is too small to encode single bytes.")

    blocks: List[int] = []

    if max_block_bytes >= 2:
        # Self-describing blocks: 1 byte for length L (1 <= L <= max_block_bytes - 1), followed by data
        chunk_capacity = max_block_bytes - 1
        for i in range(0, len(data), chunk_capacity):
            chunk = data[i : i + chunk_capacity]
            # Pack: [1 byte length] + chunk + [padding zeros to max_block_bytes to keep fixed width if desired]
            block_bytes = bytes([len(chunk)]) + chunk
            block_int = int.from_bytes(block_bytes, byteorder="big")
            if block_int >= n:
                raise ValueError("Block integer exceeded modulus n.")
            blocks.append(block_int)
    else:
        # Single byte per block
        for b in data:
            if b >= n:
                raise ValueError("Byte value exceeds modulus n.")
            blocks.append(b)

    return blocks


def blocks_to_text(blocks: List[int], n: int) -> str:
    """
    R-14: Converts a list of integers (blocks) back into the original text string.
    """
    if not blocks:
        return ""

    modulus_bits = n.bit_length()
    max_block_bytes = (modulus_bits - 1) // 8
    if max_block_bytes < 1:
        raise ValueError("Modulus n is too small.")

    byte_chunks: List[bytes] = []

    if max_block_bytes >= 2:
        for block in blocks:
            # Reconstruct bytes representation
            # Length prefix is at the start
            raw_bytes = block.to_bytes((block.bit_length() + 7) // 8 or 1, byteorder="big")
            # If the block was smaller than expected, the leading length might have fewer bytes or zero
            # Since length byte is the highest order byte, unpack carefully:
            # We know block = len_byte * 256^(len) + data
            length = raw_bytes[0]
            data = raw_bytes[1 : 1 + length]
            byte_chunks.append(data)
    else:
        for block in blocks:
            byte_chunks.append(bytes([block & 0xFF]))

    full_bytes = b"".join(byte_chunks)
    return full_bytes.decode("utf-8", errors="replace")
