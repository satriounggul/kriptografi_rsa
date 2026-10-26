"""
Enkoding & Dekoding Teks dan Blok
Menangani konversi : 
- Plaintext (String), dengan blok berisi list integers
- Setiap blok integer harus < modulus n untuk validitas RSA
"""

from typing import List

def text_to_blocks(text: str, n: int) -> List[int]:
    """
    Konversi teks UTF-8 ke list integer dengan setiap blok integer harus < modulus n
    
    Kapasitas data per blok : Maksimal byte pada blok - 1 byte
    Maksimal byte pada blok : (panjang bit n - 1) // 8
    Blok terbesar < 2^(panjang bit - 1) < n
    """
    
    if not text:
        return []
    
    data = text.encode("utf-8")
    modulus_bits = n.bit_length()
    max_block_bytes = (modulus_bits - 1) // 8
    
    if max_block_bytes < 1:
        raise ValueError(f"Modulus n ({modulus_bits} bit) terlalu kecil untuk enkode satu byte.")

    blocks: List[int] = []

    if max_block_bytes >= 2:
        chunk_capacity = max_block_bytes - 1
        for i in range(0, len(data), chunk_capacity):
            chunk = data[i : i + chunk_capacity]
            block_bytes = bytes([len(chunk)]) + chunk
            block_int = int.from_bytes(block_bytes, byteorder="big")
            if block_int >= n:
                raise ValueError("Blok integer melebihi modulus n.")
            blocks.append(block_int)
    else:
        # Single byte per block
        for b in data:
            if b >= n:
                raise ValueError("Nilai byte melebihi modulus n.")
            blocks.append(b)

    return blocks

def blocks_to_text(blocks: List[int], n: int) -> str:
    """
    Konversi balik list integer ke teks UTF-8
    """
    if not blocks:
        return ""

    modulus_bits = n.bit_length()
    max_block_bytes = (modulus_bits - 1) // 8
    if max_block_bytes < 1:
        raise ValueError("Modulus n terlalu kecil.")

    byte_chunks: List[bytes] = []

    if max_block_bytes >= 2:
        for block in blocks:
            raw_bytes = block.to_bytes((block.bit_length() + 7) // 8 or 1, byteorder="big")
            
            # Byte pertama adalah length prefix
            length = raw_bytes[0]
            data = raw_bytes[1 : 1 + length]
            byte_chunks.append(data)
    else:
        for block in blocks:
            byte_chunks.append(bytes([block & 0xFF]))

    full_bytes = b"".join(byte_chunks)
    return full_bytes.decode("utf-8", errors="replace")