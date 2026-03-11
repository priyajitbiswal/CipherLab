"""IDEA (International Data Encryption Algorithm) — 128-bit key, 64-bit block cipher."""

import base64
import struct
from ciphers.base import Cipher


class IDEACipher(Cipher):
    """
    Pure-Python educational implementation of the IDEA cipher.
    IDEA uses 128-bit keys and operates on 64-bit blocks through 8.5 rounds
    of modular arithmetic operations.
    """

    def _prepare_key(self, key: str) -> bytes:
        if not key:
            key = "IDEACipherKey128"
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 16:
            key_bytes = key_bytes.ljust(16, b"\0")
        return key_bytes[:16]

    @staticmethod
    def _mul(a, b):
        """Multiplication modulo 2^16 + 1, where 0 is treated as 2^16."""
        if a == 0: a = 0x10000
        if b == 0: b = 0x10000
        r = (a * b) % 0x10001
        return r & 0xFFFF

    @staticmethod
    def _add(a, b):
        """Addition modulo 2^16."""
        return (a + b) & 0xFFFF

    @staticmethod
    def _mul_inv(a):
        """Multiplicative inverse modulo 2^16 + 1."""
        if a <= 1:
            return a
        t1, t0 = 1, 0
        r1, r0 = a, 0x10001
        while r1 > 0:
            q = r0 // r1
            r0, r1 = r1, r0 - q * r1
            t0, t1 = t1, t0 - q * t1
        return t0 % 0x10001

    @staticmethod
    def _add_inv(a):
        """Additive inverse modulo 2^16."""
        return (0x10000 - a) & 0xFFFF

    def _expand_key(self, key_bytes: bytes) -> list:
        """Generate 52 encryption sub-keys from the 128-bit key."""
        key_bits = int.from_bytes(key_bytes, 'big')
        subkeys = []
        for i in range(52):
            idx = (i * 16) % 128
            shifted = (key_bits << (idx % 128)) & ((1 << 128) - 1)
            shifted |= key_bits >> (128 - (idx % 128))
            shifted &= (1 << 128) - 1
            subkeys.append((shifted >> (128 - 16)) & 0xFFFF)
            if (i + 1) % 8 == 0 and i < 51:
                key_bits = ((key_bits << 25) | (key_bits >> 103)) & ((1 << 128) - 1)
        return subkeys

    def _expand_key_simple(self, key_bytes: bytes) -> list:
        """Simple key schedule for IDEA."""
        k = int.from_bytes(key_bytes, 'big')
        subkeys = []
        for round_num in range(7):
            for i in range(8):
                subkeys.append((k >> (128 - 16 * (i + 1))) & 0xFFFF)
            k = ((k << 25) | (k >> 103)) & ((1 << 128) - 1)
        # Only need 52 subkeys
        return subkeys[:52]

    def _decrypt_subkeys(self, ek: list) -> list:
        """Derive decryption sub-keys from encryption sub-keys."""
        dk = [0] * 52

        # Output transformation (last 4 subkeys become first 4 for decryption)
        dk[0] = self._mul_inv(ek[48])
        dk[1] = self._add_inv(ek[49])
        dk[2] = self._add_inv(ek[50])
        dk[3] = self._mul_inv(ek[51])

        # For rounds 1-7: derive keys with MA sub-keys from previous round
        for r in range(1, 8):
            si = r * 6
            ei = 48 - r * 6
            dk[si - 2] = ek[ei + 4]  # MA sub-key 1
            dk[si - 1] = ek[ei + 5]  # MA sub-key 2
            dk[si + 0] = self._mul_inv(ek[ei + 0])
            dk[si + 1] = self._add_inv(ek[ei + 2])  # note: indices 1,2 swapped
            dk[si + 2] = self._add_inv(ek[ei + 1])
            dk[si + 3] = self._mul_inv(ek[ei + 3])

        # Last round's MA keys
        dk[46] = ek[4]
        dk[47] = ek[5]
        # Final output transformation keys
        dk[48] = self._mul_inv(ek[0])
        dk[49] = self._add_inv(ek[1])
        dk[50] = self._add_inv(ek[2])
        dk[51] = self._mul_inv(ek[3])
        return dk

    def _idea_block(self, block: bytes, subkeys: list) -> bytes:
        """Process a single 64-bit block through IDEA."""
        x1, x2, x3, x4 = struct.unpack('>HHHH', block)

        for r in range(8):
            i = r * 6
            x1 = self._mul(x1, subkeys[i + 0])
            x2 = self._add(x2, subkeys[i + 1])
            x3 = self._add(x3, subkeys[i + 2])
            x4 = self._mul(x4, subkeys[i + 3])

            t1 = x1 ^ x3
            t2 = x2 ^ x4

            t1 = self._mul(t1, subkeys[i + 4])
            t2 = self._add(t2, t1)
            t2 = self._mul(t2, subkeys[i + 5])
            t1 = self._add(t1, t2)

            x1 ^= t2
            x3 ^= t2
            x2 ^= t1
            x4 ^= t1

            x2, x3 = x3, x2

        # Output transformation
        y1 = self._mul(x1, subkeys[48])
        y2 = self._add(x3, subkeys[49])  # note: x3/x2 swapped back
        y3 = self._add(x2, subkeys[50])
        y4 = self._mul(x4, subkeys[51])

        return struct.pack('>HHHH', y1, y2, y3, y4)

    def _pad(self, data: bytes) -> bytes:
        """PKCS7 padding for 8-byte blocks."""
        pad_len = 8 - (len(data) % 8)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt(self, plaintext: str, key: str = "IDEACipherKey128") -> str:
        key_bytes = self._prepare_key(key)
        subkeys = self._expand_key_simple(key_bytes)
        data = self._pad(plaintext.encode("utf-8"))
        result = b""
        for i in range(0, len(data), 8):
            result += self._idea_block(data[i:i+8], subkeys)
        return base64.b64encode(result).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str = "IDEACipherKey128") -> str:
        key_bytes = self._prepare_key(key)
        ek = self._expand_key_simple(key_bytes)
        dk = self._decrypt_subkeys(ek)
        data = base64.b64decode(ciphertext)
        result = b""
        for i in range(0, len(data), 8):
            result += self._idea_block(data[i:i+8], dk)
        return self._unpad(result).decode("utf-8")

    def get_info(self) -> dict:
        return {
            "name": "IDEA",
            "slug": "idea",
            "category": "Modern",
            "subcategory": "Block Ciphers",
            "key_info": "16 ASCII characters (128-bit key). Default: IDEACipherKey128",
            "description": (
                "The International Data Encryption Algorithm (IDEA) is a symmetric block "
                "cipher that encrypts 64-bit blocks using a 128-bit key. It performs 8.5 "
                "rounds using three algebraic operations: XOR, addition mod 2¹⁶, and "
                "multiplication mod 2¹⁶+1 — chosen because they are incompatible and "
                "create strong confusion and diffusion."
            ),
            "history": (
                "Designed by Xuejia Lai and James Massey at ETH Zürich in 1991 as a "
                "replacement for DES. Originally called IPES before being renamed IDEA. "
                "It was used in the early versions of PGP (Pretty Good Privacy) for email "
                "encryption. The patent expired in 2012, making it freely available."
            ),
            "advantages": [
                "Elegant design using three incompatible algebraic operations.",
                "128-bit key provides strong security against brute force.",
                "No practical attacks found against the full 8.5-round version.",
                "Historically important — used in PGP for secure email.",
            ],
            "disadvantages": [
                "64-bit block size is vulnerable to birthday attacks on large data.",
                "Large class of weak keys (2^51) exist, though practically irrelevant.",
                "Slower than AES in modern software implementations.",
                "Patent restrictions (now expired) limited its historical adoption.",
            ],
            "improvements": (
                "IDEA was among the strongest alternatives to DES during the 1990s. "
                "Modern applications prefer AES for its larger 128-bit blocks and "
                "hardware acceleration support. ChaCha20 is preferred for software-only "
                "implementations where AES-NI is unavailable."
            ),
        }

    def explain_steps(self, text: str, key: str = "IDEACipherKey128", mode: str = "encrypt") -> list[dict]:
        key_bytes = self._prepare_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Key Expansion",
            "content": (
                f"The 128-bit key generates 52 sub-keys (16 bits each). "
                f"The key is divided into eight 16-bit blocks, then cyclically "
                f"left-shifted by 25 bits to produce additional sub-keys."
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            data = self._pad(text.encode("utf-8"))
            steps.append({
                "title": "Step 2 — Padding & Block Division",
                "content": (
                    f"Input padded to {len(data)} bytes → {len(data)//8} block(s) of 64 bits. "
                    f"Each block is split into four 16-bit sub-blocks: X₁, X₂, X₃, X₄."
                ),
                "data": {"type": "info"},
            })
        else:
            data = base64.b64decode(text)
            steps.append({
                "title": "Step 2 — Decode & Compute Decryption Keys",
                "content": (
                    f"Ciphertext decoded to {len(data)} bytes. Decryption sub-keys are "
                    f"derived as multiplicative/additive inverses of encryption keys."
                ),
                "data": {"type": "info"},
            })

        steps.append({
            "title": "Step 3 — 8 IDEA Rounds",
            "content": (
                "Each round performs:\n"
                "• Multiply X₁ with sub-key K₁ (mod 2¹⁶+1)\n"
                "• Add X₂ with sub-key K₂ (mod 2¹⁶)\n"
                "• Add X₃ with sub-key K₃ (mod 2¹⁶)\n"
                "• Multiply X₄ with sub-key K₄ (mod 2¹⁶+1)\n"
                "• XOR and multiply intermediate values through the MA structure\n"
                "• Swap middle sub-blocks X₂ ↔ X₃"
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 4 — Output Transformation (Half Round)",
            "content": (
                "Final half-round applies: Multiply, Add, Add, Multiply with the "
                "last four sub-keys (K₄₉–K₅₂), without the MA structure or swap."
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            subkeys = self._expand_key_simple(key_bytes)
            result_bytes = b""
            for i in range(0, len(data), 8):
                result_bytes += self._idea_block(data[i:i+8], subkeys)
            result = base64.b64encode(result_bytes).decode("utf-8")
        else:
            ek = self._expand_key_simple(key_bytes)
            dk = self._decrypt_subkeys(ek)
            result_bytes = b""
            for i in range(0, len(data), 8):
                result_bytes += self._idea_block(data[i:i+8], dk)
            result = self._unpad(result_bytes).decode("utf-8")

        steps.append({
            "title": "Step 5 — Final Result",
            "content": f"The {'ciphertext (base64)' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
