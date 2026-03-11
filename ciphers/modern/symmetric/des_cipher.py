"""DES (Data Encryption Standard) — 56-bit block cipher."""

import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from ciphers.base import Cipher


class DESCipher(Cipher):

    def _prepare_key(self, key: str) -> bytes:
        """Ensure key is exactly 8 bytes."""
        if not key:
            key = "DES8KEY!"
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 8:
            key_bytes = key_bytes.ljust(8, b"\0")
        return key_bytes[:8]

    def encrypt(self, plaintext: str, key: str = "DES8KEY!") -> str:
        key_bytes = self._prepare_key(key)
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        padded = pad(plaintext.encode("utf-8"), DES.block_size)
        ct = cipher.encrypt(padded)
        return base64.b64encode(ct).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str = "DES8KEY!") -> str:
        key_bytes = self._prepare_key(key)
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        ct = base64.b64decode(ciphertext)
        pt = unpad(cipher.decrypt(ct), DES.block_size)
        return pt.decode("utf-8")

    def get_info(self) -> dict:
        return {
            "name": "DES",
            "slug": "des",
            "category": "Modern",
            "subcategory": "Block Ciphers",
            "key_info": "Exactly 8 ASCII characters (56-bit effective key). Default: DES8KEY!",
            "description": (
                "The Data Encryption Standard (DES) is a symmetric-key block cipher that "
                "encrypts data in 64-bit blocks using a 56-bit key. It applies 16 rounds "
                "of Feistel network transformations including permutation, substitution "
                "(S-boxes), and XOR operations."
            ),
            "history": (
                "Developed by IBM in the early 1970s and adopted as a federal standard "
                "by NIST in 1977. DES was the dominant encryption algorithm for over two "
                "decades. It was broken publicly in 1999 by the EFF's 'Deep Crack' machine "
                "in under 24 hours, leading to its replacement by AES."
            ),
            "advantages": [
                "Historically significant — the first widely adopted encryption standard.",
                "Well-studied Feistel structure with strong theoretical foundation.",
                "Hardware implementations are very fast and compact.",
                "Simple and elegant design with clear round structure.",
            ],
            "disadvantages": [
                "56-bit key is far too short — brute-force attacks are now trivial.",
                "64-bit block size is vulnerable to birthday attacks on large data.",
                "S-box design criteria were classified, raising suspicion (later vindicated).",
                "Superseded by AES; should not be used for new applications.",
            ],
            "improvements": (
                "DES's key length weakness led to Triple DES (3DES), which applies DES "
                "three times with two or three keys. Ultimately, the Advanced Encryption "
                "Standard (AES) replaced DES entirely, offering 128/192/256-bit keys and "
                "128-bit blocks with superior performance and security."
            ),
        }

    def explain_steps(self, text: str, key: str = "DES8KEY!", mode: str = "encrypt") -> list[dict]:
        key_bytes = self._prepare_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Prepare the Key",
            "content": (
                f"The 8-character key '{key}' is converted to bytes. "
                f"DES uses a 64-bit key where 8 bits are parity, giving 56 effective key bits. "
                f"Key bytes (hex): {key_bytes.hex()}"
            ),
            "data": {"type": "info", "key_hex": key_bytes.hex()},
        })

        if mode == "encrypt":
            plaintext_bytes = text.encode("utf-8")
            padded = pad(plaintext_bytes, DES.block_size)
            steps.append({
                "title": "Step 2 — PKCS7 Padding",
                "content": (
                    f"Plaintext is {len(plaintext_bytes)} bytes. DES requires 8-byte blocks. "
                    f"PKCS7 padding adds {len(padded) - len(plaintext_bytes)} byte(s) to make "
                    f"the total length {len(padded)} bytes ({len(padded)//8} block(s))."
                ),
                "data": {"type": "info"},
            })

            steps.append({
                "title": "Step 3 — Feistel Network (16 Rounds)",
                "content": (
                    "Each 64-bit block passes through: Initial Permutation (IP) → "
                    "16 rounds of expansion, S-box substitution, permutation, and XOR → "
                    "Final Permutation (FP). Each round splits the block into left/right halves."
                ),
                "data": {"type": "info"},
            })

            cipher = DES.new(key_bytes, DES.MODE_ECB)
            ct = cipher.encrypt(padded)
            result = base64.b64encode(ct).decode("utf-8")
        else:
            ct = base64.b64decode(text)
            steps.append({
                "title": "Step 2 — Decode Base64",
                "content": f"The base64 ciphertext decodes to {len(ct)} bytes ({len(ct)//8} block(s)).",
                "data": {"type": "info"},
            })

            steps.append({
                "title": "Step 3 — Inverse Feistel Network (16 Rounds)",
                "content": (
                    "Decryption uses the same Feistel structure but applies subkeys in "
                    "reverse order (round key 16 first, round key 1 last)."
                ),
                "data": {"type": "info"},
            })

            cipher = DES.new(key_bytes, DES.MODE_ECB)
            pt = unpad(cipher.decrypt(ct), DES.block_size)
            result = pt.decode("utf-8")

        steps.append({
            "title": "Step 4 — Final Result",
            "content": f"The {'ciphertext (base64)' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
