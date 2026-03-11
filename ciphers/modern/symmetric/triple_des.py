"""Triple DES (3DES / TDEA) — applies DES three times for stronger encryption."""

import base64
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from ciphers.base import Cipher


class TripleDESCipher(Cipher):

    def _prepare_key(self, key: str) -> bytes:
        """Ensure key is exactly 24 bytes (three 8-byte DES keys)."""
        if not key:
            key = "TripleDES24ByteKeyHere!"
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 24:
            key_bytes = key_bytes.ljust(24, b"\0")
        key_bytes = key_bytes[:24]
        # DES3 requires keys where each 8-byte segment differs
        try:
            DES3.adjust_key_parity(key_bytes)
        except ValueError:
            # If key parity adjustment fails, use a default
            key_bytes = DES3.adjust_key_parity(b"TripleDES24ByteKeyHere!")
        return key_bytes

    def encrypt(self, plaintext: str, key: str = "TripleDES24ByteKeyHere!") -> str:
        key_bytes = self._prepare_key(key)
        cipher = DES3.new(key_bytes, DES3.MODE_ECB)
        padded = pad(plaintext.encode("utf-8"), DES3.block_size)
        ct = cipher.encrypt(padded)
        return base64.b64encode(ct).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str = "TripleDES24ByteKeyHere!") -> str:
        key_bytes = self._prepare_key(key)
        cipher = DES3.new(key_bytes, DES3.MODE_ECB)
        ct = base64.b64decode(ciphertext)
        pt = unpad(cipher.decrypt(ct), DES3.block_size)
        return pt.decode("utf-8")

    def get_info(self) -> dict:
        return {
            "name": "Triple DES (3DES)",
            "slug": "3des",
            "category": "Modern",
            "subcategory": "Block Ciphers",
            "key_info": "24 ASCII characters (three 8-byte keys). Default: TripleDES24ByteKeyHere!",
            "description": (
                "Triple DES applies the DES algorithm three times to each data block. "
                "In EDE (Encrypt-Decrypt-Encrypt) mode with three distinct keys, it provides "
                "an effective key length of 168 bits, significantly stronger than single DES."
            ),
            "history": (
                "Developed as a simple way to extend DES's lifetime after its 56-bit key "
                "became inadequate. Standardized by NIST in SP 800-67. Widely used in "
                "financial systems and payment card industry (EMV chip cards). Being phased "
                "out in favor of AES since 2017."
            ),
            "advantages": [
                "Much stronger than single DES — up to 168-bit effective key length.",
                "Uses the same well-understood DES algorithm, leveraging existing hardware.",
                "Backward compatible with single DES (when K1 = K2 = K3).",
                "Still considered secure enough for legacy systems.",
            ],
            "disadvantages": [
                "Three times slower than single DES due to triple encryption.",
                "64-bit block size still vulnerable to birthday attacks (Sweet32).",
                "Increasingly replaced by AES, which is faster and more secure.",
                "Complex key management with three separate keys.",
            ],
            "improvements": (
                "3DES was a transitional solution between DES and AES. The Advanced "
                "Encryption Standard (AES) offers 128-bit blocks and keys up to 256 bits, "
                "with much better performance. NIST deprecated 3DES for new applications "
                "in 2017 and plans full disallowance after 2023."
            ),
        }

    def explain_steps(self, text: str, key: str = "TripleDES24ByteKeyHere!", mode: str = "encrypt") -> list[dict]:
        key_bytes = self._prepare_key(key)
        steps = []

        k1, k2, k3 = key_bytes[:8], key_bytes[8:16], key_bytes[16:24]
        steps.append({
            "title": "Step 1 — Split Key into Three Sub-keys",
            "content": (
                f"The 24-byte key is split into three 8-byte DES keys:\n"
                f"K1: {k1.hex()}, K2: {k2.hex()}, K3: {k3.hex()}"
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            padded = pad(text.encode("utf-8"), DES3.block_size)
            steps.append({
                "title": "Step 2 — PKCS7 Padding",
                "content": (
                    f"Input padded to {len(padded)} bytes ({len(padded)//8} blocks of 8 bytes)."
                ),
                "data": {"type": "info"},
            })
            steps.append({
                "title": "Step 3 — EDE: Encrypt-Decrypt-Encrypt",
                "content": (
                    "Each block is processed: Encrypt with K1 → Decrypt with K2 → Encrypt with K3. "
                    "This three-pass approach provides the security gain over single DES."
                ),
                "data": {"type": "info"},
            })
            cipher = DES3.new(key_bytes, DES3.MODE_ECB)
            ct = cipher.encrypt(padded)
            result = base64.b64encode(ct).decode("utf-8")
        else:
            ct = base64.b64decode(text)
            steps.append({
                "title": "Step 2 — Decode Base64",
                "content": f"Ciphertext decodes to {len(ct)} bytes ({len(ct)//8} blocks).",
                "data": {"type": "info"},
            })
            steps.append({
                "title": "Step 3 — DED: Decrypt-Encrypt-Decrypt",
                "content": (
                    "Each block is processed in reverse: Decrypt with K3 → Encrypt with K2 → "
                    "Decrypt with K1."
                ),
                "data": {"type": "info"},
            })
            cipher = DES3.new(key_bytes, DES3.MODE_ECB)
            pt = unpad(cipher.decrypt(ct), DES3.block_size)
            result = pt.decode("utf-8")

        steps.append({
            "title": "Step 4 — Final Result",
            "content": f"The {'ciphertext (base64)' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
