"""AES (Advanced Encryption Standard) — the gold standard of symmetric encryption."""

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from ciphers.base import Cipher


class AESCipher(Cipher):

    def _prepare_key(self, key: str) -> bytes:
        """Ensure key is exactly 16, 24, or 32 bytes (AES-128/192/256)."""
        if not key:
            key = "AES128BitKey1234"
        key_bytes = key.encode("utf-8")
        # Choose closest valid key size
        if len(key_bytes) <= 16:
            key_bytes = key_bytes.ljust(16, b"\0")
            return key_bytes[:16]
        elif len(key_bytes) <= 24:
            key_bytes = key_bytes.ljust(24, b"\0")
            return key_bytes[:24]
        else:
            key_bytes = key_bytes.ljust(32, b"\0")
            return key_bytes[:32]

    def encrypt(self, plaintext: str, key: str = "AES128BitKey1234") -> str:
        key_bytes = self._prepare_key(key)
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        padded = pad(plaintext.encode("utf-8"), AES.block_size)
        ct = cipher.encrypt(padded)
        return base64.b64encode(ct).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str = "AES128BitKey1234") -> str:
        key_bytes = self._prepare_key(key)
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        ct = base64.b64decode(ciphertext)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode("utf-8")

    def get_info(self) -> dict:
        return {
            "name": "AES",
            "slug": "aes",
            "category": "Modern",
            "subcategory": "Block Ciphers",
            "key_info": "16, 24, or 32 ASCII characters (AES-128/192/256). Default: AES128BitKey1234",
            "description": (
                "The Advanced Encryption Standard (AES) is a symmetric block cipher that "
                "encrypts 128-bit blocks using keys of 128, 192, or 256 bits. It uses a "
                "substitution-permutation network (SPN) with 10, 12, or 14 rounds depending "
                "on key size. AES is the most widely used encryption algorithm in the world."
            ),
            "history": (
                "Selected by NIST in 2001 after a five-year public competition. The winning "
                "algorithm, Rijndael, was designed by Belgian cryptographers Joan Daemen and "
                "Vincent Rijmen. AES replaced DES and has become the global standard for "
                "symmetric encryption, used in TLS, VPNs, disk encryption, and more."
            ),
            "advantages": [
                "Extremely well-analyzed — no practical attacks after 20+ years.",
                "Fast in both software and hardware (AES-NI CPU instructions).",
                "Flexible key sizes: 128, 192, or 256 bits for varying security levels.",
                "Used everywhere: TLS, IPsec, WPA2/3, BitLocker, FileVault, etc.",
            ],
            "disadvantages": [
                "ECB mode (shown here for education) leaks patterns in structured data.",
                "Related-key attacks exist on reduced-round versions (theoretical only).",
                "Key management remains the practical challenge, not the algorithm.",
                "128-bit block size could theoretically be limiting for very high throughput.",
            ],
            "improvements": (
                "AES itself was the improvement over DES/3DES. Modern usage combines AES "
                "with authenticated encryption modes like GCM (Galois/Counter Mode) that "
                "provide both confidentiality and integrity. AES-GCM is the standard in "
                "TLS 1.3. For even stronger requirements, XTS mode is used for disk encryption."
            ),
        }

    def explain_steps(self, text: str, key: str = "AES128BitKey1234", mode: str = "encrypt") -> list[dict]:
        key_bytes = self._prepare_key(key)
        key_bits = len(key_bytes) * 8
        num_rounds = {16: 10, 24: 12, 32: 14}[len(key_bytes)]
        steps = []

        steps.append({
            "title": "Step 1 — Key Setup",
            "content": (
                f"Key is {len(key_bytes)} bytes → AES-{key_bits} with {num_rounds} rounds. "
                f"Key Schedule expands the key into {num_rounds + 1} round keys using "
                f"RotWord, SubWord, and XOR with round constants (Rcon)."
            ),
            "data": {"type": "info", "key_size": key_bits, "rounds": num_rounds},
        })

        if mode == "encrypt":
            pt_bytes = text.encode("utf-8")
            padded = pad(pt_bytes, AES.block_size)
            steps.append({
                "title": "Step 2 — PKCS7 Padding",
                "content": (
                    f"Plaintext ({len(pt_bytes)} bytes) padded to {len(padded)} bytes "
                    f"({len(padded)//16} block(s) of 16 bytes)."
                ),
                "data": {"type": "info"},
            })
            steps.append({
                "title": f"Step 3 — {num_rounds} Rounds of AES",
                "content": (
                    "Each round applies four transformations:\n"
                    "• SubBytes — non-linear S-box substitution for confusion\n"
                    "• ShiftRows — cyclic shifts of rows for diffusion\n"
                    "• MixColumns — column mixing in GF(2⁸) (skipped in last round)\n"
                    "• AddRoundKey — XOR with the round key"
                ),
                "data": {"type": "info"},
            })
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            ct = cipher.encrypt(padded)
            result = base64.b64encode(ct).decode("utf-8")
        else:
            ct = base64.b64decode(text)
            steps.append({
                "title": "Step 2 — Decode Base64",
                "content": f"Ciphertext decodes to {len(ct)} bytes ({len(ct)//16} block(s)).",
                "data": {"type": "info"},
            })
            steps.append({
                "title": f"Step 3 — {num_rounds} Inverse Rounds",
                "content": (
                    "Decryption applies inverse operations in reverse order:\n"
                    "• InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns"
                ),
                "data": {"type": "info"},
            })
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            result = pt.decode("utf-8")

        steps.append({
            "title": "Step 4 — Final Result",
            "content": f"The {'ciphertext (base64)' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
