"""RC4 (Rivest Cipher 4) — variable-key-length stream cipher."""

import base64
from ciphers.base import Cipher


class RC4Cipher(Cipher):
    """
    Pure-Python educational implementation of the RC4 stream cipher.
    RC4 generates a pseudo-random keystream via KSA and PRGA.
    """

    def _prepare_key(self, key: str) -> bytes:
        if not key:
            key = "RC4SecretKey"
        return key.encode("utf-8")

    @staticmethod
    def _ksa(key: bytes) -> list:
        """Key Scheduling Algorithm — initialise the permutation."""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    @staticmethod
    def _prga(S: list, length: int) -> list:
        """Pseudo-Random Generation Algorithm — produce keystream bytes."""
        i = j = 0
        keystream = []
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            keystream.append(S[(S[i] + S[j]) % 256])
        return keystream

    def _rc4(self, data: bytes, key: bytes) -> bytes:
        S = self._ksa(key)
        keystream = self._prga(S, len(data))
        return bytes(d ^ k for d, k in zip(data, keystream))

    def encrypt(self, plaintext: str, key: str = "RC4SecretKey") -> str:
        key_bytes = self._prepare_key(key)
        ct = self._rc4(plaintext.encode("utf-8"), key_bytes)
        return base64.b64encode(ct).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str = "RC4SecretKey") -> str:
        key_bytes = self._prepare_key(key)
        ct = base64.b64decode(ciphertext)
        pt = self._rc4(ct, key_bytes)
        return pt.decode("utf-8")

    def get_info(self) -> dict:
        return {
            "name": "RC4",
            "slug": "rc4",
            "category": "Modern",
            "subcategory": "Stream Ciphers",
            "key_info": "Any text string (1-256 bytes). Default: RC4SecretKey",
            "description": (
                "RC4 (Rivest Cipher 4) is a stream cipher that generates a pseudo-random "
                "keystream byte by byte, which is XORed with the plaintext. It uses a "
                "variable-length key (1-256 bytes) and maintains a 256-byte permutation "
                "table that is continuously shuffled during operation."
            ),
            "history": (
                "Designed by Ron Rivest of RSA Security in 1987. Kept as a trade secret "
                "until it was anonymously posted to a mailing list in 1994. Was the most "
                "widely used stream cipher — used in SSL/TLS, WEP, WPA-TKIP. Now deprecated "
                "due to multiple discovered vulnerabilities."
            ),
            "advantages": [
                "Extremely simple to implement — just a few lines of code.",
                "Very fast in software — minimal computational overhead.",
                "Variable key length provides flexibility.",
                "No need for padding — stream ciphers encrypt byte by byte.",
            ],
            "disadvantages": [
                "Initial keystream bytes are biased — first 256 bytes should be dropped.",
                "Broken when used in WEP due to related-key attacks.",
                "Prohibited in TLS since RFC 7465 (2015).",
                "Modern alternatives (ChaCha20) are more secure and equally fast.",
            ],
            "improvements": (
                "RC4's vulnerabilities led to its deprecation. ChaCha20, designed by "
                "Daniel Bernstein, provides a secure modern stream cipher alternative. "
                "It's used in TLS 1.3 (as ChaCha20-Poly1305) and is particularly fast "
                "on platforms without AES hardware acceleration."
            ),
        }

    def explain_steps(self, text: str, key: str = "RC4SecretKey", mode: str = "encrypt") -> list[dict]:
        key_bytes = self._prepare_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Key Scheduling Algorithm (KSA)",
            "content": (
                f"Initialize array S[0..255] = identity permutation. "
                f"Using key '{key}' ({len(key_bytes)} bytes), shuffle S by swapping "
                f"elements based on running sum of S[i] + key[i mod keylen]."
            ),
            "data": {"type": "info"},
        })

        S = self._ksa(key_bytes)
        steps.append({
            "title": "Step 2 — Initial Permutation State",
            "content": (
                f"After KSA, the first 16 values of S are: "
                f"{S[:16]}... The permutation is now key-dependent."
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            data = text.encode("utf-8")
        else:
            data = base64.b64decode(text)

        S2 = self._ksa(key_bytes)
        keystream = self._prga(S2, min(len(data), 10))

        steps.append({
            "title": "Step 3 — Pseudo-Random Generation (PRGA)",
            "content": (
                f"Generate {len(data)} keystream bytes. First {min(len(data),10)} keystream "
                f"bytes: {keystream}. Each byte is produced by swapping S elements "
                f"and outputting S[(S[i]+S[j]) mod 256]."
            ),
            "data": {"type": "info"},
        })

        rows = []
        full_result = self._rc4(data, key_bytes)
        for idx in range(min(len(data), 20)):
            rows.append({
                "input": f"0x{data[idx]:02x}",
                "output": f"0x{full_result[idx]:02x}",
            })

        steps.append({
            "title": "Step 4 — XOR Keystream with Data",
            "content": "Each input byte is XORed with the corresponding keystream byte.",
            "data": {"type": "transformation", "rows": rows},
        })

        if mode == "encrypt":
            result = base64.b64encode(full_result).decode("utf-8")
        else:
            result = full_result.decode("utf-8")

        steps.append({
            "title": "Step 5 — Final Result",
            "content": f"The {'ciphertext (base64)' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
