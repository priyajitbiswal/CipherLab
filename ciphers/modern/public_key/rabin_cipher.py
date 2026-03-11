"""Rabin Cryptosystem — public-key encryption based on quadratic residuosity."""

import math
from ciphers.base import Cipher


class RabinCipher(Cipher):
    """
    Educational Rabin cryptosystem implementation.
    Encryption: c = m² mod n. Decryption uses the Chinese Remainder Theorem.
    Security is provably as hard as integer factorization.
    """

    def _parse_key(self, key: str):
        if not key:
            p, q = 7, 11
        else:
            parts = [s.strip() for s in key.split(",")]
            if len(parts) >= 2:
                p, q = int(parts[0]), int(parts[1])
            else:
                p, q = 7, 11
        # Both p and q should be ≡ 3 mod 4 for simple square root extraction
        n = p * q
        return p, q, n

    @staticmethod
    def _mod_sqrt(a, p):
        """Compute modular square root when p ≡ 3 (mod 4)."""
        return pow(a, (p + 1) // 4, p)

    @staticmethod
    def _extended_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = RabinCipher._extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    def encrypt(self, plaintext: str, key: str = "7,11") -> str:
        p, q, n = self._parse_key(key)
        encrypted = []
        for ch in plaintext:
            m = ord(ch)
            if m >= n:
                raise ValueError(f"Character '{ch}' (value {m}) >= n={n}. Use larger primes.")
            c = (m * m) % n
            encrypted.append(str(c))
        return ",".join(encrypted)

    def decrypt(self, ciphertext: str, key: str = "7,11") -> str:
        p, q, n = self._parse_key(key)
        parts = ciphertext.split(",")
        result = []
        for part in parts:
            c = int(part.strip())
            # Compute square roots mod p and mod q
            r = self._mod_sqrt(c, p)
            s = self._mod_sqrt(c, q)
            # CRT to combine
            _, yp, yq = self._extended_gcd(p, q)
            x1 = (r * q * yq + s * p * yp) % n
            x2 = n - x1
            x3 = (r * q * yq - s * p * yp) % n
            x4 = n - x3
            # Choose the root that gives a valid ASCII character
            candidates = [x1, x2, x3, x4]
            # Pick the one most likely to be a printable character
            chosen = None
            for x in candidates:
                if 32 <= x < 127:
                    chosen = x
                    break
            if chosen is None:
                chosen = min(candidates, key=lambda x: x if x >= 0 else n)
            result.append(chr(chosen))
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Rabin Cryptosystem",
            "slug": "rabin",
            "category": "Modern",
            "subcategory": "Integer Factorization",
            "key_info": "Two primes ≡ 3 mod 4: p,q (e.g., 7,11). Default: 7,11",
            "description": (
                "The Rabin cryptosystem encrypts by squaring: c = m² mod n, where n = pq. "
                "Decryption requires finding the four square roots of c modulo n using "
                "the Chinese Remainder Theorem. Its security is provably equivalent to "
                "the difficulty of integer factorization."
            ),
            "history": (
                "Proposed by Michael Rabin in 1979 as the first provably secure public-key "
                "encryption scheme under the integer factorization assumption. Despite its "
                "theoretical elegance, it has seen less practical adoption than RSA due to "
                "the ambiguity in decryption (four possible plaintexts)."
            ),
            "advantages": [
                "Provably as hard as integer factorization — strongest security guarantee.",
                "Encryption is very fast — just one modular squaring.",
                "Simpler mathematics than RSA — no need to find modular inverse.",
                "Academic importance as a provably secure encryption scheme.",
            ],
            "disadvantages": [
                "Decryption produces 4 candidates — requires disambiguation.",
                "Chosen-ciphertext attacks can factor n if oracle access is available.",
                "Less practical than RSA for most applications.",
                "Requires p ≡ q ≡ 3 (mod 4) for efficient square root extraction.",
            ],
            "improvements": (
                "The ambiguity problem led to variants like the Williams scheme that "
                "produce unique decryption. RSA avoids the issue entirely with its "
                "unique decryption. Modern systems use elliptic curve cryptography, "
                "which provides equivalent security with much smaller keys."
            ),
        }

    def explain_steps(self, text: str, key: str = "7,11", mode: str = "encrypt") -> list[dict]:
        p, q, n = self._parse_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Key Setup",
            "content": (
                f"p = {p}, q = {q} (primes ≡ 3 mod 4)\n"
                f"n = p × q = {n}\n"
                f"Public key: n = {n}\n"
                f"Private key: (p={p}, q={q})"
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            rows = []
            result_parts = []
            for ch in text:
                m = ord(ch)
                c = (m * m) % n
                rows.append({
                    "input": ch,
                    "position": str(m),
                    "calc": f"{m}² mod {n} = {m*m} mod {n}",
                    "output": str(c),
                })
                result_parts.append(str(c))

            steps.append({
                "title": "Step 2 — Encryption: c = m² mod n",
                "content": "Each character value is squared modulo n.",
                "data": {"type": "transformation", "rows": rows},
            })
            result = ",".join(result_parts)
        else:
            parts = text.split(",")
            rows = []
            result_chars = []
            for part in parts:
                c = int(part.strip())
                r = self._mod_sqrt(c, p)
                s = self._mod_sqrt(c, q)
                _, yp, yq = self._extended_gcd(p, q)
                x1 = (r * q * yq + s * p * yp) % n
                x2 = n - x1
                x3 = (r * q * yq - s * p * yp) % n
                x4 = n - x3
                candidates = [x1, x2, x3, x4]
                chosen = None
                for x in candidates:
                    if 32 <= x < 127:
                        chosen = x
                        break
                if chosen is None:
                    chosen = min(candidates, key=lambda x: x if x >= 0 else n)
                rows.append({
                    "input": str(c),
                    "calc": f"√{c} mod {n} → [{x1},{x2},{x3},{x4}]",
                    "output": chr(chosen),
                })
                result_chars.append(chr(chosen))

            steps.append({
                "title": "Step 2 — Decryption via CRT",
                "content": (
                    "Find 4 square roots using Chinese Remainder Theorem, "
                    "then select the printable ASCII candidate."
                ),
                "data": {"type": "transformation", "rows": rows},
            })
            result = "".join(result_chars)

        steps.append({
            "title": "Step 3 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
