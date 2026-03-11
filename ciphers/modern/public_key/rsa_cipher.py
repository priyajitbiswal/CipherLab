"""RSA — the foundational public-key cryptosystem based on integer factorization."""

import base64
import random
import math
from ciphers.base import Cipher


class RSACipher(Cipher):
    """
    Educational RSA implementation with small key sizes for demonstration.
    In production, RSA uses 2048+ bit keys — here we use small primes for visualization.
    """

    @staticmethod
    def _is_prime(n):
        if n < 2: return False
        if n < 4: return True
        if n % 2 == 0 or n % 3 == 0: return False
        i = 5
        while i * i <= n:
            if n % i == 0 or n % (i + 2) == 0: return False
            i += 6
        return True

    @staticmethod
    def _generate_prime(bits=10):
        while True:
            n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if RSACipher._is_prime(n):
                return n

    @staticmethod
    def _mod_inverse(e, phi):
        g, x, _ = RSACipher._extended_gcd(e, phi)
        if g != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phi

    @staticmethod
    def _extended_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = RSACipher._extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    def _parse_key(self, key: str):
        """Parse key as 'p,q' or 'p,q,e', or generate defaults."""
        if not key:
            p, q, e = 61, 53, 17
        else:
            parts = [s.strip() for s in key.split(",")]
            if len(parts) >= 3:
                p, q, e = int(parts[0]), int(parts[1]), int(parts[2])
            elif len(parts) == 2:
                p, q = int(parts[0]), int(parts[1])
                e = 65537
                phi = (p - 1) * (q - 1)
                if math.gcd(e, phi) != 1:
                    e = 17
                    if math.gcd(e, phi) != 1:
                        for candidate in [3, 5, 7, 11, 13, 19, 23]:
                            if math.gcd(candidate, phi) == 1:
                                e = candidate
                                break
            else:
                p, q, e = 61, 53, 17

        n = p * q
        phi = (p - 1) * (q - 1)
        d = self._mod_inverse(e, phi)
        return p, q, e, d, n, phi

    def encrypt(self, plaintext: str, key: str = "61,53,17") -> str:
        p, q, e, d, n, phi = self._parse_key(key)
        # Encrypt each character as a number
        encrypted = []
        for ch in plaintext:
            m = ord(ch)
            if m >= n:
                raise ValueError(f"Character '{ch}' (value {m}) is >= n={n}. Use larger primes.")
            c = pow(m, e, n)
            encrypted.append(str(c))
        return ",".join(encrypted)

    def decrypt(self, ciphertext: str, key: str = "61,53,17") -> str:
        p, q, e, d, n, phi = self._parse_key(key)
        parts = ciphertext.split(",")
        result = []
        for part in parts:
            c = int(part.strip())
            m = pow(c, d, n)
            result.append(chr(m))
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "RSA",
            "slug": "rsa",
            "category": "Modern",
            "subcategory": "Integer Factorization",
            "key_info": "Two primes and exponent: p,q,e (e.g., 61,53,17). Default: 61,53,17",
            "description": (
                "RSA (Rivest-Shamir-Adleman) is a public-key cryptosystem where security "
                "relies on the difficulty of factoring the product of two large primes. "
                "The public key (n, e) encrypts via c = m^e mod n, and the private key d "
                "decrypts via m = c^d mod n, where d is the modular inverse of e mod φ(n)."
            ),
            "history": (
                "Published in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman at MIT. "
                "It was the first practical public-key encryption system and remains the "
                "most widely deployed. Clifford Cocks at GCHQ independently discovered "
                "an equivalent system in 1973, but it was classified until 1997."
            ),
            "advantages": [
                "Enables secure communication without shared secret key exchange.",
                "Digital signatures provide authentication and non-repudiation.",
                "Well-understood mathematical foundation (integer factorization).",
                "Universal support — used in TLS, PGP, SSH, and digital certificates.",
            ],
            "disadvantages": [
                "Very slow compared to symmetric ciphers — used for key exchange, not bulk data.",
                "Large key sizes needed (2048+ bits) for modern security.",
                "Vulnerable to quantum computing attacks (Shor's algorithm).",
                "Padding schemes (OAEP) are critical — textbook RSA is insecure.",
            ],
            "improvements": (
                "Textbook RSA (shown here) is deterministic and insecure. PKCS#1 v2 (OAEP) "
                "adds random padding for CPA security. Elliptic curve cryptography (ECC) "
                "provides equivalent security with much smaller keys. Post-quantum algorithms "
                "like CRYSTALS-Kyber are being standardized to replace RSA."
            ),
        }

    def explain_steps(self, text: str, key: str = "61,53,17", mode: str = "encrypt") -> list[dict]:
        p, q, e, d, n, phi = self._parse_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Key Generation",
            "content": (
                f"p = {p}, q = {q} (two primes)\n"
                f"n = p × q = {n}\n"
                f"φ(n) = (p-1)(q-1) = {phi}\n"
                f"e = {e} (public exponent, gcd(e, φ) = {math.gcd(e, phi)})\n"
                f"d = e⁻¹ mod φ = {d} (private exponent)\n"
                f"Public key: (n={n}, e={e}) | Private key: (n={n}, d={d})"
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            rows = []
            result_parts = []
            for ch in text:
                m = ord(ch)
                c = pow(m, e, n)
                rows.append({
                    "input": ch,
                    "position": str(m),
                    "calc": f"{m}^{e} mod {n}",
                    "output": str(c),
                })
                result_parts.append(str(c))

            steps.append({
                "title": "Step 2 — Encryption: c = m^e mod n",
                "content": "Each character's Unicode value is raised to power e modulo n.",
                "data": {"type": "transformation", "rows": rows},
            })
            result = ",".join(result_parts)
        else:
            parts = text.split(",")
            rows = []
            result_chars = []
            for part in parts:
                c = int(part.strip())
                m = pow(c, d, n)
                ch = chr(m)
                rows.append({
                    "input": str(c),
                    "calc": f"{c}^{d} mod {n}",
                    "position": str(m),
                    "output": ch,
                })
                result_chars.append(ch)

            steps.append({
                "title": "Step 2 — Decryption: m = c^d mod n",
                "content": "Each ciphertext number is raised to power d modulo n.",
                "data": {"type": "transformation", "rows": rows},
            })
            result = "".join(result_chars)

        steps.append({
            "title": "Step 3 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
