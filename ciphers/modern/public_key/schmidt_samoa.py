"""Schmidt-Samoa Cryptosystem — public-key encryption based on integer factorization."""

import math
from ciphers.base import Cipher


class SchmidtSamoaCipher(Cipher):
    """
    Educational Schmidt-Samoa implementation.
    n = p²q, encrypt: c = m^n mod n, decrypt: m = c^d mod pq
    """

    @staticmethod
    def _mod_inverse(a, m):
        g, x, _ = SchmidtSamoaCipher._extended_gcd(a, m)
        if g != 1:
            raise ValueError("Modular inverse does not exist")
        return x % m

    @staticmethod
    def _extended_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = SchmidtSamoaCipher._extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    def _parse_key(self, key: str):
        if not key:
            p, q = 7, 11
        else:
            parts = [s.strip() for s in key.split(",")]
            if len(parts) >= 2:
                p, q = int(parts[0]), int(parts[1])
            else:
                p, q = 7, 11

        n = p * p * q
        pq = p * q
        lcm_val = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        d = self._mod_inverse(n, lcm_val)
        return p, q, n, pq, d, lcm_val

    def encrypt(self, plaintext: str, key: str = "7,11") -> str:
        p, q, n, pq, d, lcm_val = self._parse_key(key)
        encrypted = []
        for ch in plaintext:
            m = ord(ch)
            if m >= pq:
                raise ValueError(f"Character '{ch}' (value {m}) >= pq={pq}. Use larger primes.")
            c = pow(m, n, n)
            encrypted.append(str(c))
        return ",".join(encrypted)

    def decrypt(self, ciphertext: str, key: str = "7,11") -> str:
        p, q, n, pq, d, lcm_val = self._parse_key(key)
        parts = ciphertext.split(",")
        result = []
        for part in parts:
            c = int(part.strip())
            m = pow(c, d, pq)
            result.append(chr(m))
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Schmidt-Samoa",
            "slug": "schmidt-samoa",
            "category": "Modern",
            "subcategory": "Integer Factorization",
            "key_info": "Two primes: p,q (e.g., 7,11). Default: 7,11",
            "description": (
                "The Schmidt-Samoa cryptosystem uses n = p²q as the public key. "
                "Encryption computes c = m^n mod n, and decryption uses c^d mod pq, "
                "where d = n⁻¹ mod lcm(p-1, q-1). Like Rabin, its security is based "
                "on the difficulty of integer factorization."
            ),
            "history": (
                "Proposed by Katja Schmidt-Samoa in 2006 as a variant of public-key "
                "encryption systems based on integer factorization. It combines ideas "
                "from RSA and Rabin with a unique structure where n = p²q, which simplifies "
                "some operations while maintaining comparable security."
            ),
            "advantages": [
                "Unique decryption — unlike Rabin, no ambiguity in plaintext recovery.",
                "Based on well-understood integer factorization hardness.",
                "Simple encryption — just modular exponentiation with n as exponent.",
                "No separate public exponent needed — n serves double duty.",
            ],
            "disadvantages": [
                "Less studied than RSA — fewer security proofs and analyses.",
                "n = p²q is larger than RSA's n = pq for similar security.",
                "Not widely implemented in practice.",
                "Vulnerable to quantum attacks like all factorization-based schemes.",
            ],
            "improvements": (
                "Schmidt-Samoa demonstrates that public-key systems can be built from "
                "different factorization structures. Modern trends favor elliptic curve "
                "cryptography for efficiency and post-quantum lattice-based systems "
                "(like CRYSTALS-Kyber) for quantum resistance."
            ),
        }

    def explain_steps(self, text: str, key: str = "7,11", mode: str = "encrypt") -> list[dict]:
        p, q, n, pq, d, lcm_val = self._parse_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Key Generation",
            "content": (
                f"p = {p}, q = {q}\n"
                f"n = p²q = {p}² × {q} = {n} (public key)\n"
                f"pq = {pq} (used in decryption)\n"
                f"lcm(p-1, q-1) = {lcm_val}\n"
                f"d = n⁻¹ mod lcm = {d} (private key)"
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            rows = []
            result_parts = []
            for ch in text:
                m = ord(ch)
                c = pow(m, n, n)
                rows.append({
                    "input": ch,
                    "position": str(m),
                    "calc": f"{m}^{n} mod {n}",
                    "output": str(c),
                })
                result_parts.append(str(c))

            steps.append({
                "title": "Step 2 — Encryption: c = m^n mod n",
                "content": "Each character value is raised to power n modulo n.",
                "data": {"type": "transformation", "rows": rows},
            })
            result = ",".join(result_parts)
        else:
            parts = text.split(",")
            rows = []
            result_chars = []
            for part in parts:
                c = int(part.strip())
                m = pow(c, d, pq)
                rows.append({
                    "input": str(c),
                    "calc": f"{c}^{d} mod {pq}",
                    "output": chr(m),
                })
                result_chars.append(chr(m))

            steps.append({
                "title": "Step 2 — Decryption: m = c^d mod pq",
                "content": "Each ciphertext value is raised to power d modulo pq.",
                "data": {"type": "transformation", "rows": rows},
            })
            result = "".join(result_chars)

        steps.append({
            "title": "Step 3 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
