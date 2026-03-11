"""Massey-Omura Cryptosystem — three-pass protocol using discrete logarithms."""

import random
import math
from ciphers.base import Cipher


class MasseyOmuraCipher(Cipher):
    """
    Educational Massey-Omura implementation.
    A three-pass protocol where no keys are exchanged — both parties
    use their own secret exponents to encrypt and decrypt.
    """

    def _parse_key(self, key: str):
        """Parse key as 'p,ea,da' (prime, Alice's encryption/decryption exponents)."""
        if not key:
            p = 467
            # Alice's keys: ea * da ≡ 1 mod (p-1)
            ea = 37
            da = self._mod_inverse(ea, p - 1)
        else:
            parts = [s.strip() for s in key.split(",")]
            if len(parts) >= 3:
                p, ea, da = int(parts[0]), int(parts[1]), int(parts[2])
            elif len(parts) >= 2:
                p, ea = int(parts[0]), int(parts[1])
                da = self._mod_inverse(ea, p - 1)
            else:
                p = 467
                ea = 37
                da = self._mod_inverse(ea, p - 1)
        return p, ea, da

    @staticmethod
    def _extended_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = MasseyOmuraCipher._extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    @staticmethod
    def _mod_inverse(a, m):
        g, x, _ = MasseyOmuraCipher._extended_gcd(a % m, m)
        if g != 1:
            raise ValueError(f"Modular inverse of {a} mod {m} does not exist (gcd={g})")
        return x % m

    def encrypt(self, plaintext: str, key: str = "467,37") -> str:
        """Simulate the three-pass protocol (Alice → Bob → Alice → Bob)."""
        p, ea, da = self._parse_key(key)
        # Simulate Bob's keys
        eb = 73
        while math.gcd(eb, p - 1) != 1:
            eb += 2
        db = self._mod_inverse(eb, p - 1)

        encrypted = []
        for ch in plaintext:
            m = ord(ch)
            if m >= p:
                raise ValueError(f"Character '{ch}' (value {m}) >= p={p}.")
            # Pass 1: Alice encrypts with ea
            step1 = pow(m, ea, p)
            # Pass 2: Bob encrypts with eb
            step2 = pow(step1, eb, p)
            # Pass 3: Alice removes her encryption with da
            step3 = pow(step2, da, p)
            # Now Bob has m^eb and can decrypt with db
            encrypted.append(f"{step3}")
        # The output is Bob's encrypted message, along with Bob's exponent for decryption
        return f"[{eb},{db}]:" + ",".join(encrypted)

    def decrypt(self, ciphertext: str, key: str = "467,37") -> str:
        p, ea, da = self._parse_key(key)
        # Extract Bob's keys and ciphertext
        if ciphertext.startswith("["):
            bracket_end = ciphertext.index("]")
            bob_keys = ciphertext[1:bracket_end].split(",")
            eb, db = int(bob_keys[0]), int(bob_keys[1])
            data = ciphertext[bracket_end + 2:]
        else:
            eb = 73
            while math.gcd(eb, p - 1) != 1:
                eb += 2
            db = self._mod_inverse(eb, p - 1)
            data = ciphertext

        parts = data.split(",")
        result = []
        for part in parts:
            c = int(part.strip())
            # Bob decrypts with db to recover original message
            m = pow(c, db, p)
            result.append(chr(m))
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Massey-Omura",
            "slug": "massey-omura",
            "category": "Modern",
            "subcategory": "Discrete Logarithm",
            "key_info": "Prime and exponent: p,e (e.g., 467,37). Default: 467,37",
            "description": (
                "The Massey-Omura cryptosystem is a three-pass protocol where Alice "
                "and Bob each have their own secret exponents e and d (with ed ≡ 1 mod p-1). "
                "No keys are exchanged: Alice encrypts m → m^ea, Bob adds his encryption "
                "→ m^(ea·eb), Alice removes hers → m^eb, and Bob decrypts → m."
            ),
            "history": (
                "Proposed by James Massey and Jim K. Omura in 1982. Based on Shamir's "
                "no-key protocol concept combined with the Diffie-Hellman discrete log "
                "assumption. It elegantly demonstrates that secure communication is "
                "possible without any prior key exchange or public-key infrastructure."
            ),
            "advantages": [
                "No key exchange needed — each party uses only their own secret.",
                "Conceptually elegant — demonstrates commutative encryption.",
                "Based on the well-studied discrete logarithm problem.",
                "Illustrates the possibility of keyless secure communication.",
            ],
            "disadvantages": [
                "Requires three message passes (vs. one for RSA or ElGamal).",
                "Vulnerable to man-in-the-middle attacks without authentication.",
                "Higher communication overhead than standard public-key schemes.",
                "Rarely used in practice due to the three-pass requirement.",
            ],
            "improvements": (
                "The three-pass overhead makes Massey-Omura impractical for most uses. "
                "Public-key systems (RSA, ElGamal, ECIES) achieve the same goal with a "
                "single pass plus a separate key exchange. Authenticated key exchange "
                "protocols (like Signal Protocol) provide additional security guarantees."
            ),
        }

    def explain_steps(self, text: str, key: str = "467,37", mode: str = "encrypt") -> list[dict]:
        p, ea, da = self._parse_key(key)
        eb = 73
        while math.gcd(eb, p - 1) != 1:
            eb += 2
        db = self._mod_inverse(eb, p - 1)
        steps = []

        steps.append({
            "title": "Step 1 — Key Setup",
            "content": (
                f"p = {p} (shared prime)\n"
                f"Alice: eₐ = {ea}, dₐ = {da} (eₐ·dₐ ≡ 1 mod {p-1})\n"
                f"Bob: e_b = {eb}, d_b = {db} (e_b·d_b ≡ 1 mod {p-1})\n"
                f"No keys are exchanged between parties!"
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            rows = []
            result_parts = []
            for ch in text:
                m = ord(ch)
                s1 = pow(m, ea, p)
                s2 = pow(s1, eb, p)
                s3 = pow(s2, da, p)
                rows.append({
                    "input": ch,
                    "position": str(m),
                    "calc": f"m^eₐ={s1} → ×e_b={s2} → ×dₐ={s3}",
                    "output": str(s3),
                })
                result_parts.append(str(s3))

            steps.append({
                "title": "Step 2 — Three-Pass Protocol",
                "content": (
                    "Pass 1: Alice sends m^eₐ mod p\n"
                    "Pass 2: Bob sends m^(eₐ·e_b) mod p\n"
                    "Pass 3: Alice sends m^e_b mod p (removing her layer)\n"
                    "Bob can now decrypt with d_b."
                ),
                "data": {"type": "transformation", "rows": rows},
            })
            result = f"[{eb},{db}]:" + ",".join(result_parts)
        else:
            if text.startswith("["):
                bracket_end = text.index("]")
                data = text[bracket_end + 2:]
            else:
                data = text
            parts = data.split(",")
            rows = []
            result_chars = []
            for part in parts:
                c = int(part.strip())
                m = pow(c, db, p)
                rows.append({
                    "input": str(c),
                    "calc": f"{c}^{db} mod {p}",
                    "output": chr(m),
                })
                result_chars.append(chr(m))

            steps.append({
                "title": "Step 2 — Bob Decrypts",
                "content": f"Bob applies d_b to each value: m = c^d_b mod p.",
                "data": {"type": "transformation", "rows": rows},
            })
            result = "".join(result_chars)

        steps.append({
            "title": "Step 3 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
