"""ElGamal Cryptosystem — public-key encryption based on the discrete logarithm problem."""

import random
from ciphers.base import Cipher


class ElGamalCipher(Cipher):
    """
    Educational ElGamal implementation using small primes.
    Security relies on the difficulty of computing discrete logarithms.
    """

    def _parse_key(self, key: str):
        """Parse key as 'p,g,x' (prime, generator, private key)."""
        if not key:
            p, g, x = 467, 2, 153
        else:
            parts = [s.strip() for s in key.split(",")]
            if len(parts) >= 3:
                p, g, x = int(parts[0]), int(parts[1]), int(parts[2])
            elif len(parts) == 2:
                p, g = int(parts[0]), int(parts[1])
                x = random.randint(2, p - 2)
            else:
                p, g, x = 467, 2, 153
        h = pow(g, x, p)  # public key component
        return p, g, x, h

    def encrypt(self, plaintext: str, key: str = "467,2,153") -> str:
        p, g, x, h = self._parse_key(key)
        encrypted = []
        for ch in plaintext:
            m = ord(ch)
            if m >= p:
                raise ValueError(f"Character '{ch}' (value {m}) >= p={p}. Use larger prime.")
            y = random.randint(2, p - 2)
            c1 = pow(g, y, p)
            s = pow(h, y, p)
            c2 = (m * s) % p
            encrypted.append(f"{c1}:{c2}")
        return ";".join(encrypted)

    def decrypt(self, ciphertext: str, key: str = "467,2,153") -> str:
        p, g, x, h = self._parse_key(key)
        pairs = ciphertext.split(";")
        result = []
        for pair in pairs:
            c1_s, c2_s = pair.strip().split(":")
            c1, c2 = int(c1_s), int(c2_s)
            s = pow(c1, x, p)
            s_inv = pow(s, p - 2, p)  # Fermat's little theorem
            m = (c2 * s_inv) % p
            result.append(chr(m))
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "ElGamal",
            "slug": "elgamal",
            "category": "Modern",
            "subcategory": "Discrete Logarithm",
            "key_info": "Prime, generator, private key: p,g,x (e.g., 467,2,153). Default: 467,2,153",
            "description": (
                "The ElGamal cryptosystem encrypts messages using the Diffie-Hellman "
                "key exchange mechanism. For a prime p, generator g, and private key x, "
                "the public key is h = g^x mod p. Encryption picks random y and computes "
                "c1 = g^y mod p, c2 = m × h^y mod p. Decryption recovers m using the "
                "private key x."
            ),
            "history": (
                "Proposed by Taher Elgamal in 1985 based on the Diffie-Hellman key "
                "exchange. It was used in the original DSA (Digital Signature Algorithm) "
                "standard and in PGP. ElGamal is a foundational scheme for understanding "
                "discrete-log based cryptography."
            ),
            "advantages": [
                "Probabilistic encryption — same plaintext encrypts to different ciphertexts.",
                "Based on the well-studied discrete logarithm problem.",
                "Semantic security against chosen-plaintext attacks.",
                "Foundation for many advanced schemes (Cramer-Shoup, EC-ElGamal).",
            ],
            "disadvantages": [
                "Ciphertext is twice the size of plaintext (expansion factor 2).",
                "Slower than RSA for equivalent security levels.",
                "Requires a good source of randomness for each encryption.",
                "Not IND-CCA2 secure — vulnerable to chosen-ciphertext attacks.",
            ],
            "improvements": (
                "ElGamal's CCA vulnerability was addressed by Cramer and Shoup in 1998 "
                "with a provably CCA2-secure variant. Moving to elliptic curve groups "
                "(EC-ElGamal) gives the same security with much smaller keys. "
                "Modern systems often use ECIES for practical EC-based encryption."
            ),
        }

    def explain_steps(self, text: str, key: str = "467,2,153", mode: str = "encrypt") -> list[dict]:
        p, g, x, h = self._parse_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Key Setup",
            "content": (
                f"p = {p} (prime), g = {g} (generator)\n"
                f"x = {x} (private key)\n"
                f"h = g^x mod p = {g}^{x} mod {p} = {h} (public key)\n"
                f"Public: (p={p}, g={g}, h={h}) | Private: x={x}"
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            rows = []
            result_parts = []
            for ch in text:
                m = ord(ch)
                y = random.randint(2, p - 2)
                c1 = pow(g, y, p)
                s = pow(h, y, p)
                c2 = (m * s) % p
                rows.append({
                    "input": ch,
                    "position": str(m),
                    "calc": f"y={y}, c1={g}^{y}={c1}, s={h}^{y}={s}, c2={m}×{s}={c2}",
                    "output": f"{c1}:{c2}",
                })
                result_parts.append(f"{c1}:{c2}")

            steps.append({
                "title": "Step 2 — Encrypt Each Character",
                "content": "Pick random y, compute c1=g^y mod p, s=h^y mod p, c2=m×s mod p.",
                "data": {"type": "transformation", "rows": rows},
            })
            result = ";".join(result_parts)
        else:
            pairs = text.split(";")
            rows = []
            result_chars = []
            for pair in pairs:
                c1_s, c2_s = pair.strip().split(":")
                c1, c2 = int(c1_s), int(c2_s)
                s = pow(c1, x, p)
                s_inv = pow(s, p - 2, p)
                m = (c2 * s_inv) % p
                rows.append({
                    "input": f"{c1}:{c2}",
                    "calc": f"s={c1}^{x}={s}, s⁻¹={s_inv}, m={c2}×{s_inv}={m}",
                    "output": chr(m),
                })
                result_chars.append(chr(m))

            steps.append({
                "title": "Step 2 — Decrypt Each Pair",
                "content": "Compute s=c1^x mod p, then m = c2 × s⁻¹ mod p.",
                "data": {"type": "transformation", "rows": rows},
            })
            result = "".join(result_chars)

        steps.append({
            "title": "Step 3 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
