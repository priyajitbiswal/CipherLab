"""Cramer-Shoup Cryptosystem — the first practical IND-CCA2 secure public-key encryption."""

import random
import hashlib
from ciphers.base import Cipher


class CramerShoupCipher(Cipher):
    """
    Educational Cramer-Shoup implementation.
    Extends ElGamal with hash-based verification for CCA2 security.
    """

    def _parse_key(self, key: str):
        """Parse key as 'p,g1,g2,x1,x2,y1,y2,z' or use defaults."""
        if not key:
            p = 467
            g1, g2 = 2, 5
            x1, x2, y1, y2, z = 37, 91, 17, 53, 127
        else:
            parts = [s.strip() for s in key.split(",")]
            if len(parts) >= 8:
                p = int(parts[0])
                g1, g2 = int(parts[1]), int(parts[2])
                x1, x2, y1, y2, z = int(parts[3]), int(parts[4]), int(parts[5]), int(parts[6]), int(parts[7])
            else:
                p = 467
                g1, g2 = 2, 5
                x1, x2, y1, y2, z = 37, 91, 17, 53, 127

        c_val = (pow(g1, x1, p) * pow(g2, x2, p)) % p
        d_val = (pow(g1, y1, p) * pow(g2, y2, p)) % p
        h = pow(g1, z, p)
        return p, g1, g2, x1, x2, y1, y2, z, c_val, d_val, h

    @staticmethod
    def _hash(*args):
        """Universal hash function for the verification step."""
        h = hashlib.sha256()
        for a in args:
            h.update(str(a).encode())
        return int(h.hexdigest(), 16)

    def encrypt(self, plaintext: str, key: str = "") -> str:
        p, g1, g2, x1, x2, y1, y2, z, c, d, h = self._parse_key(key)
        encrypted = []
        for ch in plaintext:
            m = ord(ch)
            if m >= p:
                raise ValueError(f"Character '{ch}' (value {m}) >= p={p}. Use larger prime.")
            k = random.randint(2, p - 2)
            u1 = pow(g1, k, p)
            u2 = pow(g2, k, p)
            e = (m * pow(h, k, p)) % p
            alpha = self._hash(u1, u2, e) % (p - 1)
            v = (pow(c, k, p) * pow(d, k * alpha, p)) % p
            encrypted.append(f"{u1}:{u2}:{e}:{v}")
        return ";".join(encrypted)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        p, g1, g2, x1, x2, y1, y2, z, c, d, h = self._parse_key(key)
        tuples = ciphertext.split(";")
        result = []
        for t in tuples:
            parts = t.strip().split(":")
            u1, u2, e, v = int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
            alpha = self._hash(u1, u2, e) % (p - 1)
            # Verify
            check = (pow(u1, x1 + y1 * alpha, p) * pow(u2, x2 + y2 * alpha, p)) % p
            if check != v:
                raise ValueError("Cramer-Shoup verification failed — ciphertext may be tampered.")
            # Decrypt
            s_inv = pow(pow(u1, z, p), p - 2, p)
            m = (e * s_inv) % p
            result.append(chr(m))
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Cramer-Shoup",
            "slug": "cramer-shoup",
            "category": "Modern",
            "subcategory": "Discrete Logarithm",
            "key_info": "p,g1,g2,x1,x2,y1,y2,z (8 values). Default: built-in small parameters.",
            "description": (
                "The Cramer-Shoup cryptosystem extends ElGamal with a hash-based "
                "verification step, making it the first practical public-key scheme "
                "proven secure against adaptive chosen-ciphertext attacks (IND-CCA2). "
                "Each ciphertext includes a proof of consistency verified during decryption."
            ),
            "history": (
                "Proposed by Ronald Cramer and Victor Shoup in 1998, extending earlier "
                "work by Naor and Yung. It was a breakthrough: the first efficient "
                "public-key scheme with a full CCA2 security proof under standard "
                "assumptions (DDH). Published at CRYPTO 1998."
            ),
            "advantages": [
                "Provably IND-CCA2 secure under the DDH assumption.",
                "Built-in ciphertext integrity verification — detects tampering.",
                "Based on standard, well-studied mathematical assumptions.",
                "Demonstrates how to achieve CCA2 security efficiently.",
            ],
            "disadvantages": [
                "Ciphertext is 4× the plaintext size (four group elements).",
                "More complex than ElGamal — harder to implement correctly.",
                "Slower than RSA-OAEP in practice.",
                "Requires careful parameter selection and a collision-resistant hash.",
            ],
            "improvements": (
                "Cramer-Shoup showed CCA2 security was practically achievable. "
                "Modern alternatives include RSA-OAEP (simpler, in practice), ECIES "
                "(smaller keys via elliptic curves), and post-quantum schemes like "
                "CRYSTALS-Kyber (lattice-based CCA2 security)."
            ),
        }

    def explain_steps(self, text: str, key: str = "", mode: str = "encrypt") -> list[dict]:
        p, g1, g2, x1, x2, y1, y2, z, c, d, h = self._parse_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Key Setup",
            "content": (
                f"p = {p}, g₁ = {g1}, g₂ = {g2}\n"
                f"Private: (x₁={x1}, x₂={x2}, y₁={y1}, y₂={y2}, z={z})\n"
                f"Public: c = g₁^x₁·g₂^x₂ = {c}, d = g₁^y₁·g₂^y₂ = {d}, h = g₁^z = {h}"
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            rows = []
            result_parts = []
            for ch in text:
                m = ord(ch)
                k = random.randint(2, p - 2)
                u1 = pow(g1, k, p)
                u2 = pow(g2, k, p)
                e = (m * pow(h, k, p)) % p
                alpha = self._hash(u1, u2, e) % (p - 1)
                v = (pow(c, k, p) * pow(d, k * alpha, p)) % p
                rows.append({
                    "input": ch,
                    "calc": f"k={k}, u1={u1}, u2={u2}, e={e}, v={v}",
                    "output": f"{u1}:{u2}:{e}:{v}",
                })
                result_parts.append(f"{u1}:{u2}:{e}:{v}")

            steps.append({
                "title": "Step 2 — Encrypt with Verification Tag",
                "content": (
                    "For each character: pick random k, compute u₁=g₁^k, u₂=g₂^k, "
                    "e=m·h^k, α=H(u₁,u₂,e), v=c^k·d^(kα) mod p."
                ),
                "data": {"type": "transformation", "rows": rows},
            })
            result = ";".join(result_parts)
        else:
            tuples = text.split(";")
            rows = []
            result_chars = []
            for t in tuples:
                parts_t = t.strip().split(":")
                u1, u2, e, v = int(parts_t[0]), int(parts_t[1]), int(parts_t[2]), int(parts_t[3])
                alpha = self._hash(u1, u2, e) % (p - 1)
                check = (pow(u1, x1 + y1 * alpha, p) * pow(u2, x2 + y2 * alpha, p)) % p
                s_inv = pow(pow(u1, z, p), p - 2, p)
                m = (e * s_inv) % p
                rows.append({
                    "input": f"{u1}:{u2}:{e}:{v}",
                    "calc": f"verify={'✓' if check == v else '✗'}, m={m}",
                    "output": chr(m),
                })
                result_chars.append(chr(m))

            steps.append({
                "title": "Step 2 — Verify & Decrypt",
                "content": "Verify v = u₁^(x₁+y₁α) · u₂^(x₂+y₂α), then m = e · (u₁^z)⁻¹ mod p.",
                "data": {"type": "transformation", "rows": rows},
            })
            result = "".join(result_chars)

        steps.append({
            "title": "Step 3 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
