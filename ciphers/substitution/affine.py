"""Affine Cipher — encrypts via E(x) = (a·x + b) mod 26."""

import math
from ciphers.base import Cipher

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _mod_inverse(a: int, m: int = 26) -> int:
    """Compute modular multiplicative inverse of a mod m using extended Euclidean."""
    if math.gcd(a, m) != 1:
        raise ValueError(f"No modular inverse for a={a} mod {m} (gcd != 1).")
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    raise ValueError(f"No modular inverse for a={a} mod {m}.")


class AffineCipher(Cipher):

    def encrypt(self, plaintext: str, key: str = "5,8") -> str:
        a, b = self._parse_key(key)
        return self._transform(plaintext, a, b, encrypt=True)

    def decrypt(self, ciphertext: str, key: str = "5,8") -> str:
        a, b = self._parse_key(key)
        return self._transform(ciphertext, a, b, encrypt=False)

    # ── helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _parse_key(key) -> tuple[int, int]:
        if isinstance(key, str):
            parts = key.replace(" ", "").split(",")
            a, b = int(parts[0]), int(parts[1])
        else:
            a, b = int(key[0]), int(key[1])
        if math.gcd(a, 26) != 1:
            raise ValueError(
                f"'a' must be coprime with 26. Got a={a}, gcd(a,26)={math.gcd(a,26)}. "
                f"Valid values for a: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25."
            )
        return a, b

    def _transform(self, text: str, a: int, b: int, encrypt: bool) -> str:
        a_inv = _mod_inverse(a)
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                x = ord(ch) - base
                if encrypt:
                    y = (a * x + b) % 26
                else:
                    y = (a_inv * (x - b)) % 26
                result.append(chr(y + base))
            else:
                result.append(ch)
        return "".join(result)

    # ── educational ──────────────────────────────────────────────────

    def get_info(self) -> dict:
        return {
            "name": "Affine Cipher",
            "slug": "affine",
            "category": "Classical",
            "subcategory": "Monoalphabetic Substitution",
            "key_info": "Two integers a,b (e.g. '5,8'). 'a' must be coprime with 26.",
            "description": (
                "The Affine cipher generalises the Caesar cipher with the formula "
                "E(x) = (a*x + b) mod 26, where 'a' and 'b' are the key. "
                "Decryption uses D(x) = a^-1*(x - b) mod 26. The value 'a' must be "
                "coprime with 26 so that a modular inverse exists."
            ),
            "history": (
                "The Affine cipher is a type of monoalphabetic substitution cipher "
                "that combines multiplicative and additive shifts. It demonstrates "
                "core concepts of modular arithmetic and is widely taught in "
                "introductory cryptography courses."
            ),
            "advantages": [
                "Larger key space than Caesar: 12 valid 'a' values x 26 'b' values = 312 keys.",
                "Introduces modular arithmetic and the concept of modular inverses.",
                "Generalises both Caesar (a=1) and Multiplicative (b=0) ciphers.",
                "Demonstrates the mathematical foundation behind modern cryptosystems.",
            ],
            "disadvantages": [
                "Still monoalphabetic — each plaintext letter always maps to the same ciphertext letter.",
                "312 possible keys is still small enough to brute force in milliseconds.",
                "Vulnerable to frequency analysis — 'E' still maps to one fixed letter.",
                "The constraint that 'a' must be coprime with 26 limits key choices.",
            ],
            "improvements": (
                "Affine improves on Caesar by combining multiplication and addition, "
                "expanding the key space from 25 to 312. However, being monoalphabetic, "
                "it cannot resist frequency analysis. Polyalphabetic ciphers like "
                "Vigenere solve this by varying the shift at each position, so the same "
                "letter encrypts differently depending on its position in the text."
            ),
        }

    def explain_steps(self, text: str, key: str = "5,8", mode: str = "encrypt") -> list[dict]:
        a, b = self._parse_key(key)
        a_inv = _mod_inverse(a)
        steps = []

        steps.append({
            "title": "Step 1 — Parse the Key",
            "content": (
                f"Key (a, b) = ({a}, {b}). "
                f"gcd({a}, 26) = {math.gcd(a, 26)} ✓ (coprime). "
                f"a⁻¹ mod 26 = {a_inv}."
            ),
            "data": {"type": "info", "a": a, "b": b, "a_inv": a_inv},
        })

        if mode == "encrypt":
            formula = f"E(x) = ({a}·x + {b}) mod 26"
        else:
            formula = f"D(x) = {a_inv}·(x − {b}) mod 26"

        steps.append({
            "title": "Step 2 — The Affine Formula",
            "content": f"Formula: {formula}",
            "data": {"type": "formula", "formula": formula},
        })

        mapping_from, mapping_to = [], []
        for i in range(26):
            mapping_from.append(ALPHA[i])
            if mode == "encrypt":
                mapping_to.append(ALPHA[(a * i + b) % 26])
            else:
                mapping_to.append(ALPHA[(a_inv * (i - b)) % 26])

        steps.append({
            "title": "Step 3 — Full Substitution Table",
            "content": "Applying the formula to every letter produces this mapping:",
            "data": {"type": "mapping", "from": mapping_from, "to": mapping_to},
        })

        rows, result = [], []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                x = ord(ch) - base
                if mode == "encrypt":
                    y = (a * x + b) % 26
                    calc = f"({a}×{x} + {b}) mod 26 = {y}"
                else:
                    y = (a_inv * (x - b)) % 26
                    calc = f"{a_inv}×({x} − {b}) mod 26 = {y}"
                out = chr(y + base)
                rows.append({"input": ch, "x": x, "calculation": calc, "y": y, "output": out})
                result.append(out)
            else:
                rows.append({"input": ch, "x": "—", "calculation": "—", "y": "—", "output": ch})
                result.append(ch)

        steps.append({
            "title": "Step 4 — Transform Each Letter",
            "content": "Apply the formula to each character of the input.",
            "data": {"type": "transformation", "rows": rows},
        })

        steps.append({
            "title": "Step 5 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'}:",
            "data": {"type": "result", "output": "".join(result)},
        })
        return steps
