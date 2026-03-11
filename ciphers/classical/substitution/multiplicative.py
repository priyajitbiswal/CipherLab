"""Multiplicative Cipher — encrypts via E(x) = (a·x) mod 26."""

import math
from ciphers.base import Cipher

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _mod_inverse(a: int, m: int = 26) -> int:
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    raise ValueError(f"No modular inverse for a={a} mod {m}.")


class MultiplicativeCipher(Cipher):

    def encrypt(self, plaintext: str, key: int = 7) -> str:
        a = int(key)
        self._validate(a)
        return self._transform(plaintext, a, encrypt=True)

    def decrypt(self, ciphertext: str, key: int = 7) -> str:
        a = int(key)
        self._validate(a)
        return self._transform(ciphertext, a, encrypt=False)

    @staticmethod
    def _validate(a: int):
        if math.gcd(a, 26) != 1:
            raise ValueError(
                f"Key must be coprime with 26. Got {a}. "
                f"Valid keys: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25."
            )

    def _transform(self, text: str, a: int, encrypt: bool) -> str:
        a_inv = _mod_inverse(a)
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                x = ord(ch) - base
                y = (a * x) % 26 if encrypt else (a_inv * x) % 26
                result.append(chr(y + base))
            else:
                result.append(ch)
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Multiplicative Cipher",
            "slug": "multiplicative",
            "category": "Classical",
            "subcategory": "Monoalphabetic Substitution",
            "key_info": "An integer coprime with 26 (e.g. 3, 5, 7, 9, 11, ...).",
            "description": (
                "The Multiplicative cipher encrypts each letter by multiplying its "
                "numeric position by a key value modulo 26: E(x) = (a*x) mod 26. "
                "It is a special case of the Affine cipher where b = 0."
            ),
            "history": (
                "The Multiplicative cipher is a fundamental building block of "
                "modular-arithmetic-based cryptography. While simple, it introduces "
                "the critical concept of modular inverses — 'a' must be coprime with "
                "26 so that decryption is possible."
            ),
            "advantages": [
                "Introduces non-linear letter mapping (multiplication vs. addition).",
                "Demonstrates the mathematical concept of modular multiplicative inverses.",
                "Scrambles the alphabet more thoroughly than a simple shift.",
                "Foundation for understanding the Affine cipher and RSA-like systems.",
            ],
            "disadvantages": [
                "Only 12 valid key values (integers coprime with 26) — tiny key space.",
                "A=0 always maps to itself, leaking information about word starts.",
                "Still monoalphabetic — one-to-one letter correspondence preserved.",
                "Frequency analysis breaks it just as easily as Caesar.",
            ],
            "improvements": (
                "Multiplicative improves on Caesar by using multiplication instead of "
                "addition, creating a less predictable alphabet ordering. The Affine "
                "cipher combines both operations (ax + b) for a larger key space. "
                "However, all monoalphabetic ciphers share the fatal weakness of "
                "preserving letter frequencies — the Vigenere cipher was the first "
                "major step toward solving this problem."
            ),
        }

    def explain_steps(self, text: str, key: int = 7, mode: str = "encrypt") -> list[dict]:
        a = int(key)
        self._validate(a)
        a_inv = _mod_inverse(a)
        steps = []

        steps.append({
            "title": "Step 1 — Validate the Key",
            "content": (
                f"Key a = {a}. gcd({a}, 26) = {math.gcd(a, 26)} ✓ (coprime). "
                f"Modular inverse a⁻¹ = {a_inv}."
            ),
            "data": {"type": "info", "a": a, "a_inv": a_inv},
        })

        formula = f"E(x) = ({a}·x) mod 26" if mode == "encrypt" else f"D(x) = ({a_inv}·x) mod 26"
        steps.append({
            "title": "Step 2 — Formula",
            "content": formula,
            "data": {"type": "formula", "formula": formula},
        })

        mapping_from, mapping_to = [], []
        for i in range(26):
            mapping_from.append(ALPHA[i])
            if mode == "encrypt":
                mapping_to.append(ALPHA[(a * i) % 26])
            else:
                mapping_to.append(ALPHA[(a_inv * i) % 26])
        steps.append({
            "title": "Step 3 — Substitution Table",
            "content": "The full mapping derived from the formula:",
            "data": {"type": "mapping", "from": mapping_from, "to": mapping_to},
        })

        rows, result = [], []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                x = ord(ch) - base
                if mode == "encrypt":
                    y = (a * x) % 26
                    calc = f"({a}×{x}) mod 26 = {y}"
                else:
                    y = (a_inv * x) % 26
                    calc = f"({a_inv}×{x}) mod 26 = {y}"
                out = chr(y + base)
                rows.append({"input": ch, "x": x, "calc": calc, "output": out})
                result.append(out)
            else:
                rows.append({"input": ch, "x": "—", "calc": "—", "output": ch})
                result.append(ch)

        steps.append({
            "title": "Step 4 — Transform",
            "content": "Multiply each letter position by the key.",
            "data": {"type": "transformation", "rows": rows},
        })
        steps.append({
            "title": "Step 5 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'}:",
            "data": {"type": "result", "output": "".join(result)},
        })
        return steps
