"""Caesar Cipher — shifts every letter by a fixed number of positions."""

from ciphers.base import Cipher

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class CaesarCipher(Cipher):

    def encrypt(self, plaintext: str, key: int = 3) -> str:
        return self._shift(plaintext, int(key))

    def decrypt(self, ciphertext: str, key: int = 3) -> str:
        return self._shift(ciphertext, -int(key))

    def _shift(self, text: str, shift: int) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                result.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                result.append(ch)
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Caesar Cipher",
            "slug": "caesar",
            "category": "Classical",
            "subcategory": "Monoalphabetic Substitution",
            "key_info": "An integer shift value (1-25). Default is 3.",
            "description": (
                "The Caesar cipher shifts every letter in the plaintext by a fixed "
                "number of positions down the alphabet. With a shift of 3, A->D, B->E, "
                "C->F, and so on. It wraps around so that X->A, Y->B, Z->C."
            ),
            "history": (
                "Named after Julius Caesar, who reportedly used it with a shift of 3 "
                "to communicate with his generals. Suetonius documents Caesar's use "
                "of this simple substitution in his private correspondence."
            ),
            "advantages": [
                "Simple to understand and implement — just shift letters.",
                "Introduces the concept of a variable key (shift amount).",
                "Improves on Atbash by having 25 possible key values instead of 1.",
                "Can be performed quickly by hand or mentally.",
            ],
            "disadvantages": [
                "Only 25 possible keys — easily broken by brute force.",
                "Monoalphabetic: each letter always maps to the same cipher letter.",
                "Preserves letter frequency patterns, making frequency analysis trivial.",
                "Word boundaries and punctuation remain unchanged, leaking structure.",
            ],
            "improvements": (
                "Caesar improves on Atbash by adding a key, but 25 keys is still too "
                "few. The Affine cipher extends this with two parameters (ax + b mod 26), "
                "yielding 312 possible keys. Polyalphabetic ciphers like Vigenere go "
                "further by using different shifts for each position, destroying the "
                "one-to-one letter frequency pattern that makes Caesar so vulnerable."
            ),
        }

    def explain_steps(self, text: str, key: int = 3, mode: str = "encrypt") -> list[dict]:
        key = int(key)
        shift = key if mode == "encrypt" else -key
        steps = []

        steps.append({
            "title": "Step 1 — Determine the Shift",
            "content": (
                f"Mode: {mode}. Key = {key}. "
                f"{'Shift each letter forward' if mode == 'encrypt' else 'Shift each letter backward'} "
                f"by {key} positions in the alphabet."
            ),
            "data": {"type": "info", "shift": shift, "key": key},
        })

        shifted_alpha = "".join(ALPHA[(i + shift) % 26] for i in range(26))
        steps.append({
            "title": "Step 2 — Build the Shifted Alphabet",
            "content": "Each letter in the plain alphabet maps to the letter 'shift' positions away.",
            "data": {"type": "mapping", "from": list(ALPHA), "to": list(shifted_alpha)},
        })

        rows = []
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                original_pos = ord(ch.upper()) - ord("A")
                new_pos = (original_pos + shift) % 26
                out = chr(new_pos + base)
                rows.append({
                    "input": ch,
                    "position": original_pos,
                    "shift": shift,
                    "new_position": new_pos,
                    "output": out,
                })
                result.append(out)
            else:
                rows.append({"input": ch, "position": "—", "shift": "—", "new_position": "—", "output": ch})
                result.append(ch)

        steps.append({
            "title": "Step 3 — Apply the Shift Letter by Letter",
            "content": "Substitute every letter using the shifted alphabet; non-letters are unchanged.",
            "data": {"type": "transformation", "rows": rows},
        })

        steps.append({
            "title": "Step 4 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": "".join(result)},
        })
        return steps
