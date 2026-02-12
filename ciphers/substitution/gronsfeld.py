"""Gronsfeld Cipher — Vigenère variant using a numeric key."""

from ciphers.base import Cipher

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class GronsfeldCipher(Cipher):

    def encrypt(self, plaintext: str, key: str = "31415") -> str:
        digits = self._parse_key(key)
        return self._transform(plaintext, digits, encrypt=True)

    def decrypt(self, ciphertext: str, key: str = "31415") -> str:
        digits = self._parse_key(key)
        return self._transform(ciphertext, digits, encrypt=False)

    @staticmethod
    def _parse_key(key) -> list[int]:
        digits = [int(d) for d in str(key) if d.isdigit()]
        if not digits:
            raise ValueError("Key must contain at least one digit (0-9).")
        return digits

    def _transform(self, text: str, digits: list[int], encrypt: bool) -> str:
        result, ki = [], 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                shift = digits[ki % len(digits)]
                if not encrypt:
                    shift = -shift
                result.append(chr((ord(ch) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Gronsfeld Cipher",
            "slug": "gronsfeld",
            "category": "Classical",
            "subcategory": "Polyalphabetic Substitution",
            "key_info": "A sequence of digits (e.g. '31415').",
            "description": (
                "The Gronsfeld cipher works identically to the Vigenere cipher but "
                "uses a numeric key (digits 0-9) instead of a keyword. Each digit "
                "determines the shift for the corresponding plaintext letter. Because "
                "shifts are limited to 0-9, it has a smaller keyspace than Vigenere."
            ),
            "history": (
                "Attributed to Count Gronsfeld, a 17th-century Flemish cryptographer. "
                "It was designed to be easier to remember (numeric keys) while still "
                "providing polyalphabetic security, though the restricted keyspace "
                "makes it weaker than the full Vigenere cipher."
            ),
            "advantages": [
                "Numeric keys are easier to memorize and communicate than word keys.",
                "Still polyalphabetic — better than any monoalphabetic cipher.",
                "Simpler to use than Vigenere (only 10 shift values per position).",
                "Can use mathematical constants (pi, e) as memorable key sources.",
            ],
            "disadvantages": [
                "Only 10 possible shifts per position (0-9) vs. Vigenere's 26.",
                "Much smaller effective key space makes brute force faster.",
                "Same repeating-key weakness as Vigenere — vulnerable to Kasiski examination.",
                "The limited shift range makes statistical attacks more effective.",
            ],
            "improvements": (
                "Gronsfeld is a convenience trade-off: easier-to-remember numeric keys "
                "at the cost of a weaker key space. Vigenere improves upon it by "
                "allowing the full 26-letter alphabet as key values. The Autokey cipher "
                "renders the repeating-key weakness moot entirely by self-extending the "
                "key with plaintext, removing periodicity."
            ),
        }

    def explain_steps(self, text: str, key: str = "31415", mode: str = "encrypt") -> list[dict]:
        digits = self._parse_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Parse the Numeric Key",
            "content": f"Key digits: {digits}. These cycle to cover the message length.",
            "data": {"type": "info", "digits": digits},
        })

        steps.append({
            "title": "Step 2 — Align Digits with Text",
            "content": "Each letter gets paired with the next digit from the key.",
            "data": {"type": "alignment", "text_chars": list(text), "key_chars": []},
        })
        ki = 0
        for ch in text:
            if ch.isalpha():
                steps[-1]["data"]["key_chars"].append(str(digits[ki % len(digits)]))
                ki += 1
            else:
                steps[-1]["data"]["key_chars"].append("—")

        rows, result, ki = [], [], 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                shift = digits[ki % len(digits)]
                if mode == "encrypt":
                    y = (ord(ch) - base + shift) % 26
                else:
                    y = (ord(ch) - base - shift) % 26
                out = chr(y + base)
                sign = "+" if mode == "encrypt" else "−"
                rows.append({
                    "input": ch, "shift": shift,
                    "calc": f"({ord(ch.upper()) - ord('A')} {sign} {shift}) mod 26 = {y}",
                    "output": out,
                })
                result.append(out)
                ki += 1
            else:
                rows.append({"input": ch, "shift": "—", "calc": "—", "output": ch})
                result.append(ch)

        steps.append({
            "title": "Step 3 — Apply Shifts",
            "content": f"{'Add' if mode == 'encrypt' else 'Subtract'} each digit shift to the letter position.",
            "data": {"type": "transformation", "rows": rows},
        })
        steps.append({
            "title": "Step 4 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'}:",
            "data": {"type": "result", "output": "".join(result)},
        })
        return steps
