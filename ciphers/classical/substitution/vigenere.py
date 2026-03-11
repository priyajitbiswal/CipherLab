"""Vigenère Cipher — polyalphabetic substitution using a repeating keyword."""

from ciphers.base import Cipher

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class VigenereCipher(Cipher):

    def encrypt(self, plaintext: str, key: str = "KEY") -> str:
        return self._transform(plaintext, str(key).upper(), encrypt=True)

    def decrypt(self, ciphertext: str, key: str = "KEY") -> str:
        return self._transform(ciphertext, str(key).upper(), encrypt=False)

    def _transform(self, text: str, key: str, encrypt: bool) -> str:
        key = "".join(c for c in key if c.isalpha())
        if not key:
            raise ValueError("Key must contain at least one letter.")
        result, ki = [], 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                shift = ord(key[ki % len(key)]) - ord("A")
                if not encrypt:
                    shift = -shift
                result.append(chr((ord(ch) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Vigenere Cipher",
            "slug": "vigenere",
            "category": "Classical",
            "subcategory": "Polyalphabetic Substitution",
            "key_info": "A keyword string (e.g. 'LEMON').",
            "description": (
                "The Vigenere cipher uses a keyword to create multiple Caesar shifts. "
                "Each letter of the key determines the shift for the corresponding "
                "plaintext letter. The key repeats cyclically to cover the entire "
                "message. This makes frequency analysis much harder than a simple "
                "monoalphabetic cipher."
            ),
            "history": (
                "Described by Giovan Battista Bellaso in 1553, it was later "
                "misattributed to Blaise de Vigenere. For three centuries it was "
                "considered unbreakable — earning the nickname 'le chiffre "
                "indechiffrable' — until Friedrich Kasiski published a general "
                "method of breaking it in 1863."
            ),
            "advantages": [
                "First cipher to defeat simple frequency analysis by using multiple alphabets.",
                "Same letter can encrypt to different ciphertext letters depending on position.",
                "Dramatically larger key space than any monoalphabetic cipher.",
                "Remained unbroken for ~300 years — a testament to polyalphabetic design.",
            ],
            "disadvantages": [
                "Repeating key creates periodic patterns detectable by Kasiski examination.",
                "Once key length is found, each column reduces to a simple Caesar cipher.",
                "Short keys offer limited security; key length determines effective strength.",
                "The key must be shared securely between parties (key distribution problem).",
            ],
            "improvements": (
                "Vigenere was a revolutionary leap over monoalphabetic ciphers, but its "
                "repeating key is its downfall. The Autokey cipher fixes this by extending "
                "the key with the plaintext itself, eliminating repetition. The Running Key "
                "cipher uses a long, non-repeating text as the key. The Hill cipher takes a "
                "completely different approach: encrypting multiple letters at once via "
                "matrix multiplication."
            ),
        }

    def explain_steps(self, text: str, key: str = "KEY", mode: str = "encrypt") -> list[dict]:
        key = "".join(c for c in str(key).upper() if c.isalpha())
        steps = []

        steps.append({
            "title": "Step 1 — Prepare the Key",
            "content": f"Keyword: '{key}'. It will repeat cyclically to match the length of the text.",
            "data": {"type": "info", "key": key},
        })

        # Build repeated key visually
        alpha_count = sum(1 for c in text if c.isalpha())
        extended_key = "".join(key[i % len(key)] for i in range(alpha_count))
        steps.append({
            "title": "Step 2 — Align Key with Text",
            "content": "Each alphabetic character gets paired with the next key letter.",
            "data": {
                "type": "alignment",
                "text_chars": list(text),
                "key_chars": [],
            },
        })
        ki = 0
        for ch in text:
            if ch.isalpha():
                steps[-1]["data"]["key_chars"].append(key[ki % len(key)])
                ki += 1
            else:
                steps[-1]["data"]["key_chars"].append("—")

        rows, result, ki = [], [], 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                k = key[ki % len(key)]
                shift = ord(k) - ord("A")
                if mode == "encrypt":
                    y = (ord(ch) - base + shift) % 26
                else:
                    y = (ord(ch) - base - shift) % 26
                out = chr(y + base)
                sign = "+" if mode == "encrypt" else "−"
                rows.append({
                    "input": ch,
                    "key_char": k,
                    "shift": shift,
                    "calc": f"({ord(ch.upper()) - ord('A')} {sign} {shift}) mod 26 = {y}",
                    "output": out,
                })
                result.append(out)
                ki += 1
            else:
                rows.append({"input": ch, "key_char": "—", "shift": "—", "calc": "—", "output": ch})
                result.append(ch)

        steps.append({
            "title": "Step 3 — Apply Shifts",
            "content": (
                f"For each letter: {'add' if mode == 'encrypt' else 'subtract'} the key letter's "
                f"position to get the output."
            ),
            "data": {"type": "transformation", "rows": rows},
        })

        steps.append({
            "title": "Step 4 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'}:",
            "data": {"type": "result", "output": "".join(result)},
        })
        return steps
