"""Beaufort Cipher — a reciprocal cipher closely related to Vigenère."""

from ciphers.base import Cipher

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class BeaufortCipher(Cipher):
    """Beaufort cipher: C_i = (K_i − P_i) mod 26.

    Unlike Vigenère, Beaufort is reciprocal — the same operation encrypts and
    decrypts.
    """

    def encrypt(self, plaintext: str, key: str = "KEY") -> str:
        return self._transform(plaintext, str(key).upper())

    def decrypt(self, ciphertext: str, key: str = "KEY") -> str:
        return self._transform(ciphertext, str(key).upper())  # reciprocal

    def _transform(self, text: str, key: str) -> str:
        key = "".join(c for c in key if c.isalpha())
        if not key:
            raise ValueError("Key must contain at least one letter.")
        result, ki = [], 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                k = ord(key[ki % len(key)]) - ord("A")
                p = ord(ch) - base
                y = (k - p) % 26
                result.append(chr(y + base))
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Beaufort Cipher",
            "slug": "beaufort",
            "category": "Classical",
            "subcategory": "Polyalphabetic Substitution",
            "key_info": "A keyword string (e.g. 'FORTIFICATION').",
            "description": (
                "The Beaufort cipher is similar to Vigenere but uses subtraction "
                "from the key instead of addition: C = (K - P) mod 26. A crucial "
                "property is that it is reciprocal — applying the same operation "
                "to ciphertext with the same key recovers the plaintext."
            ),
            "history": (
                "Created by Sir Francis Beaufort, an Irish-born Royal Navy officer "
                "best known for the Beaufort wind force scale. The cipher was "
                "adopted by the British military and remains an important example "
                "of reciprocal ciphers in cryptography education."
            ),
            "advantages": [
                "Reciprocal: encryption and decryption use the exact same operation.",
                "Simplifies implementation — no need for separate decrypt logic.",
                "Same polyalphabetic strength as Vigenere against frequency analysis.",
                "Used in real military communications (British military).",
            ],
            "disadvantages": [
                "Same repeating-key vulnerability as Vigenere (Kasiski examination).",
                "Reciprocal property means if an attacker knows the method, the security is identical to Vigenere.",
                "Not widely known, so fewer historical analyses and educational resources.",
                "The subtraction can be confusing for manual encryption compared to Vigenere.",
            ],
            "improvements": (
                "Beaufort does not improve security over Vigenere — it offers the same "
                "strength with a different operation. Its key advantage is the reciprocal "
                "property (same algorithm for encrypt and decrypt), which simplifies "
                "implementation. The Autokey cipher improves on both by eliminating "
                "the repeating-key weakness entirely."
            ),
        }

    def explain_steps(self, text: str, key: str = "KEY", mode: str = "encrypt") -> list[dict]:
        key = "".join(c for c in str(key).upper() if c.isalpha())
        steps = []

        steps.append({
            "title": "Step 1 — Prepare the Key",
            "content": (
                f"Keyword: '{key}'. The Beaufort cipher is reciprocal — the same "
                f"formula C = (K − P) mod 26 works for both encryption and decryption."
            ),
            "data": {"type": "info", "key": key},
        })

        steps.append({
            "title": "Step 2 — Align Key with Text",
            "content": "Pair each letter with the next key letter cyclically.",
            "data": {"type": "alignment", "text_chars": list(text), "key_chars": []},
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
                k_char = key[ki % len(key)]
                k = ord(k_char) - ord("A")
                p = ord(ch) - base
                y = (k - p) % 26
                out = chr(y + base)
                rows.append({
                    "input": ch, "key_char": k_char,
                    "calc": f"({k} − {p}) mod 26 = {y}",
                    "output": out,
                })
                result.append(out)
                ki += 1
            else:
                rows.append({"input": ch, "key_char": "—", "calc": "—", "output": ch})
                result.append(ch)

        steps.append({
            "title": "Step 3 — Apply the Beaufort Formula",
            "content": "For each letter: output = (key_position − text_position) mod 26.",
            "data": {"type": "transformation", "rows": rows},
        })
        steps.append({
            "title": "Step 4 — Final Result",
            "content": "The output text:",
            "data": {"type": "result", "output": "".join(result)},
        })
        return steps
