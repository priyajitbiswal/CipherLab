"""Autokey Cipher — the key is extended with the plaintext itself."""

from ciphers.base import Cipher

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class AutokeyCipher(Cipher):

    def encrypt(self, plaintext: str, key: str = "KEY") -> str:
        key_seed = "".join(c for c in str(key).upper() if c.isalpha())
        if not key_seed:
            raise ValueError("Key must contain at least one letter.")
        # Build the full key: seed + plaintext letters
        clean_plain = [c for c in plaintext if c.isalpha()]
        full_key = list(key_seed) + [c.upper() for c in clean_plain]

        result, ki = [], 0
        for ch in plaintext:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                shift = ord(full_key[ki]) - ord("A")
                result.append(chr((ord(ch) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "KEY") -> str:
        key_seed = "".join(c for c in str(key).upper() if c.isalpha())
        if not key_seed:
            raise ValueError("Key must contain at least one letter.")
        full_key = list(key_seed)
        result, ki = [], 0
        for ch in ciphertext:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                shift = ord(full_key[ki]) - ord("A")
                plain_val = (ord(ch) - base - shift) % 26
                plain_ch = chr(plain_val + base)
                result.append(plain_ch)
                full_key.append(plain_ch.upper())  # extend key with decrypted letter
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Autokey Cipher",
            "slug": "autokey",
            "category": "Classical",
            "subcategory": "Polyalphabetic Substitution",
            "key_info": "A short keyword (e.g. 'QUEEN'). The key self-extends with plaintext.",
            "description": (
                "The Autokey cipher improves on the Vigenere cipher by extending "
                "the key with the plaintext itself (during encryption) or with "
                "the recovered plaintext (during decryption). This avoids the "
                "repeating-key weakness that makes standard Vigenere vulnerable "
                "to Kasiski examination."
            ),
            "history": (
                "Blaise de Vigenere described this autokey mechanism in 1586. "
                "It was a significant improvement over the simple repeating-key "
                "approach, though it was still eventually broken by Charles Babbage "
                "and others through statistical techniques."
            ),
            "advantages": [
                "Eliminates the repeating-key weakness of standard Vigenere.",
                "Key stream is as long as the message — no periodicity to exploit.",
                "Kasiski examination and index of coincidence attacks do not apply.",
                "Significant conceptual advance toward modern stream ciphers.",
            ],
            "disadvantages": [
                "The key stream is derived from plaintext, which has non-random frequency distribution.",
                "Vulnerable to statistical attacks because plaintext letters have known frequencies.",
                "A single decryption error propagates through all subsequent characters.",
                "More complex to implement correctly than standard Vigenere.",
            ],
            "improvements": (
                "Autokey fixes Vigenere's biggest flaw (repeating key), but introduces a "
                "new weakness: the key stream inherits the statistical properties of the "
                "plaintext. The Running Key cipher addresses this by using a long, "
                "pre-agreed text as the key. Truly secure stream ciphers (like the One-Time "
                "Pad) use genuinely random key streams that share no statistical "
                "properties with the plaintext."
            ),
        }

    def explain_steps(self, text: str, key: str = "KEY", mode: str = "encrypt") -> list[dict]:
        key_seed = "".join(c for c in str(key).upper() if c.isalpha())
        steps = []

        steps.append({
            "title": "Step 1 — Initial Key Seed",
            "content": (
                f"Keyword seed: '{key_seed}'. In Autokey, the key extends with "
                f"{'the plaintext letters' if mode == 'encrypt' else 'decrypted letters as they are recovered'}."
            ),
            "data": {"type": "info", "key_seed": key_seed},
        })

        if mode == "encrypt":
            clean_plain = [c.upper() for c in text if c.isalpha()]
            full_key = list(key_seed) + clean_plain
        else:
            full_key = list(key_seed)

        rows, result, ki = [], [], 0
        growing_key = list(key_seed)

        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                if mode == "encrypt":
                    k_ch = full_key[ki]
                else:
                    k_ch = growing_key[ki]
                shift = ord(k_ch) - ord("A")
                if mode == "encrypt":
                    y = (ord(ch) - base + shift) % 26
                else:
                    y = (ord(ch) - base - shift) % 26
                out = chr(y + base)
                rows.append({
                    "input": ch, "key_char": k_ch, "shift": shift,
                    "output": out,
                })
                result.append(out)
                if mode == "decrypt":
                    growing_key.append(out.upper())
                ki += 1
            else:
                rows.append({"input": ch, "key_char": "—", "shift": "—", "output": ch})
                result.append(ch)

        steps.append({
            "title": "Step 2 — Build the Extended Key",
            "content": (
                "As we process each letter, the key grows. "
                + (f"Full key stream: {''.join(full_key[:ki])}" if mode == "encrypt"
                   else f"Key grew to: {''.join(growing_key)}")
            ),
            "data": {"type": "info", "full_key": "".join(full_key[:ki]) if mode == "encrypt" else "".join(growing_key)},
        })

        steps.append({
            "title": "Step 3 — Transform Each Letter",
            "content": f"{'Add' if mode == 'encrypt' else 'Subtract'} the key letter shift from each text letter.",
            "data": {"type": "transformation", "rows": rows},
        })

        steps.append({
            "title": "Step 4 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'}:",
            "data": {"type": "result", "output": "".join(result)},
        })
        return steps
