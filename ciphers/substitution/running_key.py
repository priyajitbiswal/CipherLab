"""Running Key Cipher — uses a long prose passage as the key."""

from ciphers.base import Cipher

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

DEFAULT_KEY_TEXT = (
    "TO BE OR NOT TO BE THAT IS THE QUESTION WHETHER TIS NOBLER IN THE MIND "
    "TO SUFFER THE SLINGS AND ARROWS OF OUTRAGEOUS FORTUNE OR TO TAKE ARMS "
    "AGAINST A SEA OF TROUBLES"
)


class RunningKeyCipher(Cipher):

    def encrypt(self, plaintext: str, key: str = DEFAULT_KEY_TEXT) -> str:
        return self._transform(plaintext, str(key).upper(), encrypt=True)

    def decrypt(self, ciphertext: str, key: str = DEFAULT_KEY_TEXT) -> str:
        return self._transform(ciphertext, str(key).upper(), encrypt=False)

    def _transform(self, text: str, key_text: str, encrypt: bool) -> str:
        key_letters = [c for c in key_text if c.isalpha()]
        if not key_letters:
            raise ValueError("Key text must contain letters.")
        result, ki = [], 0
        for ch in text:
            if ch.isalpha():
                if ki >= len(key_letters):
                    raise ValueError("Key text is shorter than the message. Provide a longer key.")
                base = ord("A") if ch.isupper() else ord("a")
                shift = ord(key_letters[ki]) - ord("A")
                if not encrypt:
                    shift = -shift
                result.append(chr((ord(ch) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Running Key Cipher",
            "slug": "running-key",
            "category": "Classical",
            "subcategory": "Polyalphabetic Substitution",
            "key_info": "A long passage of text (e.g. from a book). Must be at least as long as the message.",
            "description": (
                "The Running Key cipher is a Vigenere variant that uses a long, "
                "meaningful text (such as a passage from a book) as the key instead "
                "of a short repeating keyword. Because the key doesn't repeat, it "
                "resists Kasiski examination, but the non-random letter frequencies "
                "of natural language still make it vulnerable to attack."
            ),
            "history": (
                "Used historically when communicating parties could agree on a "
                "specific book and page as their key source. It was considered "
                "more secure than standard Vigenere because the key never repeats, "
                "but modern analysis shows that natural-language keys still leak "
                "statistical information."
            ),
            "advantages": [
                "No repeating key — immune to Kasiski examination.",
                "Key can be any agreed-upon book or text, making key exchange practical.",
                "Much longer effective key than standard Vigenere.",
                "Simple to use — just look up the agreed text and apply Vigenere shifts.",
            ],
            "disadvantages": [
                "Natural-language keys have predictable letter frequencies (e.g. 'E' is common).",
                "Vulnerable to statistical analysis due to correlations between plaintext and key.",
                "Both parties must have identical copies of the key text.",
                "Not a true one-time pad because the key is not random.",
            ],
            "improvements": (
                "Running Key improves on Vigenere by using a non-repeating key, and on "
                "Autokey by using a key independent of the plaintext. However, natural "
                "language is far from random. The One-Time Pad is the theoretical "
                "perfection of this approach: a truly random key as long as the message, "
                "proven unbreakable by Claude Shannon in 1949."
            ),
        }

    def explain_steps(self, text: str, key: str = DEFAULT_KEY_TEXT, mode: str = "encrypt") -> list[dict]:
        key_text = str(key).upper()
        key_letters = [c for c in key_text if c.isalpha()]
        steps = []

        preview = "".join(key_letters[:40]) + ("…" if len(key_letters) > 40 else "")
        steps.append({
            "title": "Step 1 — The Running Key",
            "content": f"Key text (first 40 letters): '{preview}'. Unlike Vigenère, this key does not repeat.",
            "data": {"type": "info", "key_preview": preview, "key_length": len(key_letters)},
        })

        steps.append({
            "title": "Step 2 — Align Key Letters",
            "content": "Each alphabetic character pairs with the next unused key letter.",
            "data": {"type": "alignment", "text_chars": [], "key_chars": []},
        })
        ki = 0
        for ch in text:
            steps[-1]["data"]["text_chars"].append(ch)
            if ch.isalpha():
                steps[-1]["data"]["key_chars"].append(key_letters[ki] if ki < len(key_letters) else "?")
                ki += 1
            else:
                steps[-1]["data"]["key_chars"].append("—")

        rows, result, ki = [], [], 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                k = key_letters[ki]
                shift = ord(k) - ord("A")
                if mode == "encrypt":
                    y = (ord(ch) - base + shift) % 26
                else:
                    y = (ord(ch) - base - shift) % 26
                out = chr(y + base)
                sign = "+" if mode == "encrypt" else "−"
                rows.append({
                    "input": ch, "key_char": k, "shift": shift,
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
            "content": f"{'Add' if mode == 'encrypt' else 'Subtract'} each key letter's position.",
            "data": {"type": "transformation", "rows": rows},
        })
        steps.append({
            "title": "Step 4 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'}:",
            "data": {"type": "result", "output": "".join(result)},
        })
        return steps
