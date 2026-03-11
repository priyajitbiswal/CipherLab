"""Augustus Cipher — Caesar-variant with a shift of 1 and special wrapping rules.

Augustus reportedly shifted letters by one position, but instead of wrapping,
he replaced the last letter with 'AA'. In this implementation we use a clean
shift-by-one for the standard Latin alphabet for educational clarity.
"""

from ciphers.base import Cipher

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class AugustusCipher(Cipher):

    SHIFT = 1

    def encrypt(self, plaintext: str, key=None) -> str:
        return self._shift(plaintext, self.SHIFT)

    def decrypt(self, ciphertext: str, key=None) -> str:
        return self._shift(ciphertext, -self.SHIFT)

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
            "name": "Augustus Cipher",
            "slug": "augustus",
            "category": "Classical",
            "subcategory": "Monoalphabetic Substitution",
            "key_info": "No key — always uses a fixed shift of 1.",
            "description": (
                "The Augustus cipher is a variant of the Caesar cipher attributed to "
                "Emperor Augustus. Instead of shifting by 3 positions like Caesar, "
                "Augustus used a shift of just 1 position (A->B, B->C, ... Z->A). It is "
                "one of the simplest possible substitution ciphers."
            ),
            "history": (
                "According to Suetonius, Augustus used a simple shift cipher in his "
                "personal letters. Unlike Caesar's shift of 3, Augustus shifted each "
                "letter only one place — making it even simpler to use but also "
                "easier to break."
            ),
            "advantages": [
                "As simple as a cipher can get — trivial to learn and apply.",
                "Fast to use in any situation with no tools needed.",
                "Historically significant as one of the earliest documented ciphers.",
            ],
            "disadvantages": [
                "Fixed shift of 1 means there is effectively no key at all.",
                "Even easier to break than Caesar — adjacent letters are obvious.",
                "Provides virtually no real security; purely obscurity-based.",
                "Anyone recognising the pattern decodes it immediately.",
            ],
            "improvements": (
                "Augustus is arguably weaker than Caesar because the shift is fixed "
                "and well-known. Caesar's variable shift (1-25) at least forces a "
                "brute-force attempt. The Multiplicative cipher improves further by "
                "using multiplication instead of addition, creating non-linear mappings "
                "that are harder to spot visually."
            ),
        }

    def explain_steps(self, text: str, key=None, mode: str = "encrypt") -> list[dict]:
        shift = self.SHIFT if mode == "encrypt" else -self.SHIFT
        steps = []

        steps.append({
            "title": "Step 1 — The Augustus Rule",
            "content": (
                f"Augustus always shifts by 1. Mode: {mode}. "
                f"{'Shift forward' if mode == 'encrypt' else 'Shift backward'} by 1."
            ),
            "data": {"type": "info", "shift": shift},
        })

        shifted_alpha = "".join(ALPHA[(i + shift) % 26] for i in range(26))
        steps.append({
            "title": "Step 2 — Substitution Table",
            "content": "Each letter maps to the next (or previous) letter in the alphabet.",
            "data": {"type": "mapping", "from": list(ALPHA), "to": list(shifted_alpha)},
        })

        rows, result = [], []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                out = chr((ord(ch) - base + shift) % 26 + base)
                rows.append({"input": ch, "output": out})
                result.append(out)
            else:
                rows.append({"input": ch, "output": ch})
                result.append(ch)

        steps.append({
            "title": "Step 3 — Transform Each Letter",
            "content": "Apply the shift to every alphabetic character.",
            "data": {"type": "transformation", "rows": rows},
        })
        steps.append({
            "title": "Step 4 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'}:",
            "data": {"type": "result", "output": "".join(result)},
        })
        return steps
