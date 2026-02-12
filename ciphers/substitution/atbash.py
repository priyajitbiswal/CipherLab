"""Atbash Cipher — reverses the alphabet (A↔Z, B↔Y, …)."""

from ciphers.base import Cipher

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
REV = ALPHA[::-1]


class AtbashCipher(Cipher):

    def encrypt(self, plaintext: str, key=None) -> str:
        return self._transform(plaintext)

    def decrypt(self, ciphertext: str, key=None) -> str:
        return self._transform(ciphertext)  # symmetric

    # ── internals ─────────────────────────────────────────────────────

    def _transform(self, text: str) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                idx = ALPHA.index(ch.upper())
                mapped = REV[idx]
                result.append(mapped if ch.isupper() else mapped.lower())
            else:
                result.append(ch)
        return "".join(result)

    # ── educational ──────────────────────────────────────────────────

    def get_info(self) -> dict:
        return {
            "name": "Atbash Cipher",
            "slug": "atbash",
            "category": "Classical",
            "subcategory": "Monoalphabetic Substitution",
            "key_info": "No key required — the mapping is fixed.",
            "description": (
                "The Atbash cipher is one of the oldest known ciphers, originally "
                "used with the Hebrew alphabet. It works by replacing the first letter "
                "of the alphabet with the last, the second with the second-to-last, "
                "and so on. Because the mapping is its own inverse, encryption and "
                "decryption are the same operation."
            ),
            "history": (
                "Named after the first, last, second, and second-to-last Hebrew "
                "letters (Aleph-Tav-Beth-Shin), the Atbash cipher appears in the "
                "Hebrew Bible — for example, 'Sheshach' is an Atbash encoding of "
                "'Babel' (Babylon) in the Book of Jeremiah."
            ),
            "advantages": [
                "Extremely simple to memorize and use — no key required.",
                "Symmetric: the same operation encrypts and decrypts.",
                "Can be performed mentally without any tools.",
            ],
            "disadvantages": [
                "No key means anyone who knows the method can decode it instantly.",
                "Only one possible mapping exists, so there is nothing to guess.",
                "Trivially broken by frequency analysis — just 26 possible checks.",
                "Letter frequency patterns are perfectly preserved but reversed.",
            ],
            "improvements": (
                "As the simplest possible substitution cipher, Atbash has no key "
                "space at all. The Caesar cipher improves on this by introducing a "
                "variable shift key (1-25), giving 25 possible mappings instead of "
                "just one. The Affine cipher further generalises with two key "
                "parameters (a, b), greatly expanding the key space."
            ),
        }

    def explain_steps(self, text: str, key=None, mode: str = "encrypt") -> list[dict]:
        steps = []
        steps.append({
            "title": "Step 1 — Build the Atbash Mapping",
            "content": (
                "Create a reversed alphabet mapping where A↔Z, B↔Y, C↔X … "
                "Each letter maps to its mirror in the alphabet."
            ),
            "data": {
                "type": "mapping",
                "from": list(ALPHA),
                "to": list(REV),
            },
        })
        steps.append({
            "title": "Step 2 — Apply the Mapping",
            "content": "Replace every letter with its Atbash counterpart; non-letters stay unchanged.",
            "data": {
                "type": "transformation",
                "rows": [],
            },
        })
        rows = steps[-1]["data"]["rows"]
        result = []
        for ch in text:
            if ch.isalpha():
                idx = ALPHA.index(ch.upper())
                mapped = REV[idx]
                out = mapped if ch.isupper() else mapped.lower()
                rows.append({"input": ch, "position": idx, "mapped": out})
                result.append(out)
            else:
                rows.append({"input": ch, "position": "—", "mapped": ch})
                result.append(ch)

        steps.append({
            "title": "Step 3 — Final Result",
            "content": f"After replacing every letter we get the output.",
            "data": {"type": "result", "output": "".join(result)},
        })
        return steps
