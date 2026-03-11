"""Double Transposition Cipher — applies columnar transposition twice."""

import math
from ciphers.base import Cipher


class DoubleTranspositionCipher(Cipher):
    """Applies columnar transposition twice using two keywords (or the same
    keyword twice for simplicity). Key format: 'KEY1,KEY2' or just 'KEY'."""

    def encrypt(self, plaintext: str, key: str = "ZEBRAS,STRIPE") -> str:
        k1, k2 = self._parse_keys(key)
        intermediate = self._columnar_encrypt(self._clean(plaintext), k1)
        return self._columnar_encrypt(intermediate, k2)

    def decrypt(self, ciphertext: str, key: str = "ZEBRAS,STRIPE") -> str:
        k1, k2 = self._parse_keys(key)
        intermediate = self._columnar_decrypt(self._clean(ciphertext), k2)
        return self._columnar_decrypt(intermediate, k1)

    @staticmethod
    def _parse_keys(key: str) -> tuple[str, str]:
        parts = str(key).upper().split(",")
        k1 = "".join(c for c in parts[0] if c.isalpha())
        k2 = "".join(c for c in parts[-1] if c.isalpha()) if len(parts) > 1 else k1
        if not k1 or not k2:
            raise ValueError("Key must contain letters. Format: 'KEY1,KEY2' or 'KEY'.")
        return k1, k2

    @staticmethod
    def _key_order(key: str) -> list[int]:
        return [i for i, _ in sorted(enumerate(key), key=lambda x: x[1])]

    def _columnar_encrypt(self, text: str, key: str) -> str:
        cols = len(key)
        rows = math.ceil(len(text) / cols)
        padded = text.ljust(rows * cols, "X")
        grid = [list(padded[i * cols:(i + 1) * cols]) for i in range(rows)]
        order = self._key_order(key)
        result = []
        for c in order:
            for r in range(rows):
                result.append(grid[r][c])
        return "".join(result)

    def _columnar_decrypt(self, text: str, key: str) -> str:
        cols = len(key)
        rows = math.ceil(len(text) / cols)
        order = self._key_order(key)
        grid = [[""] * cols for _ in range(rows)]
        idx = 0
        for c in order:
            for r in range(rows):
                if idx < len(text):
                    grid[r][c] = text[idx]
                    idx += 1
        return "".join("".join(row) for row in grid).rstrip("X")

    def get_info(self) -> dict:
        return {
            "name": "Double Transposition Cipher",
            "slug": "double-transposition",
            "category": "Classical",
            "subcategory": "Transposition",
            "key_info": "Two keywords separated by comma (e.g. 'ZEBRAS,STRIPE'). Same key used twice if only one provided.",
            "description": (
                "The Double Transposition cipher applies columnar transposition "
                "twice — first with one key, then with a second. This dramatically "
                "increases security compared to a single transposition because the "
                "letter rearrangement becomes far more complex."
            ),
            "history": (
                "Double transposition was used extensively in World War I and II. "
                "It was a favourite of the French and German armies. Even with "
                "moderate key lengths, the dual rearrangement made cryptanalysis "
                "significantly harder than single columnar transposition."
            ),
            "advantages": [
                "Two rounds of transposition make anagramming attacks vastly harder.",
                "Using different keys for each round multiplies the effective key space.",
                "Was considered highly secure for manual ciphers during both World Wars.",
                "Simple to implement — just apply columnar transposition twice.",
            ],
            "disadvantages": [
                "Still theoretically breakable with sufficient ciphertext and computing power.",
                "More cumbersome to encrypt/decrypt by hand than single transposition.",
                "Errors in either round corrupt the entire message.",
                "Does not change letter frequencies — only rearranges positions.",
            ],
            "improvements": (
                "Double Transposition is the strongest of the classical transposition "
                "ciphers, applying two independent rearrangements. However, all classical "
                "transposition ciphers share a fundamental limitation: they only move "
                "letters around without changing them. Modern ciphers combine transposition "
                "(permutation) with substitution and key-dependent non-linear operations "
                "for dramatically stronger security."
            ),
        }

    def explain_steps(self, text: str, key: str = "ZEBRAS,STRIPE", mode: str = "encrypt") -> list[dict]:
        k1, k2 = self._parse_keys(key)
        clean = self._clean(text)
        steps = []

        steps.append({
            "title": "Step 1 — Parse Keys",
            "content": f"Key 1: '{k1}', Key 2: '{k2}'. Two rounds of columnar transposition will be applied.",
            "data": {"type": "info", "key1": k1, "key2": k2},
        })

        if mode == "encrypt":
            # First transposition
            cols1 = len(k1)
            rows1 = math.ceil(len(clean) / cols1)
            padded1 = clean.ljust(rows1 * cols1, "X")
            grid1 = [list(padded1[i * cols1:(i + 1) * cols1]) for i in range(rows1)]
            steps.append({
                "title": "Step 2 — First Transposition Grid",
                "content": f"Fill {rows1}×{cols1} grid with key '{k1}'.",
                "data": {"type": "grid", "grid": grid1, "key": list(k1)},
            })
            intermediate = self._columnar_encrypt(clean, k1)
            steps.append({
                "title": "Step 3 — First Transposition Result",
                "content": f"Read columns in key order: {intermediate}",
                "data": {"type": "info", "intermediate": intermediate},
            })

            cols2 = len(k2)
            rows2 = math.ceil(len(intermediate) / cols2)
            padded2 = intermediate.ljust(rows2 * cols2, "X")
            grid2 = [list(padded2[i * cols2:(i + 1) * cols2]) for i in range(rows2)]
            steps.append({
                "title": "Step 4 — Second Transposition Grid",
                "content": f"Fill {rows2}×{cols2} grid with key '{k2}'.",
                "data": {"type": "grid", "grid": grid2, "key": list(k2)},
            })
            final = self._columnar_encrypt(intermediate, k2)
            steps.append({
                "title": "Step 5 — Final Result",
                "content": "The doubly-transposed ciphertext:",
                "data": {"type": "result", "output": final},
            })
        else:
            intermediate = self._columnar_decrypt(clean, k2)
            steps.append({
                "title": "Step 2 — Reverse Second Transposition",
                "content": f"Undo key '{k2}' transposition: {intermediate}",
                "data": {"type": "info", "intermediate": intermediate},
            })
            final = self._columnar_decrypt(intermediate, k1)
            steps.append({
                "title": "Step 3 — Reverse First Transposition",
                "content": "Undo key '{k1}' transposition to get plaintext.",
                "data": {"type": "result", "output": final},
            })
        return steps
