"""Myszkowski Transposition Cipher — columnar transposition with duplicate key letters."""

import math
from ciphers.base import Cipher


class MyszkowskiCipher(Cipher):
    """Like columnar transposition, but columns with the same key letter
    are read left-to-right across all rows before moving to the next group."""

    def encrypt(self, plaintext: str, key: str = "TOMATO") -> str:
        key = str(key).upper()
        clean = self._clean(plaintext)
        cols = len(key)
        rows = math.ceil(len(clean) / cols)
        padded = clean.ljust(rows * cols, "X")
        grid = [list(padded[i * cols:(i + 1) * cols]) for i in range(rows)]
        order = self._key_groups(key)
        result = []
        for group in order:
            if len(group) == 1:
                c = group[0]
                for r in range(rows):
                    result.append(grid[r][c])
            else:
                for r in range(rows):
                    for c in group:
                        result.append(grid[r][c])
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "TOMATO") -> str:
        key = str(key).upper()
        clean = self._clean(ciphertext)
        cols = len(key)
        rows = math.ceil(len(clean) / cols)
        order = self._key_groups(key)
        grid = [[""] * cols for _ in range(rows)]
        idx = 0
        for group in order:
            if len(group) == 1:
                c = group[0]
                for r in range(rows):
                    if idx < len(clean):
                        grid[r][c] = clean[idx]
                        idx += 1
            else:
                for r in range(rows):
                    for c in group:
                        if idx < len(clean):
                            grid[r][c] = clean[idx]
                            idx += 1
        return "".join("".join(row) for row in grid).rstrip("X")

    @staticmethod
    def _key_groups(key: str) -> list[list[int]]:
        """Group column indices by key letter, sorted alphabetically."""
        from collections import defaultdict
        groups = defaultdict(list)
        for i, ch in enumerate(key):
            groups[ch].append(i)
        return [groups[ch] for ch in sorted(groups.keys())]

    def get_info(self) -> dict:
        return {
            "name": "Myszkowski Transposition Cipher",
            "slug": "myszkowski",
            "category": "Classical",
            "subcategory": "Transposition",
            "key_info": "A keyword with duplicate letters (e.g. 'TOMATO').",
            "description": (
                "The Myszkowski cipher is a variant of columnar transposition "
                "designed for keywords with repeated letters. Columns sharing the "
                "same key letter are read across all rows together (left-to-right "
                "within each row) rather than one column at a time."
            ),
            "history": (
                "Developed by Emile Victor Theodore Myszkowski, this cipher "
                "addressed the ambiguity in standard columnar transposition when "
                "the key contains duplicate letters. It provided a well-defined "
                "rule for handling repeats."
            ),
            "advantages": [
                "Handles duplicate key letters with a well-defined, unambiguous rule.",
                "Multi-column reading creates more complex rearrangements than standard columnar.",
                "Keywords with repetitions are common in natural language, making it practical.",
                "Slightly harder to cryptanalyze than standard columnar transposition.",
            ],
            "disadvantages": [
                "More complex to implement than standard columnar transposition.",
                "The multi-column reading rule can be confusing without careful explanation.",
                "Still vulnerable to the same anagramming attacks as columnar ciphers.",
                "Requires keywords with repeated letters to offer any advantage over columnar.",
            ],
            "improvements": (
                "Myszkowski improves on standard columnar transposition by handling "
                "duplicate key letters unambiguously. The multi-column read-across "
                "pattern creates more irregular output. However, the real leap in "
                "transposition security comes from Double Transposition, which applies "
                "two separate transpositions with different keys."
            ),
        }

    def explain_steps(self, text: str, key: str = "TOMATO", mode: str = "encrypt") -> list[dict]:
        key = str(key).upper()
        clean = self._clean(text)
        cols = len(key)
        rows_count = math.ceil(len(clean) / cols)
        padded = clean.ljust(rows_count * cols, "X")
        grid = [list(padded[i * cols:(i + 1) * cols]) for i in range(rows_count)]
        order = self._key_groups(key)
        steps = []

        steps.append({
            "title": "Step 1 — Identify Column Groups",
            "content": f"Key: '{key}'. Columns with the same letter form a group.",
            "data": {
                "type": "key_order",
                "key_letters": list(key),
                "groups": [{"letter": key[g[0]], "columns": g} for g in order],
            },
        })

        steps.append({
            "title": "Step 2 — Fill the Grid",
            "content": f"Write text into a {rows_count}×{cols} grid.",
            "data": {"type": "grid", "grid": [row[:] for row in grid], "key": list(key)},
        })

        if mode == "encrypt":
            group_reads = []
            result = []
            for group in order:
                segment = ""
                if len(group) == 1:
                    c = group[0]
                    for r in range(rows_count):
                        segment += grid[r][c]
                else:
                    for r in range(rows_count):
                        for c in group:
                            segment += grid[r][c]
                group_reads.append({"columns": group, "content": segment})
                result.append(segment)

            steps.append({
                "title": "Step 3 — Read Groups",
                "content": "Read each column group. Multi-column groups are read across rows.",
                "data": {"type": "columns", "columns": group_reads},
            })
            steps.append({
                "title": "Step 4 — Final Result",
                "content": "The ciphertext:",
                "data": {"type": "result", "output": "".join(result)},
            })
        else:
            steps.append({
                "title": "Step 3 — Fill Columns by Group",
                "content": "Distribute ciphertext into groups in key order, then read rows.",
                "data": {"type": "info"},
            })
            plain = self.decrypt(text, key)
            steps.append({
                "title": "Step 4 — Final Result",
                "content": "The plaintext:",
                "data": {"type": "result", "output": plain},
            })
        return steps
