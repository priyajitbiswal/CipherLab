"""Columnar Transposition Cipher — rearranges columns of a grid by keyword order."""

import math
from ciphers.base import Cipher


class ColumnarCipher(Cipher):

    def encrypt(self, plaintext: str, key: str = "ZEBRAS") -> str:
        key = str(key).upper()
        order = self._key_order(key)
        clean = self._clean(plaintext)
        cols = len(key)
        rows = math.ceil(len(clean) / cols)
        padded = clean.ljust(rows * cols, "X")
        grid = [list(padded[i * cols:(i + 1) * cols]) for i in range(rows)]
        result = []
        for col_idx in order:
            for row in grid:
                result.append(row[col_idx])
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "ZEBRAS") -> str:
        key = str(key).upper()
        order = self._key_order(key)
        clean = self._clean(ciphertext)
        cols = len(key)
        rows = math.ceil(len(clean) / cols)

        # Fill columns in key order
        grid = [[""] * cols for _ in range(rows)]
        idx = 0
        for col_idx in order:
            for row in range(rows):
                if idx < len(clean):
                    grid[row][col_idx] = clean[idx]
                    idx += 1
        return "".join("".join(row) for row in grid).rstrip("X")

    @staticmethod
    def _key_order(key: str) -> list[int]:
        """Return column read order based on alphabetical sorting of key letters."""
        return [i for i, _ in sorted(enumerate(key), key=lambda x: x[1])]

    def get_info(self) -> dict:
        return {
            "name": "Columnar Transposition Cipher",
            "slug": "columnar",
            "category": "Classical",
            "subcategory": "Transposition",
            "key_info": "A keyword string (e.g. 'ZEBRAS').",
            "description": (
                "The Columnar Transposition cipher writes the plaintext into a grid "
                "with as many columns as the key length, then reads the columns in "
                "alphabetical order of the key letters. This rearranges letter "
                "positions without changing the letters themselves."
            ),
            "history": (
                "Columnar transposition was widely used in World War I and II. "
                "It formed the basis of many military cipher systems and is still "
                "taught as a fundamental transposition technique. The German ADFGVX "
                "cipher combined it with substitution."
            ),
            "advantages": [
                "Keyword-based key gives a much larger key space than Rail Fence or Route.",
                "Easy to use with pen and paper — write rows, read columns in key order.",
                "Can be combined with substitution for powerful product ciphers (e.g. ADFGVX).",
                "The longer the keyword, the stronger the cipher.",
            ],
            "disadvantages": [
                "Anagramming attacks can recover the key by analyzing column patterns.",
                "Short keywords produce weak ciphers vulnerable to brute force.",
                "Incomplete last row can leak information about key length.",
                "Single transposition is vulnerable to multiple-anagramming techniques.",
            ],
            "improvements": (
                "Columnar transposition is a significant step up from Rail Fence and "
                "Route ciphers. Its main weakness is that a single transposition can be "
                "attacked by anagramming. Double Transposition applies the operation twice "
                "with different keys, making cryptanalysis exponentially harder. The "
                "Myszkowski variant handles duplicate key letters more elegantly."
            ),
        }

    def explain_steps(self, text: str, key: str = "ZEBRAS", mode: str = "encrypt") -> list[dict]:
        key = str(key).upper()
        order = self._key_order(key)
        clean = self._clean(text)
        cols = len(key)
        rows_count = math.ceil(len(clean) / cols)
        padded = clean.ljust(rows_count * cols, "X")
        steps = []

        steps.append({
            "title": "Step 1 — Determine Column Order",
            "content": f"Key: '{key}'. Alphabetical order of key letters gives column read order: {order}",
            "data": {
                "type": "key_order",
                "key_letters": list(key),
                "order": order,
                "sorted_key": sorted(range(len(key)), key=lambda i: key[i]),
            },
        })

        grid = [list(padded[i * cols:(i + 1) * cols]) for i in range(rows_count)]
        steps.append({
            "title": "Step 2 — Fill the Grid",
            "content": f"Write text into a {rows_count}×{cols} grid row by row.",
            "data": {"type": "grid", "grid": [row[:] for row in grid], "key": list(key)},
        })

        if mode == "encrypt":
            columns = []
            result = []
            for col_idx in order:
                col_data = "".join(grid[r][col_idx] for r in range(rows_count))
                columns.append({"column": col_idx, "key_letter": key[col_idx], "content": col_data})
                result.append(col_data)
            steps.append({
                "title": "Step 3 — Read Columns in Key Order",
                "content": "Read columns in alphabetical order of the key letters.",
                "data": {"type": "columns", "columns": columns},
            })
            steps.append({
                "title": "Step 4 — Final Result",
                "content": "Concatenate the columns:",
                "data": {"type": "result", "output": "".join(result)},
            })
        else:
            # Show how columns are filled back
            dec_grid = [[""] * cols for _ in range(rows_count)]
            idx = 0
            col_fills = []
            for col_idx in order:
                col_content = ""
                for r in range(rows_count):
                    if idx < len(clean):
                        dec_grid[r][col_idx] = clean[idx]
                        col_content += clean[idx]
                        idx += 1
                col_fills.append({"column": col_idx, "key_letter": key[col_idx], "content": col_content})
            steps.append({
                "title": "Step 3 — Fill Columns in Key Order",
                "content": "Distribute ciphertext letters into columns by key order.",
                "data": {"type": "columns", "columns": col_fills},
            })
            result = "".join("".join(row) for row in dec_grid).rstrip("X")
            steps.append({
                "title": "Step 4 — Read Rows",
                "content": "Read the grid row by row for the plaintext.",
                "data": {"type": "result", "output": result},
            })
        return steps
