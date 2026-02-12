"""Disrupted Transposition Cipher — columnar transposition with irregular fill."""

import math
from ciphers.base import Cipher


class DisruptedCipher(Cipher):
    """Fills the grid irregularly by leaving predetermined cells empty,
    then reads columns in key order. The 'disruption' pattern is derived
    from the key itself — cells on the diagonal (based on key order) are
    skipped during the first pass, then filled afterward."""

    def encrypt(self, plaintext: str, key: str = "SECRET") -> str:
        key = str(key).upper()
        order = self._key_order(key)
        clean = self._clean(plaintext)
        cols = len(key)
        rows = math.ceil(len(clean) / cols) + 1  # extra row for disruption
        grid = [["" for _ in range(cols)] for _ in range(rows)]

        # Mark disrupted cells (triangular staircase based on key order)
        disrupted = set()
        for rank, col in enumerate(order):
            for r in range(min(rank, rows)):
                disrupted.add((r, col))

        # First pass: fill non-disrupted cells
        idx = 0
        for r in range(rows):
            for c in range(cols):
                if (r, c) not in disrupted and idx < len(clean):
                    grid[r][c] = clean[idx]
                    idx += 1

        # Second pass: fill disrupted cells
        for r in range(rows):
            for c in range(cols):
                if (r, c) in disrupted and idx < len(clean):
                    grid[r][c] = clean[idx]
                    idx += 1

        # Read columns in key order
        result = []
        for c in order:
            for r in range(rows):
                if grid[r][c]:
                    result.append(grid[r][c])
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "SECRET") -> str:
        key = str(key).upper()
        order = self._key_order(key)
        clean = self._clean(ciphertext)
        cols = len(key)
        rows = math.ceil(len(clean) / cols) + 1

        # Determine disrupted cells
        disrupted = set()
        for rank, col in enumerate(order):
            for r in range(min(rank, rows)):
                disrupted.add((r, col))

        # Count how many filled cells per column
        total_filled = len(clean)
        # Build a mask of which cells exist
        grid = [["" for _ in range(cols)] for _ in range(rows)]
        fill_order_normal = []
        fill_order_disrupted = []
        for r in range(rows):
            for c in range(cols):
                if (r, c) not in disrupted:
                    fill_order_normal.append((r, c))
                else:
                    fill_order_disrupted.append((r, c))

        filled_cells = set()
        for i, (r, c) in enumerate(fill_order_normal):
            if i < total_filled:
                filled_cells.add((r, c))
        remaining = total_filled - len([x for x in fill_order_normal if fill_order_normal.index(x) < total_filled])
        for i, (r, c) in enumerate(fill_order_disrupted):
            if i < remaining:
                filled_cells.add((r, c))

        # Fill grid from ciphertext via column order
        idx = 0
        for c in order:
            for r in range(rows):
                if (r, c) in filled_cells and idx < len(clean):
                    grid[r][c] = clean[idx]
                    idx += 1

        # Read back in fill order
        result = []
        for r, c in fill_order_normal:
            if grid[r][c]:
                result.append(grid[r][c])
        for r, c in fill_order_disrupted:
            if grid[r][c]:
                result.append(grid[r][c])

        return "".join(result)

    @staticmethod
    def _key_order(key: str) -> list[int]:
        return [i for i, _ in sorted(enumerate(key), key=lambda x: x[1])]

    def get_info(self) -> dict:
        return {
            "name": "Disrupted Transposition Cipher",
            "slug": "disrupted",
            "category": "Classical",
            "subcategory": "Transposition",
            "key_info": "A keyword string (e.g. 'SECRET').",
            "description": (
                "The Disrupted Transposition cipher is a columnar transposition "
                "variant where the grid is filled irregularly. Certain cells are "
                "skipped during the initial fill and filled later, creating a "
                "'disrupted' pattern that makes cryptanalysis harder. The disruption "
                "pattern is derived from the key order."
            ),
            "history": (
                "Disrupted transposition was used in World War II, particularly by "
                "SOE (Special Operations Executive) agents. The irregular fill "
                "pattern made it significantly harder to break than standard "
                "columnar transposition, even with short messages."
            ),
            "advantages": [
                "Irregular fill pattern makes standard anagramming attacks much less effective.",
                "The disruption creates an unpredictable rearrangement even with a short key.",
                "Used successfully by SOE agents in real wartime operations.",
                "Harder to cryptanalyze than standard columnar transposition.",
            ],
            "disadvantages": [
                "More complex to implement — requires tracking which cells are filled in each pass.",
                "The disruption pattern is still deterministic from the key, limiting true randomness.",
                "Errors during manual encryption are more likely due to the irregular fill pattern.",
                "Still a transposition-only cipher — letter frequencies are preserved.",
            ],
            "improvements": (
                "Disrupted transposition improves on standard columnar by using an irregular "
                "fill pattern that breaks the regular structure attackers exploit. However, "
                "like all classical transposition ciphers, it only rearranges letter positions. "
                "The Grille cipher takes a different approach with physical templates, while "
                "modern ciphers combine permutation with substitution for true security."
            ),
        }

    def explain_steps(self, text: str, key: str = "SECRET", mode: str = "encrypt") -> list[dict]:
        key = str(key).upper()
        order = self._key_order(key)
        clean = self._clean(text)
        cols = len(key)
        rows_count = math.ceil(len(clean) / cols) + 1
        steps = []

        disrupted = set()
        for rank, col in enumerate(order):
            for r in range(min(rank, rows_count)):
                disrupted.add((r, col))

        steps.append({
            "title": "Step 1 — Key Order & Disruption Pattern",
            "content": f"Key: '{key}'. Column order: {order}. Disrupted cells (skipped first): {len(disrupted)} cells.",
            "data": {"type": "info", "key": list(key), "order": order, "disrupted_count": len(disrupted)},
        })

        # Show the grid fill
        grid = [["·" for _ in range(cols)] for _ in range(rows_count)]
        for (r, c) in disrupted:
            grid[r][c] = "◻"  # mark disrupted

        steps.append({
            "title": "Step 2 — Grid Template",
            "content": "'·' = normal fill order, '◻' = disrupted (filled second).",
            "data": {"type": "grid", "grid": [row[:] for row in grid], "key": list(key)},
        })

        if mode == "encrypt":
            result = self.encrypt(text, key)
            steps.append({
                "title": "Step 3 — Fill and Read",
                "content": "Fill normal cells first, then disrupted cells, then read columns in key order.",
                "data": {"type": "info"},
            })
            steps.append({
                "title": "Step 4 — Final Result",
                "content": "The ciphertext:",
                "data": {"type": "result", "output": result},
            })
        else:
            result = self.decrypt(text, key)
            steps.append({
                "title": "Step 3 — Reverse the Process",
                "content": "Fill columns in key order, then read in normal → disrupted order.",
                "data": {"type": "info"},
            })
            steps.append({
                "title": "Step 4 — Final Result",
                "content": "The plaintext:",
                "data": {"type": "result", "output": result},
            })
        return steps
