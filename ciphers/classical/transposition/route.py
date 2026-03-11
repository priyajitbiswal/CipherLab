"""Route Cipher — arranges text in a grid and reads it in a spiral route."""

import math
from ciphers.base import Cipher


class RouteCipher(Cipher):

    def encrypt(self, plaintext: str, key: int = 4) -> str:
        """Key = number of columns."""
        cols = int(key)
        clean = self._clean(plaintext)
        rows = math.ceil(len(clean) / cols)
        clean = clean.ljust(rows * cols, "X")
        grid = [list(clean[i * cols:(i + 1) * cols]) for i in range(rows)]
        return "".join(self._spiral_read(grid))

    def decrypt(self, ciphertext: str, key: int = 4) -> str:
        cols = int(key)
        clean = self._clean(ciphertext)
        rows = math.ceil(len(clean) / cols)
        clean = clean.ljust(rows * cols, "X")
        # Determine spiral order indices and reverse-map
        grid = [[""] * cols for _ in range(rows)]
        order = self._spiral_indices(rows, cols)
        for i, (r, c) in enumerate(order):
            if i < len(clean):
                grid[r][c] = clean[i]
        return "".join("".join(row) for row in grid).rstrip("X")

    def _spiral_read(self, grid: list[list[str]]) -> list[str]:
        result = []
        if not grid:
            return result
        top, bottom, left, right = 0, len(grid) - 1, 0, len(grid[0]) - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                result.append(grid[top][c])
            top += 1
            for r in range(top, bottom + 1):
                result.append(grid[r][right])
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    result.append(grid[bottom][c])
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    result.append(grid[r][left])
                left += 1
        return result

    def _spiral_indices(self, rows: int, cols: int) -> list[tuple[int, int]]:
        order = []
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                order.append((top, c))
            top += 1
            for r in range(top, bottom + 1):
                order.append((r, right))
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    order.append((bottom, c))
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    order.append((r, left))
                left += 1
        return order

    def get_info(self) -> dict:
        return {
            "name": "Route Cipher",
            "slug": "route",
            "category": "Classical",
            "subcategory": "Transposition",
            "key_info": "Number of columns (e.g. 4).",
            "description": (
                "The Route cipher writes the plaintext into a grid row by row, "
                "then reads it off in a spiral (clockwise) pattern. The key "
                "determines the number of columns. Different route patterns "
                "(spirals, snakes, diagonals) can be used, but the classic spiral "
                "is the most common."
            ),
            "history": (
                "Route ciphers were used in the American Civil War. Union forces "
                "were particularly fond of them, writing messages into grids and "
                "reading them off in pre-arranged patterns. The recipient needed "
                "to know the grid dimensions and the reading route."
            ),
            "advantages": [
                "The spiral reading pattern creates complex letter rearrangements.",
                "Multiple route patterns (spiral, snake, diagonal) add variety.",
                "Grid-based approach is visually intuitive to understand.",
                "Historical significance in real military communications.",
            ],
            "disadvantages": [
                "The key (column count) has very few valid values for typical messages.",
                "Once the grid dimensions are guessed, the route pattern is easily deduced.",
                "Padding characters at the end can reveal the grid dimensions.",
                "Spiral patterns are predictable — not truly complex rearrangements.",
            ],
            "improvements": (
                "Route cipher improves on Rail Fence by using a 2D grid with more "
                "complex reading patterns. Columnar transposition improves further by "
                "using a keyword to permute columns, making the rearrangement much harder "
                "to reverse without the key. Double transposition applies the operation "
                "twice for dramatically increased security."
            ),
        }

    def explain_steps(self, text: str, key: int = 4, mode: str = "encrypt") -> list[dict]:
        cols = int(key)
        clean = self._clean(text)
        rows_count = math.ceil(len(clean) / cols)
        padded = clean.ljust(rows_count * cols, "X")
        steps = []

        grid = [list(padded[i * cols:(i + 1) * cols]) for i in range(rows_count)]
        steps.append({
            "title": "Step 1 — Build the Grid",
            "content": f"Fill a {rows_count}×{cols} grid row by row (pad with X if needed).",
            "data": {"type": "grid", "grid": [row[:] for row in grid]},
        })

        if mode == "encrypt":
            spiral = self._spiral_read(grid)
            order = self._spiral_indices(rows_count, cols)
            steps.append({
                "title": "Step 2 — Read in Spiral Order",
                "content": "Starting from top-left, read clockwise spiral: top row → right column → bottom row reversed → left column upward → repeat inward.",
                "data": {"type": "spiral", "order": [{"pos": list(p), "char": spiral[i]} for i, p in enumerate(order)]},
            })
            steps.append({
                "title": "Step 3 — Final Result",
                "content": "The ciphertext from the spiral reading:",
                "data": {"type": "result", "output": "".join(spiral)},
            })
        else:
            order = self._spiral_indices(rows_count, cols)
            reconstructed_grid = [[""] * cols for _ in range(rows_count)]
            for i, (r, c) in enumerate(order):
                if i < len(padded):
                    reconstructed_grid[r][c] = padded[i]
            steps.append({
                "title": "Step 2 — Place Letters in Spiral Order",
                "content": "Place each ciphertext letter at the spiral positions to reconstruct the grid.",
                "data": {"type": "grid", "grid": reconstructed_grid},
            })
            plaintext = "".join("".join(row) for row in reconstructed_grid).rstrip("X")
            steps.append({
                "title": "Step 3 — Read Rows Left-to-Right",
                "content": "Read the reconstructed grid row by row.",
                "data": {"type": "result", "output": plaintext},
            })
        return steps
