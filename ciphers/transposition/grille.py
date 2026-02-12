"""Grille Cipher (turning grille / Cardan grille) — uses a rotating mask."""

import math
from ciphers.base import Cipher


class GrilleCipher(Cipher):
    """Implements a turning grille cipher.

    The key is a string of hole positions for a grid (e.g. '0,2,5,7' for a 4×4
    grille means holes at positions 0,2,5,7 in row-major order). The grille is
    rotated 90° clockwise three more times to fill all cells.

    For simplicity the grille size is always the smallest even square ≥ text length.
    """

    def encrypt(self, plaintext: str, key: str = "0,2,5,7") -> str:
        clean = self._clean(plaintext)
        holes = self._parse_holes(key)
        size = self._grid_size(len(clean))
        grid = [["" for _ in range(size)] for _ in range(size)]

        idx = 0
        current_holes = holes[:]
        for rotation in range(4):
            for (r, c) in current_holes:
                if r < size and c < size and idx < len(clean):
                    if not grid[r][c]:
                        grid[r][c] = clean[idx]
                        idx += 1
            current_holes = self._rotate_holes(current_holes, size)

        # Fill remaining empty cells
        for r in range(size):
            for c in range(size):
                if not grid[r][c]:
                    if idx < len(clean):
                        grid[r][c] = clean[idx]
                        idx += 1
                    else:
                        grid[r][c] = "X"

        return "".join("".join(row) for row in grid)

    def decrypt(self, ciphertext: str, key: str = "0,2,5,7") -> str:
        clean = self._clean(ciphertext)
        holes = self._parse_holes(key)
        size = self._grid_size(len(clean))
        grid = [list(clean[i * size:(i + 1) * size]) for i in range(size)]

        result = []
        current_holes = holes[:]
        for rotation in range(4):
            for (r, c) in current_holes:
                if r < size and c < size:
                    result.append(grid[r][c])
            current_holes = self._rotate_holes(current_holes, size)

        return "".join(result)

    @staticmethod
    def _parse_holes(key) -> list[tuple[int, int]]:
        """Parse hole positions. Format: 'r1c1,r2c2,...' or flat indices '0,2,5,7'."""
        positions = []
        parts = str(key).replace(" ", "").split(",")
        # Determine grid size from max index
        indices = [int(p) for p in parts if p.isdigit()]
        if not indices:
            raise ValueError("Key must be comma-separated hole positions (e.g. '0,2,5,7').")
        max_idx = max(indices)
        size = math.isqrt(max_idx) + 1
        if size % 2 != 0:
            size += 1
        for idx in indices:
            r, c = divmod(idx, size)
            if r < size and c < size:
                positions.append((r, c))
        return positions

    @staticmethod
    def _rotate_holes(holes: list[tuple[int, int]], size: int) -> list[tuple[int, int]]:
        """Rotate hole positions 90° clockwise."""
        return [(c, size - 1 - r) for (r, c) in holes]

    @staticmethod
    def _grid_size(text_len: int) -> int:
        size = 2
        while size * size < text_len:
            size += 2
        return size

    def get_info(self) -> dict:
        return {
            "name": "Grille Cipher",
            "slug": "grille",
            "category": "Classical",
            "subcategory": "Transposition",
            "key_info": "Comma-separated hole positions in row-major order (e.g. '0,2,5,7' for a 4x4 grid).",
            "description": (
                "The Grille cipher (or Turning Grille / Cardan Grille) uses a "
                "physical card with holes cut in it. The card is placed over a grid, "
                "letters are written through the holes, then the card is rotated 90 "
                "degrees and the process repeats. After four rotations, the entire grid is "
                "filled. The ciphertext is read row by row from the grid."
            ),
            "history": (
                "Girolamo Cardano described the original concept in 1550. The "
                "rotating-grille variant was developed by Eduard Fleissner von "
                "Wostrowitz in 1881 and was used by Germany in World War I. "
                "Jules Verne featured it in his novel 'Mathias Sandorf' (1885)."
            ),
            "advantages": [
                "Physical implementation makes the cipher tangible and educational.",
                "The rotating mechanism creates complex, non-obvious rearrangements.",
                "Multiple valid grille patterns exist for any given grid size.",
                "Featured in literature and espionage — rich historical context.",
            ],
            "disadvantages": [
                "Message length is constrained to the grid size (n^2 characters).",
                "Requires a physical card or careful bookkeeping of hole positions.",
                "The grille must have exactly n^2/4 holes for an n x n grid — constraining the key space.",
                "Vulnerable to brute-force search for small grid sizes.",
            ],
            "improvements": (
                "The Grille cipher is unique among transposition ciphers in using a "
                "physical rotating template. While it creates complex rearrangements, "
                "it is limited by fixed message sizes and small key spaces for practical "
                "grid dimensions. It represents the creative peak of manual transposition "
                "techniques before the advent of machine ciphers like Enigma."
            ),
        }

    def explain_steps(self, text: str, key: str = "0,2,5,7", mode: str = "encrypt") -> list[dict]:
        clean = self._clean(text)
        holes = self._parse_holes(key)
        size = self._grid_size(len(clean))
        steps = []

        steps.append({
            "title": "Step 1 — Set Up the Grille",
            "content": f"Grid size: {size}×{size}. Hole positions: {holes}.",
            "data": {"type": "info", "size": size, "holes": [list(h) for h in holes]},
        })

        # Show grille mask
        mask = [["■" for _ in range(size)] for _ in range(size)]
        for r, c in holes:
            if r < size and c < size:
                mask[r][c] = "○"
        steps.append({
            "title": "Step 2 — Initial Grille Mask",
            "content": "'○' = hole (write/read here), '■' = blocked.",
            "data": {"type": "grid", "grid": mask},
        })

        if mode == "encrypt":
            grid = [["·" for _ in range(size)] for _ in range(size)]
            idx = 0
            current_holes = holes[:]
            rotations = []
            for rot in range(4):
                placed = []
                for (r, c) in current_holes:
                    if r < size and c < size and not grid[r][c].isalpha() and idx < len(clean):
                        grid[r][c] = clean[idx]
                        placed.append({"pos": [r, c], "char": clean[idx]})
                        idx += 1
                rotations.append({"rotation": rot * 90, "placed": placed})
                current_holes = self._rotate_holes(current_holes, size)

            steps.append({
                "title": "Step 3 — Fill Through 4 Rotations",
                "content": "Rotate the grille 90° clockwise after each fill pass.",
                "data": {"type": "rotations", "rotations": rotations},
            })

            result = "".join("".join(row) for row in grid).replace("·", "X")
            steps.append({
                "title": "Step 4 — Final Grid & Result",
                "content": "Read the grid row by row.",
                "data": {"type": "result", "output": result, "grid": [row[:] for row in grid]},
            })
        else:
            grid = [list(clean[i * size:(i + 1) * size]) if i * size < len(clean) else ["X"] * size for i in range(size)]
            result_chars = []
            current_holes = holes[:]
            for rot in range(4):
                for (r, c) in current_holes:
                    if r < size and c < size:
                        result_chars.append(grid[r][c])
                current_holes = self._rotate_holes(current_holes, size)

            steps.append({
                "title": "Step 3 — Read Through 4 Rotations",
                "content": "Place grille on grid, read through holes, rotate, repeat.",
                "data": {"type": "info"},
            })
            steps.append({
                "title": "Step 4 — Final Result",
                "content": "The plaintext:",
                "data": {"type": "result", "output": "".join(result_chars)},
            })
        return steps
