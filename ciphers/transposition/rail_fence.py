"""Rail Fence Cipher — writes text in a zigzag across 'rails', then reads rows."""

from ciphers.base import Cipher


class RailFenceCipher(Cipher):

    def encrypt(self, plaintext: str, key: int = 3) -> str:
        key = int(key)
        if key < 2:
            return plaintext
        rails = ["" for _ in range(key)]
        rail, direction = 0, 1
        for ch in plaintext:
            rails[rail] += ch
            if rail == 0:
                direction = 1
            elif rail == key - 1:
                direction = -1
            rail += direction
        return "".join(rails)

    def decrypt(self, ciphertext: str, key: int = 3) -> str:
        key = int(key)
        if key < 2:
            return ciphertext
        n = len(ciphertext)
        # Determine the length of each rail
        rail_lens = [0] * key
        rail, direction = 0, 1
        for _ in range(n):
            rail_lens[rail] += 1
            if rail == 0:
                direction = 1
            elif rail == key - 1:
                direction = -1
            rail += direction

        # Split ciphertext into rails
        rails = []
        idx = 0
        for length in rail_lens:
            rails.append(list(ciphertext[idx:idx + length]))
            idx += length

        # Read off in zigzag order
        result = []
        rail_indices = [0] * key
        rail, direction = 0, 1
        for _ in range(n):
            result.append(rails[rail][rail_indices[rail]])
            rail_indices[rail] += 1
            if rail == 0:
                direction = 1
            elif rail == key - 1:
                direction = -1
            rail += direction
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Rail Fence Cipher",
            "slug": "rail-fence",
            "category": "Classical",
            "subcategory": "Transposition",
            "key_info": "Number of rails (integer >= 2, e.g. 3).",
            "description": (
                "The Rail Fence cipher writes the plaintext in a zigzag pattern "
                "across a given number of 'rails' (rows), then reads each rail "
                "left-to-right to produce the ciphertext. The letters are not "
                "changed — only their positions are rearranged."
            ),
            "history": (
                "One of the oldest and simplest transposition ciphers. It was "
                "used during the American Civil War by both Union and Confederate "
                "forces. Although easy to break, it introduces the fundamental "
                "concept of transposition — rearranging letter positions rather "
                "than substituting them."
            ),
            "advantages": [
                "Fundamentally different approach from substitution — rearranges positions, not letters.",
                "Simple to implement and understand with the zigzag visualization.",
                "Can be combined with substitution ciphers for layered security.",
                "Preserves all original characters, making the output look natural.",
            ],
            "disadvantages": [
                "Very small key space — the number of rails is typically 2-10.",
                "Easy to brute force by trying all possible rail counts.",
                "The zigzag pattern is predictable and well-known.",
                "Letter frequencies remain unchanged, aiding frequency analysis.",
            ],
            "improvements": (
                "Rail Fence is the simplest transposition cipher. The Route cipher "
                "improves on it by using a 2D grid with various reading patterns (spiral, "
                "snake, etc.), creating less predictable rearrangements. Columnar "
                "transposition further improves by using a keyword to determine column "
                "ordering, vastly expanding the key space."
            ),
        }

    def explain_steps(self, text: str, key: int = 3, mode: str = "encrypt") -> list[dict]:
        key = int(key)
        steps = []

        steps.append({
            "title": "Step 1 — Set Up the Rails",
            "content": f"Number of rails: {key}. Text length: {len(text)} characters.",
            "data": {"type": "info", "rails": key, "text_length": len(text)},
        })

        if mode == "encrypt":
            # Build zigzag grid
            grid = [["" for _ in range(len(text))] for _ in range(key)]
            rail, direction = 0, 1
            for i, ch in enumerate(text):
                grid[rail][i] = ch
                if rail == 0:
                    direction = 1
                elif rail == key - 1:
                    direction = -1
                rail += direction

            steps.append({
                "title": "Step 2 — Write in Zigzag Pattern",
                "content": "Place each character on the current rail, bouncing between top and bottom.",
                "data": {
                    "type": "grid",
                    "grid": [["·" if c == "" else c for c in row] for row in grid],
                },
            })

            result = "".join("".join(row).replace("", "") for row in grid).replace("·", "")
            rails_content = []
            for r in range(key):
                content = "".join(c for c in grid[r] if c)
                rails_content.append(content)

            steps.append({
                "title": "Step 3 — Read Off Each Rail",
                "content": "Read each rail left-to-right and concatenate.",
                "data": {"type": "rails", "rails": rails_content},
            })

            result = "".join(rails_content)
            steps.append({
                "title": "Step 4 — Final Result",
                "content": "The ciphertext:",
                "data": {"type": "result", "output": result},
            })
        else:
            # Decryption — show reconstruction
            n = len(text)
            rail_lens = [0] * key
            rail, direction = 0, 1
            for _ in range(n):
                rail_lens[rail] += 1
                if rail == 0:
                    direction = 1
                elif rail == key - 1:
                    direction = -1
                rail += direction

            rails_content = []
            idx = 0
            for length in rail_lens:
                rails_content.append(text[idx:idx + length])
                idx += length

            steps.append({
                "title": "Step 2 — Split Ciphertext into Rails",
                "content": f"Rail lengths: {rail_lens}. Distribute ciphertext accordingly.",
                "data": {"type": "rails", "rails": rails_content, "lengths": rail_lens},
            })

            # Reconstruct zigzag
            rails = [list(r) for r in rails_content]
            rail_indices = [0] * key
            result = []
            rail, direction = 0, 1
            for _ in range(n):
                result.append(rails[rail][rail_indices[rail]])
                rail_indices[rail] += 1
                if rail == 0:
                    direction = 1
                elif rail == key - 1:
                    direction = -1
                rail += direction

            steps.append({
                "title": "Step 3 — Read in Zigzag Order",
                "content": "Follow the zigzag pattern, picking one letter at a time from each rail.",
                "data": {"type": "info", "zigzag_order": "".join(result)},
            })
            steps.append({
                "title": "Step 4 — Final Result",
                "content": "The plaintext:",
                "data": {"type": "result", "output": "".join(result)},
            })
        return steps
