"""Hill Cipher — polygraphic substitution using matrix multiplication mod 26."""

import math
import numpy as np
from ciphers.base import Cipher

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _matrix_mod_inverse(matrix: np.ndarray, mod: int = 26) -> np.ndarray:
    """Compute the modular inverse of a square matrix mod 26."""
    det = int(round(np.linalg.det(matrix))) % mod
    if math.gcd(det, mod) != 1:
        raise ValueError(
            f"Matrix determinant ({det}) is not coprime with 26 — not invertible."
        )
    # Modular inverse of the determinant
    det_inv = pow(det, -1, mod)
    # Adjugate (cofactor matrix transposed)
    n = matrix.shape[0]
    cofactors = np.zeros((n, n), dtype=int)
    for i in range(n):
        for j in range(n):
            minor = np.delete(np.delete(matrix, i, axis=0), j, axis=1)
            cofactors[i][j] = ((-1) ** (i + j)) * int(round(np.linalg.det(minor)))
    adjugate = cofactors.T
    inv = (det_inv * adjugate) % mod
    return inv.astype(int)


def _parse_matrix_key(key: str, size: int = 2) -> np.ndarray:
    """Parse a key string into a square matrix.

    Accepts either comma-separated numbers (e.g. '3,3,2,5') or letters
    (e.g. 'DCBF') for a 2×2 matrix.
    """
    if any(c.isdigit() for c in str(key)):
        nums = [int(x.strip()) for x in str(key).replace(" ", ",").split(",") if x.strip()]
    else:
        nums = [ord(c.upper()) - ord("A") for c in str(key) if c.isalpha()]
    n = int(math.isqrt(len(nums)))
    if n * n != len(nums):
        raise ValueError(f"Key must have a perfect square count of values. Got {len(nums)}.")
    return np.array(nums, dtype=int).reshape(n, n)


class HillCipher(Cipher):

    def encrypt(self, plaintext: str, key: str = "3,3,2,5") -> str:
        matrix = _parse_matrix_key(key)
        return self._transform(plaintext, matrix, encrypt=True)

    def decrypt(self, ciphertext: str, key: str = "3,3,2,5") -> str:
        matrix = _parse_matrix_key(key)
        return self._transform(ciphertext, matrix, encrypt=False)

    def _transform(self, text: str, key_matrix: np.ndarray, encrypt: bool) -> str:
        n = key_matrix.shape[0]
        m = _matrix_mod_inverse(key_matrix) if not encrypt else key_matrix
        clean = self._clean(text)
        # Pad with X if needed
        while len(clean) % n != 0:
            clean += "X"
        result = []
        for i in range(0, len(clean), n):
            block = np.array([ord(c) - ord("A") for c in clean[i:i + n]])
            transformed = m.dot(block) % 26
            result.extend(chr(int(v) + ord("A")) for v in transformed)
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "Hill Cipher",
            "slug": "hill",
            "category": "Classical",
            "subcategory": "Polygraphic Substitution",
            "key_info": "Comma-separated numbers for a square matrix (e.g. '3,3,2,5' for 2x2, or '6,24,1,13,16,10,20,17,15' for 3x3).",
            "description": (
                "The Hill cipher encrypts blocks of letters using matrix "
                "multiplication modulo 26. A 2x2 key matrix encrypts two letters at "
                "a time, a 3x3 matrix encrypts three, etc. Decryption uses the "
                "modular inverse of the key matrix. It was the first polygraphic "
                "cipher that was practical for more than two-letter blocks."
            ),
            "history": (
                "Invented by Lester S. Hill in 1929. It was the first cipher to use "
                "linear algebra for encryption, demonstrating how mathematics could "
                "be applied to cryptography. While broken by known-plaintext attacks, "
                "it remains fundamental to cryptography education."
            ),
            "advantages": [
                "Encrypts multiple letters at once, hiding single-letter frequency patterns.",
                "Completely different approach: uses linear algebra instead of shift/substitution.",
                "Larger block sizes provide exponentially stronger resistance to frequency analysis.",
                "Foundation for understanding modern block ciphers (AES, DES).",
            ],
            "disadvantages": [
                "Vulnerable to known-plaintext attacks — with enough known pairs, the key matrix is recoverable.",
                "The key matrix must have a modular inverse (determinant coprime with 26).",
                "Requires linear algebra knowledge to understand and implement.",
                "Does not resist chosen-plaintext attacks at all.",
            ],
            "improvements": (
                "Hill was revolutionary as the first practical polygraphic cipher, "
                "encrypting blocks of letters simultaneously. This hides single-letter "
                "frequencies entirely. However, its linear nature makes it vulnerable "
                "to known-plaintext attacks. Modern block ciphers like AES build on the "
                "block-encryption idea but add non-linear operations (S-boxes), key "
                "scheduling, and multiple rounds to resist cryptanalysis."
            ),
        }

    def explain_steps(self, text: str, key: str = "3,3,2,5", mode: str = "encrypt") -> list[dict]:
        key_matrix = _parse_matrix_key(key)
        n = key_matrix.shape[0]
        steps = []

        steps.append({
            "title": "Step 1 — Parse the Key Matrix",
            "content": f"Key matrix ({n}×{n}):",
            "data": {
                "type": "matrix",
                "matrix": key_matrix.tolist(),
                "size": n,
            },
        })

        det = int(round(np.linalg.det(key_matrix))) % 26
        inv_matrix = _matrix_mod_inverse(key_matrix)
        steps.append({
            "title": "Step 2 — Compute the Inverse Matrix",
            "content": (
                f"Determinant mod 26 = {det}. gcd({det}, 26) = {math.gcd(det, 26)} ✓. "
                f"{'Using original matrix for encryption.' if mode == 'encrypt' else 'Using inverse matrix for decryption.'}"
            ),
            "data": {
                "type": "matrix",
                "matrix": inv_matrix.tolist(),
                "label": "Inverse Matrix (mod 26)",
            },
        })

        clean = self._clean(text)
        while len(clean) % n != 0:
            clean += "X"
        blocks = [clean[i:i + n] for i in range(0, len(clean), n)]
        steps.append({
            "title": "Step 3 — Split into Blocks",
            "content": f"Text is split into blocks of {n} letters (padded with X if needed): {blocks}",
            "data": {"type": "info", "blocks": blocks},
        })

        m = key_matrix if mode == "encrypt" else inv_matrix
        block_results = []
        result_letters = []
        for block in blocks:
            vec = [ord(c) - ord("A") for c in block]
            transformed = (m.dot(vec)) % 26
            out_letters = [chr(int(v) + ord("A")) for v in transformed]
            block_results.append({
                "block": block,
                "vector": vec,
                "result_vector": [int(v) for v in transformed],
                "output": "".join(out_letters),
            })
            result_letters.extend(out_letters)

        steps.append({
            "title": "Step 4 — Matrix Multiply Each Block",
            "content": f"Multiply each block vector by the {'key' if mode == 'encrypt' else 'inverse'} matrix mod 26.",
            "data": {"type": "block_transform", "blocks": block_results},
        })

        steps.append({
            "title": "Step 5 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'}:",
            "data": {"type": "result", "output": "".join(result_letters)},
        })
        return steps
