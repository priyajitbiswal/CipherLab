"""Salsa20 — a high-speed stream cipher by Daniel Bernstein."""

import base64
import struct
import os
from ciphers.base import Cipher


class Salsa20Cipher(Cipher):
    """
    Pure-Python educational implementation of Salsa20.
    Uses a 256-bit key and 64-bit nonce with 20 rounds of quarter-round operations.
    """

    def _prepare_key(self, key: str) -> bytes:
        if not key:
            key = "Salsa20Key-32BytesLong!!"
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 32:
            key_bytes = key_bytes.ljust(32, b"\0")
        return key_bytes[:32]

    @staticmethod
    def _rotl32(v, c):
        return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF

    @staticmethod
    def _quarter_round(y, a, b, c, d):
        y[b] ^= Salsa20Cipher._rotl32((y[a] + y[d]) & 0xFFFFFFFF, 7)
        y[c] ^= Salsa20Cipher._rotl32((y[b] + y[a]) & 0xFFFFFFFF, 9)
        y[d] ^= Salsa20Cipher._rotl32((y[c] + y[b]) & 0xFFFFFFFF, 13)
        y[a] ^= Salsa20Cipher._rotl32((y[d] + y[c]) & 0xFFFFFFFF, 18)

    def _salsa20_block(self, key: bytes, nonce: bytes, counter: int) -> bytes:
        """Generate one 64-byte keystream block."""
        # Constants "expand 32-byte k"
        sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        k = struct.unpack('<8I', key)
        n = struct.unpack('<2I', nonce)

        state = [
            sigma[0], k[0], k[1], k[2],
            k[3], sigma[1], n[0], n[1],
            counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF, sigma[2], k[4],
            k[5], k[6], k[7], sigma[3],
        ]

        working = list(state)
        for _ in range(10):  # 20 rounds = 10 double-rounds
            # Column rounds
            self._quarter_round(working, 0, 4, 8, 12)
            self._quarter_round(working, 5, 9, 13, 1)
            self._quarter_round(working, 10, 14, 2, 6)
            self._quarter_round(working, 15, 3, 7, 11)
            # Row rounds
            self._quarter_round(working, 0, 1, 2, 3)
            self._quarter_round(working, 5, 6, 7, 4)
            self._quarter_round(working, 10, 11, 8, 9)
            self._quarter_round(working, 15, 12, 13, 14)

        output = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
        return struct.pack('<16I', *output)

    def _salsa20_crypt(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        result = bytearray()
        for i in range(0, len(data), 64):
            block = self._salsa20_block(key, nonce, i // 64)
            chunk = data[i:i+64]
            result.extend(c ^ k for c, k in zip(chunk, block[:len(chunk)]))
        return bytes(result)

    def encrypt(self, plaintext: str, key: str = "Salsa20Key-32BytesLong!!") -> str:
        key_bytes = self._prepare_key(key)
        nonce = os.urandom(8)
        ct = self._salsa20_crypt(plaintext.encode("utf-8"), key_bytes, nonce)
        # Prepend nonce to ciphertext
        return base64.b64encode(nonce + ct).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str = "Salsa20Key-32BytesLong!!") -> str:
        key_bytes = self._prepare_key(key)
        raw = base64.b64decode(ciphertext)
        nonce = raw[:8]
        ct = raw[8:]
        pt = self._salsa20_crypt(ct, key_bytes, nonce)
        return pt.decode("utf-8")

    def get_info(self) -> dict:
        return {
            "name": "Salsa20",
            "slug": "salsa20",
            "category": "Modern",
            "subcategory": "Stream Ciphers",
            "key_info": "32 ASCII characters (256-bit key). Default: Salsa20Key-32BytesLong!!",
            "description": (
                "Salsa20 is a stream cipher that generates keystream blocks of 64 bytes "
                "using a 256-bit key and 64-bit nonce. It applies 20 rounds of ARX "
                "(Add-Rotate-XOR) quarter-round operations on a 4×4 matrix of 32-bit words. "
                "Its design emphasizes simplicity and provable resistance to differential "
                "cryptanalysis."
            ),
            "history": (
                "Designed by Daniel J. Bernstein in 2005 and submitted to the eSTREAM "
                "project, where it was selected for Profile 1 (software). Salsa20 is one "
                "of the most influential modern stream cipher designs and spawned the "
                "widely adopted ChaCha20 variant."
            ),
            "advantages": [
                "Very fast in software — no table lookups, cache-timing safe.",
                "Simple ARX design is easy to analyze and implement correctly.",
                "Inherently seekable — can compute any keystream block independently.",
                "Selected by eSTREAM as a recommended stream cipher.",
            ],
            "disadvantages": [
                "Nonce reuse is catastrophic — same nonce+key produces same keystream.",
                "No built-in authentication (must pair with Poly1305 or similar).",
                "Superseded by ChaCha20 which has better per-round diffusion.",
                "64-bit nonce limits the number of messages per key.",
            ],
            "improvements": (
                "Bernstein's ChaCha20 variant reorders the quarter-round operations "
                "for better diffusion per round. ChaCha20 is now preferred and is "
                "standardized in RFC 8439 as ChaCha20-Poly1305 for authenticated "
                "encryption, widely used in TLS 1.3 and WireGuard VPN."
            ),
        }

    def explain_steps(self, text: str, key: str = "Salsa20Key-32BytesLong!!", mode: str = "encrypt") -> list[dict]:
        key_bytes = self._prepare_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Setup the Salsa20 State Matrix",
            "content": (
                "Build a 4×4 matrix of 32-bit words from:\n"
                "• Four constants ('expand 32-byte k')\n"
                "• Eight 32-bit words from the 256-bit key\n"
                "• Two 32-bit words from the 64-bit nonce\n"
                "• Two 32-bit words for the block counter"
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 2 — 20 Rounds of Quarter-Round Operations",
            "content": (
                "Each double-round consists of:\n"
                "• 4 column quarter-rounds (operating on columns of the matrix)\n"
                "• 4 row quarter-rounds (operating on rows)\n"
                "Each quarter-round performs: b ^= rotl(a+d, 7); c ^= rotl(b+a, 9); "
                "d ^= rotl(c+b, 13); a ^= rotl(d+c, 18)"
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 3 — Add Original State & XOR",
            "content": (
                "The working state is added (mod 2³²) to the original state to produce "
                "a 64-byte keystream block. This is XORed with the plaintext/ciphertext."
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            nonce = os.urandom(8)
            ct = self._salsa20_crypt(text.encode("utf-8"), key_bytes, nonce)
            result = base64.b64encode(nonce + ct).decode("utf-8")
        else:
            raw = base64.b64decode(text)
            nonce = raw[:8]
            ct = raw[8:]
            pt = self._salsa20_crypt(ct, key_bytes, nonce)
            result = pt.decode("utf-8")

        steps.append({
            "title": "Step 4 — Final Result",
            "content": (
                f"{'Nonce (8 bytes) is prepended to ciphertext and base64-encoded.' if mode == 'encrypt' else 'Nonce extracted, keystream regenerated, XOR recovers plaintext.'}"
            ),
            "data": {"type": "result", "output": result},
        })
        return steps
