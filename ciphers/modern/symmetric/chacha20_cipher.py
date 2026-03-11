"""ChaCha20 — improved Salsa20 stream cipher, standardized in RFC 8439."""

import base64
import struct
import os
from ciphers.base import Cipher


class ChaCha20Cipher(Cipher):
    """
    Pure-Python educational implementation of ChaCha20.
    Uses 256-bit key and 96-bit nonce with 20 rounds of quarter-round ops.
    """

    def _prepare_key(self, key: str) -> bytes:
        if not key:
            key = "ChaCha20Key-32BytesLong!"
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 32:
            key_bytes = key_bytes.ljust(32, b"\0")
        return key_bytes[:32]

    @staticmethod
    def _rotl32(v, c):
        return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF

    def _quarter_round(self, state, a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = self._rotl32(state[d], 16)

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = self._rotl32(state[b], 12)

        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = self._rotl32(state[d], 8)

        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = self._rotl32(state[b], 7)

    def _chacha20_block(self, key: bytes, nonce: bytes, counter: int) -> bytes:
        """Generate one 64-byte keystream block."""
        sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        k = struct.unpack('<8I', key)
        n = struct.unpack('<3I', nonce)

        state = [
            sigma[0], sigma[1], sigma[2], sigma[3],
            k[0], k[1], k[2], k[3],
            k[4], k[5], k[6], k[7],
            counter, n[0], n[1], n[2],
        ]

        working = list(state)
        for _ in range(10):  # 20 rounds = 10 double-rounds
            # Column rounds
            self._quarter_round(working, 0, 4, 8, 12)
            self._quarter_round(working, 1, 5, 9, 13)
            self._quarter_round(working, 2, 6, 10, 14)
            self._quarter_round(working, 3, 7, 11, 15)
            # Diagonal rounds
            self._quarter_round(working, 0, 5, 10, 15)
            self._quarter_round(working, 1, 6, 11, 12)
            self._quarter_round(working, 2, 7, 8, 13)
            self._quarter_round(working, 3, 4, 9, 14)

        output = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
        return struct.pack('<16I', *output)

    def _chacha20_crypt(self, data: bytes, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
        result = bytearray()
        for i in range(0, len(data), 64):
            block = self._chacha20_block(key, nonce, counter + i // 64)
            chunk = data[i:i+64]
            result.extend(c ^ k for c, k in zip(chunk, block[:len(chunk)]))
        return bytes(result)

    def encrypt(self, plaintext: str, key: str = "ChaCha20Key-32BytesLong!") -> str:
        key_bytes = self._prepare_key(key)
        nonce = os.urandom(12)  # 96-bit nonce
        ct = self._chacha20_crypt(plaintext.encode("utf-8"), key_bytes, nonce)
        return base64.b64encode(nonce + ct).decode("utf-8")

    def decrypt(self, ciphertext: str, key: str = "ChaCha20Key-32BytesLong!") -> str:
        key_bytes = self._prepare_key(key)
        raw = base64.b64decode(ciphertext)
        nonce = raw[:12]
        ct = raw[12:]
        pt = self._chacha20_crypt(ct, key_bytes, nonce)
        return pt.decode("utf-8")

    def get_info(self) -> dict:
        return {
            "name": "ChaCha20",
            "slug": "chacha20",
            "category": "Modern",
            "subcategory": "Stream Ciphers",
            "key_info": "32 ASCII characters (256-bit key). Default: ChaCha20Key-32BytesLong!",
            "description": (
                "ChaCha20 is a stream cipher and variant of Salsa20 with improved "
                "per-round diffusion. It uses a 256-bit key and 96-bit nonce, generating "
                "64-byte keystream blocks via 20 rounds of ARX (Add-Rotate-XOR) operations "
                "on a 4×4 matrix. Standardized in RFC 8439 as part of ChaCha20-Poly1305."
            ),
            "history": (
                "Designed by Daniel J. Bernstein in 2008 as an improvement to Salsa20. "
                "Adopted by Google for use in TLS on Android devices and later standardized "
                "by the IETF in RFC 7539/8439. Now widely used in TLS 1.3, WireGuard VPN, "
                "SSH, and the Linux kernel's random number generator."
            ),
            "advantages": [
                "Better diffusion per round than Salsa20 — more secure at same speed.",
                "Very fast in software — no lookup tables, resistant to timing attacks.",
                "96-bit nonce (vs Salsa20's 64-bit) allows more messages per key.",
                "Used in TLS 1.3, WireGuard, and SSH — battle-tested in production.",
            ],
            "disadvantages": [
                "Nonce reuse still catastrophic — must never reuse nonce with same key.",
                "Not as fast as AES on hardware with AES-NI instructions.",
                "Requires separate MAC (Poly1305) for authenticated encryption.",
                "32-bit counter limits encryption to 256 GB per nonce.",
            ],
            "improvements": (
                "ChaCha20 improved on Salsa20's quarter-round structure for better "
                "diffusion. The IETF variant (RFC 8439) uses a 96-bit nonce and 32-bit "
                "counter, compared to Bernstein's original 64-bit/64-bit split. "
                "XChaCha20 extends the nonce to 192 bits for even safer random generation."
            ),
        }

    def explain_steps(self, text: str, key: str = "ChaCha20Key-32BytesLong!", mode: str = "encrypt") -> list[dict]:
        key_bytes = self._prepare_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Build the ChaCha20 State Matrix",
            "content": (
                "4×4 matrix of 32-bit words:\n"
                "Row 0: Constants ('expand 32-byte k')\n"
                "Row 1-2: 256-bit key (8 words)\n"
                "Row 3: 32-bit counter + 96-bit nonce (4 words)\n"
                "Layout differs from Salsa20 — constants are in a row, not diagonal."
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 2 — 20 Rounds (10 Double-Rounds)",
            "content": (
                "Each double-round applies:\n"
                "• 4 column quarter-rounds: (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15)\n"
                "• 4 diagonal quarter-rounds: (0,5,10,15), (1,6,11,12), (2,7,8,13), (3,4,9,14)\n\n"
                "Each quarter-round: a+=b; d^=a; d<<<16; c+=d; b^=c; b<<<12; "
                "a+=b; d^=a; d<<<8; c+=d; b^=c; b<<<7"
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 3 — Keystream Generation & XOR",
            "content": (
                "Working state is added (mod 2³²) to original state, producing 64 "
                "keystream bytes. Counter increments for each new block. "
                "Plaintext/ciphertext is XORed with the keystream."
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            nonce = os.urandom(12)
            ct = self._chacha20_crypt(text.encode("utf-8"), key_bytes, nonce)
            result = base64.b64encode(nonce + ct).decode("utf-8")
        else:
            raw = base64.b64decode(text)
            nonce = raw[:12]
            ct = raw[12:]
            pt = self._chacha20_crypt(ct, key_bytes, nonce)
            result = pt.decode("utf-8")

        steps.append({
            "title": "Step 4 — Final Result",
            "content": (
                f"{'12-byte nonce prepended to ciphertext, then base64-encoded.' if mode == 'encrypt' else 'Nonce extracted from first 12 bytes, keystream regenerated to recover plaintext.'}"
            ),
            "data": {"type": "result", "output": result},
        })
        return steps
