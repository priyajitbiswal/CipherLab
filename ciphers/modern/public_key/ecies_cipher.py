"""ECIES — Elliptic Curve Integrated Encryption Scheme."""

import random
import hashlib
import base64
import struct
from ciphers.base import Cipher


class ECPoint:
    """Point on an elliptic curve y² = x³ + ax + b mod p."""

    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve

    def is_infinity(self):
        return self.x is None and self.y is None

    @staticmethod
    def infinity(curve):
        return ECPoint(None, None, curve)

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity(): return "O"
        return f"({self.x},{self.y})"

    def __add__(self, other):
        if self.is_infinity(): return other
        if other.is_infinity(): return self
        p = self.curve['p']
        if self.x == other.x and (self.y + other.y) % p == 0:
            return ECPoint.infinity(self.curve)
        if self == other:
            lam = (3 * self.x * self.x + self.curve['a']) * pow(2 * self.y, -1, p) % p
        else:
            lam = (other.y - self.y) * pow(other.x - self.x, -1, p) % p
        x3 = (lam * lam - self.x - other.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3, self.curve)

    def __mul__(self, scalar):
        result = ECPoint.infinity(self.curve)
        addend = self
        n = scalar
        while n > 0:
            if n & 1: result = result + addend
            addend = addend + addend
            n >>= 1
        return result

    def __rmul__(self, scalar):
        return self.__mul__(scalar)


CURVE = {'a': 2, 'b': 3, 'p': 97}
G = ECPoint(3, 6, CURVE)


def curve_order(G, curve):
    point = G
    for i in range(2, curve['p'] * 2):
        point = point + G
        if point.is_infinity(): return i
    return curve['p']


class ECIESCipher(Cipher):
    """
    Educational ECIES implementation.
    Combines ECDH key agreement with symmetric encryption (XOR with KDF output).
    """

    def _parse_key(self, key: str):
        if not key:
            d = 5
        else:
            try:
                d = int(key.strip())
            except ValueError:
                d = 5
        n = curve_order(G, CURVE)
        Q = d * G
        return d, Q, n

    @staticmethod
    def _kdf(shared_point, length):
        """Key Derivation Function using SHA-256."""
        material = f"{shared_point.x},{shared_point.y}".encode()
        derived = b""
        counter = 0
        while len(derived) < length:
            h = hashlib.sha256(material + counter.to_bytes(4, 'big')).digest()
            derived += h
            counter += 1
        return derived[:length]

    def encrypt(self, plaintext: str, key: str = "5") -> str:
        d, Q, n = self._parse_key(key)
        pt_bytes = plaintext.encode("utf-8")

        # Ephemeral key pair
        r = random.randint(1, n - 1)
        R = r * G  # Ephemeral public key
        S = r * Q  # Shared secret

        # Derive symmetric key
        sym_key = self._kdf(S, len(pt_bytes))

        # Encrypt with XOR
        ct = bytes(a ^ b for a, b in zip(pt_bytes, sym_key))

        # MAC
        mac = hashlib.sha256(ct + str(S.x).encode() + str(S.y).encode()).hexdigest()[:16]

        # Output: R point + ciphertext + MAC
        return f"R:{R.x},{R.y}|CT:{base64.b64encode(ct).decode()}|MAC:{mac}"

    def decrypt(self, ciphertext: str, key: str = "5") -> str:
        d, Q, n = self._parse_key(key)

        # Parse
        parts = {}
        for segment in ciphertext.split("|"):
            k, v = segment.split(":", 1)
            parts[k] = v

        rx, ry = [int(x) for x in parts["R"].split(",")]
        R = ECPoint(rx, ry, CURVE)
        ct = base64.b64decode(parts["CT"])
        mac_received = parts["MAC"]

        # Recover shared secret
        S = d * R

        # Verify MAC
        mac_computed = hashlib.sha256(ct + str(S.x).encode() + str(S.y).encode()).hexdigest()[:16]
        if mac_computed != mac_received:
            raise ValueError("ECIES MAC verification failed — ciphertext tampered!")

        # Derive symmetric key and decrypt
        sym_key = self._kdf(S, len(ct))
        pt = bytes(a ^ b for a, b in zip(ct, sym_key))
        return pt.decode("utf-8")

    def get_info(self) -> dict:
        return {
            "name": "ECIES",
            "slug": "ecies",
            "category": "Modern",
            "subcategory": "Elliptic Curve",
            "key_info": "Private key scalar (integer). Default: 5",
            "description": (
                "ECIES (Elliptic Curve Integrated Encryption Scheme) combines three "
                "primitives: ECDH key agreement to establish a shared secret, a KDF "
                "to derive a symmetric key, and symmetric encryption + MAC for "
                "confidentiality and integrity. It is the practical standard for "
                "EC-based encryption."
            ),
            "history": (
                "Standardized in IEEE 1363a, ANSI X9.63, and ISO/IEC 18033-2. ECIES "
                "evolved from the idea of combining Diffie-Hellman with symmetric "
                "encryption, known as DHAES (later DHIES). Apple uses ECIES for "
                "iMessage encryption, and it's used in Ethereum's devp2p protocol."
            ),
            "advantages": [
                "Integrated scheme — combines key agreement, encryption, and MAC.",
                "IND-CCA2 secure under standard assumptions (Gap-DH).",
                "Small keys: 256-bit EC provides 128-bit security.",
                "Practical and standardized — used in iMessage, Ethereum, etc.",
            ],
            "disadvantages": [
                "More complex than basic RSA encryption.",
                "Ciphertext expansion due to ephemeral public key + MAC tag.",
                "Specific curve choice matters — some curves have weaknesses.",
                "Vulnerable to quantum attacks (like all EC-based schemes).",
            ],
            "improvements": (
                "ECIES is the recommended approach for EC-based encryption today. "
                "For key exchange, X25519 (Curve25519 ECDH) is preferred. For post-quantum "
                "safety, NIST has standardized CRYSTALS-Kyber as the replacement for "
                "EC-based key encapsulation mechanisms."
            ),
        }

    def explain_steps(self, text: str, key: str = "5", mode: str = "encrypt") -> list[dict]:
        d, Q, n = self._parse_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — ECIES Setup",
            "content": (
                f"Curve: y² = x³ + {CURVE['a']}x + {CURVE['b']} mod {CURVE['p']}\n"
                f"G = {G}, Order = {n}\n"
                f"Private key d = {d}, Public key Q = {Q}"
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            r = random.randint(1, n - 1)
            R = r * G
            S = r * Q
            steps.append({
                "title": "Step 2 — ECDH Key Agreement",
                "content": (
                    f"Generate ephemeral key r = {r}\n"
                    f"Ephemeral public key R = r·G = {R}\n"
                    f"Shared secret S = r·Q = {S}\n"
                    f"Derive symmetric key via KDF(S)"
                ),
                "data": {"type": "info"},
            })

            pt_bytes = text.encode("utf-8")
            sym_key = self._kdf(S, len(pt_bytes))
            ct = bytes(a ^ b for a, b in zip(pt_bytes, sym_key))
            mac = hashlib.sha256(ct + str(S.x).encode() + str(S.y).encode()).hexdigest()[:16]

            steps.append({
                "title": "Step 3 — Symmetric Encrypt + MAC",
                "content": (
                    f"Plaintext XORed with KDF-derived key ({len(pt_bytes)} bytes)\n"
                    f"MAC = SHA-256(ciphertext || S)[:16] = {mac}\n"
                    f"Output: R + ciphertext + MAC"
                ),
                "data": {"type": "info"},
            })
            result = f"R:{R.x},{R.y}|CT:{base64.b64encode(ct).decode()}|MAC:{mac}"
        else:
            segments = {}
            for seg in text.split("|"):
                k, v = seg.split(":", 1)
                segments[k] = v
            rx, ry = [int(x) for x in segments["R"].split(",")]
            R = ECPoint(rx, ry, CURVE)
            ct = base64.b64decode(segments["CT"])
            S = d * R

            steps.append({
                "title": "Step 2 — Recover Shared Secret",
                "content": (
                    f"R = ({rx},{ry}) (ephemeral public key)\n"
                    f"S = d·R = {d}·{R} = {S}\n"
                    f"Same shared secret as sender!"
                ),
                "data": {"type": "info"},
            })

            mac_received = segments["MAC"]
            mac_computed = hashlib.sha256(ct + str(S.x).encode() + str(S.y).encode()).hexdigest()[:16]
            sym_key = self._kdf(S, len(ct))
            pt = bytes(a ^ b for a, b in zip(ct, sym_key))

            steps.append({
                "title": "Step 3 — Verify MAC & Decrypt",
                "content": (
                    f"MAC check: computed={mac_computed}, received={mac_received} "
                    f"→ {'✅ Match' if mac_computed == mac_received else '❌ Mismatch'}\n"
                    f"Decrypt: XOR ciphertext with KDF-derived key"
                ),
                "data": {"type": "info"},
            })
            result = pt.decode("utf-8")

        steps.append({
            "title": "Step 4 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
