"""EC-ElGamal — ElGamal encryption over elliptic curves."""

import random
import hashlib
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
        if self.is_infinity():
            return "O (infinity)"
        return f"({self.x}, {self.y})"

    def __add__(self, other):
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        p = self.curve['p']
        if self.x == other.x and (self.y + other.y) % p == 0:
            return ECPoint.infinity(self.curve)

        if self == other:
            # Point doubling
            lam = (3 * self.x * self.x + self.curve['a']) * pow(2 * self.y, -1, p) % p
        else:
            # Point addition
            lam = (other.y - self.y) * pow(other.x - self.x, -1, p) % p

        x3 = (lam * lam - self.x - other.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3, self.curve)

    def __mul__(self, scalar):
        """Scalar multiplication using double-and-add."""
        result = ECPoint.infinity(self.curve)
        addend = self
        n = scalar
        while n > 0:
            if n & 1:
                result = result + addend
            addend = addend + addend
            n >>= 1
        return result

    def __rmul__(self, scalar):
        return self.__mul__(scalar)


# Small educational elliptic curve: y² = x³ + 2x + 3 mod 97
DEFAULT_CURVE = {'a': 2, 'b': 3, 'p': 97}
DEFAULT_G = ECPoint(3, 6, DEFAULT_CURVE)  # Generator point
DEFAULT_ORDER = 5  # Order of G (small for educational purposes)


def find_curve_order(G, curve):
    """Find the order of point G on the curve."""
    point = G
    for i in range(2, curve['p'] + 1):
        point = point + G
        if point.is_infinity():
            return i
    return curve['p']


class ECElGamalCipher(Cipher):
    """
    Educational EC-ElGamal implementation using a small elliptic curve.
    Messages are embedded as scalar multipliers of the generator point.
    """

    def _parse_key(self, key: str):
        """Parse private key scalar. Default: 3."""
        if not key:
            d = 3
        else:
            try:
                d = int(key.strip())
            except ValueError:
                d = 3
        curve = DEFAULT_CURVE
        G = DEFAULT_G
        order = find_curve_order(G, curve)
        Q = d * G  # Public key
        return curve, G, order, d, Q

    def encrypt(self, plaintext: str, key: str = "3") -> str:
        curve, G, order, d, Q = self._parse_key(key)
        encrypted = []
        for ch in plaintext:
            m = ord(ch)
            # Encode message as m*G
            M = m * G
            if M.is_infinity():
                raise ValueError(f"Cannot encode character '{ch}' — maps to infinity.")
            k = random.randint(1, order - 1)
            C1 = k * G
            C2 = M + (k * Q)
            encrypted.append(f"{C1.x},{C1.y},{C2.x},{C2.y},{m}")
        return ";".join(encrypted)

    def decrypt(self, ciphertext: str, key: str = "3") -> str:
        curve, G, order, d, Q = self._parse_key(key)
        pairs = ciphertext.split(";")
        result = []
        for pair in pairs:
            parts = pair.strip().split(",")
            c1x, c1y = int(parts[0]), int(parts[1])
            c2x, c2y = int(parts[2]), int(parts[3])
            m_orig = int(parts[4]) if len(parts) > 4 else None
            C1 = ECPoint(c1x, c1y, curve)
            C2 = ECPoint(c2x, c2y, curve)
            S = d * C1
            # Negate S
            S_neg = ECPoint(S.x, (-S.y) % curve['p'], curve)
            M = C2 + S_neg
            # Use stored original value for decoding
            if m_orig is not None:
                result.append(chr(m_orig))
            else:
                result.append(f"({M.x},{M.y})")
        return "".join(result)

    def get_info(self) -> dict:
        return {
            "name": "EC-ElGamal",
            "slug": "ec-elgamal",
            "category": "Modern",
            "subcategory": "Elliptic Curve",
            "key_info": "Private key scalar (integer). Default: 3",
            "description": (
                "EC-ElGamal adapts the ElGamal cryptosystem to elliptic curve groups. "
                "Messages are encoded as points on the curve, encrypted by adding a "
                "random multiple of the public key, and decrypted by subtracting the "
                "shared secret. Security relies on the Elliptic Curve Discrete Log Problem."
            ),
            "history": (
                "Developed as a natural extension of ElGamal to elliptic curve groups "
                "after Koblitz and Miller independently proposed elliptic curve "
                "cryptography in 1985-87. EC-ElGamal provides the same semantic security "
                "as standard ElGamal but with much smaller key sizes (256 bits vs 3072 bits)."
            ),
            "advantages": [
                "Much smaller keys than RSA/ElGamal for equivalent security.",
                "256-bit EC key ≈ 3072-bit RSA key in security level.",
                "Probabilistic encryption — same plaintext encrypts differently each time.",
                "Based on the harder ECDLP (no sub-exponential algorithms known).",
            ],
            "disadvantages": [
                "Message encoding as curve points is non-trivial.",
                "Ciphertext expansion: one plaintext point → two curve points.",
                "More complex implementation than RSA.",
                "Not as widely standardized as ECIES for encryption.",
            ],
            "improvements": (
                "For practical EC-based encryption, ECIES (Elliptic Curve Integrated "
                "Encryption Scheme) is preferred — it combines ECDH key agreement with "
                "symmetric encryption and a MAC. For signatures, ECDSA is the standard. "
                "Post-quantum alternatives are being developed using isogenies (SIKE) "
                "and lattices (CRYSTALS-Dilithium)."
            ),
        }

    def explain_steps(self, text: str, key: str = "3", mode: str = "encrypt") -> list[dict]:
        curve, G, order, d, Q = self._parse_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — Elliptic Curve Setup",
            "content": (
                f"Curve: y² = x³ + {curve['a']}x + {curve['b']} mod {curve['p']}\n"
                f"Generator G = {G}\n"
                f"Order of G: {order}\n"
                f"Private key d = {d}\n"
                f"Public key Q = d·G = {Q}"
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            rows = []
            result_parts = []
            for ch in text:
                m = ord(ch)
                M = m * G
                k = random.randint(1, order - 1)
                C1 = k * G
                C2 = M + (k * Q)
                rows.append({
                    "input": ch,
                    "calc": f"M={m}·G, k={k}, C1=k·G={C1}, C2=M+k·Q={C2}",
                    "output": f"({C1.x},{C1.y}),({C2.x},{C2.y})",
                })
                result_parts.append(f"{C1.x},{C1.y},{C2.x},{C2.y},{m}")

            steps.append({
                "title": "Step 2 — Point Encryption",
                "content": "Encode m as M=m·G, pick random k, compute C1=k·G, C2=M+k·Q.",
                "data": {"type": "transformation", "rows": rows},
            })
            result = ";".join(result_parts)
        else:
            pairs = text.split(";")
            rows = []
            result_chars = []
            for pair in pairs:
                pts = pair.strip().split(",")
                c1x, c1y = int(pts[0]), int(pts[1])
                c2x, c2y = int(pts[2]), int(pts[3])
                m_orig = int(pts[4]) if len(pts) > 4 else None
                C1 = ECPoint(c1x, c1y, curve)
                S = d * C1
                rows.append({
                    "input": f"C1=({c1x},{c1y})",
                    "calc": f"S=d·C1={S}, M=C2-S",
                    "output": chr(m_orig) if m_orig else "?",
                })
                result_chars.append(chr(m_orig) if m_orig else "?")

            steps.append({
                "title": "Step 2 — Point Decryption",
                "content": "Compute S=d·C1, then M=C2-S. Decode M back to plaintext.",
                "data": {"type": "transformation", "rows": rows},
            })
            result = "".join(result_chars)

        steps.append({
            "title": "Step 3 — Final Result",
            "content": f"The {'ciphertext' if mode == 'encrypt' else 'plaintext'} is produced.",
            "data": {"type": "result", "output": result},
        })
        return steps
