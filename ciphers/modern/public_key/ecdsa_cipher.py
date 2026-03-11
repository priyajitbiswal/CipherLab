"""ECDSA — Elliptic Curve Digital Signature Algorithm."""

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
            return "O"
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


# secp256k1-like small curve for education
CURVE = {'a': 2, 'b': 3, 'p': 97}
G = ECPoint(3, 6, CURVE)


def curve_order(G, curve):
    point = G
    for i in range(2, curve['p'] * 2):
        point = point + G
        if point.is_infinity():
            return i
    return curve['p']


class ECDSACipher(Cipher):
    """
    Educational ECDSA implementation.
    'Encrypt' = Sign, 'Decrypt' = Verify.
    """

    def _parse_key(self, key: str):
        if not key:
            d = 7
        else:
            try:
                d = int(key.strip())
            except ValueError:
                d = 7
        n = curve_order(G, CURVE)
        Q = d * G
        return d, Q, n

    def encrypt(self, plaintext: str, key: str = "7") -> str:
        """Sign the message."""
        d, Q, n = self._parse_key(key)
        z = int(hashlib.sha256(plaintext.encode()).hexdigest(), 16) % n
        if z == 0:
            z = 1

        # Sign
        while True:
            k = random.randint(1, n - 1)
            R = k * G
            if R.is_infinity():
                continue
            r = R.x % n
            if r == 0:
                continue
            k_inv = pow(k, -1, n)
            s = (k_inv * (z + r * d)) % n
            if s == 0:
                continue
            break

        # Return signature with original message
        return f"{plaintext}||SIG:{r},{s}||PUB:{Q.x},{Q.y}"

    def decrypt(self, ciphertext: str, key: str = "7") -> str:
        """Verify the signature."""
        d, Q, n = self._parse_key(key)

        # Parse
        parts = ciphertext.split("||")
        message = parts[0]
        sig_str = parts[1].replace("SIG:", "")
        r, s = [int(x) for x in sig_str.split(",")]
        pub_str = parts[2].replace("PUB:", "")
        qx, qy = [int(x) for x in pub_str.split(",")]
        Q_verify = ECPoint(qx, qy, CURVE)

        z = int(hashlib.sha256(message.encode()).hexdigest(), 16) % n
        if z == 0:
            z = 1

        s_inv = pow(s, -1, n)
        u1 = (z * s_inv) % n
        u2 = (r * s_inv) % n
        P = (u1 * G) + (u2 * Q_verify)

        if P.is_infinity():
            return f"❌ INVALID SIGNATURE — verification point is infinity\nMessage: {message}"

        if P.x % n == r:
            return f"✅ VALID SIGNATURE\nMessage: {message}"
        else:
            return f"❌ INVALID SIGNATURE — r={r} ≠ P.x={P.x % n}\nMessage: {message}"

    def get_info(self) -> dict:
        return {
            "name": "ECDSA",
            "slug": "ecdsa",
            "category": "Modern",
            "subcategory": "Elliptic Curve",
            "key_info": "Private key scalar (integer). Default: 7. Encrypt=Sign, Decrypt=Verify.",
            "description": (
                "ECDSA (Elliptic Curve Digital Signature Algorithm) provides digital "
                "signatures using elliptic curve cryptography. The signer uses a private "
                "key to create a signature (r, s) over a message hash, and anyone with "
                "the public key can verify the signature's authenticity."
            ),
            "history": (
                "Proposed by Scott Vanstone in 1992 and standardized in ANSI X9.62 (1998), "
                "FIPS 186-2 (2000), and ISO 14888-3. ECDSA is used in Bitcoin and Ethereum "
                "for transaction signing, in TLS certificates, and in Apple's code signing. "
                "It is the elliptic curve analogue of the classic DSA algorithm."
            ),
            "advantages": [
                "Compact signatures — 64 bytes (vs RSA's 256-384 bytes).",
                "256-bit keys provide 128-bit security (equivalent to RSA-3072).",
                "Fast signature generation and verification.",
                "Widely deployed: Bitcoin, TLS, SSH, code signing.",
            ],
            "disadvantages": [
                "Nonce reuse catastrophically leaks the private key (the PlayStation 3 hack).",
                "Requires high-quality randomness for each signature.",
                "Malleable signatures — (r, s) and (r, n-s) are both valid.",
                "Being superseded by EdDSA (Ed25519) which is deterministic.",
            ],
            "improvements": (
                "RFC 6979 introduced deterministic ECDSA to eliminate nonce reuse risks. "
                "EdDSA (Ed25519/Ed448) is the modern preferred alternative — it's "
                "deterministic, faster, and resistant to side-channel attacks. "
                "Post-quantum signature schemes like CRYSTALS-Dilithium will eventually "
                "replace ECDSA."
            ),
        }

    def explain_steps(self, text: str, key: str = "7", mode: str = "encrypt") -> list[dict]:
        d, Q, n = self._parse_key(key)
        steps = []

        steps.append({
            "title": "Step 1 — ECDSA Setup",
            "content": (
                f"Curve: y² = x³ + {CURVE['a']}x + {CURVE['b']} mod {CURVE['p']}\n"
                f"Generator G = {G}, Order n = {n}\n"
                f"Private key d = {d}, Public key Q = d·G = {Q}"
            ),
            "data": {"type": "info"},
        })

        if mode == "encrypt":
            z = int(hashlib.sha256(text.encode()).hexdigest(), 16) % n
            if z == 0: z = 1
            steps.append({
                "title": "Step 2 — Hash the Message",
                "content": (
                    f"z = SHA-256(message) mod n = {z}\n"
                    f"Full hash: {hashlib.sha256(text.encode()).hexdigest()[:32]}..."
                ),
                "data": {"type": "info"},
            })

            k = random.randint(1, n - 1)
            R = k * G
            r = R.x % n
            k_inv = pow(k, -1, n)
            s = (k_inv * (z + r * d)) % n

            steps.append({
                "title": "Step 3 — Compute Signature (r, s)",
                "content": (
                    f"Random k = {k}\n"
                    f"R = k·G = {R}\n"
                    f"r = R.x mod n = {r}\n"
                    f"s = k⁻¹(z + r·d) mod n = {s}"
                ),
                "data": {"type": "info"},
            })

            result = f"{text}||SIG:{r},{s}||PUB:{Q.x},{Q.y}"
        else:
            steps.append({
                "title": "Step 2 — Parse & Verify",
                "content": "Extract message, signature (r,s), and public key from input.",
                "data": {"type": "info"},
            })

            parts = text.split("||")
            message = parts[0]
            sig_str = parts[1].replace("SIG:", "")
            r, s = [int(x) for x in sig_str.split(",")]
            z = int(hashlib.sha256(message.encode()).hexdigest(), 16) % n
            if z == 0: z = 1
            s_inv = pow(s, -1, n)
            u1 = (z * s_inv) % n
            u2 = (r * s_inv) % n
            P = (u1 * G) + (u2 * Q)
            valid = not P.is_infinity() and P.x % n == r

            steps.append({
                "title": "Step 3 — Verification Computation",
                "content": (
                    f"u₁ = z·s⁻¹ mod n = {u1}\n"
                    f"u₂ = r·s⁻¹ mod n = {u2}\n"
                    f"P = u₁·G + u₂·Q = {P}\n"
                    f"Check: P.x mod n = {P.x % n if not P.is_infinity() else 'INF'} {'==' if valid else '!='} r = {r}\n"
                    f"Result: {'✅ VALID' if valid else '❌ INVALID'}"
                ),
                "data": {"type": "info"},
            })
            result = f"{'✅ VALID' if valid else '❌ INVALID'} SIGNATURE\nMessage: {message}"

        steps.append({
            "title": "Step 4 — Final Result",
            "content": f"{'Signature generated.' if mode == 'encrypt' else 'Verification complete.'}",
            "data": {"type": "result", "output": result},
        })
        return steps
