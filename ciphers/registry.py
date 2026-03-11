"""Cipher Registry — auto-discovers and provides access to all cipher implementations."""

# ── Classical Ciphers ─────────────────────────────────────────────────────
from ciphers.classical.substitution.atbash import AtbashCipher
from ciphers.classical.substitution.caesar import CaesarCipher
from ciphers.classical.substitution.augustus import AugustusCipher
from ciphers.classical.substitution.affine import AffineCipher
from ciphers.classical.substitution.multiplicative import MultiplicativeCipher
from ciphers.classical.substitution.vigenere import VigenereCipher
from ciphers.classical.substitution.gronsfeld import GronsfeldCipher
from ciphers.classical.substitution.beaufort import BeaufortCipher
from ciphers.classical.substitution.autokey import AutokeyCipher
from ciphers.classical.substitution.running_key import RunningKeyCipher
from ciphers.classical.substitution.hill import HillCipher
from ciphers.classical.transposition.rail_fence import RailFenceCipher
from ciphers.classical.transposition.route import RouteCipher
from ciphers.classical.transposition.columnar import ColumnarCipher
from ciphers.classical.transposition.myszkowski import MyszkowskiCipher
from ciphers.classical.transposition.double_transposition import DoubleTranspositionCipher
from ciphers.classical.transposition.disrupted import DisruptedCipher
from ciphers.classical.transposition.grille import GrilleCipher

# ── Modern Symmetric Ciphers ──────────────────────────────────────────────
from ciphers.modern.symmetric.des_cipher import DESCipher
from ciphers.modern.symmetric.triple_des import TripleDESCipher
from ciphers.modern.symmetric.aes_cipher import AESCipher
from ciphers.modern.symmetric.idea_cipher import IDEACipher
from ciphers.modern.symmetric.rc4_cipher import RC4Cipher
from ciphers.modern.symmetric.salsa20_cipher import Salsa20Cipher
from ciphers.modern.symmetric.chacha20_cipher import ChaCha20Cipher

# ── Modern Public-Key Ciphers ─────────────────────────────────────────────
from ciphers.modern.public_key.rsa_cipher import RSACipher
from ciphers.modern.public_key.rabin_cipher import RabinCipher
from ciphers.modern.public_key.schmidt_samoa import SchmidtSamoaCipher
from ciphers.modern.public_key.elgamal_cipher import ElGamalCipher
from ciphers.modern.public_key.cramer_shoup import CramerShoupCipher
from ciphers.modern.public_key.massey_omura import MasseyOmuraCipher
from ciphers.modern.public_key.ec_elgamal import ECElGamalCipher
from ciphers.modern.public_key.ecdsa_cipher import ECDSACipher
from ciphers.modern.public_key.ecies_cipher import ECIESCipher

# ── Cryptographic Hash Functions ──────────────────────────────────────────
from ciphers.modern.hash_functions.hashes import (
    MD5Hash, SHA1Hash, SHA2Hash, SHA3Hash, SHA256Hash, BLAKE2Hash, BLAKE3Hash,
)


# ── Registry ─────────────────────────────────────────────────────────────

_CIPHERS: dict[str, object] = {}


def _register() -> None:
    """Instantiate all ciphers and register them by slug."""
    cipher_classes = [
        # Classical — Substitution
        AtbashCipher, CaesarCipher, AugustusCipher, AffineCipher,
        MultiplicativeCipher, VigenereCipher, GronsfeldCipher,
        BeaufortCipher, AutokeyCipher, RunningKeyCipher, HillCipher,
        # Classical — Transposition
        RailFenceCipher, RouteCipher, ColumnarCipher, MyszkowskiCipher,
        DoubleTranspositionCipher, DisruptedCipher, GrilleCipher,
        # Modern — Block Ciphers
        DESCipher, TripleDESCipher, AESCipher, IDEACipher,
        # Modern — Stream Ciphers
        RC4Cipher, Salsa20Cipher, ChaCha20Cipher,
        # Modern — Integer Factorization
        RSACipher, RabinCipher, SchmidtSamoaCipher,
        # Modern — Discrete Logarithm
        ElGamalCipher, CramerShoupCipher, MasseyOmuraCipher,
        # Modern — Elliptic Curve
        ECElGamalCipher, ECDSACipher, ECIESCipher,
        # Modern — Hash Functions
        MD5Hash, SHA1Hash, SHA2Hash, SHA3Hash, SHA256Hash, BLAKE2Hash, BLAKE3Hash,
    ]
    for cls in cipher_classes:
        instance = cls()
        info = instance.get_info()
        _CIPHERS[info["slug"]] = instance


# Auto-register on import
_register()


def get_cipher(slug: str):
    """Return a cipher instance by its slug, or None."""
    return _CIPHERS.get(slug)


def list_ciphers() -> list[dict]:
    """Return info dicts for all registered ciphers."""
    return [c.get_info() for c in _CIPHERS.values()]


def list_by_category() -> dict[str, list[dict]]:
    """Return ciphers grouped by subcategory."""
    grouped: dict[str, list[dict]] = {}
    for cipher in _CIPHERS.values():
        info = cipher.get_info()
        sub = info.get("subcategory", "Other")
        grouped.setdefault(sub, []).append(info)
    return grouped
