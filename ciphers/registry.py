"""Cipher Registry — auto-discovers and provides access to all cipher implementations."""

from ciphers.substitution.atbash import AtbashCipher
from ciphers.substitution.caesar import CaesarCipher
from ciphers.substitution.augustus import AugustusCipher
from ciphers.substitution.affine import AffineCipher
from ciphers.substitution.multiplicative import MultiplicativeCipher
from ciphers.substitution.vigenere import VigenereCipher
from ciphers.substitution.gronsfeld import GronsfeldCipher
from ciphers.substitution.beaufort import BeaufortCipher
from ciphers.substitution.autokey import AutokeyCipher
from ciphers.substitution.running_key import RunningKeyCipher
from ciphers.substitution.hill import HillCipher
from ciphers.transposition.rail_fence import RailFenceCipher
from ciphers.transposition.route import RouteCipher
from ciphers.transposition.columnar import ColumnarCipher
from ciphers.transposition.myszkowski import MyszkowskiCipher
from ciphers.transposition.double_transposition import DoubleTranspositionCipher
from ciphers.transposition.disrupted import DisruptedCipher
from ciphers.transposition.grille import GrilleCipher


# ── Registry ─────────────────────────────────────────────────────────────

_CIPHERS: dict[str, object] = {}


def _register() -> None:
    """Instantiate all ciphers and register them by slug."""
    cipher_classes = [
        AtbashCipher, CaesarCipher, AugustusCipher, AffineCipher,
        MultiplicativeCipher, VigenereCipher, GronsfeldCipher,
        BeaufortCipher, AutokeyCipher, RunningKeyCipher, HillCipher,
        RailFenceCipher, RouteCipher, ColumnarCipher, MyszkowskiCipher,
        DoubleTranspositionCipher, DisruptedCipher, GrilleCipher,
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
