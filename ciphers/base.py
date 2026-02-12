"""Base class for all cipher implementations."""

from abc import ABC, abstractmethod


class Cipher(ABC):
    """Abstract base class for all ciphers.

    Every cipher must implement encrypt, decrypt, get_info, and explain_steps.
    The explain_steps method is the educational core — it returns a list of
    step-by-step dicts that the frontend renders as an animated walkthrough.
    """

    @abstractmethod
    def encrypt(self, plaintext: str, key) -> str:
        """Encrypt the plaintext using the given key."""
        ...

    @abstractmethod
    def decrypt(self, ciphertext: str, key) -> str:
        """Decrypt the ciphertext using the given key."""
        ...

    @abstractmethod
    def get_info(self) -> dict:
        """Return metadata about this cipher.

        Returns a dict with keys:
            name, slug, category, subcategory, description, history,
            key_info (description of what the key looks like)
        """
        ...

    @abstractmethod
    def explain_steps(self, text: str, key, mode: str = "encrypt") -> list[dict]:
        """Return a list of explanation steps for the cipher operation.

        Each step dict has:
            title   — short heading
            content — detailed explanation of what happens at this step
            data    — optional dict with visual data (tables, grids, mappings)
        """
        ...

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _clean(text: str) -> str:
        """Convert to uppercase and strip non-alpha chars."""
        return "".join(c for c in text.upper() if c.isalpha())

    @staticmethod
    def _clean_keep_case(text: str) -> str:
        """Strip non-alpha chars but preserve case."""
        return "".join(c for c in text if c.isalpha())
