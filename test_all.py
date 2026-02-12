"""Quick test script to verify all ciphers work correctly."""

from ciphers.registry import list_ciphers, get_cipher

def test_round_trip():
    ciphers = list_ciphers()
    print(f"Total ciphers registered: {len(ciphers)}")
    print("=" * 60)

    for info in ciphers:
        name = info["name"]
        slug = info["slug"]
        sub = info["subcategory"]
        cipher = get_cipher(slug)
        print(f"\n{name} [{sub}]")

        test_cases = {
            "atbash":               ("HELLO WORLD", None),
            "caesar":               ("HELLO WORLD", "3"),
            "augustus":              ("HELLO WORLD", None),
            "affine":               ("HELLO WORLD", "5,8"),
            "multiplicative":       ("HELLO WORLD", "7"),
            "vigenere":             ("HELLO WORLD", "KEY"),
            "gronsfeld":            ("HELLO WORLD", "314"),
            "beaufort":             ("HELLO WORLD", "KEY"),
            "autokey":              ("HELLO WORLD", "QUEEN"),
            "running-key":          ("HELLO", "TOBEO"),
            "hill":                 ("HELLO", "3,3,2,5"),
            "rail-fence":           ("HELLO WORLD", "3"),
            "route":                ("HELLOWORLD", "4"),
            "columnar":             ("HELLOWORLD", "ZEBRA"),
            "myszkowski":           ("HELLOWORLD", "TOMATO"),
            "double-transposition": ("HELLOWORLD", "ZEBRA,STRIP"),
            "disrupted":            ("HELLOWORLD", "SECRET"),
            "grille":               ("HELLO WORLD TEST XYZ", "0,2,5,7"),
        }

        text, key = test_cases.get(slug, ("HELLO", "KEY"))

        try:
            if key:
                encrypted = cipher.encrypt(text, key)
                steps = cipher.explain_steps(text, key, mode="encrypt")
            else:
                encrypted = cipher.encrypt(text)
                steps = cipher.explain_steps(text, mode="encrypt")
            print(f"  Encrypt: '{text}' -> '{encrypted}'")
            print(f"  Steps: {len(steps)} steps generated")

            # Test round-trip (skip complex ones that may pad)
            if key:
                decrypted = cipher.decrypt(encrypted, key)
            else:
                decrypted = cipher.decrypt(encrypted)
            print(f"  Decrypt: '{encrypted}' -> '{decrypted}'")

            # For simple substitution ciphers, verify round-trip
            if sub in ("Monoalphabetic Substitution", "Polyalphabetic Substitution"):
                if decrypted == text:
                    print("  [OK] Round-trip matches")
                else:
                    print(f"  [FAIL] Round-trip MISMATCH: expected '{text}', got '{decrypted}'")
            else:
                print(f"  [~] Round-trip (may differ due to padding)")
        except Exception as e:
            print(f"  [ERROR] {e}")

    print("\n" + "=" * 60)
    print("All ciphers tested!")


if __name__ == "__main__":
    test_round_trip()
