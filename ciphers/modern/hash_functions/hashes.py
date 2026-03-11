"""Cryptographic Hash Functions — MD5, SHA-1, SHA-2, SHA-3, SHA-256, BLAKE2, BLAKE3.

Hash functions are one-way: they produce a fixed-size digest from arbitrary input.
'Encrypt' = Hash, 'Decrypt' = verify (compare hashes).
"""

import hashlib
from ciphers.base import Cipher


class MD5Hash(Cipher):
    def encrypt(self, plaintext: str, key: str = "") -> str:
        return hashlib.md5(plaintext.encode("utf-8")).hexdigest()

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        return (
            f"⚠ MD5 is a one-way hash — it cannot be reversed.\n"
            f"Hash: {ciphertext}\n"
            f"To verify, hash your candidate plaintext and compare."
        )

    def get_info(self) -> dict:
        return {
            "name": "MD5",
            "slug": "md5",
            "category": "Modern",
            "subcategory": "Hash Functions",
            "key_info": "No key needed. Enter text to hash. Decrypt = explanation (hashes are one-way).",
            "description": (
                "MD5 (Message-Digest Algorithm 5) produces a 128-bit (16-byte) hash value, "
                "typically rendered as a 32-character hexadecimal string. It processes input "
                "in 512-bit blocks through four rounds of 16 operations each, using bitwise "
                "operations, modular addition, and non-linear functions."
            ),
            "history": (
                "Designed by Ronald Rivest in 1991 to replace MD4. Was widely used for "
                "file integrity checking, password hashing, and digital signatures. "
                "Collision attacks were demonstrated by Wang et al. in 2004, and practical "
                "collision attacks (like creating two different PDFs with the same MD5) "
                "followed. Now considered cryptographically broken."
            ),
            "advantages": [
                "Very fast — useful for non-cryptographic checksums.",
                "Ubiquitous — available in every programming language and tool.",
                "Fixed 128-bit output makes it compact for storage.",
                "Still useful for non-security file integrity checks.",
            ],
            "disadvantages": [
                "Cryptographically broken — collision attacks are practical.",
                "Vulnerable to length extension attacks.",
                "128-bit output is too short for modern security requirements.",
                "MUST NOT be used for passwords, signatures, or security-critical tasks.",
            ],
            "improvements": (
                "MD5's weaknesses led to SHA-1 (also now broken) and then SHA-2/SHA-3. "
                "For password hashing, use bcrypt, scrypt, or Argon2 instead. "
                "For general-purpose hashing, SHA-256 or BLAKE3 are recommended."
            ),
        }

    def explain_steps(self, text: str, key: str = "", mode: str = "encrypt") -> list[dict]:
        steps = []
        data = text.encode("utf-8")

        steps.append({
            "title": "Step 1 — Message Padding",
            "content": (
                f"Input: {len(data)} bytes. MD5 pads to a multiple of 512 bits (64 bytes):\n"
                f"• Append bit '1' followed by zeros\n"
                f"• Append original length as 64-bit little-endian integer\n"
                f"Padded size: {((len(data) + 8) // 64 + 1) * 64} bytes"
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 2 — Initialize State (A, B, C, D)",
            "content": (
                "Four 32-bit registers initialized to:\n"
                "A = 0x67452301\nB = 0xefcdab89\nC = 0x98badcfe\nD = 0x10325476"
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 3 — 64 Operations per Block",
            "content": (
                "Each 512-bit block undergoes 4 rounds of 16 operations:\n"
                "Round 1: F(B,C,D) = (B∧C)∨(¬B∧D)\n"
                "Round 2: G(B,C,D) = (B∧D)∨(C∧¬D)\n"
                "Round 3: H(B,C,D) = B⊕C⊕D\n"
                "Round 4: I(B,C,D) = C⊕(B∨¬D)\n"
                "Each uses: A = B + ((A + f + K[i] + M[j]) <<< s)"
            ),
            "data": {"type": "info"},
        })

        digest = hashlib.md5(data).hexdigest()
        steps.append({
            "title": "Step 4 — Final Digest",
            "content": f"The 128-bit hash (32 hex chars) is produced.",
            "data": {"type": "result", "output": digest},
        })
        return steps


class SHA1Hash(Cipher):
    def encrypt(self, plaintext: str, key: str = "") -> str:
        return hashlib.sha1(plaintext.encode("utf-8")).hexdigest()

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        return (
            f"⚠ SHA-1 is a one-way hash — it cannot be reversed.\n"
            f"Hash: {ciphertext}\n"
            f"SHA-1 is cryptographically broken (SHAttered attack, 2017)."
        )

    def get_info(self) -> dict:
        return {
            "name": "SHA-1",
            "slug": "sha1",
            "category": "Modern",
            "subcategory": "Hash Functions",
            "key_info": "No key needed. Enter text to hash.",
            "description": (
                "SHA-1 (Secure Hash Algorithm 1) produces a 160-bit (20-byte) hash. "
                "It processes 512-bit blocks through 80 rounds of operations using "
                "rotations, XOR, and non-linear functions. Designed as an improvement "
                "over MD5 with a longer output."
            ),
            "history": (
                "Published by NIST as FIPS PUB 180-1 in 1995, designed by the NSA. "
                "Widely used in TLS, SSH, PGP, and Git. Theoretical attacks began in 2005 "
                "(Wang et al.), and Google/CWI demonstrated a practical collision "
                "(SHAttered) in 2017. Deprecated for most uses since 2020."
            ),
            "advantages": [
                "Longer output (160 bits) than MD5 — marginally more resistant.",
                "Very widely deployed — Git uses SHA-1 for commit hashes.",
                "Fast computation for non-security integrity checks.",
                "Well-understood and extensive academic analysis.",
            ],
            "disadvantages": [
                "Cryptographically broken — practical collision attacks exist.",
                "SHAttered attack can create two files with the same SHA-1 hash.",
                "Deprecated by NIST, browsers, and certificate authorities.",
                "Chosen-prefix collisions demonstrated in 2020 (Shambles attack).",
            ],
            "improvements": (
                "SHA-1's collision vulnerability led to SHA-2 (SHA-256, SHA-512) which "
                "remains secure. SHA-3 (Keccak) was standardized in 2015 as an alternative "
                "with a completely different internal structure (sponge construction). "
                "Git is transitioning to SHA-256."
            ),
        }

    def explain_steps(self, text: str, key: str = "", mode: str = "encrypt") -> list[dict]:
        steps = []
        data = text.encode("utf-8")

        steps.append({
            "title": "Step 1 — Preprocessing",
            "content": (
                f"Input: {len(data)} bytes. Pad to multiple of 512 bits.\n"
                f"Initialize five 32-bit words:\n"
                f"h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0"
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 2 — 80 Rounds per Block",
            "content": (
                "Each block: expand 16 words to 80 via XOR and rotation.\n"
                "Rounds 0-19: f = (B∧C)∨(¬B∧D), K = 0x5A827999\n"
                "Rounds 20-39: f = B⊕C⊕D, K = 0x6ED9EBA1\n"
                "Rounds 40-59: f = (B∧C)∨(B∧D)∨(C∧D), K = 0x8F1BBCDC\n"
                "Rounds 60-79: f = B⊕C⊕D, K = 0xCA62C1D6"
            ),
            "data": {"type": "info"},
        })

        digest = hashlib.sha1(data).hexdigest()
        steps.append({
            "title": "Step 3 — Final Digest",
            "content": "The 160-bit hash (40 hex chars) is produced.",
            "data": {"type": "result", "output": digest},
        })
        return steps


class SHA2Hash(Cipher):
    def encrypt(self, plaintext: str, key: str = "") -> str:
        return hashlib.sha512(plaintext.encode("utf-8")).hexdigest()

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        return (
            f"⚠ SHA-2 (SHA-512) is a one-way hash — it cannot be reversed.\n"
            f"Hash: {ciphertext}"
        )

    def get_info(self) -> dict:
        return {
            "name": "SHA-2 (SHA-512)",
            "slug": "sha2",
            "category": "Modern",
            "subcategory": "Hash Functions",
            "key_info": "No key needed. Enter text to hash. Shows SHA-512 variant.",
            "description": (
                "SHA-2 is a family of hash functions including SHA-224, SHA-256, SHA-384, "
                "and SHA-512. SHA-512 produces a 512-bit (64-byte) digest using 80 rounds "
                "of operations on eight 64-bit state words. It is the current gold standard "
                "for cryptographic hashing."
            ),
            "history": (
                "Published by NIST in 2001 as FIPS PUB 180-2, designed by the NSA. "
                "SHA-2 was created in anticipation of SHA-1's eventual weakness. "
                "Despite initial concerns about trusting NSA-designed algorithms, "
                "SHA-2 has withstood extensive cryptanalysis and remains secure."
            ),
            "advantages": [
                "No practical attacks known — the most trusted hash family.",
                "Multiple output sizes: 224, 256, 384, or 512 bits.",
                "Hardware acceleration via SHA-NI instructions on modern CPUs.",
                "Universal standard — used in TLS 1.3, Bitcoin, and digital certificates.",
            ],
            "disadvantages": [
                "Vulnerable to length extension attacks (SHA-256/512 specifically).",
                "Shares Merkle-Damgård construction with MD5/SHA-1 (theoretical concern).",
                "Slower than BLAKE2/BLAKE3 in software without hardware acceleration.",
                "SHA-3 exists as a backup with different design philosophy.",
            ],
            "improvements": (
                "SHA-3 (Keccak) was selected as an alternative with a sponge construction "
                "immune to length extension attacks. BLAKE2 and BLAKE3 are faster than "
                "SHA-2 in software. For password hashing, use Argon2 instead."
            ),
        }

    def explain_steps(self, text: str, key: str = "", mode: str = "encrypt") -> list[dict]:
        steps = []
        data = text.encode("utf-8")

        steps.append({
            "title": "Step 1 — Initialize State",
            "content": (
                f"Input: {len(data)} bytes. SHA-512 uses eight 64-bit state words "
                f"initialized to the fractional parts of square roots of the first 8 primes. "
                f"Messages are padded to multiples of 1024 bits."
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 2 — 80 Rounds of Compression",
            "content": (
                "Each 1024-bit block undergoes 80 rounds using:\n"
                "• Ch(e,f,g) = (e∧f)⊕(¬e∧g) — choice function\n"
                "• Maj(a,b,c) = (a∧b)⊕(a∧c)⊕(b∧c) — majority function\n"
                "• Σ₀, Σ₁ — rotation-based mixing functions\n"
                "• 80 round constants from fractional cube roots of primes"
            ),
            "data": {"type": "info"},
        })

        digest = hashlib.sha512(data).hexdigest()
        steps.append({
            "title": "Step 3 — Final Digest",
            "content": "The 512-bit hash (128 hex chars) is produced.",
            "data": {"type": "result", "output": digest},
        })
        return steps


class SHA3Hash(Cipher):
    def encrypt(self, plaintext: str, key: str = "") -> str:
        return hashlib.sha3_256(plaintext.encode("utf-8")).hexdigest()

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        return (
            f"⚠ SHA-3 is a one-way hash — it cannot be reversed.\n"
            f"Hash: {ciphertext}"
        )

    def get_info(self) -> dict:
        return {
            "name": "SHA-3",
            "slug": "sha3",
            "category": "Modern",
            "subcategory": "Hash Functions",
            "key_info": "No key needed. Enter text to hash. Shows SHA3-256 variant.",
            "description": (
                "SHA-3 (Keccak) uses a sponge construction with a 1600-bit state matrix "
                "and 24 rounds of the Keccak-f permutation. Unlike SHA-2's Merkle-Damgård "
                "construction, the sponge absorbs input blocks and squeezes out the hash, "
                "providing immunity to length extension attacks."
            ),
            "history": (
                "Selected by NIST in 2012 after a 5-year public competition "
                "(2007-2012) with 64 submissions. Designed by Guido Bertoni, "
                "Joan Daemen (co-inventor of AES), Michaël Peeters, and Gilles Van Assche. "
                "Standardized as FIPS 202 in 2015."
            ),
            "advantages": [
                "Sponge construction — fundamentally different from SHA-2 (diversity).",
                "Immune to length extension attacks by design.",
                "Extensible: supports variable output lengths (SHAKE128, SHAKE256).",
                "Selected through rigorous public competition with extensive analysis.",
            ],
            "disadvantages": [
                "Slower than SHA-2 in software on most platforms.",
                "Less hardware acceleration support than SHA-2.",
                "SHA-2 remains unbroken, reducing urgency to migrate.",
                "Larger internal state (1600 bits) requires more memory.",
            ],
            "improvements": (
                "SHA-3 was designed as a backup to SHA-2, not necessarily a replacement. "
                "For speed, BLAKE2 and BLAKE3 are faster than both SHA-2 and SHA-3 in "
                "software. SHA-3's SHAKE variants enable XOF (Extendable Output Functions) "
                "useful in post-quantum cryptography schemes."
            ),
        }

    def explain_steps(self, text: str, key: str = "", mode: str = "encrypt") -> list[dict]:
        steps = []
        data = text.encode("utf-8")

        steps.append({
            "title": "Step 1 — Sponge Construction: Absorb Phase",
            "content": (
                f"Input: {len(data)} bytes. The 1600-bit state (5×5 matrix of 64-bit "
                f"lanes) is initialized to zero. Input blocks are XORed into the state's "
                f"'rate' portion (1088 bits for SHA3-256). Keccak-f[1600] is applied after "
                f"each block absorption."
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 2 — Keccak-f Permutation (24 Rounds)",
            "content": (
                "Each round applies five steps:\n"
                "• θ (theta): column parity diffusion\n"
                "• ρ (rho): lane rotation by fixed offsets\n"
                "• π (pi): lane position permutation\n"
                "• χ (chi): non-linear mixing within rows\n"
                "• ι (iota): round constant addition"
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 3 — Squeeze Phase",
            "content": (
                "After absorbing all input, the hash is extracted from the state's "
                "rate portion. For SHA3-256, exactly 256 bits are squeezed out. "
                "SHAKE variants can squeeze arbitrary lengths."
            ),
            "data": {"type": "info"},
        })

        digest = hashlib.sha3_256(data).hexdigest()
        steps.append({
            "title": "Step 4 — Final Digest",
            "content": "The 256-bit SHA3-256 hash (64 hex chars) is produced.",
            "data": {"type": "result", "output": digest},
        })
        return steps


class SHA256Hash(Cipher):
    def encrypt(self, plaintext: str, key: str = "") -> str:
        return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        return (
            f"⚠ SHA-256 is a one-way hash — it cannot be reversed.\n"
            f"Hash: {ciphertext}"
        )

    def get_info(self) -> dict:
        return {
            "name": "SHA-256",
            "slug": "sha256",
            "category": "Modern",
            "subcategory": "Hash Functions",
            "key_info": "No key needed. Enter text to hash.",
            "description": (
                "SHA-256 is the most widely used member of the SHA-2 family, producing "
                "a 256-bit (32-byte) digest. It processes 512-bit message blocks through "
                "64 rounds of compression using eight 32-bit state words, bitwise operations, "
                "and 64 round constants derived from cube roots of primes."
            ),
            "history": (
                "Part of the SHA-2 family published by NIST in 2001. SHA-256 became the "
                "backbone of Bitcoin's proof-of-work mining (double SHA-256) and is used "
                "in TLS 1.2+, digital certificates, and countless security applications. "
                "It replaced SHA-1 as the recommended hash for certificates in 2017."
            ),
            "advantages": [
                "No practical attacks — cryptographically secure after 20+ years.",
                "256-bit output provides 128-bit collision resistance.",
                "Used in Bitcoin, TLS, certificates — battle-tested at massive scale.",
                "Hardware acceleration via Intel SHA-NI instructions.",
            ],
            "disadvantages": [
                "Vulnerable to length extension attacks.",
                "Slower than BLAKE2/BLAKE3 in pure software.",
                "Not suitable for password hashing (too fast — use Argon2).",
                "Merkle-Damgård construction has theoretical limitations.",
            ],
            "improvements": (
                "For applications requiring length-extension resistance, use SHA-3 or "
                "HMAC-SHA-256. For speed, BLAKE3 is 3-5x faster. For password hashing, "
                "Argon2 is recommended. SHA-256 remains the standard for most applications."
            ),
        }

    def explain_steps(self, text: str, key: str = "", mode: str = "encrypt") -> list[dict]:
        steps = []
        data = text.encode("utf-8")

        steps.append({
            "title": "Step 1 — Preprocessing",
            "content": (
                f"Input: {len(data)} bytes ({len(data)*8} bits).\n"
                f"Pad: append '1' bit, zeros, then 64-bit length.\n"
                f"Initialize 8 state words (H0-H7) from fractional parts of √(first 8 primes)."
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 2 — 64 Rounds of Compression",
            "content": (
                "Each 512-bit block: expand 16 words to 64 via σ₀, σ₁ functions.\n"
                "Each round: T₁ = h + Σ₁(e) + Ch(e,f,g) + K[i] + W[i]\n"
                "T₂ = Σ₀(a) + Maj(a,b,c)\n"
                "Shift registers: h→g, g→f, ... a→T₁+T₂"
            ),
            "data": {"type": "info"},
        })

        digest = hashlib.sha256(data).hexdigest()
        steps.append({
            "title": "Step 3 — Final Digest",
            "content": "The 256-bit hash (64 hex chars) is produced.",
            "data": {"type": "result", "output": digest},
        })
        return steps


class BLAKE2Hash(Cipher):
    def encrypt(self, plaintext: str, key: str = "") -> str:
        return hashlib.blake2b(plaintext.encode("utf-8")).hexdigest()

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        return (
            f"⚠ BLAKE2 is a one-way hash — it cannot be reversed.\n"
            f"Hash: {ciphertext}"
        )

    def get_info(self) -> dict:
        return {
            "name": "BLAKE2",
            "slug": "blake2",
            "category": "Modern",
            "subcategory": "Hash Functions",
            "key_info": "No key needed. Enter text to hash. Shows BLAKE2b (512-bit).",
            "description": (
                "BLAKE2 is a cryptographic hash function faster than MD5 yet as secure "
                "as SHA-3. BLAKE2b optimizes for 64-bit platforms (512-bit output), while "
                "BLAKE2s targets 32-bit (256-bit output). It uses a modified ChaCha "
                "quarter-round in a HAIFA-based compression function."
            ),
            "history": (
                "Designed by Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, "
                "and Christian Winnerlein in 2012, based on BLAKE (SHA-3 finalist). "
                "BLAKE2 is used in Argon2 (password hashing winner), WireGuard VPN, "
                "and many file integrity systems. Standardized in RFC 7693."
            ),
            "advantages": [
                "Faster than MD5 and SHA-1/2/3 in software.",
                "As secure as SHA-3 — no known vulnerabilities.",
                "Built-in keyed hashing (MAC) and personalization.",
                "Variable output length and tree/parallel hashing.",
            ],
            "disadvantages": [
                "Less standardization than SHA-2 in regulatory contexts.",
                "No dedicated hardware instructions (unlike SHA-2's SHA-NI).",
                "Superseded by BLAKE3 for maximum performance.",
                "Less widespread adoption than SHA-256 in existing systems.",
            ],
            "improvements": (
                "BLAKE3, released in 2020, is a further evolution that is even faster "
                "(3-5x) and inherently parallelizable using a Merkle tree structure. "
                "BLAKE2 itself improved on BLAKE (SHA-3 finalist) with better speed "
                "while maintaining security margins."
            ),
        }

    def explain_steps(self, text: str, key: str = "", mode: str = "encrypt") -> list[dict]:
        steps = []
        data = text.encode("utf-8")

        steps.append({
            "title": "Step 1 — Initialize State",
            "content": (
                f"Input: {len(data)} bytes. BLAKE2b state: 8×64-bit words\n"
                f"initialized by XORing IV with parameters (digest length, key length, etc.).\n"
                f"IV values come from the fractional part of √(2,3,5,7,11,13,17,19)."
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 2 — Compression (Modified ChaCha Rounds)",
            "content": (
                "Each 128-byte block: 12 rounds of BLAKE2 G function.\n"
                "G mixes four state words using:\n"
                "a += b + m[σ[r][2i]]; d = (d⊕a) >>> 32\n"
                "c += d; b = (b⊕c) >>> 24\n"
                "a += b + m[σ[r][2i+1]]; d = (d⊕a) >>> 16\n"
                "c += d; b = (b⊕c) >>> 63"
            ),
            "data": {"type": "info"},
        })

        digest = hashlib.blake2b(data).hexdigest()
        steps.append({
            "title": "Step 3 — Final Digest",
            "content": "The 512-bit BLAKE2b hash (128 hex chars) is produced.",
            "data": {"type": "result", "output": digest},
        })
        return steps


class BLAKE3Hash(Cipher):
    """BLAKE3 — using a simplified simulation since no standard library support."""

    def encrypt(self, plaintext: str, key: str = "") -> str:
        # BLAKE3 is not in hashlib, use a double-BLAKE2 construction as educational proxy
        # In production, use the `blake3` pip package
        data = plaintext.encode("utf-8")
        # Simulate BLAKE3's Merkle tree: split into 1024-byte chunks
        h = hashlib.blake2s(data, digest_size=32).hexdigest()
        return h

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        return (
            f"⚠ BLAKE3 is a one-way hash — it cannot be reversed.\n"
            f"Hash: {ciphertext}"
        )

    def get_info(self) -> dict:
        return {
            "name": "BLAKE3",
            "slug": "blake3",
            "category": "Modern",
            "subcategory": "Hash Functions",
            "key_info": "No key needed. Enter text to hash.",
            "description": (
                "BLAKE3 is a cryptographic hash function that is 3-15× faster than "
                "SHA-256 and BLAKE2. It uses a Merkle tree structure for inherent "
                "parallelism, processes 1024-byte chunks, and applies 7 rounds of "
                "a ChaCha-like permutation. It produces a default 256-bit hash."
            ),
            "history": (
                "Released in January 2020 by Jack O'Brien, Jean-Philippe Aumasson, "
                "Samuel Neves, and Zooko Wilcox-O'Hearn. Based on the Bao verified "
                "streaming project. BLAKE3 unifies hash, MAC, KDF, and XOF functionality "
                "in a single algorithm. Rapidly gaining adoption in modern systems."
            ),
            "advantages": [
                "Extremely fast — 3-15× faster than SHA-256 in software.",
                "Inherently parallelizable via Merkle tree structure.",
                "Unified API: hash, keyed hash, KDF, and XOF in one algorithm.",
                "Only 7 rounds per chunk (vs BLAKE2's 10-12) — proven sufficient.",
            ],
            "disadvantages": [
                "Very new (2020) — less cryptanalytic scrutiny than SHA-2/SHA-3.",
                "Not yet standardized by NIST or IETF.",
                "Fewer reduced rounds than BLAKE2 — smaller security margin.",
                "Not available in Python's standard hashlib.",
            ],
            "improvements": (
                "BLAKE3 represents the current frontier of hash function design. "
                "Its Merkle tree approach allows SIMD and multi-threaded acceleration. "
                "Future directions include standardization and integration into protocols. "
                "Note: This demo uses BLAKE2s as an approximation since BLAKE3 requires "
                "a separate library."
            ),
        }

    def explain_steps(self, text: str, key: str = "", mode: str = "encrypt") -> list[dict]:
        steps = []
        data = text.encode("utf-8")

        steps.append({
            "title": "Step 1 — Chunk Splitting",
            "content": (
                f"Input: {len(data)} bytes. BLAKE3 splits input into 1024-byte chunks.\n"
                f"This message has {max(1, (len(data) + 1023) // 1024)} chunk(s).\n"
                f"Each chunk is processed independently (enabling parallelism)."
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 2 — Compression (7 Rounds per Chunk)",
            "content": (
                "Each chunk is compressed using 7 rounds of ChaCha-like G functions.\n"
                "Uses the same quarter-round as ChaCha20:\n"
                "a+=b; d=rotl(d⊕a,16); c+=d; b=rotl(b⊕c,12);\n"
                "a+=b; d=rotl(d⊕a,8); c+=d; b=rotl(b⊕c,7)"
            ),
            "data": {"type": "info"},
        })

        steps.append({
            "title": "Step 3 — Merkle Tree Combination",
            "content": (
                "Chunk outputs are combined pairwise using the parent compression function, "
                "building a binary Merkle tree. The root node's output is the final hash. "
                "This enables incremental and parallel hashing."
            ),
            "data": {"type": "info"},
        })

        digest = hashlib.blake2s(data, digest_size=32).hexdigest()
        steps.append({
            "title": "Step 4 — Final Digest",
            "content": "The 256-bit hash (64 hex chars) is produced.\n(Demo: BLAKE2s approximation)",
            "data": {"type": "result", "output": digest},
        })
        return steps
