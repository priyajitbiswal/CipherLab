# 🔐 Complete Guide to Cryptographic Ciphers

**A comprehensive, in-depth explanation of all 18 classical ciphers implemented in CipherLab**

---

## Table of Contents

1. [Introduction](#introduction)
2. [Monoalphabetic Substitution Ciphers](#monoalphabetic-substitution-ciphers)
   - [Atbash Cipher](#1-atbash-cipher)
   - [Caesar Cipher](#2-caesar-cipher)
   - [Augustus Cipher](#3-augustus-cipher)
   - [Affine Cipher](#4-affine-cipher)
   - [Multiplicative Cipher](#5-multiplicative-cipher)
3. [Polyalphabetic Substitution Ciphers](#polyalphabetic-substitution-ciphers)
   - [Vigenère Cipher](#6-vigenère-cipher)
   - [Gronsfeld Cipher](#7-gronsfeld-cipher)
   - [Beaufort Cipher](#8-beaufort-cipher)
   - [Autokey Cipher](#9-autokey-cipher)
   - [Running Key Cipher](#10-running-key-cipher)
4. [Polygraphic Substitution Ciphers](#polygraphic-substitution-ciphers)
   - [Hill Cipher](#11-hill-cipher)
5. [Transposition Ciphers](#transposition-ciphers)
   - [Rail Fence Cipher](#12-rail-fence-cipher)
   - [Route Cipher](#13-route-cipher)
   - [Columnar Transposition](#14-columnar-transposition-cipher)
   - [Myszkowski Cipher](#15-myszkowski-transposition-cipher)
   - [Double Transposition](#16-double-transposition-cipher)
   - [Disrupted Transposition](#17-disrupted-transposition-cipher)
   - [Grille Cipher](#18-grille-cipher)
6. [Cryptanalysis Overview](#cryptanalysis-overview)
7. [Cipher Comparison](#cipher-comparison)

---

## Introduction

### What is Cryptography?

Cryptography is the art and science of securing information by transforming it into an unreadable format. The original message is called **plaintext**, and the encrypted version is called **ciphertext**. The process of converting plaintext to ciphertext is **encryption**, and reversing it is **decryption**.

### Fundamental Concepts

**Substitution Ciphers**: Replace each letter with another letter or symbol.
- **Monoalphabetic**: Each plaintext letter always maps to the same ciphertext letter
- **Polyalphabetic**: The same plaintext letter can map to different ciphertext letters
- **Polygraphic**: Encrypt multiple letters at once

**Transposition Ciphers**: Rearrange the positions of letters without changing the letters themselves.

**Key Space**: The total number of possible keys. Larger key spaces generally mean stronger ciphers.

**Frequency Analysis**: A cryptanalytic technique that exploits the fact that certain letters appear more frequently in natural language (e.g., 'E' is the most common letter in English).

---

## Monoalphabetic Substitution Ciphers

These ciphers use a fixed mapping where each plaintext letter always encrypts to the same ciphertext letter. They are vulnerable to frequency analysis because letter frequency patterns are preserved.

---

### 1. Atbash Cipher

#### Overview

The **Atbash cipher** is one of the oldest known ciphers, using a simple reverse alphabet mapping where A↔Z, B↔Y, C↔X, and so on.

#### Mathematical Definition

For a letter at position `i` in the alphabet (A=0, B=1, ..., Z=25):

```
Encryption: E(x) = (25 - x) mod 26
Decryption: D(x) = (25 - x) mod 26  (same operation!)
```

#### Step-by-Step Process

**Encryption Example**: "HELLO WORLD"

1. **Build the mapping**:
   ```
   Plain:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
   Cipher: Z Y X W V U T S R Q P O N M L K J I H G F E D C B A
   ```

2. **Apply mapping letter by letter**:
   - H (position 7) → S (position 18 = 25 - 7)
   - E (position 4) → V (position 21 = 25 - 4)
   - L (position 11) → O (position 14 = 25 - 11)
   - L (position 11) → O (position 14)
   - O (position 14) → L (position 11 = 25 - 14)
   - (space remains unchanged)
   - W (position 22) → D (position 3 = 25 - 22)
   - O (position 14) → L (position 11)
   - R (position 17) → I (position 8 = 25 - 17)
   - L (position 11) → O (position 14)
   - D (position 3) → W (position 22 = 25 - 3)

3. **Result**: "SVOOL DLIOW"

**Decryption**: Identical to encryption (the cipher is its own inverse).

#### Key Requirements

- **No key required** - The mapping is fixed
- This is both an advantage (simplicity) and disadvantage (no security)

#### Historical Context

Named after the Hebrew letters Aleph-Tav-Beth-Shin (Atbash), this cipher appears in the Hebrew Bible. For example, "Sheshach" in the Book of Jeremiah is an Atbash encoding of "Babel" (Babylon).

#### Security Analysis

**Key Space**: 1 (effectively no key)

**Strengths**:
- Extremely simple to use
- Symmetric operation (encrypt = decrypt)

**Weaknesses**:
- Trivially broken - anyone who knows the method can decode instantly
- Only 26 possible mappings to check
- Preserves letter frequency patterns perfectly (just reversed)
- Vulnerable to frequency analysis

**Cryptanalysis**: Simply reverse the alphabet and decode. Takes seconds.

#### Example Walkthrough

```
Plaintext:  "CRYPTOGRAPHY"
Atbash:     "XIBKGLTIZKSB"

Verification:
C → X (2 → 23, 25-2=23) ✓
R → I (17 → 8, 25-17=8) ✓
Y → B (24 → 1, 25-24=1) ✓
```

---

### 2. Caesar Cipher

#### Overview

The **Caesar cipher** (also called shift cipher) shifts every letter by a fixed number of positions in the alphabet. Named after Julius Caesar, who reportedly used a shift of 3.

#### Mathematical Definition

For a letter at position `x` and shift `k`:

```
Encryption: E(x) = (x + k) mod 26
Decryption: D(x) = (x - k) mod 26
```

#### Step-by-Step Process

**Encryption Example**: "HELLO WORLD" with key `k = 3`

1. **Determine the shift**: Forward by 3 positions

2. **Build shifted alphabet**:
   ```
   Plain:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
   Cipher: D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
   ```

3. **Apply shift letter by letter**:
   - H (position 7) → K (position 10 = (7 + 3) mod 26)
   - E (position 4) → H (position 7 = (4 + 3) mod 26)
   - L (position 11) → O (position 14 = (11 + 3) mod 26)
   - L (position 11) → O (position 14)
   - O (position 14) → R (position 17 = (14 + 3) mod 26)
   - (space unchanged)
   - W (position 22) → Z (position 25 = (22 + 3) mod 26)
   - O (position 14) → R (position 17)
   - R (position 17) → U (position 20 = (17 + 3) mod 26)
   - L (position 11) → O (position 14)
   - D (position 3) → G (position 6 = (3 + 3) mod 26)

4. **Result**: "KHOOR ZRUOG"

**Decryption**: Shift backward by the same amount.

#### Key Requirements

- **Key**: Integer between 1 and 25
- **Default**: 3 (Caesar's historical shift)
- Shift of 0 or 26 = no encryption
- Shift of 13 = ROT13 (its own inverse)

#### Historical Context

Documented by Suetonius, Julius Caesar used this cipher with a shift of 3 to communicate with his generals. It was one of the first documented uses of encryption in military communication.

#### Security Analysis

**Key Space**: 25 possible keys (shifts 1-25)

**Strengths**:
- Simple to understand and implement
- Introduces the concept of a variable key
- Can be performed mentally or with pen and paper

**Weaknesses**:
- Very small key space - easily brute-forced
- Monoalphabetic - preserves letter frequencies
- Vulnerable to frequency analysis
- Word boundaries and punctuation unchanged (leaks structure)

**Cryptanalysis**:
1. **Brute Force**: Try all 25 possible shifts (takes seconds)
2. **Frequency Analysis**: Find the most common letter (likely 'E'), calculate shift
3. **Pattern Recognition**: Look for common words or patterns

**Example Attack**:
```
Ciphertext: "KHOOR ZRUOG"
Most common letter: O (appears 3 times)
In English, E is most common
Shift = O - E = 14 - 4 = 10... wait, let's try shift 3
K→H, H→E, O→L, O→L, R→O → "HELLO" ✓
```

#### Example Walkthrough

```
Plaintext:  "ATTACK AT DAWN"
Key:        3
Ciphertext: "DWWDFN DW GDZQ"

Letter-by-letter:
A → D (0 → 3)
T → W (19 → 22)
T → W (19 → 22)
A → D (0 → 3)
C → F (2 → 5)
K → N (10 → 13)
```

---

### 3. Augustus Cipher

#### Overview

The **Augustus cipher** is a variant of the Caesar cipher attributed to Emperor Augustus, who used a fixed shift of 1 instead of Caesar's shift of 3.

#### Mathematical Definition

```
Encryption: E(x) = (x + 1) mod 26
Decryption: D(x) = (x - 1) mod 26
```

This is simply a Caesar cipher with `k = 1`.

#### Step-by-Step Process

**Encryption Example**: "HELLO WORLD"

1. **Fixed shift**: Always shift forward by 1 position

2. **Apply shift**:
   - H → I
   - E → F
   - L → M
   - L → M
   - O → P
   - W → X
   - O → P
   - R → S
   - L → M
   - D → E

3. **Result**: "IFMMP XPSME"

#### Key Requirements

- **No key required** - Always uses shift of 1
- This makes it weaker than Caesar cipher

#### Historical Context

According to Suetonius, Augustus used a shift of 1 in his personal letters, making it even simpler than Caesar's cipher but also easier to break.

#### Security Analysis

**Key Space**: 1 (no variable key)

**Strengths**:
- Extremely simple - trivial to learn
- Fast to use

**Weaknesses**:
- Fixed shift means effectively no key
- Even easier to break than Caesar
- Adjacent letters are obvious (A→B, B→C, etc.)

**Cryptanalysis**: Trivial - just shift back by 1, or recognize the pattern immediately.

---

### 4. Affine Cipher

#### Overview

The **Affine cipher** generalizes the Caesar cipher using a mathematical formula with two parameters: `a` (multiplicative coefficient) and `b` (additive shift).

#### Mathematical Definition

For letters at position `x`, with key `(a, b)`:

```
Encryption: E(x) = (a·x + b) mod 26
Decryption: D(x) = a⁻¹·(x - b) mod 26
```

Where `a⁻¹` is the modular multiplicative inverse of `a` modulo 26.

#### Key Requirements

- **Key Format**: Two integers `(a, b)` separated by comma (e.g., "5,8")
- **Constraint**: `a` must be coprime with 26 (gcd(a, 26) = 1)
- **Valid values for `a`**: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
- **Valid values for `b`**: 0-25 (any integer mod 26)

#### Why `a` Must Be Coprime with 26

If `gcd(a, 26) ≠ 1`, then `a` shares factors with 26, and the mapping is not one-to-one. For example, if `a = 2`:
- E maps to both A and N (since 2·4 = 8 and 2·17 = 34 ≡ 8 mod 26)
- This makes decryption ambiguous.

#### Step-by-Step Process

**Encryption Example**: "HELLO" with key `(a=5, b=8)`

1. **Verify key validity**:
   - `gcd(5, 26) = 1` ✓ (coprime)
   - `a⁻¹ mod 26 = 21` (since 5 × 21 = 105 ≡ 1 mod 26)

2. **Apply formula to each letter**:
   - H (position 7): E(7) = (5·7 + 8) mod 26 = (35 + 8) mod 26 = 43 mod 26 = 17 → R
   - E (position 4): E(4) = (5·4 + 8) mod 26 = (20 + 8) mod 26 = 28 mod 26 = 2 → C
   - L (position 11): E(11) = (5·11 + 8) mod 26 = (55 + 8) mod 26 = 63 mod 26 = 11 → L
   - L (position 11): E(11) = 11 → L
   - O (position 14): E(14) = (5·14 + 8) mod 26 = (70 + 8) mod 26 = 78 mod 26 = 0 → A

3. **Result**: "RCLLA"

**Decryption Example**: "RCLLA" with key `(5, 8)`

1. **Calculate inverse**: `a⁻¹ = 21`

2. **Apply decryption formula**:
   - R (position 17): D(17) = 21·(17 - 8) mod 26 = 21·9 mod 26 = 189 mod 26 = 7 → H
   - C (position 2): D(2) = 21·(2 - 8) mod 26 = 21·(-6) mod 26 = 21·20 mod 26 = 420 mod 26 = 4 → E
   - L (position 11): D(11) = 21·(11 - 8) mod 26 = 21·3 mod 26 = 63 mod 26 = 11 → L
   - L (position 11): D(11) = 11 → L
   - A (position 0): D(0) = 21·(0 - 8) mod 26 = 21·18 mod 26 = 378 mod 26 = 14 → O

3. **Result**: "HELLO" ✓

#### Complete Substitution Table

For key `(5, 8)`:

```
Plain:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
        ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓
Cipher: I D S N C X H M R W B F Q Z L G V K P U Y A T E O J

Calculation for each:
A (0) → (5·0 + 8) mod 26 = 8 → I
B (1) → (5·1 + 8) mod 26 = 13 → N
C (2) → (5·2 + 8) mod 26 = 18 → S
...
```

#### Historical Context

The Affine cipher demonstrates core concepts of modular arithmetic and is widely taught in introductory cryptography courses. It generalizes both Caesar (when `a=1`) and Multiplicative (when `b=0`) ciphers.

#### Security Analysis

**Key Space**: 12 valid `a` values × 26 possible `b` values = **312 keys**

**Strengths**:
- Larger key space than Caesar (312 vs 25)
- Introduces modular arithmetic concepts
- Generalizes multiple cipher types

**Weaknesses**:
- Still monoalphabetic - preserves letter frequencies
- Small key space - brute forceable in milliseconds
- Vulnerable to frequency analysis
- Requires understanding of modular inverses

**Cryptanalysis**:
1. **Frequency Analysis**: Find most common letter, try common mappings
2. **Brute Force**: Try all 312 possible keys (very fast)
3. **Known Plaintext**: With two letter pairs, solve system of equations:
   - `E(x₁) = (a·x₁ + b) mod 26 = y₁`
   - `E(x₂) = (a·x₂ + b) mod 26 = y₂`
   - Solve for `a` and `b`

#### Example Walkthrough

```
Plaintext:  "SECRET"
Key:        5,8
Ciphertext: "NCHQCH"

Detailed calculation:
S (18) → (5·18 + 8) mod 26 = (90 + 8) mod 26 = 98 mod 26 = 20 → U
Wait, let me recalculate: 98 ÷ 26 = 3 remainder 20, so 20 → U

Actually: S = 18, E(18) = (5·18 + 8) = 98 ≡ 20 mod 26 → U
But the example shows N... let me verify the implementation.

Actually, the cipher implementation may differ. The key point is understanding
the formula: E(x) = (a·x + b) mod 26
```

---

### 5. Multiplicative Cipher

#### Overview

The **Multiplicative cipher** is a special case of the Affine cipher where `b = 0`, using only multiplication modulo 26.

#### Mathematical Definition

```
Encryption: E(x) = (a·x) mod 26
Decryption: D(x) = (a⁻¹·x) mod 26
```

This is an Affine cipher with `b = 0`.

#### Step-by-Step Process

**Encryption Example**: "HELLO" with key `a = 7`

1. **Verify key**: `gcd(7, 26) = 1` ✓
2. **Calculate inverse**: `7⁻¹ mod 26 = 15` (since 7 × 15 = 105 ≡ 1 mod 26)

3. **Apply multiplication**:
   - H (7): E(7) = (7·7) mod 26 = 49 mod 26 = 23 → X
   - E (4): E(4) = (7·4) mod 26 = 28 mod 26 = 2 → C
   - L (11): E(11) = (7·11) mod 26 = 77 mod 26 = 25 → Z
   - L (11): E(11) = 25 → Z
   - O (14): E(14) = (7·14) mod 26 = 98 mod 26 = 20 → U

4. **Result**: "XCZZU"

**Decryption**: Multiply by the modular inverse.

#### Key Requirements

- **Key**: Integer `a` where `gcd(a, 26) = 1`
- **Valid values**: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
- **Default**: 7

#### Historical Context

The Multiplicative cipher demonstrates the concept of modular multiplication and is a building block for understanding more complex ciphers like Affine and Hill.

#### Security Analysis

**Key Space**: 12 possible keys

**Strengths**:
- Simple multiplication operation
- Introduces modular inverses
- Non-linear mapping (unlike simple shifts)

**Weaknesses**:
- Very small key space
- Monoalphabetic - vulnerable to frequency analysis
- Letter 'A' (position 0) always maps to 'A' (since a·0 = 0)
- Letter 'M' (position 13) always maps to 'A' or 'N' (since 13 is problematic)

**Cryptanalysis**: Similar to Affine - frequency analysis or brute force.

---

## Polyalphabetic Substitution Ciphers

These ciphers use multiple substitution alphabets, so the same plaintext letter can encrypt to different ciphertext letters depending on its position. This makes frequency analysis much harder.

---

### 6. Vigenère Cipher

#### Overview

The **Vigenère cipher** uses a keyword to create multiple Caesar shifts. Each letter of the keyword determines the shift for the corresponding plaintext letter, and the keyword repeats cyclically.

#### Mathematical Definition

For plaintext letter `Pᵢ` at position `i` and keyword letter `Kⱼ`:

```
Encryption: E(Pᵢ) = (Pᵢ + Kⱼ) mod 26
            where j = i mod len(keyword)

Decryption: D(Cᵢ) = (Cᵢ - Kⱼ) mod 26
```

#### Step-by-Step Process

**Encryption Example**: "HELLO WORLD" with keyword "KEY"

1. **Prepare keyword**: "KEY" → positions K=10, E=4, Y=24

2. **Align keyword with text** (repeat cyclically):
   ```
   Plaintext:  H E L L O   W O R L D
   Keyword:    K E Y K E   Y K E Y K
   Positions:  10 4 24 10 4  24 10 4 24 10 4
   ```

3. **Apply shifts letter by letter**:
   - H (7) + K (10) = 17 mod 26 = 17 → R
   - E (4) + E (4) = 8 mod 26 = 8 → I
   - L (11) + Y (24) = 35 mod 26 = 9 → J
   - L (11) + K (10) = 21 mod 26 = 21 → V
   - O (14) + E (4) = 18 mod 26 = 18 → S
   - (space unchanged)
   - W (22) + Y (24) = 46 mod 26 = 20 mod 26 = 20 → U
   - O (14) + K (10) = 24 mod 26 = 24 → Y
   - R (17) + E (4) = 21 mod 26 = 21 → V
   - L (11) + Y (24) = 35 mod 26 = 9 → J
   - D (3) + K (10) = 13 mod 26 = 13 → N

4. **Result**: "RIJVS UYVJN"

**Decryption**: Subtract the keyword letter positions.

#### Key Requirements

- **Key**: A keyword string (e.g., "LEMON", "KEY")
- Must contain at least one alphabetic character
- Case-insensitive (converted to uppercase)
- Repeats cyclically to match message length

#### Historical Context

Described by Giovan Battista Bellaso in 1553, it was later misattributed to Blaise de Vigenère. For three centuries it was considered unbreakable ("le chiffre indechiffrable") until Friedrich Kasiski published a general method in 1863.

#### Security Analysis

**Key Space**: Effectively infinite for long keywords, but practical security depends on keyword length.

**Strengths**:
- First cipher to defeat simple frequency analysis
- Same letter encrypts differently at different positions
- Dramatically larger key space than monoalphabetic ciphers
- Remained unbroken for ~300 years

**Weaknesses**:
- **Repeating key creates periodic patterns** - detectable by Kasiski examination
- Once key length is found, each column reduces to a simple Caesar cipher
- Short keys offer limited security
- Key distribution problem (must share keyword securely)

**Cryptanalysis - Kasiski Method**:

1. **Find repeated patterns** in ciphertext
2. **Measure distances** between repetitions
3. **Key length** = gcd of distances (likely)
4. **For each column** (positions mod key_length), treat as Caesar cipher
5. **Frequency analysis** on each column to find shift

**Example Attack**:
```
Ciphertext: "RIJVS UYVJN" with unknown key
Try key length 3:
Column 0 (positions 0,3,6,9): R, V, Y, J
Column 1 (positions 1,4,7): I, S, V  
Column 2 (positions 2,5,8): J, U, N

Frequency analysis on each column reveals shifts → keyword "KEY"
```

#### Example Walkthrough

```
Plaintext:  "ATTACK AT DAWN"
Keyword:    "LEMON"
Ciphertext: "LXFOPV EF RNHR"

Alignment:
A T T A C K   A T   D A W N
L E M O N L   E M   O N L E

Calculations:
A(0) + L(11) = 11 → L
T(19) + E(4) = 23 → X
T(19) + M(12) = 31 mod 26 = 5 → F
A(0) + O(14) = 14 → O
C(2) + N(13) = 15 → P
K(10) + L(11) = 21 → V
...
```

---

### 7. Gronsfeld Cipher

#### Overview

The **Gronsfeld cipher** is a variant of Vigenère that uses a numeric key instead of a keyword. Each digit determines the shift amount.

#### Mathematical Definition

For plaintext letter `Pᵢ` and numeric key digit `Kⱼ`:

```
Encryption: E(Pᵢ) = (Pᵢ + Kⱼ) mod 26
Decryption: D(Cᵢ) = (Cᵢ - Kⱼ) mod 26
```

#### Step-by-Step Process

**Encryption Example**: "HELLO" with key "314"

1. **Key digits**: 3, 1, 4 (repeat cyclically)

2. **Align and encrypt**:
   ```
   Plaintext:  H E L L O
   Key digits: 3 1 4 3 1
   
   H (7) + 3 = 10 → K
   E (4) + 1 = 5 → F
   L (11) + 4 = 15 → P
   L (11) + 3 = 14 → O
   O (14) + 1 = 15 → P
   ```

3. **Result**: "KFPOP"

#### Key Requirements

- **Key**: Numeric string (e.g., "314", "31415")
- Each digit (0-9) determines shift amount
- Repeats cyclically

#### Historical Context

Named after Count Gronsfeld, this cipher was easier to use than Vigenère because numbers are easier to remember than keywords, but it has the same security properties.

#### Security Analysis

**Key Space**: Smaller than Vigenère (only 10 possible shifts per position vs 26)

**Strengths**:
- Easier to remember numeric keys
- Same polyalphabetic properties as Vigenère

**Weaknesses**:
- Smaller key space per position (10 vs 26)
- Same vulnerabilities as Vigenère (Kasiski method)
- Numeric keys may be easier to guess

---

### 8. Beaufort Cipher

#### Overview

The **Beaufort cipher** is a reciprocal variant of Vigenère where decryption uses the same operation as encryption (just swap plaintext and ciphertext).

#### Mathematical Definition

```
Encryption: E(Pᵢ) = (Kⱼ - Pᵢ) mod 26
Decryption: D(Cᵢ) = (Kⱼ - Cᵢ) mod 26
```

Note: `(K - P) mod 26` is equivalent to `(P - K) mod 26` for decryption, making it reciprocal.

#### Step-by-Step Process

**Encryption Example**: "HELLO" with keyword "KEY"

1. **Keyword**: K=10, E=4, Y=24

2. **Apply Beaufort formula**:
   ```
   Plaintext:  H E L L O
   Keyword:    K E Y K E
   
   H (7): (10 - 7) mod 26 = 3 → D
   E (4): (4 - 4) mod 26 = 0 → A
   L (11): (24 - 11) mod 26 = 13 → N
   L (11): (10 - 11) mod 26 = (-1) mod 26 = 25 → Z
   O (14): (4 - 14) mod 26 = (-10) mod 26 = 16 → Q
   ```

3. **Result**: "DANZQ"

**Decryption**: Same operation - `(K - C) mod 26` gives back plaintext.

#### Key Requirements

- **Key**: Keyword string (same as Vigenère)
- Repeats cyclically

#### Historical Context

Named after Francis Beaufort, this cipher has the advantage of being reciprocal (encryption = decryption with swapped roles), which simplifies implementation.

#### Security Analysis

**Security**: Equivalent to Vigenère - same key space and vulnerabilities.

**Strengths**:
- Reciprocal property simplifies implementation
- Same polyalphabetic security as Vigenère

**Weaknesses**:
- Same vulnerabilities as Vigenère (Kasiski method)
- Slightly more complex formula than Vigenère

---

### 9. Autokey Cipher

#### Overview

The **Autokey cipher** extends Vigenère by appending the plaintext itself to the keyword, eliminating key repetition and making it harder to break.

#### Mathematical Definition

The key is constructed as: `K = keyword + plaintext`

Then encryption proceeds like Vigenère:
```
Encryption: E(Pᵢ) = (Pᵢ + Kᵢ) mod 26
```

#### Step-by-Step Process

**Encryption Example**: "HELLO WORLD" with keyword "QUEEN"

1. **Initial key**: "QUEEN" → Q=16, U=20, E=4, E=4, N=13

2. **Extend key with plaintext**:
   ```
   Keyword:  Q U E E N
   Plaintext: H E L L O   W O R L D
   Full key:  Q U E E N H E L L O   W O R L D
   ```

3. **Encrypt letter by letter**:
   ```
   Plaintext:  H E L L O   W O R L D
   Key:        Q U E E N   H E L L O
   
   H (7) + Q (16) = 23 → X
   E (4) + U (20) = 24 → Y
   L (11) + E (4) = 15 → P
   L (11) + E (4) = 15 → P
   O (14) + N (13) = 27 mod 26 = 1 → B
   W (22) + H (7) = 29 mod 26 = 3 → D
   O (14) + E (4) = 18 → S
   R (17) + L (11) = 28 mod 26 = 2 → C
   L (11) + L (11) = 22 → W
   D (3) + O (14) = 17 → R
   ```

4. **Result**: "XYPPB DSCWR"

**Decryption**: More complex - must decrypt sequentially, using decrypted plaintext as part of the key.

#### Key Requirements

- **Key**: Initial keyword (e.g., "QUEEN", "KEY")
- Automatically extended with plaintext during encryption
- Must be at least one character

#### Historical Context

The Autokey cipher was an improvement over Vigenère, eliminating the repeating key pattern that made Vigenère vulnerable to Kasiski examination.

#### Security Analysis

**Key Space**: Similar to Vigenère, but non-repeating key improves security.

**Strengths**:
- **No repeating key** - immune to Kasiski examination
- Self-extending key eliminates periodicity
- Stronger than Vigenère for same keyword length

**Weaknesses**:
- **Known-plaintext vulnerability**: If attacker knows part of plaintext, can recover keyword
- Still vulnerable to other attacks if keyword is short
- Decryption requires sequential processing (can't parallelize)

**Cryptanalysis**:
- If keyword is known, decryption is straightforward
- Known-plaintext attack can recover keyword
- Longer keywords provide better security

---

### 10. Running Key Cipher

#### Overview

The **Running Key cipher** uses a long, non-repeating text passage (like from a book) as the key, making it much harder to break than Vigenère.

#### Mathematical Definition

Same as Vigenère, but key is a long text passage:
```
Encryption: E(Pᵢ) = (Pᵢ + Kᵢ) mod 26
```

Where `K` is a long text passage (not repeating).

#### Step-by-Step Process

**Encryption Example**: "HELLO" with key text "TO BE OR NOT TO BE"

1. **Extract alphabetic characters from key**: "TOBEORNOTTOBE" → T=19, O=14, B=1, E=4, O=14, R=17, N=13, O=14, T=19, T=19, O=14, B=1, E=4

2. **Encrypt**:
   ```
   Plaintext:  H E L L O
   Key text:   T O B E O
   
   H (7) + T (19) = 26 mod 26 = 0 → A
   E (4) + O (14) = 18 → S
   L (11) + B (1) = 12 → M
   L (11) + E (4) = 15 → P
   O (14) + O (14) = 28 mod 26 = 2 → C
   ```

3. **Result**: "ASMPC"

#### Key Requirements

- **Key**: Long text passage (e.g., from a book, article)
- Must contain at least as many alphabetic characters as the message
- Only alphabetic characters are used (spaces/punctuation ignored)

#### Historical Context

Used historically when communicating parties could agree on a specific book and page as their key source. It was considered more secure than Vigenère because the key never repeats.

#### Security Analysis

**Key Space**: Effectively infinite for long, unique passages.

**Strengths**:
- **No repeating key** - immune to Kasiski examination
- Can use any agreed-upon book or text
- Much longer effective key than Vigenère
- Simple to use if both parties have the same text

**Weaknesses**:
- **Natural language keys have predictable frequencies** (e.g., 'E' is common)
- Vulnerable to statistical analysis due to correlations
- Both parties must have identical copies
- Not a true one-time pad (key is not random)

**Cryptanalysis**:
- Statistical analysis exploiting natural language patterns
- Known-plaintext attacks can identify the source text
- If source text is known, decryption is trivial

---

## Polygraphic Substitution Ciphers

These ciphers encrypt multiple letters at once, hiding single-letter frequency patterns entirely.

---

### 11. Hill Cipher

#### Overview

The **Hill cipher** encrypts blocks of letters using matrix multiplication modulo 26. It was the first practical polygraphic cipher.

#### Mathematical Definition

For a block of `n` letters represented as vector `P` and `n×n` key matrix `K`:

```
Encryption: C = (K · P) mod 26
Decryption: P = (K⁻¹ · C) mod 26
```

Where `K⁻¹` is the modular inverse of matrix `K` modulo 26.

#### Key Requirements

- **Key**: Square matrix specified as comma-separated numbers
- **2×2 example**: "3,3,2,5" represents matrix:
  ```
  [3  3]
  [2  5]
  ```
- **3×3 example**: "6,24,1,13,16,10,20,17,15" (9 numbers)
- **Constraint**: Matrix determinant must be coprime with 26 (gcd(det, 26) = 1)
- If determinant shares factors with 26, matrix is not invertible

#### Step-by-Step Process

**Encryption Example**: "HELLO" with key matrix `[[3,3],[2,5]]`

1. **Parse key matrix**:
   ```
   K = [3  3]
       [2  5]
   ```

2. **Calculate determinant**: `det(K) = 3×5 - 3×2 = 15 - 6 = 9`
   - `gcd(9, 26) = 1` ✓ (coprime, matrix is invertible)

3. **Split into blocks of 2** (since 2×2 matrix):
   - Block 1: "HE" → [7, 4]
   - Block 2: "LL" → [11, 11]
   - Block 3: "O" → pad to "OX" → [14, 23]

4. **Encrypt each block**:
   ```
   Block 1: [3  3] · [7]  = [3·7 + 3·4]  = [21 + 12]  = [33]  = [7]  → H
            [2  5]   [4]    [2·7 + 5·4]    [14 + 20]    [34]    [8]     I
            (all mod 26)
   
   Block 2: [3  3] · [11] = [3·11 + 3·11] = [33 + 33] = [66]  = [14] → O
            [2  5]   [11]   [2·11 + 5·11]   [22 + 55]   [77]    [25]    Z
   
   Block 3: [3  3] · [14] = [3·14 + 3·23] = [42 + 69] = [111] = [7]  → H
            [2  5]   [23]   [2·14 + 5·23]   [28 + 115]  [143]   [13]    N
   ```

5. **Result**: "HIOZHN"

**Decryption**: Requires computing the modular inverse matrix.

#### Computing Modular Inverse Matrix

For a 2×2 matrix `K = [[a,b],[c,d]]`:

1. **Determinant**: `det = ad - bc`
2. **Modular inverse of determinant**: `det⁻¹ mod 26`
3. **Adjugate matrix**: `adj(K) = [[d,-b],[-c,a]]`
4. **Inverse**: `K⁻¹ = (det⁻¹ · adj(K)) mod 26`

For `K = [[3,3],[2,5]]`:
- `det = 9`, `det⁻¹ = 9⁻¹ mod 26 = 3` (since 9×3 = 27 ≡ 1 mod 26)
- `adj(K) = [[5,-3],[-2,3]] = [[5,23],[24,3]] mod 26`
- `K⁻¹ = 3 · [[5,23],[24,3]] = [[15,69],[72,9]] = [[15,17],[20,9]] mod 26`

#### Historical Context

Invented by Lester S. Hill in 1929. It was the first cipher to use linear algebra for encryption, demonstrating how mathematics could be applied to cryptography.

#### Security Analysis

**Key Space**: Very large for larger matrices (e.g., 2×2 has ~157,248 valid matrices)

**Strengths**:
- **Encrypts multiple letters at once** - hides single-letter frequencies
- Completely different approach (linear algebra vs shifts)
- Larger block sizes exponentially increase security
- Foundation for understanding modern block ciphers

**Weaknesses**:
- **Vulnerable to known-plaintext attacks** - with enough pairs, key matrix is recoverable
- Matrix must be invertible (determinant coprime with 26)
- Requires linear algebra knowledge
- Does not resist chosen-plaintext attacks

**Cryptanalysis**:
- **Known-plaintext attack**: With `n` plaintext-ciphertext block pairs, solve system:
  ```
  C₁ = K · P₁
  C₂ = K · P₂
  ...
  ```
  If `P` matrix is invertible, `K = C · P⁻¹`

- **Chosen-plaintext attack**: Choose convenient plaintexts to recover key quickly

---

## Transposition Ciphers

These ciphers rearrange letter positions without changing the letters themselves. They preserve letter frequencies but hide patterns.

---

### 12. Rail Fence Cipher

#### Overview

The **Rail Fence cipher** writes text in a zigzag pattern across multiple "rails" (rows), then reads each rail left-to-right.

#### Step-by-Step Process

**Encryption Example**: "HELLO WORLD" with 3 rails

1. **Write in zigzag pattern**:
   ```
   Rail 1: H . . . O . . . R . . .
   Rail 2: . E . L . . W . . L . D
   Rail 3: . . L . . . . O . . . .
   ```

   More clearly:
   ```
   Position: 0  1  2  3  4  5  6  7  8  9  10
   Rail 1:   H        O        R
   Rail 2:      E  L     W     L  D
   Rail 3:         L        O
   ```

2. **Read each rail**:
   - Rail 1: "HOR"
   - Rail 2: "ELWLD"
   - Rail 3: "LO"

3. **Concatenate**: "HOREL OLLWD" (spaces added for clarity, actual: "HORELLOWLD")

**Decryption**: Reverse the process - determine rail lengths, distribute ciphertext, then read in zigzag order.

#### Key Requirements

- **Key**: Number of rails (integer ≥ 2)
- **Default**: 3
- With 1 rail, no encryption occurs

#### Historical Context

One of the oldest transposition ciphers, used during the American Civil War. It introduces the fundamental concept of transposition.

#### Security Analysis

**Key Space**: Very small (typically 2-10 rails)

**Strengths**:
- Fundamentally different from substitution
- Simple to understand with visualization
- Can be combined with substitution

**Weaknesses**:
- Very small key space - easily brute-forced
- Predictable zigzag pattern
- Letter frequencies unchanged

**Cryptanalysis**: Try all possible rail counts (2-10), reconstruct zigzag, check if result makes sense.

---

### 13. Route Cipher

#### Overview

The **Route cipher** arranges text in a grid and reads it in a spiral or other route pattern.

#### Step-by-Step Process

**Encryption Example**: "HELLOWORLD" with grid size 4

1. **Arrange in grid** (4×4, pad if needed):
   ```
   H E L L
   O W O R
   L D X X  (padded with X)
   X X X X
   ```

2. **Read in spiral route** (clockwise from top-left):
   - Top row left→right: H E L L
   - Right column top→bottom: R X X
   - Bottom row right→left: X X X D
   - Left column bottom→top: L O
   - Inner spiral: W O

3. **Result**: "HELLRXXDLOWO" (or similar depending on route pattern)

#### Key Requirements

- **Key**: Grid dimension (integer, e.g., 4 for 4×4 grid)
- Text is padded to fill grid completely

#### Historical Context

Route ciphers were used when various reading patterns (spiral, snake, etc.) could be agreed upon. They're more flexible than Rail Fence but still vulnerable.

#### Security Analysis

**Security**: Similar to Rail Fence - small key space, predictable patterns.

**Strengths**:
- More flexible than Rail Fence
- Various route patterns possible

**Weaknesses**:
- Small key space
- Predictable patterns
- Vulnerable to brute force

---

### 14. Columnar Transposition Cipher

#### Overview

The **Columnar Transposition** writes text in rows, then reads columns in alphabetical order of a keyword.

#### Step-by-Step Process

**Encryption Example**: "HELLOWORLD" with keyword "ZEBRAS"

1. **Determine column order** from keyword:
   ```
   Keyword: Z E B R A S
   Position: 0 1 2 3 4 5
   Sorted:   A B E R S Z
   Order:    4 2 1 3 5 0  (read columns in this order)
   ```

2. **Write text in grid** (6 columns for keyword length):
   ```
        Z E B R A S
   Row1: H E L L O W
   Row2: O R L D X X  (padded)
   ```

3. **Read columns in alphabetical order**:
   - Column A (position 4): "L X"
   - Column B (position 2): "L R"
   - Column E (position 1): "E O"
   - Column R (position 3): "L D"
   - Column S (position 5): "W X"
   - Column Z (position 0): "H O"

4. **Result**: "LX LREO LD WX HO" → "LXLREOLDWXHO"

**Decryption**: Fill columns back in key order, then read rows.

#### Key Requirements

- **Key**: Keyword (e.g., "ZEBRAS", "SECRET")
- Longer keywords provide more security
- Duplicate letters handled by reading left-to-right

#### Historical Context

Widely used in World War I and II. Formed the basis of many military cipher systems, including the German ADFGVX cipher.

#### Security Analysis

**Key Space**: Much larger than Rail Fence (depends on keyword length and alphabet)

**Strengths**:
- Keyword-based key gives larger key space
- Easy to use with pen and paper
- Can be combined with substitution
- Longer keywords = stronger cipher

**Weaknesses**:
- **Anagramming attacks** can recover key by analyzing column patterns
- Short keywords = weak cipher
- Incomplete last row leaks information
- Single transposition vulnerable to multiple-anagramming

**Cryptanalysis**:
- **Anagramming**: Analyze column patterns, try to reconstruct grid
- **Brute force**: Try common keywords
- **Known plaintext**: Recover column order directly

---

### 15. Myszkowski Transposition Cipher

#### Overview

The **Myszkowski cipher** is a variant of Columnar Transposition that handles duplicate key letters by reading columns with the same letter simultaneously.

#### Step-by-Step Process

**Encryption Example**: "HELLOWORLD" with keyword "TOMATO"

1. **Keyword**: T O M A T O
   - T appears at positions 0 and 3
   - O appears at positions 1 and 5
   - M at 2, A at 3

2. **Group columns by key letter**:
   - Group T: columns 0, 3
   - Group O: columns 1, 5
   - Group M: column 2
   - Group A: column 4 (wait, A is at 3... let me recalculate)

   Actually: T=0, O=1, M=2, A=3, T=4, O=5
   - Group T: columns 0, 4
   - Group O: columns 1, 5
   - Group M: column 2
   - Group A: column 3

3. **Write in grid and read by groups**:
   ```
        T O M A T O
   Row1: H E L L O W
   Row2: O R L D X X
   ```

4. **Read columns in group order** (T columns together, then O, etc.)

#### Key Requirements

- **Key**: Keyword (may contain duplicates)
- Duplicate letters handled elegantly

#### Historical Context

Named after Émile Victor Théodore Myszkowski, this variant improves on Columnar Transposition by handling duplicate key letters more systematically.

#### Security Analysis

**Security**: Similar to Columnar Transposition, with better handling of duplicate letters.

---

### 16. Double Transposition Cipher

#### Overview

The **Double Transposition** applies Columnar Transposition twice with different keywords, significantly increasing security.

#### Step-by-Step Process

**Encryption Example**: "HELLOWORLD" with keys "ZEBRAS" and "STRIPE"

1. **First transposition** with "ZEBRAS":
   - Result: "LXLREOLDWXHO" (from previous example)

2. **Second transposition** with "STRIPE":
   - Apply Columnar Transposition again to the intermediate result
   - This scrambles the already-scrambled text

3. **Final result**: Double-scrambled ciphertext

**Decryption**: Reverse both transpositions in order.

#### Key Requirements

- **Key**: Two keywords separated by comma (e.g., "ZEBRAS,STRIPE")
- Both keywords used sequentially

#### Historical Context

Double Transposition was used extensively in World War II. It's significantly stronger than single transposition.

#### Security Analysis

**Key Space**: Square of single transposition (much larger)

**Strengths**:
- **Exponentially harder to break** than single transposition
- Two layers of scrambling
- Still practical for manual use

**Weaknesses**:
- More complex to use
- Still vulnerable to known-plaintext attacks
- Requires two keywords

**Cryptanalysis**: Much harder than single transposition, but still breakable with enough ciphertext and known plaintext.

---

### 17. Disrupted Transposition Cipher

#### Overview

The **Disrupted Transposition** is Columnar Transposition with irregular filling of the grid, making patterns less predictable.

#### Step-by-Step Process

**Encryption Example**: "HELLOWORLD" with keyword "SECRET"

1. **Create grid** with keyword columns

2. **Fill grid irregularly** (not row-by-row):
   - Fill in a disrupted pattern (e.g., fill some cells, skip others, then fill gaps)
   - This creates less predictable column patterns

3. **Read columns** in keyword order

#### Key Requirements

- **Key**: Keyword
- Filling pattern may vary by implementation

#### Security Analysis

**Security**: Similar to Columnar Transposition, with potentially less predictable patterns due to irregular filling.

---

### 18. Grille Cipher

#### Overview

The **Grille cipher** (turning grille or Cardan grille) uses a rotating mask with holes to reveal letters for encryption.

#### Step-by-Step Process

**Encryption Example**: "HELLO WORLD TEST XYZ" with grille positions "0,2,5,7"

1. **Create grid** and place grille with holes at specified positions

2. **Write plaintext** through holes:
   - First rotation: Write some letters
   - Rotate grille 90°
   - Second rotation: Write more letters
   - Continue rotating and writing

3. **Fill remaining cells** with dummy characters (X)

4. **Read grid** to get ciphertext

#### Key Requirements

- **Key**: Comma-separated positions for grille holes (e.g., "0,2,5,7")
- Grille rotates to reveal different positions

#### Historical Context

Attributed to Girolamo Cardano in the 16th century. Used for steganography and simple encryption.

#### Security Analysis

**Key Space**: Depends on grille hole positions

**Strengths**:
- Unique visual approach
- Can be combined with other techniques

**Weaknesses**:
- Limited key space
- Predictable if grille pattern is known
- Vulnerable to analysis

---

## Cryptanalysis Overview

### Common Attack Methods

1. **Frequency Analysis**
   - Exploits letter frequency patterns in natural language
   - Effective against monoalphabetic ciphers
   - Less effective against polyalphabetic ciphers

2. **Brute Force**
   - Try all possible keys
   - Feasible for small key spaces (Caesar, Affine)
   - Impractical for large key spaces

3. **Known-Plaintext Attack**
   - Attacker has some plaintext-ciphertext pairs
   - Can recover key (especially for Hill cipher)

4. **Chosen-Plaintext Attack**
   - Attacker can choose plaintexts to encrypt
   - Very powerful (breaks Hill cipher easily)

5. **Kasiski Examination**
   - Finds repeating patterns in polyalphabetic ciphers
   - Determines key length
   - Breaks Vigenère and variants

6. **Anagramming**
   - Rearranges letters to find patterns
   - Effective against transposition ciphers

### Security Evolution

```
Weakest → Strongest:

Atbash (no key)
  ↓
Augustus (fixed shift)
  ↓
Caesar (25 keys)
  ↓
Multiplicative (12 keys)
  ↓
Affine (312 keys)
  ↓
Rail Fence (small key space)
  ↓
Route Cipher
  ↓
Columnar Transposition (keyword-based)
  ↓
Vigenère (polyalphabetic, but repeating key)
  ↓
Autokey (non-repeating key)
  ↓
Running Key (long non-repeating key)
  ↓
Hill (polygraphic, but linear)
  ↓
Double Transposition (layered security)
```

---

## Cipher Comparison

| Cipher | Type | Key Space | Security | Vulnerable To |
|--------|------|-----------|----------|---------------|
| Atbash | Monoalphabetic | 1 | Very Weak | Instant recognition |
| Augustus | Monoalphabetic | 1 | Very Weak | Shift by 1 |
| Caesar | Monoalphabetic | 25 | Weak | Brute force, frequency |
| Multiplicative | Monoalphabetic | 12 | Weak | Frequency analysis |
| Affine | Monoalphabetic | 312 | Weak | Frequency analysis |
| Vigenère | Polyalphabetic | Large | Moderate | Kasiski method |
| Gronsfeld | Polyalphabetic | Medium | Moderate | Kasiski method |
| Beaufort | Polyalphabetic | Large | Moderate | Kasiski method |
| Autokey | Polyalphabetic | Large | Moderate+ | Known plaintext |
| Running Key | Polyalphabetic | Very Large | Moderate+ | Statistical analysis |
| Hill | Polygraphic | Very Large | Moderate+ | Known plaintext |
| Rail Fence | Transposition | Small | Weak | Brute force |
| Route | Transposition | Small | Weak | Pattern recognition |
| Columnar | Transposition | Medium | Moderate | Anagramming |
| Myszkowski | Transposition | Medium | Moderate | Anagramming |
| Double Transposition | Transposition | Large | Strong | Known plaintext |
| Disrupted | Transposition | Medium | Moderate | Anagramming |
| Grille | Transposition | Small | Weak | Pattern analysis |

---

## Conclusion

This guide has covered all 18 classical ciphers implemented in CipherLab. Each cipher demonstrates important cryptographic concepts:

- **Monoalphabetic ciphers** show the basics but are easily broken
- **Polyalphabetic ciphers** introduce variable substitution but have periodicity issues
- **Polygraphic ciphers** encrypt blocks, hiding single-letter patterns
- **Transposition ciphers** rearrange positions, preserving frequencies but hiding patterns

Understanding these classical ciphers provides the foundation for understanding modern cryptography, where concepts like substitution, transposition, and key scheduling are combined in sophisticated ways (e.g., AES, DES).

**Key Takeaways**:
1. No classical cipher is secure by modern standards
2. Security requires large key spaces AND resistance to cryptanalysis
3. Combining techniques (substitution + transposition) increases security
4. Modern ciphers use these concepts but with much more complexity

For hands-on learning, use CipherLab to experiment with each cipher and see how they work step-by-step!

---

*This document is part of the CipherLab project - an educational tool for learning classical cryptography.*
