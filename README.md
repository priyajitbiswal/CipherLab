# 🔐 CipherLab - Interactive Cryptographic Ciphers Explorer

<div align="center">

**An educational web application for exploring classical cryptographic ciphers with interactive encryption, decryption, and step-by-step visual explanations.**

[![Python](https://img.shields.io/badge/Python-3.13+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.2+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-Educational-purple.svg)](LICENSE)

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [API Reference](#-api-reference)

</div>

---

## 📖 Overview

**CipherLab** is an interactive educational platform designed to teach classical cryptography through hands-on exploration. Whether you're a student learning cryptography basics, an educator teaching security concepts, or a developer interested in historical encryption methods, CipherLab provides an intuitive interface to understand how these ciphers work.

### What Makes CipherLab Special?

✨ **18 Classical Ciphers** - From simple Caesar shifts to complex matrix-based encryption  
🎓 **Educational Focus** - Step-by-step explanations reveal the inner workings  
📊 **Visual Learning** - Interactive tables, mappings, and transformations  
📜 **Historical Context** - Learn the history and evolution of each cipher  
🎨 **Modern UI** - Beautiful dark theme with responsive design  

---

## ✨ Features

### 🔤 Cipher Categories

#### **Monoalphabetic Substitution**
- **Atbash** - Reverse alphabet mapping (A↔Z)
- **Caesar** - Shift cipher with variable key
- **Augustus** - Fixed shift-by-one variant
- **Affine** - Mathematical formula: E(x) = (a·x + b) mod 26
- **Multiplicative** - Multiplication-based substitution

#### **Polyalphabetic Substitution**
- **Vigenère** - Keyword-based repeating shifts
- **Gronsfeld** - Numeric key variant
- **Beaufort** - Reciprocal cipher variant
- **Autokey** - Self-extending key cipher
- **Running Key** - Long text passage as key

#### **Polygraphic Substitution**
- **Hill** - Matrix multiplication encryption

#### **Transposition**
- **Rail Fence** - Zigzag pattern rearrangement
- **Route** - Spiral grid reading
- **Columnar** - Keyword-ordered columns
- **Myszkowski** - Duplicate key letter handling
- **Double Transposition** - Two-stage columnar
- **Disrupted** - Irregular grid filling
- **Grille** - Rotating mask pattern

### 🎯 Key Capabilities

- **Real-time Encryption/Decryption** - Instant results with any cipher
- **Step-by-Step Explanations** - Visual breakdown of each operation
- **Key Validation** - Automatic validation with helpful error messages
- **Historical Information** - Background, advantages, and weaknesses
- **Responsive Design** - Works on desktop, tablet, and mobile devices
- **RESTful API** - Programmatic access to all cipher functions

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.13+** (Python 3.11+ may work but 3.13+ is recommended)
- **pip** or **uv** package manager

### Installation

#### Method 1: Using `uv` (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd cryptographic-ciphers

# Install dependencies
uv sync

# Run the application
uv run python app.py
```

#### Method 2: Using `pip`

```bash
# Clone the repository
git clone <repository-url>
cd cryptographic-ciphers

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install flask numpy

# Run the application
python app.py
```

### Running the Application

Once dependencies are installed, start the server:

```bash
python app.py
```

The application will be available at **http://localhost:5000**

Open your browser and start exploring!

---

## 📚 Usage Guide

### Web Interface

1. **Select a Cipher**
   - Browse the sidebar to see all available ciphers organized by category
   - Click on any cipher to view its details

2. **Enter Your Text**
   - Type or paste your plaintext in the input field
   - Supports letters, numbers, and special characters (handled appropriately by each cipher)

3. **Set the Key** (if required)
   - Some ciphers require a key (e.g., Caesar shift, Vigenère keyword)
   - Others work without keys (e.g., Atbash, Augustus)
   - Default keys are provided as placeholders

4. **Encrypt or Decrypt**
   - Click **🔒 Encrypt** to convert plaintext to ciphertext
   - Click **🔓 Decrypt** to reverse the process
   - Results appear instantly with visual feedback

5. **Learn from Steps**
   - Scroll down to see detailed step-by-step explanations
   - Visual tables show letter mappings and transformations
   - Understand exactly how each cipher operates

### Example Workflow

**Caesar Cipher Example:**
```
Input:  "HELLO WORLD"
Key:    "3"
Result: "KHOOR ZRUOG"

Step 1: Determine shift (3 positions forward)
Step 2: Build shifted alphabet (A→D, B→E, ...)
Step 3: Apply shift letter by letter
Step 4: Final ciphertext
```

**Atbash Cipher Example:**
```
Input:  "HELLO WORLD"
Key:    (none required)
Result: "SVOOL DLIOW"

Step 1: Build reverse mapping (A↔Z, B↔Y, ...)
Step 2: Apply mapping to each letter
Step 3: Final result
```

---

## 🔌 API Reference

CipherLab provides a RESTful API for programmatic access to all cipher functions.

### Base URL
```
http://localhost:5000
```

### Endpoints

#### `GET /api/ciphers`
List all available ciphers grouped by category.

**Response:**
```json
{
  "ciphers": [
    {
      "name": "Caesar Cipher",
      "slug": "caesar",
      "category": "Classical",
      "subcategory": "Monoalphabetic Substitution",
      ...
    }
  ],
  "categories": {
    "Monoalphabetic Substitution": [...],
    "Polyalphabetic Substitution": [...]
  }
}
```

#### `GET /api/cipher/<slug>`
Get detailed information about a specific cipher.

**Example:** `GET /api/cipher/caesar`

**Response:**
```json
{
  "name": "Caesar Cipher",
  "slug": "caesar",
  "category": "Classical",
  "subcategory": "Monoalphabetic Substitution",
  "description": "...",
  "history": "...",
  "key_info": "An integer shift value (1-25). Default is 3.",
  "advantages": [...],
  "disadvantages": [...],
  "improvements": "..."
}
```

#### `POST /api/cipher/<slug>/encrypt`
Encrypt text using a specific cipher.

**Request Body:**
```json
{
  "text": "HELLO WORLD",
  "key": "3"
}
```

**Response:**
```json
{
  "result": "KHOOR ZRUOG",
  "steps": [
    {
      "title": "Step 1 — Determine the Shift",
      "content": "...",
      "data": {...}
    }
  ]
}
```

#### `POST /api/cipher/<slug>/decrypt`
Decrypt text using a specific cipher.

**Request Body:**
```json
{
  "text": "KHOOR ZRUOG",
  "key": "3"
}
```

**Response:**
```json
{
  "result": "HELLO WORLD",
  "steps": [...]
}
```

### API Examples

#### Using cURL

```bash
# Encrypt with Caesar cipher
curl -X POST http://localhost:5000/api/cipher/caesar/encrypt \
  -H "Content-Type: application/json" \
  -d '{"text": "HELLO WORLD", "key": "3"}'

# Decrypt with Vigenère cipher
curl -X POST http://localhost:5000/api/cipher/vigenere/decrypt \
  -H "Content-Type: application/json" \
  -d '{"text": "RIJVS UYVJN", "key": "KEY"}'

# Encrypt with Atbash (no key needed)
curl -X POST http://localhost:5000/api/cipher/atbash/encrypt \
  -H "Content-Type: application/json" \
  -d '{"text": "HELLO WORLD", "key": ""}'
```

#### Using Python

```python
import requests

# Encrypt text
response = requests.post(
    'http://localhost:5000/api/cipher/caesar/encrypt',
    json={'text': 'HELLO WORLD', 'key': '3'}
)
data = response.json()
print(f"Ciphertext: {data['result']}")
print(f"Steps: {len(data['steps'])}")
```

#### Using JavaScript

```javascript
// Encrypt text
fetch('http://localhost:5000/api/cipher/caesar/encrypt', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ text: 'HELLO WORLD', key: '3' })
})
  .then(res => res.json())
  .then(data => {
    console.log('Ciphertext:', data.result);
    console.log('Steps:', data.steps.length);
  });
```

---

## 🧪 Testing

### Run All Tests

```bash
# Test all cipher implementations
python test_all.py

# Test Flask API endpoints
python test_decrypt.py
```

### Expected Output

The test suite verifies:
- ✅ All 18 ciphers encrypt correctly
- ✅ Round-trip encryption/decryption works
- ✅ Step-by-step explanations are generated
- ✅ API endpoints return correct responses
- ✅ Error handling works properly

---

## 📁 Project Structure

```
cryptographic-ciphers/
│
├── app.py                    # Flask application entry point
├── main.py                    # Alternative entry point
├── pyproject.toml             # Project metadata and dependencies
├── README.md                  # This file
│
├── ciphers/                   # Core cipher implementations
│   ├── __init__.py
│   ├── base.py               # Abstract base class for all ciphers
│   ├── registry.py           # Cipher discovery and registration
│   │
│   ├── substitution/         # Substitution cipher implementations
│   │   ├── __init__.py
│   │   ├── atbash.py         # Atbash cipher
│   │   ├── caesar.py         # Caesar cipher
│   │   ├── augustus.py       # Augustus cipher
│   │   ├── affine.py         # Affine cipher
│   │   ├── multiplicative.py # Multiplicative cipher
│   │   ├── vigenere.py       # Vigenère cipher
│   │   ├── gronsfeld.py      # Gronsfeld cipher
│   │   ├── beaufort.py       # Beaufort cipher
│   │   ├── autokey.py        # Autokey cipher
│   │   ├── running_key.py    # Running Key cipher
│   │   └── hill.py           # Hill cipher (matrix-based)
│   │
│   └── transposition/         # Transposition cipher implementations
│       ├── __init__.py
│       ├── rail_fence.py     # Rail Fence cipher
│       ├── route.py          # Route cipher
│       ├── columnar.py       # Columnar Transposition
│       ├── myszkowski.py     # Myszkowski cipher
│       ├── double_transposition.py
│       ├── disrupted.py     # Disrupted Transposition
│       └── grille.py         # Grille cipher
│
├── templates/                 # HTML templates
│   └── index.html            # Main application page
│
├── static/                   # Static assets
│   ├── css/
│   │   └── style.css        # Application styles
│   └── js/
│       └── app.js           # Frontend JavaScript
│
└── test_*.py                 # Test suites
    ├── test_all.py          # Comprehensive cipher tests
    └── test_decrypt.py      # API endpoint tests
```

---

## 🛠️ Development

### Code Architecture

The project follows a modular, object-oriented design:

- **Base Class** (`ciphers/base.py`) - Defines the interface all ciphers must implement
- **Registry Pattern** (`ciphers/registry.py`) - Auto-discovers and registers all ciphers
- **Separation of Concerns** - Each cipher is self-contained in its own file
- **Educational Focus** - Every cipher provides detailed step-by-step explanations

### Adding a New Cipher

1. Create a new file in the appropriate directory (`substitution/` or `transposition/`)
2. Inherit from `Cipher` base class
3. Implement required methods:
   - `encrypt(plaintext, key)` - Encrypt text
   - `decrypt(ciphertext, key)` - Decrypt text
   - `get_info()` - Return metadata
   - `explain_steps(text, key, mode)` - Generate educational steps
4. Register in `ciphers/registry.py`

### Code Style

- Follow PEP 8 Python style guide
- Use descriptive variable and function names
- Include docstrings for all classes and methods
- Keep files under 300 lines when possible
- Add comments for non-obvious logic

---

## 🐛 Troubleshooting

### Common Issues

#### Port Already in Use
```
Error: Address already in use
```
**Solution:** Change the port in `app.py`:
```python
app.run(debug=True, port=5001)  # Use a different port
```

#### Module Not Found
```
ModuleNotFoundError: No module named 'flask'
```
**Solution:** Install dependencies:
```bash
pip install flask numpy
```

#### Import Errors
```
ImportError: cannot import name 'Cipher'
```
**Solution:** Ensure you're running from the project root directory:
```bash
cd cryptographic-ciphers
python app.py
```

#### Key Validation Errors
Some ciphers have specific key requirements:
- **Affine**: `a` must be coprime with 26 (valid: 1,3,5,7,9,11,15,17,19,21,23,25)
- **Hill**: Key must form a square matrix (e.g., 4 numbers for 2×2, 9 for 3×3)
- **Running Key**: Key text must be at least as long as the message

---

## 📝 Cipher Reference

### Key Formats

| Cipher | Key Format | Example |
|--------|-----------|---------|
| Caesar | Integer (1-25) | `3` |
| Affine | Two integers `a,b` | `5,8` |
| Vigenère | Keyword string | `LEMON` |
| Gronsfeld | Numeric string | `31415` |
| Hill | Comma-separated numbers | `3,3,2,5` |
| Rail Fence | Integer (rails) | `3` |
| Columnar | Keyword | `ZEBRAS` |
| Atbash | None | (no key) |

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional cipher implementations
- Enhanced visualizations
- Performance optimizations
- Documentation improvements
- Bug fixes

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-cipher`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `python test_all.py`
6. Submit a pull request

---

## 📄 License

This project is provided for **educational purposes**. Feel free to use, modify, and learn from it.

---

## 🙏 Acknowledgments

- Historical ciphers and their inventors
- The cryptography education community
- Flask and NumPy developers

---

## 📧 Support

For questions, issues, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review the code comments for implementation details

---

<div align="center">

**Made with ❤️ for cryptography education**

[⬆ Back to Top](#-cipherlab---interactive-cryptographic-ciphers-explorer)

</div>
