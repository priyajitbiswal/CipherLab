"""Flask backend for the Cryptographic Ciphers educational app."""

from flask import Flask, render_template, jsonify, request
from ciphers.registry import get_cipher, list_ciphers, list_by_category

app = Flask(__name__)


# ── Pages ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── API ──────────────────────────────────────────────────────────────────

@app.route("/api/ciphers")
def api_list_ciphers():
    """Return all ciphers grouped by subcategory."""
    return jsonify({
        "ciphers": list_ciphers(),
        "categories": list_by_category(),
    })


@app.route("/api/cipher/<slug>")
def api_cipher_info(slug: str):
    cipher = get_cipher(slug)
    if not cipher:
        return jsonify({"error": f"Cipher '{slug}' not found."}), 404
    return jsonify(cipher.get_info())


@app.route("/api/cipher/<slug>/encrypt", methods=["POST"])
def api_encrypt(slug: str):
    cipher = get_cipher(slug)
    if not cipher:
        return jsonify({"error": f"Cipher '{slug}' not found."}), 404
    data = request.get_json(force=True)
    text = data.get("text", "")
    key = data.get("key", "")
    try:
        # Always pass key parameter - ciphers handle empty strings with defaults
        result = cipher.encrypt(text, key) if key else cipher.encrypt(text)
        steps = cipher.explain_steps(text, key, mode="encrypt") if key else cipher.explain_steps(text, mode="encrypt")
        return jsonify({"result": result, "steps": steps})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/cipher/<slug>/decrypt", methods=["POST"])
def api_decrypt(slug: str):
    cipher = get_cipher(slug)
    if not cipher:
        return jsonify({"error": f"Cipher '{slug}' not found."}), 404
    data = request.get_json(force=True)
    text = data.get("text", "")
    key = data.get("key", "")
    try:
        # Always pass key parameter - ciphers handle empty strings with defaults
        result = cipher.decrypt(text, key) if key else cipher.decrypt(text)
        steps = cipher.explain_steps(text, key, mode="decrypt") if key else cipher.explain_steps(text, mode="decrypt")
        return jsonify({"result": result, "steps": steps})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ── Run ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, port=5000)
