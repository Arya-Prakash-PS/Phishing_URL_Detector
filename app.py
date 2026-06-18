"""
AuthentURL - Flask Application
===============================
Main Flask web application for the AuthentURL phishing URL detector.
Provides RESTful API endpoints and serves the frontend.
"""

from flask import Flask, render_template, request, jsonify
import urllib.parse
import time
import re

from detector import analyze_url

# ─────────────────────────────────────────────────────────────────────────────
# App Initialisation
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _is_valid_url_format(url: str) -> bool:
    """
    Permissive sanity check — accept any input that looks even remotely
    like a URL or domain name. Rejects only:
      - Pure whitespace / empty strings
      - Strings with no dot AND no scheme (e.g. a single word like "hello")
    Accepts:
      - https://example.com, http://x.y.z/path?q=1
      - example.com, sub.domain.tld
      - http://192.168.1.1/login  (IP-based URLs)
      - netflix.com.scamwebsite.xyz
      - bit.ly/abc123
      - Any URL with a scheme (ftp://, etc.)
    """
    url = url.strip()
    if not url:
        return False

    # Allow anything that already has a scheme
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        return True

    # Allow bare domains / IPs — must contain at least one dot
    # and must not be just spaces or weird control characters
    if '.' in url and ' ' not in url:
        return True

    return False


def _normalise_url(url: str) -> str:
    """Add https:// scheme if missing, so urllib.parse can handle it properly."""
    url = url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        # No scheme present — prepend https://
        url = 'https://' + url
    return url


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the AuthentURL homepage."""
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    POST /api/analyze
    Body (JSON): { "url": "<url-to-check>" }

    Returns a JSON report with:
      - url            : original URL
      - score          : integer risk score
      - classification : Safe | Suspicious | Phishing
      - flags          : list of triggered detection rules
      - recommendations: list of security advice strings
      - is_trusted     : bool
      - elapsed_ms     : analysis duration in milliseconds
    """
    data = request.get_json(silent=True)

    # ── Input validation ──────────────────────────────────────────────────────
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field in request body."}), 400

    raw_url = str(data["url"]).strip()

    if not raw_url:
        return jsonify({"error": "URL cannot be empty."}), 400

    if len(raw_url) > 2048:
        return jsonify({"error": "URL is too long (max 2048 characters)."}), 400

    if not _is_valid_url_format(raw_url):
        return jsonify({
            "error": "Please enter a valid URL or domain name (e.g. https://example.com or example.com)."
        }), 400

    # ── Normalise & analyse ───────────────────────────────────────────────────
    url = _normalise_url(raw_url)
    t0  = time.time()

    try:
        report = analyze_url(url)
    except Exception as exc:
        app.logger.exception("Analysis error for URL: %s", url)
        return jsonify({"error": f"Analysis failed: {str(exc)}"}), 500

    elapsed_ms = int((time.time() - t0) * 1000)
    report["elapsed_ms"] = elapsed_ms

    return jsonify(report)


@app.route("/api/health")
def health():
    """Simple health-check endpoint."""
    return jsonify({"status": "ok", "service": "AuthentURL"})


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
