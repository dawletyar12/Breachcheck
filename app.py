from flask import Flask, request, jsonify, render_template
import hashlib
import requests
from zxcvbn import zxcvbn
from functools import lru_cache

app = Flask(__name__)

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"

def sha1_upper(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8')).hexdigest().upper()

@lru_cache(maxsize=2048)
def query_hibp(prefix: str) -> str:
    """Запрос к HIBP API по префиксу SHA-1 (k-anonymity)."""
    url = HIBP_RANGE_URL.format(prefix)
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text

def check_pwned(password: str) -> int:
    """Возвращает число утечек для пароля (0 если не найден)."""
    h = sha1_upper(password)
    pref, suf = h[:5], h[5:]
    body = query_hibp(pref)
    for line in body.splitlines():
        hash_suffix, count = line.split(':')
        if hash_suffix == suf:
            return int(count)
    return 0

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json()
    pw = data.get("password", "")
    if not pw:
        return jsonify({"error": "empty password"}), 400

    strength = zxcvbn(pw)
    try:
        pwned_count = check_pwned(pw)
    except requests.RequestException:
        pwned_count = -1

    return jsonify({
        "strength_score": strength["score"],  # 0..4
        "strength_feedback": strength.get("feedback", {}),
        "pwned_count": pwned_count
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
