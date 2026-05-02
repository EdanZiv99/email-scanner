from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/scan", methods=["POST"])
def scan():
    return jsonify({"score": 0, "verdict": "Safe", "signals": []})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
