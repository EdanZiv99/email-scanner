from flask import Flask, request, jsonify

from models import Email
from orchestrator import run_signals

app = Flask(__name__)


# Verdict thresholds based on the spec's 4-tier model
VERDICT_THRESHOLDS = [
    (70, "Malicious"),
    (30, "High Risk"),
    (10, "Suspicious"),
]


def _verdict(score: int) -> str:
    """Map a score to a verdict tier per the spec."""
    for threshold, verdict in VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict
    return "Safe"


@app.route("/scan", methods=["POST"])
def scan():
    """Receive email metadata from the Gmail Add-on and return a maliciousness analysis."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()

    missing = [f for f in ("from", "subject", "messageId", "rawHeaders") if f not in data]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    email = Email(
        from_address=data["from"],
        subject=data["subject"],
        message_id=data["messageId"],
        raw_headers=data["rawHeaders"],
        html_body=data.get("htmlBody", ""),
        text_body=data.get("textBody", ""),
        attachments=[
            {"filename": a.get("filename", ""), "size": a.get("size", 0), "sha256": a.get("sha256", "")}
            for a in data.get("attachments", [])
        ],
    )

    app.logger.info(
        "Scan request: from=%s, subject=%r, id=%s",
        email.from_address, email.subject, email.message_id,
    )

    results = run_signals(email)

    score = sum(r.weight for r in results if r.triggered)
    verdict = _verdict(score)

    return jsonify({
        "score": score,
        "verdict": verdict,
        "signals": [
            {
                "name": r.signal_name,
                "triggered": r.triggered,
                "explanation": r.explanation,
                "weight": r.weight,
            }
            for r in results
        ],
        "echo": {
            "from": email.from_address,
            "subject": email.subject,
        },
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
