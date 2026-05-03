"""Flask entry point. Handles /scan (POST) and /health (GET) endpoints."""
from flask import Flask, request, jsonify

from models import Email
from orchestrator import run_signals
from scoring import score_email

app = Flask(__name__)


@app.route("/scan", methods=["POST"])
def scan():
    """Receive email metadata from the Gmail Add-on and return a maliciousness analysis."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()

    missing = [f for f in ("from", "subject", "messageId", "rawHeaders") if f not in data]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    # Payload uses camelCase (JS convention); Email dataclass uses snake_case (Python convention).
    # htmlBody, textBody, and attachments are optional — older add-on versions may not send them.
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

    scored = score_email(results)

    return jsonify({
        **scored,
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
