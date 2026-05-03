from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/scan", methods=["POST"])
def scan():
    """
    Receives email metadata from the Gmail Add-on and returns a maliciousness
    analysis. For now, returns a placeholder response - real analysis comes
    in the next phase.
    """
    # Validate request has JSON body
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()

    # Extract fields with defaults
    from_address = data.get("from", "")
    subject = data.get("subject", "")
    message_id = data.get("messageId", "")

    # Log what we received (helpful for debugging)
    app.logger.info(
        f"Scan request: from={from_address}, subject={subject!r}, id={message_id}"
    )

    # Placeholder response that echoes the sender so we can verify the data flows
    return jsonify({
        "score": 0,
        "verdict": "Safe",
        "signals": [],
        "echo": {
            "from": from_address,
            "subject": subject,
        }
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)