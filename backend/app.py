"""Flask entry point. Handles /scan (POST), /scan/llm (POST), and /health (GET) endpoints."""
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify

from models import Email
from orchestrator import run_signals, run_llm_analysis_only
from scoring import score_email, compute_verdict_and_score

app = Flask(__name__)


def _build_email(data: dict) -> Email:
    """Construct an Email object from a parsed request payload."""
    return Email(
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


def _validate_payload(data: dict):
    """Return an error message if required fields are missing, else None."""
    missing = [f for f in ("from", "subject", "messageId", "rawHeaders") if f not in data]
    return f"Missing required fields: {', '.join(missing)}" if missing else None


@app.route("/scan", methods=["POST"])
def scan():
    """Receive email metadata from the Gmail Add-on and return a maliciousness analysis."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    error = _validate_payload(data)
    if error:
        return jsonify({"error": error}), 400

    email = _build_email(data)
    app.logger.info("Scan request: from=%s, subject=%r, id=%s",
                    email.from_address, email.subject, email.message_id)

    results = run_signals(email)
    scored = score_email(results)

    return jsonify({
        **scored,
        "echo": {"from": email.from_address, "subject": email.subject},
    })


@app.route("/scan/llm", methods=["POST"])
def scan_llm():
    """Run on-demand Gemini LLM analysis and return results merged with the previous scan."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    error = _validate_payload(data)
    if error:
        return jsonify({"error": error}), 400

    email = _build_email(data)
    app.logger.info("LLM scan: from=%s, subject=%r", email.from_address, email.subject)

    llm_result = run_llm_analysis_only(email)

    llm_signal_dict = {
        "name": llm_result.signal_name,
        "category": llm_result.category,
        "triggered": llm_result.triggered,
        "explanation": llm_result.explanation,
        "weight": llm_result.weight,
        "trump_card": llm_result.trump_card,
        "metadata": llm_result.metadata,
    }

    # Merge LLM result with the signals from the previous /scan call.
    previous = data.get("previousResult", {})
    prev_signals = previous.get("signals", [])
    all_signals = prev_signals + [llm_signal_dict]

    computed = compute_verdict_and_score(all_signals)

    return jsonify({
        **computed,
        "signals": all_signals,
        "echo": {"from": email.from_address, "subject": email.subject},
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
