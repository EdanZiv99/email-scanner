"""Manual test: run GeminiAnalysisSignal against representative emails. ~2 API calls."""
import sys
sys.path.insert(0, ".")
from dotenv import load_dotenv
load_dotenv()

from models import Email
from signals.external.gemini_analysis import GeminiAnalysisSignal

signal = GeminiAnalysisSignal()

# Test 1: clearly safe
email_safe = Email(
    from_address="alice@personal.com",
    subject="lunch tomorrow?",
    message_id="<test1@x>",
    raw_headers="From: alice@personal.com\r\n",
    html_body="",
    text_body="hey, want to grab lunch at the cafe near the office tomorrow at 1?",
    attachments=[],
)
result = signal.evaluate(email_safe)
print("--- Test 1: Safe email ---")
print(f"Triggered: {result.triggered}")
print(f"Weight:    {result.weight}")
print(f"Trump:     {result.trump_card}")
print(f"Expl:      {result.explanation}")
print()

# Test 2: clearly malicious
email_phish = Email(
    from_address="noreply@paypa1-security.com",
    subject="URGENT: Your account will be suspended",
    message_id="<test2@x>",
    raw_headers="From: noreply@paypa1-security.com\r\n",
    html_body="",
    text_body=(
        "Dear customer, We have detected unauthorized activity on your PayPal account. "
        "You must verify your account within 24 hours or it will be permanently suspended. "
        "Click here to verify: http://paypa1-security.com/verify-now"
    ),
    attachments=[],
)
result = signal.evaluate(email_phish)
print("--- Test 2: Phishing email ---")
print(f"Triggered: {result.triggered}")
print(f"Weight:    {result.weight}")
print(f"Trump:     {result.trump_card}")
print(f"Expl:      {result.explanation}")
print(f"Metadata:  {result.metadata}")
print()

# Test 3: empty body and subject — no API call should be made
email_empty = Email(
    from_address="someone@example.com",
    subject="",
    message_id="<test3@x>",
    raw_headers="",
    html_body="",
    text_body="",
    attachments=[],
)
result = signal.evaluate(email_empty)
print("--- Test 3: Empty content ---")
print(f"Triggered: {result.triggered}")
print(f"Expl:      {result.explanation}")
