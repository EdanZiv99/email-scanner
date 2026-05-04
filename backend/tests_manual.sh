#!/bin/bash
# Manual test suite for email-scorer.
# Run from the project root with: bash backend/tests_manual.sh
# Requires Flask running on localhost:8080.

URL="http://localhost:8080/scan"
PASS=0
FAIL=0

# Helper: run a curl test and check that a specific signal is in the expected state.
# Usage: check_signal "test_name" "json_payload" "signal_name" "should_trigger (true|false)"
check_signal() {
    local name="$1"
    local payload="$2"
    local signal="$3"
    local expected="$4"

    local response=$(curl -s -X POST "$URL" -H "Content-Type: application/json" -d "$payload")
    local triggered=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for s in data.get('signals', []):
        if s.get('signal_name') == '$signal' or s.get('name') == '$signal':
            print('true' if s.get('triggered') else 'false')
            break
    else:
        print('NOT_FOUND')
except Exception as e:
    print(f'ERROR: {e}')
")

    if [ "$triggered" = "$expected" ]; then
        echo "  PASS: $name"
        PASS=$((PASS+1))
    else
        echo "  FAIL: $name (expected triggered=$expected, got $triggered)"
        echo "       Response: $response" | head -c 500
        echo ""
        FAIL=$((FAIL+1))
    fi
}

# Helper: check that the verdict matches.
check_verdict() {
    local name="$1"
    local payload="$2"
    local expected_verdict="$3"

    local response=$(curl -s -X POST "$URL" -H "Content-Type: application/json" -d "$payload")
    local verdict=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('verdict', 'NOT_FOUND'))
except Exception:
    print('PARSE_ERROR')
")

    if [ "$verdict" = "$expected_verdict" ]; then
        echo "  PASS: $name (verdict=$verdict)"
        PASS=$((PASS+1))
    else
        echo "  FAIL: $name (expected verdict=$expected_verdict, got $verdict)"
        FAIL=$((FAIL+1))
    fi
}

# === Health check ===
echo ""
echo "=== Health check ==="
HEALTH=$(curl -s "http://localhost:8080/health")
if [ -n "$HEALTH" ]; then
    echo "  PASS: Flask is responding"
    PASS=$((PASS+1))
else
    echo "  FAIL: Flask not responding on localhost:8080"
    echo "  Aborting tests."
    exit 1
fi

# === DMARC ===
echo ""
echo "=== DMARC ==="

check_signal "DMARC: missing header → not triggered" \
'{"from":"a@b.com","subject":"x","messageId":"<1@b.com>","rawHeaders":"From: a@b.com\r\nSubject: x\r\n"}' \
"dmarc" "false"

check_signal "DMARC: dmarc=pass → not triggered" \
'{"from":"a@b.com","subject":"x","messageId":"<2@b.com>","rawHeaders":"From: a@b.com\r\nAuthentication-Results: mx.google.com; spf=pass; dmarc=pass\r\nSubject: x\r\n"}' \
"dmarc" "false"

check_signal "DMARC: dmarc=fail → triggered" \
'{"from":"a@b.com","subject":"x","messageId":"<3@b.com>","rawHeaders":"From: a@b.com\r\nAuthentication-Results: mx.google.com; dmarc=fail (p=reject)\r\nSubject: x\r\n"}' \
"dmarc" "true"

# === Display Name Email Spoof ===
echo ""
echo "=== Display Name Email Spoof ==="

check_signal "Email spoof: paypal in display name, evil.com sender → triggered" \
'{"from":"attacker@evil.com","subject":"x","messageId":"<4@evil.com>","rawHeaders":"From: \"support@paypal.com\" <attacker@evil.com>\r\nSubject: x\r\n"}' \
"display_name_email_spoof" "true"

check_signal "Email spoof: matching domains → not triggered" \
'{"from":"john@example.com","subject":"x","messageId":"<5@example.com>","rawHeaders":"From: \"john@example.com\" <john@example.com>\r\nSubject: x\r\n"}' \
"display_name_email_spoof" "false"

# === Display Name Brand Impersonation ===
echo ""
echo "=== Display Name Brand Impersonation ==="

check_signal "Brand impersonation: Microsoft from random domain → triggered" \
'{"from":"notify@random-domain.com","subject":"x","messageId":"<6@random.com>","rawHeaders":"From: \"Microsoft Account Team\" <notify@random-domain.com>\r\nSubject: x\r\n"}' \
"display_name_brand_impersonation" "true"

check_signal "Brand impersonation: Microsoft from microsoft.com → not triggered" \
'{"from":"notify@microsoft.com","subject":"x","messageId":"<7@microsoft.com>","rawHeaders":"From: \"Microsoft Account Team\" <notify@microsoft.com>\r\nSubject: x\r\n"}' \
"display_name_brand_impersonation" "false"

check_signal "Brand impersonation: no brand in display name → not triggered" \
'{"from":"john@example.com","subject":"x","messageId":"<8@example.com>","rawHeaders":"From: \"John Doe\" <john@example.com>\r\nSubject: x\r\n"}' \
"display_name_brand_impersonation" "false"

# === Lookalike Domain ===
echo ""
echo "=== Lookalike Domain ==="

check_signal "Lookalike: paypa1.com (1 instead of l) → triggered" \
'{"from":"noreply@paypa1.com","subject":"x","messageId":"<9@paypa1.com>","rawHeaders":"From: noreply@paypa1.com\r\nSubject: x\r\n"}' \
"lookalike_domain" "true"

check_signal "Lookalike: real paypal.com → not triggered" \
'{"from":"noreply@paypal.com","subject":"x","messageId":"<10@paypal.com>","rawHeaders":"From: noreply@paypal.com\r\nSubject: x\r\n"}' \
"lookalike_domain" "false"

check_signal "Lookalike: unrelated domain → not triggered" \
'{"from":"hello@my-friends-blog.com","subject":"x","messageId":"<11@blog.com>","rawHeaders":"From: hello@my-friends-blog.com\r\nSubject: x\r\n"}' \
"lookalike_domain" "false"

# === Dangerous Extensions ===
echo ""
echo "=== Dangerous Extensions ==="

check_signal "Dangerous ext: invoice.exe → triggered" \
'{"from":"a@b.com","subject":"x","messageId":"<12@b.com>","rawHeaders":"From: a@b.com\r\nSubject: x\r\n","attachments":[{"filename":"invoice.exe","size":1024,"sha256":"abc"}]}' \
"dangerous_extensions" "true"

check_signal "Dangerous ext: double extension invoice.pdf.exe → triggered" \
'{"from":"a@b.com","subject":"x","messageId":"<13@b.com>","rawHeaders":"From: a@b.com\r\nSubject: x\r\n","attachments":[{"filename":"invoice.pdf.exe","size":1024,"sha256":"abc"}]}' \
"dangerous_extensions" "true"

check_signal "Dangerous ext: report.pdf → not triggered" \
'{"from":"a@b.com","subject":"x","messageId":"<14@b.com>","rawHeaders":"From: a@b.com\r\nSubject: x\r\n","attachments":[{"filename":"report.pdf","size":1024,"sha256":"abc"}]}' \
"dangerous_extensions" "false"

# === URL/href Mismatch ===
echo ""
echo "=== URL/href Mismatch ==="

check_signal "URL mismatch: visible paypal.com, href evil.com → triggered" \
'{"from":"a@b.com","subject":"x","messageId":"<15@b.com>","rawHeaders":"From: a@b.com\r\nSubject: x\r\n","htmlBody":"<a href=\"http://evil.com/phish\">login at paypal.com</a>"}' \
"url_href_mismatch" "true"

check_signal "URL mismatch: visible and href both paypal.com → not triggered" \
'{"from":"a@b.com","subject":"x","messageId":"<16@b.com>","rawHeaders":"From: a@b.com\r\nSubject: x\r\n","htmlBody":"<a href=\"https://www.paypal.com/login\">paypal.com</a>"}' \
"url_href_mismatch" "false"

check_signal "URL mismatch: generic Click here text → not triggered" \
'{"from":"a@b.com","subject":"x","messageId":"<17@b.com>","rawHeaders":"From: a@b.com\r\nSubject: x\r\n","htmlBody":"<a href=\"http://example.com\">Click here</a>"}' \
"url_href_mismatch" "false"

# === Reply-To Mismatch ===
echo ""
echo "=== Reply-To Mismatch ==="

check_signal "Reply-To: from company.com, reply-to gmail.com → triggered" \
'{"from":"ceo@company.com","subject":"x","messageId":"<18@company.com>","rawHeaders":"From: \"CEO\" <ceo@company.com>\r\nReply-To: attacker@gmail.com\r\nSubject: x\r\n"}' \
"reply_to_mismatch" "true"

check_signal "Reply-To: same registrable domain → not triggered" \
'{"from":"newsletter@mail.github.com","subject":"x","messageId":"<19@github.com>","rawHeaders":"From: newsletter@mail.github.com\r\nReply-To: support@github.com\r\nSubject: x\r\n"}' \
"reply_to_mismatch" "false"

check_signal "Reply-To: missing header → not triggered" \
'{"from":"john@example.com","subject":"x","messageId":"<20@example.com>","rawHeaders":"From: \"John\" <john@example.com>\r\nSubject: x\r\n"}' \
"reply_to_mismatch" "false"

# === Verdict tiers ===
echo ""
echo "=== Verdict tiers ==="

check_verdict "Verdict: clean email → Safe" \
'{"from":"john@example.com","subject":"Lunch","messageId":"<21@example.com>","rawHeaders":"From: \"John Doe\" <john@example.com>\r\nAuthentication-Results: dmarc=pass\r\nSubject: Lunch\r\n"}' \
"Safe"

check_verdict "Verdict: triple signals → High Risk or Malicious" \
'{"from":"attacker@evil.com","subject":"Verify","messageId":"<22@evil.com>","rawHeaders":"From: \"support@paypal.com\" <attacker@evil.com>\r\nAuthentication-Results: dmarc=fail\r\nSubject: Verify\r\n"}' \
"High Risk"

# === Trump cards (skip if not implemented) ===
echo ""
echo "=== Trump cards ==="

check_verdict "Trump: invoice.pdf.exe attachment → Malicious" \
'{"from":"a@b.com","subject":"x","messageId":"<23@b.com>","rawHeaders":"From: a@b.com\r\nAuthentication-Results: dmarc=pass\r\nSubject: x\r\n","attachments":[{"filename":"invoice.pdf.exe","size":1024,"sha256":"abc"}]}' \
"Malicious"

# === Summary ===
echo ""
echo "=========================="
echo "  Results: $PASS passed, $FAIL failed"
echo "=========================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi