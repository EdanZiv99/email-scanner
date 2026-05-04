"""Gemini analysis signal: holistic LLM-based phishing detection on email content."""
import logging

from models import Email, SignalResult
from providers.gemini import GeminiProvider
from signals.base import Signal
from signals.external.gemini_prompts import SYSTEM_PROMPT, build_user_prompt

logger = logging.getLogger(__name__)


class GeminiAnalysisSignal(Signal):
    """LLM-based holistic analysis of email content using Gemini."""

    name = "gemini_analysis"
    category = "AI Analysis"
    weight = 25  # default; overridden dynamically based on verdict + confidence

    # Maps (verdict, confidence) → (weight, trump_card).
    # suspicious/low and all safe cases produce weight=0 (not triggered).
    # No trump card — high weight (45) is sufficient; the LLM alone should not force a verdict.
    WEIGHT_TABLE = {
        ("safe",       "low"):    (0,  False),
        ("safe",       "medium"): (0,  False),
        ("safe",       "high"):   (0,  False),
        ("suspicious", "low"):    (0,  False),
        ("suspicious", "medium"): (12, False),
        ("suspicious", "high"):   (18, False),
        ("high_risk",  "low"):    (18, False),
        ("high_risk",  "medium"): (25, False),
        ("high_risk",  "high"):   (35, False),
        ("malicious",  "low"):    (25, False),
        ("malicious",  "medium"): (35, False),
        ("malicious",  "high"):   (45, False),
    }

    def __init__(self, provider: GeminiProvider = None):
        # Provider injection enables testability without hitting the real API.
        self.provider = provider or GeminiProvider()

    def evaluate(self, email: Email) -> SignalResult:
        try:
            return self._evaluate(email)
        except Exception as e:
            logger.exception("Unexpected error in GeminiAnalysisSignal")
            return self._make_result(triggered=False, explanation=f"LLM analysis unavailable: {e}")

    def _evaluate(self, email: Email) -> SignalResult:
        body = email.text_body or email.html_body or ""

        if not body and not email.subject:
            return self._make_result(triggered=False, explanation="No content to analyze")

        user_prompt = build_user_prompt(email.from_address, email.subject, body)
        result = self.provider.analyze(SYSTEM_PROMPT, user_prompt)

        if not result.success:
            return self._make_result(
                triggered=False,
                explanation=f"LLM analysis unavailable: {result.error}",
            )

        key = (result.verdict, result.confidence)
        if key not in self.WEIGHT_TABLE:
            return self._make_result(
                triggered=False,
                explanation="LLM returned unexpected verdict/confidence combination",
            )

        weight, is_trump = self.WEIGHT_TABLE[key]

        if weight == 0:
            return self._make_result(
                triggered=False,
                explanation=f"LLM verdict '{result.verdict}' (confidence: {result.confidence}) does not warrant flagging",
            )

        return self._make_result(
            triggered=True,
            explanation=f"{result.explanation}",
            metadata={
                "verdict": result.verdict,
                "confidence": result.confidence,
                "threat_types": result.threat_types,
                "key_indicators": result.key_indicators,
            },
            weight=weight,
            trump_card=is_trump,
        )
