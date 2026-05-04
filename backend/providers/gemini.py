"""Gemini Flash API provider for LLM-based email content analysis."""
import json
import os
from dataclasses import dataclass, field

from providers.rate_limit import RateLimiter

_MAX_CONTENT_CHARS = 4000

VALID_VERDICTS = {"safe", "suspicious", "high_risk", "malicious"}
VALID_CONFIDENCES = {"low", "medium", "high"}


@dataclass
class LlmAnalysisResult:
    """Result from an LLM email analysis."""

    success: bool
    verdict: str = ""          # "safe" | "suspicious" | "high_risk" | "malicious"
    confidence: str = ""       # "low" | "medium" | "high"
    threat_types: list = None  # list of threat-type strings
    explanation: str = ""      # one-paragraph reasoning
    key_indicators: list = None  # list of specific finding strings
    error: str = ""            # set when success=False

    def __post_init__(self):
        if self.threat_types is None:
            self.threat_types = []
        if self.key_indicators is None:
            self.key_indicators = []


class GeminiProvider:
    """Gemini Flash API client for analyzing email content."""

    MODEL_NAME = "gemini-flash-latest"
    TIMEOUT_SECONDS = 10
    RATE_LIMIT_PER_MINUTE = 15

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.minute_limiter = RateLimiter(max_calls=self.RATE_LIMIT_PER_MINUTE, window_seconds=60)
        self._configured = False

    def analyze(self, system_prompt: str, email_content: str) -> LlmAnalysisResult:
        """Analyze email content with Gemini and return a structured result."""
        if not self.api_key:
            return LlmAnalysisResult(success=False, error="Gemini API key not configured")

        if not self.minute_limiter.try_acquire():
            return LlmAnalysisResult(success=False, error="Rate limit exceeded")

        # Lazy import — avoids import-time failure if the library isn't installed.
        if not self._configured:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self._configured = True
        import google.generativeai as genai

        if len(email_content) > _MAX_CONTENT_CHARS:
            email_content = email_content[:_MAX_CONTENT_CHARS] + "\n\n[... truncated]"

        user_prompt = (
            f"=== EMAIL TO ANALYZE (start) ===\n"
            f"{email_content}\n"
            f"=== EMAIL TO ANALYZE (end) ==="
        )

        generation_config = {
            "temperature": 0.1,
            "response_mime_type": "application/json",
        }

        model = genai.GenerativeModel(
            model_name=self.MODEL_NAME,
            system_instruction=system_prompt,
            generation_config=generation_config,
        )

        try:
            response = model.generate_content(
                user_prompt,
                request_options={"timeout": self.TIMEOUT_SECONDS},
            )
        except Exception as e:
            return LlmAnalysisResult(success=False, error=f"API error: {e}")

        try:
            data = json.loads(response.text)
        except (json.JSONDecodeError, ValueError):
            return LlmAnalysisResult(success=False, error="Invalid JSON from Gemini")

        if (
            data.get("verdict") not in VALID_VERDICTS
            or data.get("confidence") not in VALID_CONFIDENCES
            or not isinstance(data.get("threat_types"), list)
            or not isinstance(data.get("explanation"), str)
            or not isinstance(data.get("key_indicators"), list)
        ):
            return LlmAnalysisResult(success=False, error="Invalid response schema")

        return LlmAnalysisResult(
            success=True,
            verdict=data["verdict"],
            confidence=data["confidence"],
            threat_types=data["threat_types"],
            explanation=data["explanation"],
            key_indicators=data["key_indicators"],
        )
