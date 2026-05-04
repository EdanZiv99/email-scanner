"""Runs all signals against an Email and returns the collected SignalResult list."""
import logging

from models import Email, SignalResult
from signals.external.threat_intel_url import ThreatIntelUrlSignal
from signals.static.dangerous_extensions import DangerousExtensionsSignal
from signals.static.display_name import DisplayNameBrandImpersonationSignal, DisplayNameEmailSpoofSignal
from signals.static.dmarc import DmarcSignal
from signals.static.lookalike_domain import LookalikeDomainSignal
from signals.static.reply_to_mismatch import ReplyToMismatchSignal
from signals.static.url_href_mismatch import UrlHrefMismatchSignal

logger = logging.getLogger(__name__)

# Instantiated once at module load, not per request — lets stateful signals
# (e.g. ThreatIntelUrlSignal's rate limiter) persist their state across requests.
_SIGNALS = [
    DmarcSignal(),
    DisplayNameEmailSpoofSignal(),
    DisplayNameBrandImpersonationSignal(),
    LookalikeDomainSignal(),
    UrlHrefMismatchSignal(),
    DangerousExtensionsSignal(),
    ThreatIntelUrlSignal(),
    ReplyToMismatchSignal(),
]

# Singleton for the on-demand LLM signal — preserves rate limiter state across requests.
_gemini_signal = None


def run_signals(email: Email) -> list:
    """Run all registered signals against the email and return their results.

    Defensive: a signal that raises an exception is logged and replaced with a
    non-triggered result so the rest of scoring continues unaffected.
    """
    results = []
    for signal in _SIGNALS:
        try:
            results.append(signal.evaluate(email))
        except Exception:
            # Broad catch is intentional: a malformed email must never be able to crash the scorer
            # via a parser exploit in one signal. Failed signals surface as non-triggered so the
            # remaining signals still run and the user still gets a (partial) result.
            logger.exception("Signal %r raised an unexpected error", signal.name)
            results.append(SignalResult(
                signal_name=signal.name,
                triggered=False,
                weight=signal.weight,
                explanation=f"Signal '{signal.name}' encountered an error and was skipped",
                metadata={},
            ))
    return results


def run_llm_analysis_only(email: Email) -> SignalResult:
    """Run only the Gemini analysis signal. Used by the on-demand /scan/llm endpoint."""
    global _gemini_signal
    if _gemini_signal is None:
        from signals.external.gemini_analysis import GeminiAnalysisSignal
        _gemini_signal = GeminiAnalysisSignal()

    try:
        return _gemini_signal.evaluate(email)
    except Exception as e:
        logger.exception("GeminiAnalysisSignal raised an unexpected error")
        return SignalResult(
            signal_name="gemini_analysis",
            category="AI Analysis",
            triggered=False,
            weight=0,
            explanation=f"AI analysis failed unexpectedly: {e}",
        )
