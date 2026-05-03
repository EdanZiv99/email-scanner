import logging

from models import Email, SignalResult
from signals.dangerous_extensions import DangerousExtensionsSignal
from signals.display_name import DisplayNameBrandImpersonationSignal, DisplayNameEmailSpoofSignal
from signals.dmarc import DmarcSignal
from signals.lookalike_domain import LookalikeDomainSignal
from signals.threat_intel_url import ThreatIntelUrlSignal
from signals.url_href_mismatch import UrlHrefMismatchSignal

logger = logging.getLogger(__name__)

_SIGNALS = [
    DmarcSignal(),
    DisplayNameEmailSpoofSignal(),
    DisplayNameBrandImpersonationSignal(),
    LookalikeDomainSignal(),
    UrlHrefMismatchSignal(),
    DangerousExtensionsSignal(),
    ThreatIntelUrlSignal(),
]


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
