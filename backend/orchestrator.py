import logging

from models import Email, SignalResult
from signals.display_name import DisplayNameBrandImpersonationSignal, DisplayNameEmailSpoofSignal
from signals.dmarc import DmarcSignal

logger = logging.getLogger(__name__)

_SIGNALS = [
    DmarcSignal(),
    DisplayNameEmailSpoofSignal(),
    DisplayNameBrandImpersonationSignal(),
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
            logger.exception("Signal %r raised an unexpected error", signal.name)
            results.append(SignalResult(
                signal_name=signal.name,
                triggered=False,
                weight=signal.weight,
                explanation=f"Signal '{signal.name}' encountered an error and was skipped",
                metadata={},
            ))
    return results
