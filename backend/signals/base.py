from abc import ABC, abstractmethod

from models import Email, SignalResult


class Signal(ABC):
    """Abstract base class for all email analysis signals."""

    name: str    # e.g. "dmarc"
    weight: int  # score contribution when triggered

    @abstractmethod
    def evaluate(self, email: Email) -> SignalResult:
        """Run the signal against the email and return a result."""

    def _make_result(self, triggered: bool, explanation: str, metadata: dict = None,
                     weight: int = None, trump_card: bool = False) -> SignalResult:
        """Convenience constructor that fills in signal_name and weight automatically.

        Pass weight to override the class-level default for dynamic severity scoring.
        Pass trump_card=True to force verdict to "Malicious" regardless of total score.
        """
        return SignalResult(
            signal_name=self.name,
            triggered=triggered,
            weight=weight if weight is not None else self.weight,
            explanation=explanation,
            metadata=metadata or {},
            trump_card=trump_card,
        )
