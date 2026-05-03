from abc import ABC, abstractmethod

from models import Email, SignalResult


class Signal(ABC):
    """Abstract base class for all email analysis signals."""

    name: str    # e.g. "dmarc"
    weight: int  # score contribution when triggered

    @abstractmethod
    def evaluate(self, email: Email) -> SignalResult:
        """Run the signal against the email and return a result."""

    def _make_result(self, triggered: bool, explanation: str, metadata: dict = None) -> SignalResult:
        """Convenience constructor that fills in signal_name and weight automatically."""
        return SignalResult(
            signal_name=self.name,
            triggered=triggered,
            weight=self.weight,
            explanation=explanation,
            metadata=metadata or {},
        )
