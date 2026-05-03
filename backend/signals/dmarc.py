import re

from models import Email, SignalResult
from signals.base import Signal


class DmarcSignal(Signal):
    """Checks the Authentication-Results header for a DMARC pass/fail verdict."""

    name = "dmarc"
    weight = 20

    def evaluate(self, email: Email) -> SignalResult:
        auth_results = email.headers_dict.get("authentication-results")

        if auth_results is None:
            return self._make_result(
                triggered=True,
                explanation="DMARC authentication result not found in headers",
                metadata={},
            )

        match = re.search(r"dmarc=(\w+)", auth_results, re.IGNORECASE)

        if match is None:
            return self._make_result(
                triggered=True,
                explanation="DMARC authentication result not found in headers",
                metadata={"authentication-results": auth_results},
            )

        verdict = match.group(1).lower()

        if verdict == "pass":
            return self._make_result(
                triggered=False,
                explanation="DMARC authentication passed",
                metadata={"authentication-results": auth_results},
            )

        return self._make_result(
            triggered=True,
            explanation="DMARC authentication failed",
            metadata={"authentication-results": auth_results, "dmarc_result": verdict},
        )
