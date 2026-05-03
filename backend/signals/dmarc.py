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
                triggered=False,
                explanation="DMARC could not be evaluated: Authentication-Results header is missing",
                metadata={},
            )

        match = re.search(r"dmarc=(\w+)", auth_results, re.IGNORECASE)

        if match is None:
            return self._make_result(
                triggered=False,
                explanation="DMARC could not be evaluated: no DMARC result reported in Authentication-Results",
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
            explanation=f"DMARC authentication failed with result: {verdict}",
            metadata={"authentication-results": auth_results, "dmarc_result": verdict},
        )
