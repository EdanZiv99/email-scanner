"""Detects Reply-To headers that redirect replies to a different domain than the From sender."""

from models import Email, SignalResult
from signals.base import Signal
from signals.utils import parse_from_header


def _registrable_part(domain: str) -> str:
    """Return the last two dot-separated labels of a domain (e.g. 'mail.github.com' → 'github.com').

    Limitation: does not handle public-suffix edge cases like 'co.uk' — 'bank.co.uk' would
    return 'co.uk' rather than 'bank.co.uk'. Acceptable for MVP.
    """
    parts = domain.split(".")
    if len(parts) < 2:
        return domain
    return ".".join(parts[-2:])


class ReplyToMismatchSignal(Signal):
    """Detects BEC/phishing emails where Reply-To redirects replies to an attacker-controlled domain."""

    name = "reply_to_mismatch"
    weight = 14

    def evaluate(self, email: Email) -> SignalResult:
        from_header = email.headers_dict.get("from", "")
        _, _, from_domain = parse_from_header(from_header)

        if not from_domain:
            return self._make_result(
                triggered=False,
                explanation="From domain could not be extracted",
            )

        reply_to_header = email.headers_dict.get("reply-to", "")

        if not reply_to_header:
            return self._make_result(
                triggered=False,
                explanation="No Reply-To header present",
            )

        _, _, reply_to_domain = parse_from_header(reply_to_header)

        if not reply_to_domain:
            return self._make_result(
                triggered=False,
                explanation="Reply-To header could not be parsed",
            )

        from_registrable = _registrable_part(from_domain)
        reply_to_registrable = _registrable_part(reply_to_domain)

        if from_registrable == reply_to_registrable:
            return self._make_result(
                triggered=False,
                explanation=f"Reply-To domain matches From domain ({from_registrable})",
            )

        return self._make_result(
            triggered=True,
            explanation=f"Reply-To domain '{reply_to_domain}' differs from From domain '{from_domain}'. Replies will go to a different organization.",
            metadata={
                "from_domain": from_domain,
                "reply_to_domain": reply_to_domain,
                "from_registrable": from_registrable,
                "reply_to_registrable": reply_to_registrable,
            },
        )
