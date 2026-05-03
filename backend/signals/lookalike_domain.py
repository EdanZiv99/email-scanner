"""Lookalike domain signal: flags sender domains within edit distance 1-2 of known brand domains."""
from rapidfuzz.distance import Levenshtein

from models import Email, SignalResult
from signals.base import Signal
from signals.brands import BRANDS, domain_matches
from signals.utils import parse_from_header

# Distance of 1-2 catches common substitutions (paypa1.com) and additions (paypalll.com)
# without too many false positives. Distance 3+ produces too much noise in practice.
_MIN_DOMAIN_LEN = 5  # short domains (e.g. "ups.com") hit too many unrelated matches at distance 2
_MAX_DISTANCE = 2


def _registrable_part(domain: str) -> str:
    """Return the registrable domain (last 2 labels, e.g. 'mail.paypal.com' → 'paypal.com').

    Limitation: this naive split does not handle public-suffix edge cases like
    'co.uk' — 'bank.co.uk' would be returned as-is rather than trimmed further.
    """
    parts = domain.split(".")
    if len(parts) > 2:
        return ".".join(parts[-2:])
    return domain


class LookalikeDomainSignal(Signal):
    """Detects sender domains visually similar to known brand domains (e.g. paypa1.com)."""

    name = "lookalike_domain"
    weight = 20

    def evaluate(self, email: Email) -> SignalResult:
        from_header = email.headers_dict.get("from", "")
        _, _, sender_domain = parse_from_header(from_header)

        if not sender_domain:
            return self._make_result(
                triggered=False,
                explanation="Sender domain could not be extracted",
            )

        candidate = _registrable_part(sender_domain.lower())

        best_distance = None
        best_legit = None
        best_brand = None

        # BRANDS and domain_matches live in signals/brands.py — shared with display_name.py.
        for brand in BRANDS:
            for legit in brand["legitimate_domains"]:
                # Exact/subdomain match: bail out immediately — no need to compute distances.
                if domain_matches(sender_domain, [legit]):
                    return self._make_result(
                        triggered=False,
                        explanation=f"Sender domain {sender_domain} is a legitimate domain for {brand['name']}",
                    )

                legit_candidate = _registrable_part(legit.lower())

                if len(candidate) < _MIN_DOMAIN_LEN or len(legit_candidate) < _MIN_DOMAIN_LEN:
                    continue

                distance = Levenshtein.distance(candidate, legit_candidate)

                if 1 <= distance <= _MAX_DISTANCE:
                    if best_distance is None or distance < best_distance:
                        best_distance = distance
                        best_legit = legit
                        best_brand = brand["name"]

        if best_distance is not None:
            return self._make_result(
                triggered=True,
                explanation=f"Sender domain {sender_domain} closely resembles the legitimate {best_brand} domain {best_legit}",
                metadata={
                    "sender_domain": sender_domain,
                    "lookalike_of": best_legit,
                    "brand": best_brand,
                    "edit_distance": best_distance,
                },
            )

        return self._make_result(
            triggered=False,
            explanation="Sender domain does not closely resemble any known brand domain",
        )
