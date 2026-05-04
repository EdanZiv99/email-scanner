"""Lookalike domain signal: flags sender domains within edit distance 1-2 of known brand domains."""
import tldextract
from rapidfuzz.distance import Levenshtein

from models import Email, SignalResult
from signals.base import Signal
from signals.data.brands import BRANDS, domain_matches
from signals.utils import parse_from_header

# Distance of 1-2 catches common substitutions (paypa1.com) and additions (paypalll.com)
# without too many false positives. Distance 3+ produces too much noise in practice.
_MIN_DOMAIN_LEN = 5  # short domains (e.g. "ups.com") hit too many unrelated matches at distance 2
_MAX_DISTANCE = 2

# Use bundled PSL snapshot — avoids network calls and makes behaviour deterministic.
_extractor = tldextract.TLDExtract(suffix_list_urls=())


def _registrable(domain: str):
    """Return (registrable_domain, suffix) using the public suffix list.

    Returns ("", "") for malformed or unrecognised inputs.
    tldextract v5: TLDExtract instances are callable, not .extract().
    """
    ext = _extractor(domain.lower())
    if not ext.domain or not ext.suffix:
        return "", ""
    return f"{ext.domain}.{ext.suffix}", ext.suffix


class LookalikeDomainSignal(Signal):
    """Detects sender domains visually similar to known brand domains (e.g. paypa1.com)."""

    name = "lookalike_domain"
    category = "Impersonation"
    weight = 20

    def evaluate(self, email: Email) -> SignalResult:
        from_header = email.headers_dict.get("from", "")
        _, _, sender_domain = parse_from_header(from_header)

        if not sender_domain:
            return self._make_result(
                triggered=False,
                explanation="Sender domain could not be extracted",
            )

        sender_registrable, sender_suffix = _registrable(sender_domain)

        best_distance = None
        best_legit = None
        best_brand = None

        # BRANDS and domain_matches live in signals/data/brands.py — shared with display_name.py.
        for brand in BRANDS:
            for legit in brand["legitimate_domains"]:
                # Exact/subdomain match: bail out immediately — no need to compute distances.
                if domain_matches(sender_domain, [legit]):
                    return self._make_result(
                        triggered=False,
                        explanation=f"Sender domain {sender_domain} is a legitimate domain for {brand['name']}",
                    )

                legit_registrable, legit_suffix = _registrable(legit)

                if not sender_registrable or not legit_registrable:
                    continue

                # Different public suffixes (e.g. .gov.il vs .gov.uk) cannot be lookalikes —
                # they are under entirely different TLD trees.
                if sender_suffix != legit_suffix:
                    continue

                if len(sender_registrable) < _MIN_DOMAIN_LEN or len(legit_registrable) < _MIN_DOMAIN_LEN:
                    continue

                distance = Levenshtein.distance(sender_registrable, legit_registrable)

                if 1 <= distance <= _MAX_DISTANCE:
                    if best_distance is None or distance < best_distance:
                        best_distance = distance
                        best_legit = legit
                        best_brand = brand["name"]

        if best_distance is not None:
            return self._make_result(
                triggered=True,
                explanation=f"Sender domain '{sender_domain}' closely resembles legitimate brand domain '{best_legit}' (edit distance: {best_distance}).",
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
