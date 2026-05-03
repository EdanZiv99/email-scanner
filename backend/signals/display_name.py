import re

from models import Email, SignalResult
from signals.base import Signal
from signals.brands import BRANDS, domain_matches
from signals.utils import parse_from_header


class DisplayNameEmailSpoofSignal(Signal):
    """Detects when the display name contains an email address from a different domain than the actual sender."""

    name = "display_name_email_spoof"
    weight = 25

    def evaluate(self, email: Email) -> SignalResult:
        from_header = email.headers_dict.get("from", "")
        display_name, address, sender_domain = parse_from_header(from_header)

        if not display_name or not address:
            return self._make_result(
                triggered=False,
                explanation="Display name or sender address not present",
            )

        match = re.search(r"[\w\.\-]+@[\w\.\-]+\.\w+", display_name)

        if match is None:
            return self._make_result(
                triggered=False,
                explanation="No email address found in display name",
            )

        claimed_address = match.group(0)
        claimed_domain = claimed_address.rsplit("@", 1)[-1].lower()

        if claimed_domain == sender_domain:
            return self._make_result(
                triggered=False,
                explanation="Display name email address matches actual sender domain",
            )

        return self._make_result(
            triggered=True,
            explanation=f"Display name impersonates email address {claimed_address} but message was sent from {address}",
            metadata={
                "claimed_address": claimed_address,
                "actual_address": address,
            },
        )


class DisplayNameBrandImpersonationSignal(Signal):
    """Detects when the display name references a known brand but the sender domain is not legitimate."""

    name = "display_name_brand_impersonation"
    weight = 12

    def evaluate(self, email: Email) -> SignalResult:
        from_header = email.headers_dict.get("from", "")
        display_name, _, sender_domain = parse_from_header(from_header)

        if not display_name:
            return self._make_result(
                triggered=False,
                explanation="No display name present",
            )

        lower_name = display_name.lower()

        # BRANDS and domain_matches live in signals/brands.py — shared with lookalike_domain.py.
        for brand in BRANDS:
            for alias in brand["aliases"]:
                # Word boundaries prevent "matters" from matching "att" or "attacker" from matching "att".
                pattern = r"\b" + re.escape(alias) + r"\b"
                if re.search(pattern, lower_name, re.IGNORECASE):
                    if domain_matches(sender_domain, brand["legitimate_domains"]):
                        return self._make_result(
                            triggered=False,
                            explanation=f"Display name references {brand['name']} and sender domain is legitimate",
                        )
                    # TODO: if the display name matches multiple brands (e.g. "Apple News from Microsoft"),
                    # only the first match in BRANDS order is returned. This is an acceptable MVP limitation.
                    return self._make_result(
                        triggered=True,
                        explanation=f"Display name impersonates {brand['name']} but sender domain {sender_domain} is not a known legitimate domain for that brand",
                        metadata={
                            "impersonated_brand": brand["name"],
                            "matched_alias": alias,
                            "sender_domain": sender_domain,
                            "legitimate_domains": brand["legitimate_domains"],
                        },
                    )

        return self._make_result(
            triggered=False,
            explanation="Display name does not reference any known brand",
        )
