import re

from models import Email, SignalResult
from signals.base import Signal
from signals.utils import parse_from_header


BRANDS = [
    {"name": "Microsoft", "aliases": ["microsoft"], "legitimate_domains": ["microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com"]},
    {"name": "Google", "aliases": ["google"], "legitimate_domains": ["google.com", "gmail.com", "youtube.com"]},
    {"name": "Apple", "aliases": ["apple", "icloud"], "legitimate_domains": ["apple.com", "icloud.com", "me.com"]},
    {"name": "Amazon", "aliases": ["amazon"], "legitimate_domains": ["amazon.com", "amazon.co.uk", "amazonses.com"]},
    {"name": "Meta", "aliases": ["meta", "facebook", "instagram"], "legitimate_domains": ["facebook.com", "facebookmail.com", "meta.com", "instagram.com"]},
    {"name": "LinkedIn", "aliases": ["linkedin"], "legitimate_domains": ["linkedin.com", "linkedinmail.com"]},
    {"name": "Netflix", "aliases": ["netflix"], "legitimate_domains": ["netflix.com", "mailer.netflix.com"]},
    {"name": "Dropbox", "aliases": ["dropbox"], "legitimate_domains": ["dropbox.com", "dropboxmail.com"]},
    {"name": "Adobe", "aliases": ["adobe"], "legitimate_domains": ["adobe.com", "adobesign.com"]},
    {"name": "PayPal", "aliases": ["paypal", "pay pal"], "legitimate_domains": ["paypal.com", "paypal.co.uk"]},
    {"name": "Visa", "aliases": ["visa"], "legitimate_domains": ["visa.com"]},
    {"name": "Mastercard", "aliases": ["mastercard", "master card"], "legitimate_domains": ["mastercard.com", "mastercard.us"]},
    {"name": "Chase", "aliases": ["chase"], "legitimate_domains": ["chase.com", "jpmorgan.com"]},
    {"name": "Bank of America", "aliases": ["bank of america", "bofa"], "legitimate_domains": ["bankofamerica.com", "bofa.com"]},
    {"name": "Wells Fargo", "aliases": ["wells fargo"], "legitimate_domains": ["wellsfargo.com"]},
    {"name": "DHL", "aliases": ["dhl"], "legitimate_domains": ["dhl.com", "dhl.de"]},
    {"name": "FedEx", "aliases": ["fedex", "fed ex"], "legitimate_domains": ["fedex.com"]},
    {"name": "UPS", "aliases": ["ups"], "legitimate_domains": ["ups.com"]},
    {"name": "USPS", "aliases": ["usps"], "legitimate_domains": ["usps.com"]},
    {"name": "IRS", "aliases": ["irs", "internal revenue"], "legitimate_domains": ["irs.gov"]},
    {"name": "HMRC", "aliases": ["hmrc"], "legitimate_domains": ["hmrc.gov.uk", "gov.uk"]},
    {"name": "AT&T", "aliases": ["at&t", "att"], "legitimate_domains": ["att.com", "attmail.com"]},
    {"name": "Verizon", "aliases": ["verizon"], "legitimate_domains": ["verizon.com", "verizonwireless.com"]},
    {"name": "eBay", "aliases": ["ebay"], "legitimate_domains": ["ebay.com", "ebay.co.uk"]},
    {"name": "Walmart", "aliases": ["walmart"], "legitimate_domains": ["walmart.com"]},
]


def _domain_matches(sender_domain: str, legitimate_domains: list) -> bool:
    """
    Returns True if sender_domain exactly matches or is a subdomain of any
    legitimate domain. All comparisons are case-insensitive.
    """
    sender = sender_domain.lower()
    for legit in legitimate_domains:
        legit = legit.lower()
        if sender == legit or sender.endswith("." + legit):
            return True
    return False


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

        for brand in BRANDS:
            for alias in brand["aliases"]:
                pattern = r"\b" + re.escape(alias) + r"\b"
                if re.search(pattern, lower_name, re.IGNORECASE):
                    if _domain_matches(sender_domain, brand["legitimate_domains"]):
                        return self._make_result(
                            triggered=False,
                            explanation=f"Display name references {brand['name']} and sender domain is legitimate",
                        )
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
