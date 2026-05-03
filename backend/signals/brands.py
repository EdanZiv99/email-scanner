"""Known brand registry and domain helper. Used by display_name.py and lookalike_domain.py."""

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


def domain_matches(sender_domain: str, legitimate_domains: list) -> bool:
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
