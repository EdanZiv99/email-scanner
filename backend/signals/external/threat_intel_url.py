"""Threat intel signal: checks URLs extracted from the HTML body against VirusTotal."""
import logging

from models import Email, SignalResult
from providers.virustotal import VirusTotalProvider
from signals.base import Signal
from signals.utils import extract_domain_from_url, extract_urls_from_html

logger = logging.getLogger(__name__)

# Skip lookups for high-traffic legitimate domains to conserve the rate-limited API quota.
# These are trusted a priori; checking them wastes calls on the free tier (500/day).
KNOWN_GOOD_DOMAINS = frozenset({
    "google.com", "gmail.com", "youtube.com", "microsoft.com", "office.com",
    "outlook.com", "live.com", "apple.com", "icloud.com", "amazon.com",
    "facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com",
    "github.com", "wikipedia.org",
})

# Free tier allows 4 req/min. Checking 3 URLs leaves 1 call of headroom per minute window.
MAX_URLS_TO_CHECK = 3


def _is_known_good(domain: str) -> bool:
    return domain in KNOWN_GOOD_DOMAINS or any(
        domain.endswith("." + good) for good in KNOWN_GOOD_DOMAINS
    )


def _dynamic_weight(malicious_count: int) -> int:
    # 1-2 vendors: possible false positive (aggressive heuristics). 3-5: likely malicious.
    # 6+: broad consensus — near-certain threat.
    if malicious_count >= 6:
        return 35
    if malicious_count >= 3:
        return 25
    return 15


def _is_trump(malicious_count: int) -> bool:
    # 10+ vendors is overwhelming consensus — no reasonable scoring outcome should yield "Safe".
    return malicious_count >= 10


class ThreatIntelUrlSignal(Signal):
    """Checks URLs extracted from the HTML body against VirusTotal."""

    name = "threat_intel_url"
    weight = 30  # default; overridden dynamically based on malicious vendor count

    def __init__(self, provider=None):
        # Inject a provider to enable unit testing without hitting the real VT API.
        self._provider = provider or VirusTotalProvider()

    def evaluate(self, email: Email) -> SignalResult:
        if not email.html_body:
            return self._make_result(
                triggered=False,
                explanation="No HTML body to analyze",
            )

        all_urls = extract_urls_from_html(email.html_body)
        urls_to_check = [u for u in all_urls if not _is_known_good(extract_domain_from_url(u))]
        urls_to_check = urls_to_check[:MAX_URLS_TO_CHECK]

        if not urls_to_check:
            return self._make_result(
                triggered=False,
                explanation="No URLs to check (all filtered as known-good or none found)",
            )

        max_malicious = 0
        max_total = 0
        worst_url = ""
        permalink = ""
        errors = []

        for url in urls_to_check:
            try:
                result = self._provider.lookup_url(url)
            except Exception as e:
                # Provider errors must never propagate — a broken lookup should not crash scoring.
                logger.exception("Unexpected error from threat intel provider for URL %r", url)
                errors.append(f"Unexpected error for {url}: {e}")
                continue

            if result.error:
                errors.append(result.error)
                continue

            if result.malicious_count > max_malicious:
                max_malicious = result.malicious_count
                max_total = result.total_count
                worst_url = url
                permalink = result.permalink

        if errors and max_malicious == 0:
            return self._make_result(
                triggered=False,
                explanation=f"Threat intel lookup could not complete: {errors[0]}",
                metadata={"errors": errors},
            )

        if max_malicious == 0:
            return self._make_result(
                triggered=False,
                explanation=f"No malicious URLs detected ({len(urls_to_check)} URL(s) checked)",
                metadata={"urls_checked": len(urls_to_check), "errors": errors},
            )

        return self._make_result(
            triggered=True,
            explanation=f"URL flagged as malicious by {max_malicious}/{max_total} vendors: {worst_url}",
            weight=_dynamic_weight(max_malicious),
            trump_card=_is_trump(max_malicious),
            metadata={
                "urls_checked": len(urls_to_check),
                "max_malicious": max_malicious,
                "max_total": max_total,
                "worst_url": worst_url,
                "permalink": permalink,
                "errors": errors,
            },
        )
