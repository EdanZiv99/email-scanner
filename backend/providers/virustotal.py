import base64
import os

import requests

from providers.base import ThreatIntelProvider, ThreatIntelResult
from providers.rate_limit import RateLimiter


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal v3 API client. Lookup-only — does not submit URLs for scanning."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = None):
        # api_key resolved at construction time so the provider is testable with an injected key
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
        # Free tier: 4 requests per minute, 500 per day
        self.minute_limiter = RateLimiter(max_calls=4, window_seconds=60)
        self.daily_limiter = RateLimiter(max_calls=500, window_seconds=86400)

    def lookup_url(self, url: str) -> ThreatIntelResult:
        """Look up a URL in VirusTotal and return the analysis result."""
        if not self.api_key:
            return ThreatIntelResult(
                found=False, malicious_count=0, total_count=0,
                error="VirusTotal API key not configured",
            )

        if not self.minute_limiter.try_acquire():
            return ThreatIntelResult(
                found=False, malicious_count=0, total_count=0,
                error="Rate limit exceeded (per-minute)",
            )

        if not self.daily_limiter.try_acquire():
            return ThreatIntelResult(
                found=False, malicious_count=0, total_count=0,
                error="Rate limit exceeded (daily)",
            )

        # VT v3 URL ID = base64url(url) with no padding — required by the API spec.
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        try:
            response = requests.get(
                f"{self.BASE_URL}/urls/{url_id}",
                headers={"x-apikey": self.api_key},
                timeout=10,
            )
        except requests.exceptions.RequestException as e:
            return ThreatIntelResult(
                found=False, malicious_count=0, total_count=0,
                error=f"Network error: {e}",
            )

        # 404 means VT has never seen this URL — not a threat, not an error.
        if response.status_code == 404:
            return ThreatIntelResult(found=False, malicious_count=0, total_count=0)

        if response.status_code != 200:
            return ThreatIntelResult(
                found=False, malicious_count=0, total_count=0,
                error=f"VT API returned {response.status_code}",
            )

        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        permalink = f"https://www.virustotal.com/gui/url/{url_id}"

        return ThreatIntelResult(
            found=True,
            malicious_count=malicious,
            total_count=total,
            permalink=permalink,
        )
