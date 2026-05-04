"""Abstract ThreatIntelProvider interface and ThreatIntelResult dataclass."""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ThreatIntelResult:
    """Result from a threat intel lookup."""

    found: bool           # was the resource known to the provider?
    malicious_count: int  # number of vendors flagging it
    total_count: int      # total vendors that scanned it
    permalink: str = ""   # human-readable link to the report
    # error="" with found=False means "not in database" (clean).
    # error!="" means the lookup itself failed (network, rate limit, bad key) — treat as unknown, not clean.
    error: str = ""


class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    @abstractmethod
    def lookup_url(self, url: str) -> ThreatIntelResult:
        """Look up a URL and return its threat intel result."""
