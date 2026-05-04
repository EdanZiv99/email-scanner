"""URL/href mismatch signal: flags links where visible text shows a different domain than the href."""
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from models import Email, SignalResult
from signals.base import Signal

# Only flag links where the visible text itself looks like a domain — avoids false positives
# on legitimate "Click here" or "Read more" anchor text that links to a different domain.
_DOMAIN_PATTERN = re.compile(r'\b[\w\-]+\.[a-z]{2,}\b', re.IGNORECASE)
_SKIP_SCHEMES = {"mailto", "tel", "javascript"}


def _extract_domain(url: str) -> str:
    """Return the bare hostname from a URL, lowercased and without www. prefix."""
    try:
        netloc = urlparse(url).netloc
        host = netloc.split(":")[0].lower()
        # Strip www. so "www.paypal.com" in visible text matches "paypal.com" href.
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def _extract_visible_domain(text: str) -> str:
    """Return the first domain-like pattern found in visible text, without www. prefix."""
    match = _DOMAIN_PATTERN.search(text)
    if not match:
        return ""
    domain = match.group(0).lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _domains_related(a: str, b: str) -> bool:
    """Return True if a == b or one is a subdomain of the other."""
    if a == b:
        return True
    return a.endswith("." + b) or b.endswith("." + a)


class _LinkParser(HTMLParser):
    """Collects (href, visible_text) pairs from anchor tags."""

    def __init__(self):
        super().__init__()
        self._links = []
        self._current_href = None
        self._current_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            attrs_dict = dict(attrs)
            self._current_href = attrs_dict.get("href", "")
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            self._links.append((self._current_href, "".join(self._current_text).strip()))
            self._current_href = None
            self._current_text = []

    @property
    def links(self):
        return self._links


class UrlHrefMismatchSignal(Signal):
    """Detects anchor tags where the visible text domain differs from the href destination."""

    name = "url_href_mismatch"
    category = "Suspicious Links"
    weight = 18

    def evaluate(self, email: Email) -> SignalResult:
        if not email.html_body:
            return self._make_result(
                triggered=False,
                explanation="No HTML body to analyze",
            )

        parser = _LinkParser()
        parser.feed(email.html_body)

        mismatches = []
        for href, visible_text in parser.links:
            if not href or href in ("#",):
                continue

            scheme = urlparse(href).scheme.lower()
            if scheme in _SKIP_SCHEMES:
                continue

            visible_domain = _extract_visible_domain(visible_text)
            if not visible_domain:
                continue

            href_domain = _extract_domain(href)
            if not href_domain:
                continue

            if not _domains_related(visible_domain, href_domain):
                mismatches.append((visible_domain, href_domain))

        if not mismatches:
            return self._make_result(
                triggered=False,
                explanation="No URL/href mismatches found",
            )

        visible, actual = mismatches[0]
        n = len(mismatches)
        explanation = (
            f"Link displays '{visible}' but actually goes to '{actual}'."
            if n == 1 else
            f"Link displays '{visible}' but actually goes to '{actual}' ({n} similar mismatches found)."
        )
        return self._make_result(
            triggered=True,
            explanation=explanation,
            metadata={
                "mismatch_count": len(mismatches),
                "first_mismatch": {
                    "visible": visible,
                    "actual": actual,
                },
            },
        )
