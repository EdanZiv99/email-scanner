"""Shared parsing helpers used by multiple signals."""
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse


def parse_from_header(from_header: str) -> tuple:
    """
    Parse a From header into (display_name, address, domain).

    Uses email.utils.parseaddr from stdlib. Returns empty strings for any
    component that cannot be extracted. Domain is lowercased and extracted
    from the address (everything after the last @).
    """
    if not from_header:
        return ("", "", "")

    # parseaddr returns ("", "") for completely malformed input — never raises.
    display_name, address = parseaddr(from_header)

    if not address or "@" not in address:
        return (display_name, address, "")

    domain = address.rsplit("@", 1)[-1].lower()

    return (display_name, address, domain)


class _HrefCollector(HTMLParser):
    """Collects href values from anchor tags."""

    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.hrefs.append(value)


_SKIP_PREFIXES = ("mailto:", "tel:", "javascript:", "#")


def extract_urls_from_html(html: str) -> list:
    """Extract unique HTTP/HTTPS URLs from anchor href attributes in an HTML string."""
    if not html:
        return []

    collector = _HrefCollector()
    collector.feed(html)

    seen = set()
    urls = []
    for href in collector.hrefs:
        stripped = href.strip()
        if any(stripped.lower().startswith(p) for p in _SKIP_PREFIXES):
            continue
        if stripped not in seen:
            seen.add(stripped)
            urls.append(stripped)
    return urls


def extract_domain_from_url(url: str) -> str:
    """Return the lowercased hostname from a URL, without www. prefix or port."""
    try:
        host = urlparse(url).netloc.split(":")[0].lower()
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""
