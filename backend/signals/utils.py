from email.utils import parseaddr


def parse_from_header(from_header: str) -> tuple:
    """
    Parse a From header into (display_name, address, domain).

    Uses email.utils.parseaddr from stdlib. Returns empty strings for any
    component that cannot be extracted. Domain is lowercased and extracted
    from the address (everything after the last @).
    """
    if not from_header:
        return ("", "", "")

    display_name, address = parseaddr(from_header)

    if not address or "@" not in address:
        return (display_name, address, "")

    domain = address.rsplit("@", 1)[-1].lower()

    return (display_name, address, domain)
