import email as email_lib
from dataclasses import dataclass, field


@dataclass
class Email:
    """Represents an email message extracted from the Gmail Add-on."""

    from_address: str
    subject: str
    message_id: str
    raw_headers: str  # full RFC822 header block as a single string
    html_body: str = ""
    text_body: str = ""

    @property
    def headers_dict(self) -> dict:
        """Parse raw_headers into a lowercase-keyed dict using stdlib."""
        # Append empty body terminator if not already present
        text = self.raw_headers
        if not text.endswith("\r\n\r\n") and not text.endswith("\n\n"):
            text = text + "\r\n\r\n"
        msg = email_lib.message_from_string(self.raw_headers)
        return {k.lower(): v for k, v in msg.items()}


@dataclass
class SignalResult:
    """The outcome of running a single signal against an email."""

    signal_name: str
    triggered: bool
    weight: int       # points added to total score when triggered
    explanation: str  # human-readable verdict shown to the user
    metadata: dict = field(default_factory=dict)  # debug info, not shown to user
