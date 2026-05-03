from models import Email, SignalResult
from signals.base import Signal

DANGEROUS_EXTENSIONS = frozenset({
    "exe", "scr", "bat", "com", "cmd", "pif", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "ps1", "psm1", "jar", "msi", "msp", "lnk", "iso", "img",
    "vhd", "hta", "cpl", "reg", "dll", "scf", "inf", "sys",
})


def _dangerous_extension(filename: str) -> str:
    """Return the dangerous extension from filename, or empty string if safe.

    Also catches double-extension tricks like 'invoice.pdf.exe' — the outer
    extension is what matters for execution.
    """
    # rsplit with maxsplit=1 takes only the outermost extension, which is what the OS
    # uses to determine file type. Inner extensions (e.g. ".pdf" in "report.pdf.exe") are cosmetic.
    parts = filename.rsplit(".", 1)
    if len(parts) < 2:
        return ""
    ext = parts[-1].lower()
    return ext if ext in DANGEROUS_EXTENSIONS else ""


class DangerousExtensionsSignal(Signal):
    """Detects attachments with file extensions associated with executable or malicious files."""

    name = "dangerous_extensions"
    weight = 25

    def evaluate(self, email: Email) -> SignalResult:
        if not email.attachments:
            return self._make_result(
                triggered=False,
                explanation="No attachments to analyze",
            )

        dangerous_files = []
        extensions_found = set()

        for attachment in email.attachments:
            filename = attachment.get("filename", "")
            ext = _dangerous_extension(filename)
            if ext:
                dangerous_files.append(filename)
                extensions_found.add(ext)

        if not dangerous_files:
            return self._make_result(
                triggered=False,
                explanation="No dangerous attachment extensions found",
            )

        return self._make_result(
            triggered=True,
            explanation=f"Found {len(dangerous_files)} attachment(s) with dangerous extension(s): {', '.join(sorted(extensions_found))}",
            metadata={
                "dangerous_files": dangerous_files,
                "extensions_found": sorted(extensions_found),
            },
        )
