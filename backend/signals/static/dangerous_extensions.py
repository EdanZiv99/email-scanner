"""Dangerous extensions signal: checks attachment filenames for executable file extensions."""
from models import Email, SignalResult
from signals.base import Signal

DANGEROUS_EXTENSIONS = frozenset({
    "exe", "scr", "bat", "com", "cmd", "pif", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "ps1", "psm1", "jar", "msi", "msp", "lnk", "iso", "img",
    "vhd", "hta", "cpl", "reg", "dll", "scf", "inf", "sys",
})

# Subset that warrants a trump card: high-confidence execution vectors with almost no
# legitimate use in email. Excludes container formats (.iso, .img, .jar) that have edge-case
# legitimate uses.
STRICT_DANGEROUS = frozenset({
    "exe", "scr", "bat", "com", "cmd", "pif",
    "vbs", "jse", "wsf", "hta", "msi",
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
        is_trump = False
        trump_reason = None

        for attachment in email.attachments:
            filename = attachment.get("filename", "")
            ext = _dangerous_extension(filename)
            if not ext:
                continue

            dangerous_files.append(filename)
            extensions_found.add(ext)

            # Double-extension trick (e.g. invoice.pdf.exe) is always a trump — it's a
            # deliberate attempt to disguise an executable as a benign file type.
            is_double = filename.count(".") >= 2
            if is_double:
                is_trump = True
                trump_reason = "double_extension"
            elif ext in STRICT_DANGEROUS and not is_trump:
                is_trump = True
                trump_reason = "strict_dangerous_extension"

        if not dangerous_files:
            return self._make_result(
                triggered=False,
                explanation="No dangerous attachment extensions found",
            )

        ext_list = ", ".join(sorted(extensions_found))
        if is_trump:
            explanation = f"High-severity attachment(s) detected ({ext_list}): {', '.join(dangerous_files)}"
        else:
            explanation = f"Found {len(dangerous_files)} attachment(s) with dangerous extension(s): {ext_list}"

        metadata = {
            "dangerous_files": dangerous_files,
            "extensions_found": sorted(extensions_found),
        }
        if is_trump:
            metadata["trump_reason"] = trump_reason

        return self._make_result(
            triggered=True,
            explanation=explanation,
            metadata=metadata,
            trump_card=is_trump,
        )
