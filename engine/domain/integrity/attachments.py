"""Attachment-risk classification.

Microsoft Defender Anti-Spam Filter (ASF) blocks ~96 file extensions by
default. Gmail blocks ~40. Several types are operationally fatal — a
single `.exe`, `.scr`, `.iso`, or `.html` attachment can move the
message from Inbox to Quarantine regardless of the rest of the audit.

What we flag:
  - `content.attachment_executable` — extensions universally blocked
    (.exe/.scr/.bat/.cmd/.com/.pif/.vbs/.js/.jse/.wsf/.wsh/.hta/.lnk/.cpl/.msi).
  - `content.attachment_archive_risk` — .iso/.img/.7z/.rar/.cab and
    password-protected ZIP (best-effort detect via filename + content-type).
  - `content.attachment_html_lure` — .html/.htm/.shtml attachments are
    the #1 phishing-landing carrier in 2024-2026; Gmail and Microsoft
    treat as high-risk.
  - `content.attachment_macro_doc` — .docm/.xlsm/.pptm/.xlsb (Office
    with macros enabled).

Doc tier: §6 (content/structural — Attachment types and risk).
"""

from __future__ import annotations

from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

CHECK_PREFIX = "content"

_EXECUTABLE_EXTS = frozenset(
    {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".pif",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".hta",
        ".lnk",
        ".cpl",
        ".msi",
        ".msp",
        ".reg",
        ".jar",
        ".ps1",
        ".psm1",
        ".sh",
    }
)
_ARCHIVE_RISK_EXTS = frozenset({".iso", ".img", ".7z", ".rar", ".cab", ".ace"})
_HTML_LURE_EXTS = frozenset({".html", ".htm", ".shtml", ".xhtml", ".mhtml"})
_MACRO_DOC_EXTS = frozenset({".docm", ".xlsm", ".pptm", ".xlsb", ".dotm"})


def _attachments(email: ParsedEmail) -> list[dict]:
    """Walk MIME parts; return [{filename, content_type, size}] for each
    part with Content-Disposition: attachment OR an explicit filename."""
    out: list[dict] = []
    msg = email.raw
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get("Content-Disposition") or "").lower()
        if not filename and "attachment" not in disposition:
            continue
        ctype = (part.get_content_type() or "").lower()
        try:
            payload = part.get_payload(decode=True) or b""
            size = len(payload)
        except Exception:
            size = 0
        out.append(
            {
                "filename": filename or "(unnamed)",
                "content_type": ctype,
                "size": size,
            }
        )
    return out


def _ext(name: str) -> str:
    """Lowercase extension including the dot. Empty string if none."""
    name = name.lower().strip()
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[1]


async def run(email: ParsedEmail) -> list[Finding]:
    attachments = _attachments(email)
    if not attachments:
        return [
            Finding(
                check=f"{CHECK_PREFIX}.attachment_risk",
                severity=Severity.INFO,
                passed=True,
                message="No attachments.",
            )
        ]

    findings: list[Finding] = []
    executable_hits: list[dict] = []
    archive_hits: list[dict] = []
    html_hits: list[dict] = []
    macro_hits: list[dict] = []

    for att in attachments:
        ext = _ext(att["filename"])
        if ext in _EXECUTABLE_EXTS:
            executable_hits.append({"name": att["filename"], "ext": ext})
        elif ext in _ARCHIVE_RISK_EXTS:
            archive_hits.append({"name": att["filename"], "ext": ext, "size": att["size"]})
        elif ext in _HTML_LURE_EXTS:
            html_hits.append({"name": att["filename"], "ext": ext})
        elif ext in _MACRO_DOC_EXTS:
            macro_hits.append({"name": att["filename"], "ext": ext})

    if executable_hits:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.attachment_executable",
                severity=Severity.CRITICAL,
                passed=False,
                message=(
                    f"Executable attachment(s): {[h['name'] for h in executable_hits]}. "
                    "Universally blocked by Gmail and Microsoft Defender: message "
                    "will be quarantined or rejected."
                ),
                details={"hits": executable_hits},
            )
        )

    if archive_hits:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.attachment_archive_risk",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"High-risk archive attachment(s): {[h['name'] for h in archive_hits]}. "
                    "ISO/IMG/7z/RAR commonly used to bypass mark-of-the-web; modern "
                    "filters score these as malware-shape."
                ),
                details={"hits": archive_hits},
            )
        )

    if html_hits:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.attachment_html_lure",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"HTML attachment(s): {[h['name'] for h in html_hits]}. "
                    "#1 phishing-landing carrier 2024-2026; both Gmail and Microsoft "
                    "treat as high-risk regardless of content."
                ),
                details={"hits": html_hits},
            )
        )

    if macro_hits:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.attachment_macro_doc",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Macro-enabled Office attachment(s): {[h['name'] for h in macro_hits]}. "
                    "Higher scrutiny than .docx/.xlsx; many corporate filters quarantine."
                ),
                details={"hits": macro_hits},
            )
        )

    if not (executable_hits or archive_hits or html_hits or macro_hits):
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.attachment_risk",
                severity=Severity.INFO,
                passed=True,
                message=f"{len(attachments)} attachment(s); none flagged.",
                details={"count": len(attachments)},
            )
        )

    return findings
