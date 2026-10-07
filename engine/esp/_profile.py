"""ESP profile data classes.

`ProfileSpec` is a static declaration each vendor module exports.
`ESPProfile` is the runtime detection result handed to checks.

The split lets specs stay frozen + comparable while runtime profiles
carry a confidence score from the cascade in `_detect.py`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProfileSpec:
    name: str
    # Vendor-specific headers. Presence = ~0.95 confidence.
    vendor_headers: tuple[str, ...] = ()
    # Substrings checked against the lowercased Feedback-ID header.
    feedback_id_tokens: tuple[str, ...] = ()
    # DKIM `d=` domains (or DNS suffixes) the ESP signs with.
    signing_domains: tuple[str, ...] = ()
    # Body substrings that betray the ESP (footer text, link host).
    chrome_markers: tuple[str, ...] = ()
    # Regexes matched against text in display:none / preview-text spans.
    # If any matches a hidden-text hit, that hit is template chrome.
    preview_text_patterns: tuple[str, ...] = ()
    # Host substrings present in the List-Unsubscribe / footer link host
    # that confirm ESP ownership of footer zero-width injection.
    unsubscribe_host_markers: tuple[str, ...] = ()
    support_url: str | None = None

    def score(
        self,
        header_names: set[str],
        feedback_id: str,
        dkim_domains: set[str],
        body_lower: str,
        unsub_hosts: set[str],
    ) -> float:
        s = 0.0
        for h in self.vendor_headers:
            if h.lower() in header_names:
                s = max(s, 0.95)
        for tok in self.feedback_id_tokens:
            if tok in feedback_id:
                s = max(s, 0.9)
        for d in self.signing_domains:
            dl = d.lower()
            if any(kd == dl or kd.endswith("." + dl) for kd in dkim_domains):
                s = max(s, 0.75)
        for marker in self.unsubscribe_host_markers:
            if any(marker in h for h in unsub_hosts):
                s = max(s, 0.7)
        for marker in self.chrome_markers:
            if marker.lower() in body_lower:
                s = max(s, 0.55)
        return s


@dataclass
class ESPProfile:
    """Runtime ESP detection result. Consumed by checks to demote
    severity of findings caused by template chrome (preview-text span,
    footer zero-width characters, merge-tag artefacts).
    """
    name: str
    confidence: float
    signing_domains: list[str] = field(default_factory=list)
    chrome_markers: list[str] = field(default_factory=list)
    preview_text_patterns: list[str] = field(default_factory=list)
    support_url: str | None = None
    _compiled_preview: list[re.Pattern] = field(default_factory=list, repr=False)

    HIGH_CONFIDENCE_THRESHOLD = 0.6

    def is_high_confidence(self) -> bool:
        return self.confidence >= self.HIGH_CONFIDENCE_THRESHOLD

    def matches_preview_text(self, text: str) -> bool:
        if not self._compiled_preview and self.preview_text_patterns:
            self._compiled_preview = [
                re.compile(p, re.IGNORECASE) for p in self.preview_text_patterns
            ]
        return any(p.search(text) for p in self._compiled_preview)

    @classmethod
    def from_spec(cls, spec: ProfileSpec, confidence: float) -> "ESPProfile":
        return cls(
            name=spec.name,
            confidence=confidence,
            signing_domains=list(spec.signing_domains),
            chrome_markers=list(spec.chrome_markers),
            preview_text_patterns=list(spec.preview_text_patterns),
            support_url=spec.support_url,
        )
