"""Framework control URL resolver for compliance hyperlinks in reports."""

from __future__ import annotations

import re

# Each framework entry has:
#   url      - URL template; use {id} where the control ID should be interpolated
#   pattern  - regex to extract the control ID from a control reference string; None = no deep link
_FRAMEWORK_CONFIGS: dict[str, dict] = {
    "NIST_800-53": {
        "url": (
            "https://csrc.nist.gov/projects/cprt/catalog"
            "#/cprt/framework/version/SP_800_53_5_1_1/home?element={id}"
        ),
        # e.g. "AC-7", "SC-8", "IA-2(1)"
        "pattern": re.compile(r"^([A-Z]{1,3}-\d+(?:\(\d+\))?)"),
    },
    "NIST_CSF": {
        "url": (
            "https://csrc.nist.gov/projects/cprt/catalog"
            "#/cprt/framework/version/CSF_1_1_0/home?element={id}"
        ),
        # e.g. "PR.AC-1", "DE.CM-7"
        "pattern": re.compile(r"^([A-Z]{2}\.[A-Z]{2}-\d+)"),
    },
    "ISO27001": {
        # ISO 27001:2022 — paywalled, no stable per-control deep links
        "url": "https://www.iso.org/standard/82875.html",
        "pattern": None,
    },
    "CMMC": {
        # CMMC 2.0 official page — no stable per-practice deep links
        "url": "https://dodcio.defense.gov/CMMC/",
        "pattern": None,
    },
    "CIS": {
        "url": "https://www.cisecurity.org/cis-benchmarks",
        "pattern": None,
    },
    "DISA_STIG": {
        # Network Infrastructure Policy SRG — no per-requirement deep links
        "url": "https://public.cyber.mil/stigs/downloads/",
        "pattern": None,
    },
}


def get_control_url(framework: str, control_text: str) -> str | None:
    """Return a URL for a framework control reference string.

    For frameworks with stable per-control URLs (NIST 800-53, NIST CSF) the
    control ID is extracted from *control_text* and substituted into the URL
    template.  For frameworks without deep links (ISO 27001, CMMC, CIS,
    DISA_STIG) the framework's landing page URL is returned so every reference
    is still clickable.  Returns ``None`` only for unknown frameworks.

    Examples::

        get_control_url("NIST_800-53", "AC-7: Unsuccessful Logon Attempts")
        # → "https://csrc.nist.gov/.../home?element=AC-7"

        get_control_url("ISO27001", "A.9.4.2: Secure log-on procedures")
        # → "https://www.iso.org/standard/82875.html"
    """
    cfg = _FRAMEWORK_CONFIGS.get(framework)
    if cfg is None:
        return None

    url_template: str = cfg["url"]
    pattern: re.Pattern | None = cfg["pattern"]

    if pattern is not None and "{id}" in url_template:
        m = pattern.match(control_text.strip())
        if m:
            return url_template.format(id=m.group(1))
        # Pattern defined but didn't match — still return the base page
        return url_template.replace("?element={id}", "")

    # No per-control link — return the base landing page
    return url_template
