"""Best-effort vendor detection, used only for reporting and for nothing else:
every rule is applied to every file regardless."""

from __future__ import annotations

import re
from collections import Counter

__all__ = ["detect_vendor", "VENDOR_HINTS"]

# Weight tiers. A DECISIVE hint is an unmistakable, vendor-exclusive marker:
# seeing it once is conclusive and must outweigh any number of weak hits from
# another vendor. STRONG hints are fairly vendor-specific but not iron-clad on
# their own. WEAK hints are merely suggestive (common conventions, boilerplate
# lines) and exist only to break ties among otherwise-silent configs.
DECISIVE = 50
STRONG = 8
WEAK = 2

VENDOR_HINTS = (
    ("juniper", (
        (r"^\s*##\s*Last changed:", DECISIVE),
        (r"\$9\$", DECISIVE),
        (r"^set\s+(?:system|interfaces|protocols|routing-options|security)\s", STRONG),
        (r"^\s*(?:system|interfaces|protocols|routing-instances|policy-options)\s*\{", STRONG),
        (r"apply-groups", WEAK),
        (r"^\s*unit\s+\d+\s*\{", WEAK),
    )),
    ("arista", (
        (r"^\s*!\s*device:.*EOS", DECISIVE),
        (r"^\s*management\s+api\s+http-commands", STRONG),
        (r"^\s*service\s+routing\s+protocols\s+model", STRONG),
        (r"^\s*switchname\s+\S+", STRONG),
        (r"secret\s+sha512", WEAK),
        (r"^\s*no\s+aaa\s+root", WEAK),
    )),
    ("cisco", (
        (r"^\s*boot-start-marker", DECISIVE),
        (r"^\s*ip\s+cef\b", STRONG),
        (r"^\s*crypto\s+pki\s+", STRONG),
        (r"^\s*service\s+timestamps", WEAK),
        (r"^\s*line\s+con\s+0", WEAK),
        (r"^\s*feature\s+\S+", WEAK),
    )),
)


def detect_vendor(text: str) -> str:
    scores: Counter = Counter()
    for vendor, pats in VENDOR_HINTS:
        for pat, weight in pats:
            # Presence, not raw count: a hint that fires 25 times contributes
            # no more than a hint that fires once. Breadth of distinct
            # evidence must beat repetition of a single weak signal.
            if re.search(pat, text, re.M | re.I):
                scores[vendor] += weight
    if not scores or max(scores.values()) == 0:
        return "unknown"
    return scores.most_common(1)[0][0]
