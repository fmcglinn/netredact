"""Best-effort vendor detection, used only for reporting and for nothing else:
every rule is applied to every file regardless.

Detection reads the **input**, never the output, and ``sanitise_text`` calls it
that way on purpose. The strongest evidence a config carries -- the Arista
``! device: ... (DCS-7280SR-48C6-M, EOS-4.32.1F)`` header, the ``.swi`` boot
image, the JunOS release string -- is exactly the material the ``platform``
family exists to remove. Detecting from sanitised text would report ``unknown``
for the very files netredact had just done the most work on.

That is also why no vendor rests on a single marker. Each table below carries
several independent hints, so a config whose platform lines have been redacted
still names its vendor from the shapes that remain: the ``! device:`` comment
without its parenthesised contents, ``! Command: show running-config``,
``switchname``, ``boot-start-marker``, a ``set system`` line.
"""

from __future__ import annotations

import re
from collections import Counter

__all__ = ["detect_vendor", "VENDOR_HINTS", "VENDOR_NAMES"]

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
        # 21.4R3-S4.9, 12.3X48-D80: <major>.<minor> then a release letter is
        # the JunOS convention and nobody else's. Survives `platform` acting,
        # because it is also matched inside a `jinstall` image name.
        (r"\b\d+\.\d+[RX]\d", DECISIVE),
        (r"^set\s+(?:system|interfaces|protocols|routing-options|security)\s", STRONG),
        (r"^\s*(?:system|interfaces|protocols|routing-instances|policy-options)\s*\{", STRONG),
        (r"\bj(?:install|unos)-\S+", STRONG),
        (r"apply-groups", WEAK),
        (r"^\s*unit\s+\d+\s*\{", WEAK),
    )),
    ("arista", (
        (r"^\s*!\s*device:.*\bEOS", DECISIVE),
        (r"\bEOS(?:64)?-\d", DECISIVE),
        (r"\.swi\b", DECISIVE),
        # the header shape alone, for a file whose parenthesised model and
        # version have been redacted out of it
        (r"^\s*!\s*device:\s*\S", STRONG),
        (r"^\s*!\s*Command:\s*show\s", STRONG),
        (r"^\s*management\s+api\s+http-commands", STRONG),
        (r"^\s*service\s+routing\s+protocols\s+model", STRONG),
        (r"^\s*switchname\s+\S+", STRONG),
        (r"^\s*daemon\s+TerminAttr\b", STRONG),
        (r"secret\s+sha512", WEAK),
        (r"^\s*no\s+aaa\s+root", WEAK),
    )),
    ("cisco", (
        (r"^\s*boot-start-marker", DECISIVE),
        # the `show running-config` preamble, which Arista does not emit
        (r"^\s*Building\s+configuration", DECISIVE),
        (r"^\s*Current\s+configuration\s*:", DECISIVE),
        (r"^\s*ip\s+cef\b", STRONG),
        (r"^\s*crypto\s+pki\s+", STRONG),
        # JunOS writes the same sentiment as `## Last changed:`; the `!` is
        # what makes this one Cisco
        (r"^\s*!\s*Last\s+configuration\s+change", STRONG),
        (r"^\s*version\s+\d+\.\d+\(\d", STRONG),      # NX-OS 9.3(5)
        (r"^\s*service\s+timestamps", WEAK),
        (r"^\s*line\s+con\s+0", WEAK),
        (r"^\s*feature\s+\S+", WEAK),
    )),
)

#: the vendors this module can name, sorted. Read off the table above and never
#: written out, because ``config.VENDORS`` is built from this: a vendor added to
#: ``VENDOR_HINTS`` becomes a legal ``vendor =`` value the same day, and a
#: ``vendor =`` value with no hints behind it -- one netredact could be told
#: about but could never recognise -- cannot come into existence at all.
#:
#: Sorted, rather than in the order of the table: that order is a tie-break
#: order for :func:`detect_vendor` (``Counter.most_common`` breaks a tie by
#: first insertion), which is a detection concern and nothing a user reading
#: ``--print-config`` should inherit.
VENDOR_NAMES = tuple(sorted(name for name, _ in VENDOR_HINTS))


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
