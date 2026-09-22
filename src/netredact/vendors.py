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
``switchname``, ``boot-start-marker``, a ``set system`` line, or -- for
FortiOS, whose whole header is ``platform`` material -- the ``config <path>`` /
``edit "<name>"`` / ``next`` shapes its grammar cannot do without.

Huawei is the case that makes the point hardest. Its version marker,
``[MA5600V800R013: 3910]``, is the only line in an OLT capture that names the
product at all, and BOTH halves of it belong to ``platform`` -- so a detector
that leant on it would answer ``unknown`` for every sanitised OLT config. What
it leans on instead is the provisioning grammar, ``ont add ... sn-auth ...``
and ``service-port <n> vlan <n> gpon ...``, whose keywords survive every
action because only the values around them are ever replaced.
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
    ("mikrotik", (
        # the `/export` provenance comment, and the licence line under it. The
        # release number in the first is removed by `platform` and the id in
        # the second by `identity`, but both keywords stay -- which is the
        # whole reason detection is allowed to depend on them.
        (r"\bby\s+RouterOS\b", DECISIVE),
        (r"^#\s*software\s+id\s*=", DECISIVE),
        # a section header, or the path `/export terse` repeats on every line.
        # Nothing else puts a `/` in column zero: JunOS and IOS spell an
        # interface `xe-0/0/0` and `Gi0/0`, never at the start of a line.
        (r"^/(?:interface|ip|system|snmp|user|routing)\b", STRONG),
        # RouterOS's own way of naming an object it did not create: no other
        # configuration grammar has a selector expression at all
        (r"set\s+\[\s*find\b", STRONG),
        (r"^add\s+\S+=", WEAK),
        (r"^#\s*model\s*=", WEAK),
    )),
    ("fortinet", (
        (r"^#config-version=", DECISIVE),
        # `ENC` is FortiOS's own marker that the value after it is the
        # device's encrypted form of a credential. No other dialect writes it,
        # and it does not survive `secrets` acting -- which is why it is one
        # hint of several rather than the whole answer.
        (r"\bENC\s+[A-Za-z0-9+/=]{12,}", DECISIVE),
        # the rest of the `#`-prefixed header. `platform` acts on the values
        # after the `=` and keeps the keys, so these shapes remain.
        (r"^#(?:conf_file_ver|buildno|global_vdom|branch_pt)=", STRONG),
        # The grammar itself, which is what a headerless fragment leaves us:
        # `config <path>` at column zero, `edit "<name>"` under it, and the
        # bare `next` that closes an edit. A bare `end` is deliberately NOT
        # here -- an IOS running-config ends with one.
        (r"^config\s+system\s+\S", STRONG),
        (r"^config\s+(?:firewall|vpn|user|router|log|wireless-controller)\s+\S", STRONG),
        (r"^\s*edit\s+\"", STRONG),
        (r"^\s*next\s*$", STRONG),
        (r"^\s*set\s+vdom\b", STRONG),
        # FortiOS's spelling of "return this to its default". JunOS deletes and
        # IOS says `no`, so the word is suggestive on its own but no more.
        (r"^\s*unset\s+\S", WEAK),
    )),
    ("huawei", (
        # `ont add 0 0 sn-auth "..." password-auth "..."`. The keywords are
        # what is DECISIVE here and the values are irrelevant, which is the
        # property every hint in this table needs: `secrets` and `identity`
        # replace both values on this line, and the command still reads as
        # Huawei's afterwards.
        (r"^\s*ont\s+(?:add|confirm|modify)\s+\d+\s+\d+\s+", DECISIVE),
        # a GPON service port, the other line this box has thousands of
        (r"^\s*service-port\s+\d+\s+vlan\s+\d+\s+gpon\s+", DECISIVE),
        # the model, for as long as it is there. `platform` removes it -- both
        # halves of `[MA5600V800R013: 3910]` belong to a rule -- which is
        # exactly why it is one hint among a dozen and not the answer.
        # No trailing `\b`: the release is GLUED to the model in that marker,
        # so `\bMA5600\b` asked for a boundary between `0` and `V` and never
        # matched the one line it was written for.
        (r"\bMA5[68]\d\d(?!\d)", DECISIVE),
        # `display current-configuration` frames the file in bracketed
        # sections, and the four that every capture carries are named after
        # what they configure rather than after anything vendor-specific, so
        # they are strong rather than decisive.
        (r"^\[(?:global|public|vlan|device|platform|sysmode)-config\]\s*$", STRONG),
        (r"^\s*<(?:global|public|vlan|device|platform|sysmode)-config>\s*$", STRONG),
        (r"^\s*ont-(?:line|srv)profile\s+gpon\b", STRONG),
        (r"^\s*interface\s+gpon\s+\d+/\d+", STRONG),
        (r"^\s*terminal\s+user\s+name\s+", STRONG),
        (r"^\s*snmp-agent\s+(?:local-engineid|community|sys-info|usm-user)\b", STRONG),
        (r"^\s*sysman\s+(?:ip-access|vpn-instance)\b", STRONG),
        (r"^\s*traffic\s+table\s+\S+\s+index\s+\d+\b", STRONG),
        (r"^\s*vlan\s+\d+(?:\s+to\s+\d+)?\s+smart\b", STRONG),
        # `sysname` is H3C's word too, and the GPON provisioning verbs are
        # merely suggestive on their own -- they exist to break a tie on a
        # fragment that carries none of the above.
        (r"^\s*sysname\s+\S", WEAK),
        (r"^\s*(?:gem\s+(?:add|mapping)|tcont)\s+\d", WEAK),
        (r"^\s*dba-profile\s+add\s+profile-id\b", WEAK),
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
