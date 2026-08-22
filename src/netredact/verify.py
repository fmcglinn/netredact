"""The verification pass.

Re-scans the *output* for anything that still looks like a secret. This is a
safety net, not a proof: it only knows the shapes it has been taught, and a
clean report means "nothing known was left behind", not "this file is safe".

The **credential** checks are unconditional. They run even when the policy
deliberately keeps a credential, because a config that still carries a
password should fail ``--strict`` whatever the configuration says -- that is
what makes the secrets-only default defensible.

Everything that is not a credential is conditional, and runs only when the
policy asks for something other than ``keep``; otherwise it would fire on
every line of a config you deliberately chose not to touch. That covers the
addresses and e-mail (per family, and for addresses per class), and the
``identity`` family: an authorised SSH key or a device certificate that
``[policy] identity = "keep"`` was asked to leave alone is not a miss. A PEM
*private key* is a secret, not identity, so it stays unconditional -- the
``pem-left`` check is split along exactly that line.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from . import rules as R
from .addresses import classify_v4, classify_v6
from .config import Config
from .operational import OperationalNames
from .pseudonymise import (
    DESC_REMOVED,
    PREFIX,
    REDACT_CONST,
    REMOVED,
    Pseudonymiser,
    is_mask_like,
)
from .rules import (
    BARE_MAC_CONTEXT_RE,
    EMAIL_RE,
    ENC,
    IPV4_RE,
    IPV6_RE,
    MAC_RE,
    SSH_KEY_SIG,
)

__all__ = ["verify", "Finding", "check_names", "VERIFY_RULES"]


@dataclass(frozen=True)
class Finding:
    line: int
    check: str
    text: str

    def __str__(self) -> str:
        return f"L{self.line} [{self.check}] {self.text}"


#: tokens allowed between a credential keyword and its placeholder
VTOK = ENC[:-1] + r"|type|value|key|level\s+\d+)"

#: keywords that introduce a credential wherever they appear.
#: ``wpa-psk`` earns its place the hard way: the rule that handles it
#: once redacted the encoding type instead of the key, and because no
#: check named the keyword, a cleartext passphrase left the tool with
#: ``--strict`` reporting success.
#: ``private-key`` is named for the same reason ``wpa-psk`` is: a WireGuard key
#: is 44 characters of base64, so ``long-base64-left`` happens to catch one
#: today, but a check that only knows a shape must not be the only thing
#: standing between a regressed rule and a credential in the output.
_CRED_KEYWORDS = (r"password|passwd|passphrase|secret|pre-?shared-key|"
                  r"private-key|key-string|authentication-key|"
                  r"encrypted-password|wpa-psk")

#: ``community`` only where it is an SNMP community: after ``snmp-server`` /
#: ``snmp`` / ``set snmp``, or first on the line (the JunOS ``snmp { community
#: … }`` form). The bare word matched inside ``large-community``, so
#: ``match large-community AS64500-EXPORT`` and any description mentioning a
#: community were reported -- 44 of 46 findings on a real provider config.
_CRED_COMMUNITY = r"(?:^\s*|\bsnmp(?:-server)?\s+)community"

#: the credential checks: unconditional, whatever the policy keeps
VERIFY_RULES = [
    ("crypt-hash-left", re.compile(r"\$(?:1|2[abxy]?|5|6|y)\$")),
    ("junos-type9-left", re.compile(r"\$9\$")),
    ("ssh-key-left",
     re.compile(rf"{SSH_KEY_SIG}|ssh-(?:rsa|dss|ed25519)\s+[A-Za-z0-9+/]{{20,}}")),
    # a PEM private key or DH parameter block is a secret; a certificate is
    # identity, and is checked separately under the same name
    ("pem-left", re.compile(r"-----BEGIN(?![A-Z0-9 ]*CERTIFICATE-----)")),
    ("type7-left", re.compile(r"\b(?:password|key)\s+7\s+[0-9A-Fa-f]{6,}", re.I)),
    ("long-hex-left", re.compile(r"(?<![\w.])[0-9A-Fa-f]{24,}(?![\w.])")),
    ("long-base64-left", re.compile(r"(?<![\w+/=])[A-Za-z0-9+/]{40,}={0,2}(?![\w+/=])")),
    # the optional `=` is RouterOS's separator: `password=<REMOVED>` is a
    # credential this tool has already dealt with, and without it every
    # `key=value` pair netredact had destroyed was reported as a survivor
    ("credential-left", re.compile(
        rf"(?:\b(?:{_CRED_KEYWORDS})\b|{_CRED_COMMUNITY}\b)"
        rf"(?!\s*=?\s*(?:{VTOK}\s*)*(?:$|[;{{]|\"?<))", re.I)),
]

#: the ``identity`` half of ``pem-left``: a certificate is public material that
#: identifies the device, so it is reported only when the policy acts on it
PEM_CERT_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*CERTIFICATE-----")

#: the closing delimiter of a PEM block
PEM_END_RE = re.compile(r"-----END")

#: a body line that is one of netredact's own renderings rather than payload.
#: Derived from the marker and constant tables, so a new marker cannot fall out
#: of step with the check that has to recognise it.
HANDLED_BODY_RE = re.compile(
    r'\s*"?(?:'
    + "|".join([rf"<(?:{'|'.join(sorted({m for m, _t in PREFIX.values()}))})-[0-9a-f]{{6}}>"]
               + [re.escape(c) for c in
                  sorted({REMOVED, DESC_REMOVED, *REDACT_CONST.values()})])
    + r')"?\s*$')

#: checks gated by the resolved action of the identity rule whose material
#: they recognise. A per-rule override must activate its check even when the
#: family default is ``keep``. ``pem-left`` is only half-gated and is handled
#: separately below: see :data:`PEM_CERT_RE`.
IDENTITY_GATED = {"ssh-key-left": "ssh-public-key"}

#: checks that recognise a *shape* rather than a keyword. They cannot tell what
#: the material is, so they are blinded to anything a named ``identity`` or
#: ``text`` rule was told to keep -- see :func:`_shape_blind`.
SHAPE_CHECKS = ("ssh-key-left", "pem-left", "long-hex-left", "long-base64-left")

#: the families whose kept material blinds the shape checks. Every family whose
#: values are free text, device identity or an operator-chosen name is here --
#: ``interfaces``, ``vlans`` and ``circuits`` included: a description that is
#: kept is kept whichever section kept it, and a shape check cannot tell one
#: from a leak. A circuit name is the same case: a long enough order reference
#: reads as a base64 run to ``long-base64-left``, and if the policy was told to
#: keep it then it is not a miss. ``secrets`` is deliberately absent: see
#: :func:`_shape_blind`.
SHAPE_BLIND_FAMILIES = ("identity", "text", "locations", "interfaces",
                        "vlans", "circuits")

#: A RouterOS ``/export`` provenance-header comment that still names a value:
#: ``# software id = ABCD-EFGH``, ``# model = RB4011iGS+``.
#:
#: The ``=`` is what makes the shape recognisable and what keeps other dialects'
#: comments out of it: a RANCID content-type line and JunOS's ``## Last
#: changed:`` both use a colon, and netredact's own marker has no separator at
#: all. The key is a short lower-case word phrase, which is all RouterOS ever
#: writes there.
ROUTEROS_HEADER_RE = re.compile(
    r"^#\s*(?P<key>[a-z][a-z ]{0,22}[a-z])\s*=\s*(?P<value>\S.*?)\s*$")

#: checks that only make sense when the policy acts on that family
CONDITIONAL_CHECKS = ("email-left", "ipv4-left", "ipv6-left", "mac-left",
                      "operational-name-left", "as-number-left",
                      "location-left", "routeros-header-left")

#: our own hash markers. ``<SECRET-a1b2c3>`` says the credential is gone, but
#: it contains the word "secret", so without this the ``credential-left`` check
#: would report every line that ``secrets = "hash"`` had already dealt with.
#: Derived from the marker table so a new prefix cannot fall out of step. The
#: opening ``<`` is matched by a lookbehind, so it survives into the stripped
#: line and ``community <...> ro`` still reads as "dealt with", exactly as
#: ``<REMOVED>`` does.
MARKER_IGNORE = (r"(?<=<)(?:" + "|".join(sorted({m for m, _t in PREFIX.values()}))
                 + r")-[0-9a-f]{6}>")

#: expected artefacts of sanitising, and keywords that are not credentials
DEFAULT_IGNORE = (
    r"\buser-[0-9a-f]{4}@(?:example|d[0-9a-f]{4}\.example)\.\w+",
    r"/\*\s*(?:ACCESS-DENIED|SECRET-DATA)\s*\*/",
    r"\b(?:no|service)\s+password\b",
    r"password-(?:policy|encryption)",
    r"\bpassword\s+encryption\b",
    r"\bkey[-\s]chain\b",
    r"\bsecret-?data\b",
    # BGP communities are legitimately kept, and would otherwise swamp the
    # report in any service-provider config
    r"\b(?:set|match|add|delete)\s+community\b",
    r"\bcommunity-list\b",
    r"\bcommunity\s+[\w:.-]+\s+members\b",
    r"\bcommunity\s+\d+:\d+",
    r"\bcommunity\s+(?:additive|no-export|no-advertise|internet|local-as)\b",
    # RouterOS names an authentication METHOD with the same word Cisco uses for
    # the key: `authentication-types=wpa-psk,wpa2-psk` is an enum of methods and
    # carries no credential. Only the value of that one key is ignored, so
    # Cisco's `wpa-psk ascii 0 <key>` -- where the keyword is followed by the key
    # rather than by an `=` -- is judged exactly as before.
    r"\bauthentication-types=[\w,-]+",
    # A RouterOS section path is grammar, not a value: `/ppp secret` and `/snmp
    # community` name sections, and `/export terse` repeats the whole path on
    # every command line, so without this the words `secret` and `community` in
    # the path read as surviving credentials on every one of them. The path
    # stops at the command word, so `secret=` on the rest of the line is still
    # judged -- ignoring that too would be exactly the fail-open this check
    # exists to prevent.
    r"^/[a-z][\w-]*(?:\s+(?!(?:add|set|remove|print|get|find)\b)[a-z][\w-]*)*",
    MARKER_IGNORE,
)

# THE PRINCIPLE: a check never flags the constant that ``redact`` emits for its
# own family. Otherwise the tool fails ``--strict`` on its own output: with
# ``emails = "redact"`` every address becomes ``user@example.invalid``, and
# ``email-left`` reported all of them. Both tables are derived from
# :data:`pseudonymise.REDACT_CONST`, so a change to a constant cannot fall out
# of step with the checks that have to recognise it.

#: what ``redact`` leaves behind in place of an address, by IP version
_REDACTED_ADDR = {
    4: ipaddress.ip_address(REDACT_CONST["ipv4"]),
    6: ipaddress.ip_address(REDACT_CONST["ipv6"]),
}

#: what ``redact`` leaves behind for the name families, compared against a
#: **whole match** and never as a substring: ``usernames`` redacts to the word
#: ``user`` and ``hostnames`` to ``redacted``, so a substring ignore would mask
#: genuine findings on any line that happens to contain those words.
_REDACTED_NAME = {family: REDACT_CONST[family].lower()
                  for family in ("hostnames", "domains", "usernames", "emails")}


def _shape_blind(info: R.RuleInfo, cfg: Config) -> bool:
    """Whether shape checks must ignore values selected by this rule.

    THE PRINCIPLE, which is subtle -- do not "simplify" it away:

    * A rule in ``identity`` or ``text`` whose action is ``keep`` describes
      material the policy **deliberately** left in the output, which the
      report's ``policy`` line states. A check that only knows a shape --
      ``long-base64-left`` looking at an authorised SSH key, or at a kept
      certificate body -- cannot tell that from a miss, so it would fail
      ``--strict`` on a config that did exactly what it was told. Those checks
      are therefore blinded to the spans those rules match.
    * A rule in ``secrets`` whose action is ``keep`` is the opposite case. It is
      the whole point of the safety net: setting ``enable-secret = "keep"`` must
      still fail ``--strict``. Nothing here ever exempts ``secrets``.

    The catalogue applies this decision through the same traversal used by the
    sanitiser, so verification never learns how a rule is represented.
    """
    return (info.family in SHAPE_BLIND_FAMILIES
            and cfg.action_for_rule(info.name) == "keep")


def _pem_handled(lines: list[str], idx: int) -> bool:
    """True if the PEM block opening at ``lines[idx]`` has nothing left in it.

    The BEGIN / END delimiters are deliberately kept -- they are the config's
    structure, not the secret -- so ``pem-left`` must judge the *body*. A body
    that is one of our own markers has already been dealt with, and reporting
    it would fail ``--strict`` on a key netredact itself destroyed. A body with
    real payload still fires, and so does an unterminated delimiter with no
    marker under it -- that is a truncated key, not a handled one.
    """
    handled_body = False
    for line in lines[idx + 1:]:
        if PEM_END_RE.search(line):
            return True                   # markers only, or nothing between
        if not line.strip():
            continue
        if not HANDLED_BODY_RE.fullmatch(line):
            return False                  # payload: still there to find
        handled_body = True
    # ran off the end: only a marker is positive evidence that the block was
    # dealt with. A lone delimiter is a truncated key, not a handled one.
    return handled_body


def check_names() -> list[str]:
    """Every check name, for ``verify.disable``."""
    return [name for name, _ in VERIFY_RULES] + list(CONDITIONAL_CHECKS)


def verify(lines, config: Config | None = None, *,
           handled_macs: set[str] | None = None,
           handled_asns: set[str] | None = None) -> list[Finding]:
    cfg = config or Config()
    cfg.validate()
    # A PEM block is judged by its body, so the lines are materialised. They are
    # also normalised the way `transform` normalises its own input: a wrapped
    # RouterOS command is one logical line, `verification_view` returns one
    # masked line per logical line, and the two are zipped together below. The
    # join is idempotent, so sanitised output -- already unwrapped -- passes
    # through untouched and its line numbers are unchanged.
    lines = R.join_continuations(lines)
    disabled = set(cfg.verify.disable)
    unknown = disabled - set(check_names())
    if unknown:
        raise ValueError(
            f"verify.disable names unknown check(s): {', '.join(sorted(unknown))}")

    ignore = re.compile("|".join(DEFAULT_IGNORE + tuple(cfg.verify.ignore_patterns)),
                        re.I)
    active = [(n, p) for n, p in VERIFY_RULES
              if n not in disabled and n not in IDENTITY_GATED and n != "pem-left"]
    active += [(n, p) for n, p in VERIFY_RULES
               if n in IDENTITY_GATED and n not in disabled
               and cfg.action_for_rule(IDENTITY_GATED[n]) != "keep"]
    # ``pem-left`` is line-based like the rest, but only fires once the body is
    # known to still hold material, so it is evaluated apart from `active`
    pem_pats = [] if "pem-left" in disabled else [dict(VERIFY_RULES)["pem-left"]]
    if pem_pats and cfg.action_for_rule("pem-cert") != "keep":
        pem_pats.append(PEM_CERT_RE)
    check_email = cfg.action_for("emails") != "keep" and "email-left" not in disabled
    check_v4 = cfg.ipv4.any_active() and "ipv4-left" not in disabled
    check_v6 = cfg.ipv6.any_active() and "ipv6-left" not in disabled
    check_mac = cfg.macs.any_active() and "mac-left" not in disabled
    handled_macs = {value.lower() for value in (handled_macs or set())}
    handled_asns = {value.lower() for value in (handled_asns or set())}
    check_operational = (cfg.operational_names.any_active()
                         and "operational-name-left" not in disabled)
    check_asn = cfg.as_numbers.any_active() and "as-number-left" not in disabled
    check_location = (cfg.locations.any_active()
                      and "location-left" not in disabled)
    # Gated on `identity`, and on the family default rather than any one rule:
    # the material this check is about is by definition material no rule owns,
    # and an unclaimed value in a device's provenance header is that device's
    # identity. With `identity` kept it is kept on purpose and not a miss.
    check_ros_header = (cfg.action_for("identity") != "keep"
                        and "routeros-header-left" not in disabled)
    well_known = {4: frozenset(cfg.ipv4.well_known_resolvers),
                  6: frozenset(cfg.ipv6.well_known_resolvers)}
    keep_nets = [ipaddress.ip_network(n) for n in
                 list(cfg.ipv4.keep_networks) + list(cfg.ipv6.keep_networks)]
    pools = [ipaddress.ip_network(p) for p in cfg.ipv4.pool]
    pools.append(ipaddress.ip_network(cfg.ipv6.pool))

    def address_left(text: str) -> bool:
        """True if this address belongs to a class we were asked to act on.

        Uses the same classification as the sanitiser, so it reports genuine
        misses rather than second-guessing with a different rule.
        """
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return False
        if addr.version == 4 and is_mask_like(int(addr)):
            return False
        if addr == _REDACTED_ADDR[addr.version]:
            return False          # our own redaction constant
        if any(addr in n for n in keep_nets if n.version == addr.version):
            return False
        if any(addr in p for p in pools if p.version == addr.version):
            return False          # already a pseudonym
        klass = (classify_v4(text, well_known[4]) if addr.version == 4
                 else classify_v6(addr.compressed, well_known[6]))
        policy = cfg.ipv4 if addr.version == 4 else cfg.ipv6
        return policy.action(klass) != "keep"

    catalogue = R.RuleCatalogue.builtins().configured(cfg.custom)
    shaped_lines = catalogue.verification_view(
        lines, blind=lambda info: _shape_blind(info, cfg))
    verification_pseudo = Pseudonymiser(b"netredact-verification-probe", cfg)
    op_probe = OperationalNames(cfg.operational_names, verification_pseudo)
    operational_probe_lines = [op_probe.line(line) for line in lines]

    def location_probe(hit: R.RuleHit) -> R.RuleReplacement:
        if hit.family != "locations" or cfg.action_for_rule(hit.name) == "keep":
            return R.RuleReplacement.keep()
        if verification_pseudo.is_rendered(hit.name, hit.value):
            return R.RuleReplacement.unchanged()
        return R.RuleReplacement.with_text("<LOCATION-PROBE>")

    location_probe_lines = catalogue.transform(lines, replace=location_probe)

    def owned(line: str) -> bool:
        """True if any rule selects anything on this line.

        Asked per line, on a one-line input, and deliberately so: a whole-file
        probe that replaced every hit would collapse a banner body or a block
        and put the loop below out of step with the file it is reporting line
        numbers for. Only header-shaped lines ever reach here, so the cost is a
        handful of one-line traversals per file.

        The question is asked of the RULE TABLE rather than of a list of keys
        written out here, so a header key that gains a rule leaves this check
        the day it does, with nothing to keep in step by hand.
        """
        return catalogue.transform(
            [line],
            replace=lambda hit: R.RuleReplacement.with_text("\x00")) != [line]

    findings: list[Finding] = []
    for i, (line, shaped_line) in enumerate(zip(lines, shaped_lines, strict=True), 1):
        stripped = ignore.sub(" ", line)
        shaped = ignore.sub(" ", shaped_line)
        for name, pat in active:
            if pat.search(shaped if name in SHAPE_CHECKS else stripped):
                findings.append(Finding(i, name, line.strip()))
        if (any(pat.search(shaped) for pat in pem_pats)
                and not _pem_handled(lines, i - 1)):
            findings.append(Finding(i, "pem-left", line.strip()))
        if check_email and any(m.group(0).lower() != _REDACTED_NAME["emails"]
                               for m in EMAIL_RE.finditer(stripped)):
            findings.append(Finding(i, "email-left", line.strip()))
        if check_v4 and any(address_left(m.group(1)) for m in IPV4_RE.finditer(line)):
            findings.append(Finding(i, "ipv4-left", line.strip()))
        if check_v6 and any(address_left(m.group(1)) for m in IPV6_RE.finditer(line)):
            findings.append(Finding(i, "ipv6-left", line.strip()))
        if check_mac:
            candidates = [m.group(1) for m in MAC_RE.finditer(line)]
            candidates += [m.group("value") for m in BARE_MAC_CONTEXT_RE.finditer(line)]
            if any(value.lower() not in handled_macs for value in candidates):
                findings.append(Finding(i, "mac-left", line.strip()))
        if check_operational and operational_probe_lines[i - 1] != line:
            findings.append(Finding(i, "operational-name-left", line.strip()))
        if check_asn:
            candidates = []
            for pat in (
                r"\b(?:router\s+bgp|remote-as|local-as|autonomous-system)\s+(\d+(?:\.\d+)?)",
                r"\bas-path\s+prepend\s+([\d. ]+)",
            ):
                for match in re.finditer(pat, line, re.I):
                    candidates.extend(re.findall(r"\d+(?:\.\d+)?", match.group(1)))
            if any(value.lower() not in handled_asns
                   and value not in {"0", "23456", "65535", "4294967295"}
                   for value in candidates):
                findings.append(Finding(i, "as-number-left", line.strip()))
        if check_location and location_probe_lines[i - 1] != line:
            findings.append(Finding(i, "location-left", line.strip()))
        if check_ros_header:
            # THE POINT of this check: every other one recognises a shape or a
            # keyword, and a provenance-header value has neither -- an opaque
            # licence id is a word. So a RouterOS header key that no rule knew
            # about left the tool with nothing reported at all, which is the one
            # outcome this project treats as worse than a miss. Here the
            # evidence is structural: the value sits in a header, and no rule
            # claimed it.
            header = ROUTEROS_HEADER_RE.match(line)
            if (header and not HANDLED_BODY_RE.fullmatch(header.group("value"))
                    and not owned(line)):
                findings.append(Finding(i, "routeros-header-left", line.strip()))
    return findings
