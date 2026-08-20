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
from .pseudonymise import (
    DESC_REMOVED,
    PREFIX,
    REDACT_CONST,
    REMOVED,
    is_mask_like,
)
from .rules import EMAIL_RE, ENC, IPV4_RE, IPV6_RE

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
_CRED_KEYWORDS = (r"password|passwd|secret|pre-shared-key|key-string|"
                  r"authentication-key|encrypted-password|wpa-psk")

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
     re.compile(r"AAAAB3Nza|AAAAC3Nza|ssh-(?:rsa|dss|ed25519)\s+[A-Za-z0-9+/]{20,}")),
    # a PEM private key or DH parameter block is a secret; a certificate is
    # identity, and is checked separately under the same name
    ("pem-left", re.compile(r"-----BEGIN(?![A-Z0-9 ]*CERTIFICATE-----)")),
    ("type7-left", re.compile(r"\b(?:password|key)\s+7\s+[0-9A-Fa-f]{6,}", re.I)),
    ("long-hex-left", re.compile(r"(?<![\w.])[0-9A-Fa-f]{24,}(?![\w.])")),
    ("long-base64-left", re.compile(r"(?<![\w+/=])[A-Za-z0-9+/]{40,}={0,2}(?![\w+/=])")),
    ("credential-left", re.compile(
        rf"(?:\b(?:{_CRED_KEYWORDS})\b|{_CRED_COMMUNITY}\b)"
        rf"(?!\s*(?:{VTOK}\s*)*(?:$|[;{{]|\"?<))", re.I)),
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
SHAPE_BLIND_FAMILIES = ("identity", "text", "interfaces", "vlans", "circuits")

#: checks that only make sense when the policy acts on that family
CONDITIONAL_CHECKS = ("email-left", "ipv4-left", "ipv6-left")

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


def _shape_blind(cfg: Config) -> tuple[re.Pattern | None, list[tuple]]:
    """What the shape checks must not look at, given this policy.

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

    Returns the regex to blank out of the line, and the kept block rules whose
    *body* -- lines the start/end regexes never see -- must be skipped too.
    """
    patterns: list[str] = []
    for rule in R.build_rules(cfg.custom) + R.BLOB_RULES:
        if rule.family in SHAPE_BLIND_FAMILIES and \
                cfg.action_for_rule(rule.name) == "keep":
            patterns.append(rule.regex.pattern)
    blocks = [(start, end) for start, end, name, family in R.BLOCK_STARTS
              if family in SHAPE_BLIND_FAMILIES and cfg.action_for_rule(name) == "keep"]
    blind = re.compile("|".join(f"(?:{p})" for p in patterns), re.I) if patterns else None
    return blind, blocks


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


def verify(lines, config: Config | None = None) -> list[Finding]:
    cfg = config or Config()
    lines = list(lines)             # a PEM block is judged by its body
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

    blind, kept_blocks = _shape_blind(cfg)
    findings: list[Finding] = []
    block_end: re.Pattern | None = None
    for i, line in enumerate(lines, 1):
        stripped = ignore.sub(" ", line)
        # inside a kept identity / text block the body is the kept material
        in_kept_block = block_end is not None
        if block_end is not None:
            if block_end.search(line):
                block_end = None
        else:
            for start, end in kept_blocks:
                if start.search(line):
                    block_end, in_kept_block = end, True
                    break
        shaped = "" if in_kept_block else (blind.sub(" ", stripped) if blind
                                           else stripped)
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
    return findings
