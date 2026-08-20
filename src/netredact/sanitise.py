"""The transformation itself.

Two passes over the input:

1. :meth:`Sanitiser.collect` learns the identities this device uses -- its
   hostnames, domains and usernames -- because those are only recognisable
   from the lines that declare them. Nothing is rewritten here.
2. :meth:`Sanitiser.run` transforms line by line, tracking which blocks the
   line is inside (so ``community`` is an SNMP secret inside ``snmp { … }`` and
   never a BGP community, and a ``description`` under ``interface Gi0/0`` is an
   interface description and not any other kind) and the delimiter state of a
   multi-line banner. Both kinds of block share one set of names: see
   :meth:`Sanitiser._enter` and ``rules.BLOCK_SCOPES``.

A rule only ever *selects* a span. What happens to the span comes from the
policy, resolved once per rule name in :meth:`Config.action_for_rule`, and is
carried out by :meth:`Pseudonymiser.render`. That is why a rule whose action is
``keep`` still has to match: the report promises a count of what was left
behind, and only the rule that recognises the material can count it.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from . import rules as R
from .config import RULE_FAMILIES, Config
from .pseudonymise import Pseudonymiser, is_mask_like
from .vendors import detect_vendor

if TYPE_CHECKING:
    from .verify import Finding

__all__ = ["Sanitiser", "Result", "sanitise_text", "policy_summary"]

#: families whose substitution leaves nothing of the original: what
#: :attr:`Result.redactions` counts. Addresses and names are excluded because
#: ``pseudo`` there preserves the equality relation -- a substitution, not a
#: destruction. That is exactly the set of rule-named families, so it is read
#: off :data:`config.RULE_FAMILIES` rather than transcribed.
_DESTRUCTIVE = RULE_FAMILIES

#: the four families the collect pass discovers, and the ``kept`` category each
#: is recorded under (singular, as the report and the tests expect)
_NAME_CATEGORY = {"hostnames": "hostname", "domains": "domain",
                  "usernames": "username", "emails": "email"}


@dataclass
class Result:
    """What a sanitising run produced."""

    text: str
    vendor: str
    #: rule / family name -> number of values that were substituted
    counts: Counter = field(default_factory=Counter)
    #: rule / family name -> number of occurrences deliberately left in place
    kept_counts: Counter = field(default_factory=Counter)
    #: category -> distinct values deliberately left in place
    kept: dict[str, set[str]] = field(default_factory=dict)
    #: one line naming what the policy acted on, for the report header
    policy_summary: str = ""
    #: real addresses left in place that fall inside a pseudonym pool
    collisions: set[str] = field(default_factory=set)
    #: what the verification pass found in the OUTPUT
    findings: list[Finding] = field(default_factory=list)
    #: category -> {original: pseudonym}; the re-identification map
    mapping: dict[str, dict[str, str]] = field(default_factory=dict)
    #: every key used in :attr:`counts` / :attr:`kept_counts` -> its family, so
    #: a caller can group the report without re-deriving the rule table
    families: dict[str, str] = field(default_factory=dict)

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @property
    def redactions(self) -> int:
        """How many secrets were destroyed.

        Every substitution whose original is gone: the ``secrets``, ``text``,
        ``identity`` and ``platform`` families. Pseudonymised addresses and
        names are not counted -- their equality relation survives, so nothing
        was destroyed.
        """
        return sum(n for name, n in self.counts.items()
                   if self.families.get(name, "secrets") in _DESTRUCTIVE)


def policy_summary(cfg: Config) -> str:
    """One line naming everything the policy acts on.

    With the defaults that is ``"secrets=redact, everything else kept"``.
    """
    parts: list[str] = []
    kept: list[str] = []

    # the four rule-named families: per rule, the way a section is per class
    for family in RULE_FAMILIES:
        section = getattr(cfg, family)
        actions = {section.action(r) for r in section.RULES}
        if actions == {"keep"}:
            kept.append(family)
        elif len(actions) == 1:
            parts.append(f"{family}={actions.pop()}")
        else:
            parts.append(f"{family}={section.default} (per rule)")

    for family in ("hostnames", "domains", "usernames", "emails"):
        action = cfg.policy.action(family)
        (parts if action != "keep" else kept).append(f"{family}={action}")

    for name, pol in (("ipv4", cfg.ipv4), ("ipv6", cfg.ipv6)):
        actions = {pol.action(k) for k in pol.CLASSES}
        if actions == {"keep"}:
            kept.append(name)
        elif len(actions) == 1:
            parts.append(f"{name}={actions.pop()}")
        else:
            parts.append(f"{name}={pol.default} (per class)")

    macs = cfg.macs
    if macs.oui == macs.nic == "keep":
        kept.append("macs")
    elif macs.oui == macs.nic:
        parts.append(f"macs={macs.oui}")
    else:
        parts.append(f"macs={macs.oui}/{macs.nic}")

    custom = [f"{c.name}={c.action}" for c in cfg.custom if c.action]
    if len(custom) > 3:
        custom = custom[:3] + [f"+{len(custom) - 3} more custom rule(s)"]
    parts.extend(custom)

    if not parts:
        return "everything kept"
    if kept:
        parts.append("everything else kept")
    return ", ".join(parts)


@dataclass
class _Block:
    """A multi-line block being consumed: its body is the target."""

    end: re.Pattern
    name: str
    action: str
    body: list[str] = field(default_factory=list)


@dataclass
class _Banner:
    """A banner being consumed, waiting for its closing delimiter."""

    delim: str
    action: str
    body: list[str] = field(default_factory=list)


class Sanitiser:
    """Stateful, single-use: build one per file."""

    def __init__(self, config: Config | None = None, *, salt: bytes,
                 pseudo: Pseudonymiser | None = None):
        self.cfg = config or Config()
        self.p = pseudo or Pseudonymiser(salt, self.cfg)
        self.rules = R.build_rules(self.cfg.custom)
        self.counts: Counter = Counter()
        self.kept_counts: Counter = Counter()
        self.hostnames: list[str] = []
        self.domains: list[str] = []
        self.usernames: list[str] = []
        self._name_res: list[tuple[re.Pattern, str]] = []
        self.stanza: list[str] = []
        #: the IOS-style block the current line is in, from R.BLOCK_SCOPES
        self.block: str | None = None
        #: every block the current line is inside, JunOS stanzas and IOS blocks
        #: together, resolved once per line by :meth:`_enter`
        self.inside: tuple[str, ...] = ()

        # name -> family for everything that can be counted, and name -> action
        # for every rule. Resolving the action once means a bad override is an
        # error before any output is produced, not halfway through a file.
        self.families: dict[str, str] = {}
        self._actions: dict[str, str] = {}
        for name, family in self._rule_families():
            self.families[name] = family
            self._actions[name] = self.cfg.action_for_rule(name)
        for family in ("ipv4", "ipv6", "macs", "hostnames", "domains",
                       "usernames", "emails"):
            self.families[family] = family
        self._family_actions = {f: self.cfg.action_for(f)
                                for f in ("hostnames", "domains", "usernames",
                                          "emails")}

    def _rule_families(self):
        for rule in self.rules:
            yield rule.name, rule.family
        for rule in R.BLOB_RULES:
            yield rule.name, rule.family
        for _start, _end, name, family in R.BLOCK_STARTS:
            yield name, family
        yield R.BANNER_RULE

    # -- pass 1: learn the identities this device uses ---------------------
    def collect(self, lines) -> None:
        for line in lines:
            for pat in R.HOSTNAME_PATS:
                m = pat.search(line)
                if m:
                    self._add(self.hostnames, m.group(1).strip('";'))
            for pat in R.DOMAIN_PATS:
                m = pat.search(line)
                if m:
                    for d in m.group(1).replace(",", " ").split():
                        self._add(self.domains, d.strip('";[]'))
            for pat in R.USERNAME_PATS:
                m = pat.search(line)
                if m:
                    self._add(self.usernames, m.group(1).strip('";'))
            for m in R.EMAIL_RE.finditer(line):
                _, _, dom = m.group(0).partition("@")
                self._add(self.domains, dom)

        # A kept name is still matched in pass 2, because the report counts the
        # occurrences it left behind; the action decides what the match does.
        candidates: list[tuple[str, str]] = []
        for family, discovered, minlen in (("domains", self.domains, 0),
                                           ("hostnames", self.hostnames, 2),
                                           ("usernames", self.usernames, 2)):
            keeping = self._family_actions[family] == "keep"
            for value in discovered:
                if keeping:
                    self.p.kept.setdefault(
                        _NAME_CATEGORY[family], set()).add(value)
                # a one-character name is not worth the collateral: the word
                # scan would rewrite every bare `s` or `e` in the file
                if len(value) >= minlen:
                    candidates.append((value, family))

        # longest first ACROSS families, not within one: the hostname
        # "buildbox.northwind.test" has to be handled before the domain
        # "northwind.test", or the domain match eats the tail of the FQDN and
        # leaves the device name behind. Sorting is stable, so names of equal
        # length keep the family order above.
        candidates.sort(key=lambda pair: len(pair[0]), reverse=True)
        self._name_res = [(self._word_re(value), family)
                          for value, family in candidates]

    @staticmethod
    def _add(bucket: list, value: str) -> None:
        value = value.strip()
        if value and value.lower() not in {v.lower() for v in bucket}:
            bucket.append(value)

    @staticmethod
    def _word_re(token: str) -> re.Pattern:
        # no [\w-] either side, so "admin" never matches inside "network-admin"
        return re.compile(rf"(?<![\w-]){re.escape(token)}(?![\w-])", re.I)

    # -- pass 2: transform -------------------------------------------------
    def run(self, lines) -> list[str]:
        out: list[str] = []
        block: _Block | None = None
        banner: _Banner | None = None
        banner_action = self._actions[R.BANNER_RULE[0]]

        for line in lines:
            raw = line.rstrip("\n")

            if block is not None:
                if block.end.search(raw):
                    self._flush_block(block, out)
                    out.append(raw)
                    block = None
                else:
                    block.body.append(raw)
                continue

            if banner is not None:
                if banner.delim in raw:
                    self._flush_banner(banner, out)
                    out.append(banner.delim)
                    banner = None
                else:
                    banner.body.append(raw)
                continue

            self._enter(raw)

            hit = False
            for start, end, name, _family in R.BLOCK_STARTS:
                if start.search(raw):
                    out.append(raw)
                    block = _Block(end, name, self._actions[name])
                    hit = True
                    break
            if hit:
                continue

            m = R.BANNER_RE.match(raw)
            if m and banner_action != "keep":
                banner = self._banner(m, banner_action, out)
                continue
            if m:
                # kept banners fall through to the normal path, as before; the
                # body lines are then ordinary lines
                self.kept_counts[R.BANNER_RULE[0]] += 1

            out.append(self.line(raw))

            # JunOS stanza tracking, so `community` is only an SNMP secret
            # inside the snmp stanza and never a BGP community. The stack is
            # tested for membership, so a nested stanza counts too.
            sm = R.STANZA_OPEN.match(raw)
            if sm:
                self.stanza.append(sm.group(1).lower())
            elif R.STANZA_CLOSE.match(raw) and self.stanza:
                self.stanza.pop()

        if block is not None:                 # truncated file: still act
            self._flush_block(block, out)
        if banner is not None:
            self._flush_banner(banner, out)
        return out

    # -- scope: which blocks this line is inside ---------------------------
    def _enter(self, raw: str) -> None:
        """Resolve the blocks ``raw`` is inside, before it is transformed.

        Two kinds of block, one set of names (see ``rules.BLOCK_SCOPES``):

        * the JunOS brace stack, maintained in :meth:`run` *after* each line,
          because a stanza opener is not inside itself -- ``location {`` is a
          stanza opener, not a location;
        * an IOS-style block, which is a line at column zero plus the indented
          lines under it. Here the header IS part of its own block, and any
          other unindented line -- including the bare ``!`` -- ends it. So this
          is resolved before the line, not after.

        A JunOS ``set`` line brings its own scope for that one line, so
        ``set interfaces xe-0/0/0 description …`` is inside ``interfaces``
        without any enclosing block at all.

        Block bodies and banner bodies never reach here: their content is
        arbitrary text, and a banner that mentions an interface must not open a
        scope.
        """
        if raw.strip() and not raw[:1].isspace():
            self.block = next((name for name, pat in R.BLOCK_SCOPES
                               if pat.match(raw)), None)
        m = R.SET_SCOPE.match(raw)
        line_scope = (m.group(1).lower(),) if m else ()
        self.inside = tuple(self.stanza) + (
            (self.block,) if self.block else ()) + line_scope

    def _in_scope(self, rule: R.Rule) -> bool:
        """True if this rule may act on the line :meth:`_enter` last saw."""
        if rule.stanza and rule.stanza not in self.inside:
            return False
        return not any(name in self.inside for name in rule.outside)

    # -- multi-line material ----------------------------------------------
    def _flush_block(self, block: _Block, out: list[str]) -> None:
        """Emit the body of a block: one replacement, or the body verbatim."""
        body = "\n".join(block.body).strip()
        new = self._whole(block.name, block.action, body)
        if new is None:
            out.extend(block.body)
            return
        indent = ""
        for raw in block.body:
            if raw.strip():
                indent = raw[:len(raw) - len(raw.lstrip())]
                break
        out.append(f"{indent or '  '}{new}")

    def _banner(self, m, action: str, out: list[str]) -> _Banner | None:
        """Start a banner. Returns the state, or None if it ended on this line."""
        kind, rest = m.group(1), m.group(2)
        stripped = rest.strip()
        if not stripped:
            out.append(m.group(0))
            return None
        if len(stripped) <= 2 and not stripped[0].isalnum():
            out.append(f"banner {kind} {stripped}")    # e.g. `banner motd ^C`
            return _Banner(stripped, action)
        delim = stripped[0]
        if delim in stripped[1:]:                      # all on one line
            body = stripped[1:stripped.index(delim, 1)]
            new = self._whole(R.BANNER_RULE[0], action, body)
            out.append(m.group(0) if new is None
                       else f"banner {kind} {delim}{new}{delim}")
            return None
        out.append(f"banner {kind} {delim}")
        return _Banner(delim, action)

    def _flush_banner(self, banner: _Banner, out: list[str]) -> None:
        new = self._whole(R.BANNER_RULE[0], banner.action,
                          "\n".join(banner.body).strip())
        if new is None:
            out.extend(banner.body)
        else:
            out.append(new)

    def _whole(self, key: str, action: str, value: str) -> str | None:
        """Replacement for a whole multi-line body, or None to leave it be.

        None means one of three things, none of which is a change: the body was
        empty, it is already one of this key's own renderings (so a second run
        is a no-op), or the action is ``keep`` -- which is counted, because the
        report has to name what survived.
        """
        if not value:
            return None
        if self.p.is_rendered(key, value):
            return None
        if action == "keep":
            self.kept_counts[key] += 1
            return None
        self.counts[key] += 1
        return self.p.render(key, action, value)

    # -- one line ----------------------------------------------------------
    def line(self, text: str) -> str:
        for rule in self.rules:
            if not self._in_scope(rule):
                continue
            m = rule.regex.match(text)
            if m:
                text = self._splice(rule, m, text)

        # searched, not anchored, so a line can hold several; right to left
        for rule in R.BLOB_RULES:
            for m in reversed(list(rule.regex.finditer(text))):
                text = self._splice(rule, m, text)

        # MAC before IPv6 (both eat hex and colons); names last
        text = R.MAC_RE.sub(self._sub_mac, text)
        if self._family_actions["emails"] == "keep":
            for m in R.EMAIL_RE.finditer(text):
                self.p.kept.setdefault("email", set()).add(m.group(0))
                self.kept_counts["emails"] += 1
        else:
            text = R.EMAIL_RE.sub(self._sub_email, text)
        text = R.IPV6_RE.sub(self._sub_v6, text)
        text = R.IPV4_RE.sub(self._sub_v4, text)

        for pat, family in self._name_res:
            text = pat.sub(self._name_sub(family), text)
        return text

    def _splice(self, rule: R.Rule, m, text: str) -> str:
        """Rewrite every target group of one match, right to left.

        Each of ``rule.targets`` is an independent span, so a rule can carry
        several secrets on one line. Working from the last span backwards keeps
        the spans that have not been rewritten yet at the offsets ``m.span``
        reported.
        """
        action = self._actions.get(rule.name) or self.cfg.action_for_rule(rule.name)
        for start, end, value in reversed(self._spans(rule, m)):
            new = self._value(rule, action, value)
            if new is not None:
                text = f"{text[:start]}{new}{text[end:]}"
        return text

    @staticmethod
    def _spans(rule: R.Rule, m) -> list[tuple[int, int, str]]:
        """The target spans of a match, in order, non-overlapping.

        A group that did not participate is skipped, and a nested group is
        dropped in favour of the one that encloses it -- rewriting both would
        splice a replacement into a span that no longer exists.
        """
        spans = []
        for i in rule.targets:
            start, end = m.span(i)
            value = m.group(i)
            if start < 0 or not value or not value.strip():
                continue
            if spans and start < spans[-1][1]:
                continue
            spans.append((start, end, value))
        return spans

    def _value(self, rule: R.Rule, action: str, value: str) -> str | None:
        """The replacement for one target span, or None to leave it alone."""
        if rule.handler == "snmp-host":
            return self._snmp_host(rule.name, action, value)
        if self.p.is_rendered(rule.name, value):
            return None                       # already ours: a re-run is a no-op
        if action == "keep":
            self.kept_counts[rule.name] += 1
            return None
        quote = (value[0] if len(value) > 1 and value[0] == value[-1]
                 and value[0] in "\"'" else "")
        new = self.p.render(rule.name, action,
                            value[1:-1] if quote else value)
        self.counts[rule.name] += 1
        return f"{quote}{new}{quote}" if quote else new

    def _snmp_host(self, key: str, action: str, region: str) -> str:
        """Act on the community / v3 user name in an `snmp-server host` line.

        The target is the whole token region after the destination, because
        which token is the secret depends on the keywords in front of it.
        """
        toks, out, i = region.split(), [], 0
        while i < len(toks):
            if toks[i].lower() in R.SNMP_HOST_KEYWORDS:
                out.append(toks[i])
                i += 1
                continue
            if self.p.is_rendered(key, toks[i]):
                out.append(toks[i])
            elif action == "keep":
                self.kept_counts[key] += 1
                out.append(toks[i])
            else:
                out.append(self.p.render(key, action, toks[i]))
                self.counts[key] += 1
            out.extend(toks[i + 1:])
            break
        return " ".join(out)

    # -- substitution callbacks -------------------------------------------
    # Addresses and MACs do not go through `render`: their action is finer than
    # one string per family -- per address class, per MAC half -- so the
    # pseudonymiser resolves it, and `render`'s family-level `keep` shortcut
    # would skip a class that is active while the default is `keep`.
    def _sub_mac(self, m):
        value = m.group(1)
        new = self.p.mac(value)
        if new is None or new == value:
            self.kept_counts["macs"] += 1
            return value
        self.counts["macs"] += 1
        return new

    def _sub_email(self, m):
        value = m.group(0)
        new = self.p.render("emails", self._family_actions["emails"], value)
        if new == value:
            return value
        self.counts["emails"] += 1
        return new

    def _sub_v6(self, m):
        value = m.group(1)
        new = self.p.ipv6(value)
        if new is None:
            if _is_v6(value):
                self.kept_counts["ipv6"] += 1
            return value
        if new == value:
            return value
        self.counts["ipv6"] += 1
        return new

    def _sub_v4(self, m):
        value = m.group(1)
        new = self.p.ipv4(value)
        if new is None:
            if _is_v4_address(value):
                self.kept_counts["ipv4"] += 1
            return value
        if new == value:
            return value
        self.counts["ipv4"] += 1
        return new

    def _name_sub(self, family: str):
        action = self._family_actions[family]

        def sub(m):
            value = m.group(0)
            if action == "keep":
                self.kept_counts[family] += 1
                return value
            new = self.p.render(family, action, value)
            if new == value:
                return value
            self.counts[family] += 1
            return new

        return sub


def _is_v4_address(text: str) -> bool:
    """A dotted quad that is an address, not a netmask or a wildcard mask.

    Masks are never touched whatever the policy says, so they are not material
    that was *kept* and must not inflate the kept count.
    """
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return not is_mask_like(int(addr))


def _is_v6(text: str) -> bool:
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def sanitise_text(text: str, config: Config | None = None, *,
                  salt: bytes | None = None) -> Result:
    """Sanitise a configuration and return a :class:`Result`.

    This is the main library entry point::

        from netredact import Config, sanitise_text
        result = sanitise_text(open("running-config.txt").read())
        print(result.text)
        for f in result.findings:
            print(f.line, f.check, f.text)

    With no ``salt``, a random one is generated, so pseudonyms differ between
    runs. Pass a stable salt (or set ``salt_file`` in the config) to make them
    reproducible.
    """
    import secrets as _secrets

    from .verify import verify

    cfg = config or Config()
    salt = salt or _secrets.token_bytes(32)
    lines = text.splitlines()

    san = Sanitiser(cfg, salt=salt)
    san.collect(lines)
    out_lines = san.run(lines)
    out = "\n".join(out_lines) + ("\n" if out_lines else "")

    findings = verify(out_lines, cfg) if cfg.verify.enabled else []
    return Result(
        text=out,
        vendor=cfg.vendor if cfg.vendor != "auto" else detect_vendor(text),
        counts=san.counts,
        kept_counts=san.kept_counts,
        kept=san.p.kept,
        policy_summary=policy_summary(cfg),
        collisions=san.p.collisions,
        findings=findings,
        mapping={k: dict(v) for k, v in san.p.maps.items()},
        families=san.families,
    )
