"""The transformation itself.

Two passes over the input:

1. :meth:`Sanitiser.collect` learns the identities this device uses -- its
   hostnames, domains and usernames -- because those are only recognisable
   from the lines that declare them. Nothing is rewritten here.
2. :meth:`Sanitiser.run` asks the rule catalogue to traverse the input. The
   catalogue owns scope, multiline state and structural splicing; this module
   supplies policy-dependent replacement and non-rule substitutions.

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
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

from . import provenance
from . import rules as R
from .collection import RemovedSection, strip_rancid_diagnostics
from .config import RULE_FAMILIES, Config
from .operational import AsNumbers, OperationalNames
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

# Associated labels are commonly filenames. Unlike configuration grammar,
# ``_`` and ``-`` are separators there, so their boundaries are alphanumeric
# rather than ``\w`` boundaries. The value patterns remain strict enough not
# to select an address embedded inside a larger word or address.
_LABEL_IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9.])((?:\d{1,3}\.){3}\d{1,3})(?!(?:[A-Za-z0-9]|\.\d))")
_LABEL_IPV6_RE = re.compile(
    R.IPV6_RE.pattern.replace(r"(?<![\w:.])", r"(?<![A-Za-z0-9:.])")
    .replace(r"(?![\w:.])", r"(?![A-Za-z0-9:.])"))
_LABEL_MAC_RE = re.compile(
    R.MAC_RE.pattern.replace(r"(?<![\w.:-])", r"(?<![A-Za-z0-9:-])")
    .replace(r"(?![\w.:-])", r"(?![A-Za-z0-9:-])"))


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
    #: collector command sections deleted before sanitization
    removed_sections: list[RemovedSection] = field(default_factory=list)
    #: caller-supplied associated labels, sanitised with :attr:`text`
    labels: dict[str, str] = field(default_factory=dict)
    #: whether the INPUT already carried netredact's marker, i.e. was itself
    #: sanitised output. The run still happened -- a library caller decides
    #: what that means -- but pseudonyms in it have now been mapped twice.
    already_sanitised: bool = False
    #: label key -> family -> rendered replacements; never originals or kept values
    label_replacements: Mapping[str, Mapping[str, tuple[str, ...]]] = field(
        default_factory=lambda: MappingProxyType({})
    )

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

    op_actions = {cfg.operational_names.action(kind)
                  for kind in cfg.operational_names.TYPES}
    if op_actions == {"keep"}:
        kept.append("operational-names")
    elif len(op_actions) == 1:
        parts.append(f"operational-names={op_actions.pop()}")
    else:
        parts.append("operational-names=keep (per type)")
    if cfg.as_numbers.default == "keep":
        kept.append("as-numbers")
    else:
        parts.append(f"as-numbers={cfg.as_numbers.default}")

    custom = [f"{c.name}={c.action}" for c in cfg.custom if c.action]
    if len(custom) > 3:
        custom = custom[:3] + [f"+{len(custom) - 3} more custom rule(s)"]
    parts.extend(custom)

    if not parts:
        return "everything kept"
    if kept:
        parts.append("everything else kept")
    return ", ".join(parts)


class Sanitiser:
    """Stateful, single-use: build one per file."""

    def __init__(self, config: Config | None = None, *, salt: bytes,
                 pseudo: Pseudonymiser | None = None):
        self.cfg = config or Config()
        self.cfg.validate()
        self.p = pseudo or Pseudonymiser(salt, self.cfg)
        self.operational = OperationalNames(self.cfg.operational_names, self.p)
        self.as_numbers = AsNumbers(self.cfg.as_numbers, self.p)
        self.catalogue = R.RuleCatalogue.builtins().configured(self.cfg.custom)
        self.counts: Counter = Counter()
        self.kept_counts: Counter = Counter()
        self.hostnames: list[str] = []
        self.domains: list[str] = []
        self.usernames: list[str] = []
        self.emails: list[str] = []
        self._name_res: list[tuple[re.Pattern, str]] = []
        self._label_name_res: list[tuple[re.Pattern, str]] = []
        self._label_email_res: list[re.Pattern] = []
        self._active_label_replacements: dict[str, list[str]] | None = None
        self.handled_macs: set[str] = set()
        # name -> family for everything that can be counted, and name -> action
        # for every rule. Resolving the action once means a bad override is an
        # error before any output is produced, not halfway through a file.
        self.families: dict[str, str] = {}
        self._actions: dict[str, str] = {}
        for info in self.catalogue.inventory():
            self.families[info.name] = info.family
            self._actions[info.name] = self.cfg.action_for_rule(info.name)
        for family in ("ipv4", "ipv6", "macs", "hostnames", "domains",
                       "usernames", "emails"):
            self.families[family] = family
        for kind in self.cfg.operational_names.TYPES:
            self.families[kind] = "operational-names"
        self.families["as-numbers"] = "as-numbers"
        self._family_actions = {f: self.cfg.action_for(f)
                                for f in ("hostnames", "domains", "usernames",
                                          "emails")}

    # -- pass 1: learn the identities this device uses ---------------------
    def collect(self, lines) -> None:
        # The one piece of state this pass has, and it earns its place: a
        # RouterOS `name=` is the device's own name, a login or an interface
        # depending only on the section above it, so the flat pattern tables
        # cannot decide it. The scoped tables are consulted exactly like the
        # flat ones; the section tracker is the same one the rules use, so the
        # two can never disagree about where a line is.
        section: str | None = None
        for line in lines:
            section = R.routeros_scope(line, section)
            for pat in R.HOSTNAME_PATS:
                m = pat.search(line)
                if m:
                    self._add(self.hostnames, m.group(1).strip('";'))
            for scopes, pat in R.SCOPED_HOSTNAME_PATS:
                m = pat.search(line) if section in scopes else None
                if m:
                    self._add(self.hostnames, m.group(1).strip('";'))
            for scopes, pat in R.SCOPED_USERNAME_PATS:
                m = pat.search(line) if section in scopes else None
                if m:
                    self._add(self.usernames, m.group(1).strip('";'))
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
                self._add(self.emails, m.group(0))
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
        self._label_name_res = [(self._label_re(value), family)
                                for value, family in candidates]
        self._label_email_res = [self._label_email_re(value)
                                 for value in sorted(self.emails, key=len, reverse=True)]

    @staticmethod
    def _add(bucket: list, value: str) -> None:
        value = value.strip()
        if value and value.lower() not in {v.lower() for v in bucket}:
            bucket.append(value)

    @staticmethod
    def _word_re(token: str) -> re.Pattern:
        # no [\w-] either side, so "admin" never matches inside "network-admin"
        return re.compile(rf"(?<![\w-]){re.escape(token)}(?![\w-])", re.I)

    @staticmethod
    def _label_re(token: str) -> re.Pattern:
        """Match a discovered identity as one filename/display-label token."""
        return re.compile(
            rf"(?<![A-Za-z0-9]){re.escape(token)}(?![A-Za-z0-9])", re.I)

    @staticmethod
    def _label_email_re(email: str) -> re.Pattern:
        """Match a whole discovered address, never a suffix of another one."""
        return re.compile(
            rf"(?<![\w.!#$%&'*+/=?^_`{{|}}~-]){re.escape(email)}(?![\w.-])",
            re.I,
        )

    # -- pass 2: transform -------------------------------------------------
    def run(self, lines) -> list[str]:
        out = self.catalogue.transform(
            lines, replace=self._replace_rule_hit,
            finish_line=lambda line: self.line(
                self.as_numbers.line(self.operational.line(line))))
        self.counts.update(self.operational.counts)
        self.kept_counts.update(self.operational.kept_counts)
        self.counts.update(self.as_numbers.counts)
        self.kept_counts.update(self.as_numbers.kept_counts)
        return out

    def _replace_rule_hit(self, hit: R.RuleHit) -> R.RuleReplacement:
        """Classify and render one value selected by the rule catalogue."""
        key, value = hit.name, hit.value
        action = self._actions[key]
        if not value:
            return R.RuleReplacement.unchanged()
        if action == "keep":
            self.kept_counts[key] += 1
            return R.RuleReplacement.keep()
        if self.p.is_rendered(key, value):
            return R.RuleReplacement.unchanged()
        self.counts[key] += 1
        return R.RuleReplacement.with_text(self.p.render(key, action, value))

    # -- one line ----------------------------------------------------------
    def line(self, text: str) -> str:
        # MAC before IPv6 (both eat hex and colons); names last
        text = R.MAC_RE.sub(self._sub_mac, text)
        text = R.BARE_MAC_CONTEXT_RE.sub(
            lambda m: m.group("prefix") + self._replace_bare_mac(m.group("value")),
            text)
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

    def associated_label(self, text: str) -> tuple[str, dict[str, tuple[str, ...]]]:
        """Sanitise a filename or display label with this run's identities.

        Accounting is intentionally owned by the configuration body. The
        public entry point snapshots it before calling this method.
        """
        self._active_label_replacements = {}
        try:
            # An e-mail domain may itself be an IPv4 literal. Handle the complete
            # collected identity before generic address recognition can split it.
            for pat in self._label_email_res:
                text = pat.sub(self._name_sub("emails"), text)
            text = _LABEL_MAC_RE.sub(self._sub_mac, text)
            text = _LABEL_IPV6_RE.sub(self._sub_v6, text)
            text = _LABEL_IPV4_RE.sub(self._sub_v4, text)
            for pat, family in self._label_name_res:
                text = pat.sub(self._name_sub(family), text)
            replacements = {
                family: tuple(values)
                for family, values in self._active_label_replacements.items()
            }
            return text, replacements
        finally:
            self._active_label_replacements = None

    def _record_label_replacement(self, family: str, replacement: str) -> None:
        if self._active_label_replacements is not None:
            self._active_label_replacements.setdefault(family, []).append(replacement)

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
        self.handled_macs.add(new.lower())
        self._record_label_replacement("macs", new)
        return new

    def _replace_bare_mac(self, value: str) -> str:
        class Match:
            @staticmethod
            def group(_index):
                return value
        return self._sub_mac(Match())

    def _sub_email(self, m):
        value = m.group(0)
        new = self.p.render("emails", self._family_actions["emails"], value)
        if new == value:
            return value
        self.counts["emails"] += 1
        self._record_label_replacement("emails", new)
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
        self._record_label_replacement("ipv6", new)
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
        self._record_label_replacement("ipv4", new)
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
            self._record_label_replacement(family, new)
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
                  salt: bytes | None = None,
                  labels: Mapping[str, str] | None = None) -> Result:
    """Sanitise a configuration and return a :class:`Result`.

    This is the main library entry point::

        from netredact import Config, sanitise_text
        result = sanitise_text(open("running-config.txt").read())
        print(result.text)
        for f in result.findings:
            print(f.line, f.check, f.text)

    With no ``salt``, a random one is generated, so pseudonyms differ between
    runs. Library callers pass a stable salt explicitly to make them
    reproducible. ``Config.salt_file`` is CLI-oriented and this function never
    reads or writes it.

    ``labels`` associates filenames or display labels with the text. Their
    values are sanitised with the same collected identities and pseudonymiser;
    their keys are left unchanged. Labels do not contribute to body findings,
    counts, mapping, collisions or kept-value reporting.
    """
    import secrets as _secrets

    from .verify import verify

    cfg = config or Config()
    cfg.validate()
    if labels is None:
        labels = {}
    elif not isinstance(labels, Mapping):
        raise TypeError("labels must be a mapping of strings to strings")
    if any(not isinstance(key, str) or not isinstance(value, str)
           for key, value in labels.items()):
        raise TypeError("labels must be a mapping of strings to strings")
    salt = salt or _secrets.token_bytes(32)
    lines = text.splitlines()
    # A marked input is netredact's own output. The marker comes off before
    # the rules see it -- its version number is not material to hash, and it
    # must not be counted as a change -- and this function does not put one
    # back. Writing the marker belongs to whoever emits the file, because
    # inserting a line here would break the line-count guarantee the
    # transformation makes; see :mod:`netredact.provenance`.
    already_sanitised = provenance.is_marked(text)
    if already_sanitised:
        lines = provenance.strip(lines)
    removed_sections: list[RemovedSection] = []
    collection_mode = cfg.collection.rancid_diagnostics
    if collection_mode not in {"remove", "keep"}:
        from .config import ConfigError
        raise ConfigError(
            "[collection] rancid_diagnostics: unknown mode "
            f"{collection_mode!r}. Expected one of remove, keep"
        )
    if collection_mode == "remove":
        lines, removed_sections = strip_rancid_diagnostics(lines)
    # A wrapped RouterOS command is one logical line, and it is unwrapped once,
    # here, so the collect pass, the transformation and the verifier all read
    # the same lines. `transform` joins too and joining is idempotent, so this
    # is not a second policy -- it is the same one, applied early enough for the
    # collect pass, which has no line-joining of its own to reach a `name=` the
    # wrap carried onto the next line.
    lines = R.join_continuations(lines)
    retained_text = "\n".join(lines) + ("\n" if lines else "")

    vendor = cfg.vendor if cfg.vendor != "auto" else detect_vendor(retained_text)

    san = Sanitiser(cfg, salt=salt)
    san.collect(lines)
    out_lines = san.run(lines)
    out = "\n".join(out_lines) + ("\n" if out_lines else "")

    findings = (verify(out_lines, cfg, handled_macs=san.handled_macs,
                       handled_asns=san.as_numbers.handled)
                if cfg.verify.enabled else [])
    # Labels share the stateful pseudonymiser so equal values render equally,
    # but body reporting is a separate contract. Snapshot it first: a value
    # present only in a filename must not appear to have occurred in the config.
    body_counts = Counter(san.counts)
    body_kept_counts = Counter(san.kept_counts)
    body_kept = {key: set(values) for key, values in san.p.kept.items()}
    body_collisions = set(san.p.collisions)
    body_mapping = {key: dict(values) for key, values in san.p.maps.items()}
    sanitised_labels: dict[str, str] = {}
    label_replacements: dict[str, Mapping[str, tuple[str, ...]]] = {}
    for key, value in labels.items():
        sanitised, replacements = san.associated_label(value)
        sanitised_labels[key] = sanitised
        label_replacements[key] = MappingProxyType(replacements)
    return Result(
        text=out,
        vendor=vendor,
        already_sanitised=already_sanitised,
        labels=sanitised_labels,
        label_replacements=MappingProxyType(label_replacements),
        counts=body_counts,
        kept_counts=body_kept_counts,
        kept=body_kept,
        policy_summary=policy_summary(cfg),
        collisions=body_collisions,
        findings=findings,
        mapping=body_mapping,
        families=san.families,
        removed_sections=removed_sections,
    )
