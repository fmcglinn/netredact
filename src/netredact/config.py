"""Configuration for netredact.

Everything tunable lives here, so the CLI stays small and the library is
driven by one object. Configuration is TOML, discovered in this order:

    1. an explicit path (``--config`` / ``Config.load(path)``)
    2. ``./netredact.toml``
    3. ``./.netredact.toml``
    4. ``$XDG_CONFIG_HOME/netredact/config.toml``
       (``~/.config/netredact/config.toml``)
    5. the built-in defaults

Only the keys you set are overridden; everything else keeps its default.

The model is *selector then action*: a section of this file selects a part of
the input (a family of sensitive material, an address class, a single rule)
and gives it one of four actions:

    ``keep``    leave it alone
    ``pseudo``  replace with a type-valid substitute -- equality is preserved
                and the output still loads
    ``hash``    replace with an opaque ``<PREFIX-tag>`` marker -- equality is
                preserved, and the marker announces the sanitisation
    ``redact``  replace with a family-appropriate constant -- nothing survives

``pseudo`` is the only illegal cell: a secret has no type-valid substitute
that is safe to emit, so secrets take ``keep``, ``hash`` or ``redact``.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields, is_dataclass, make_dataclass
from pathlib import Path

from . import rules
from .addresses import V4_CLASS_NAMES, V6_CLASS_NAMES, describe
from .vendors import VENDOR_NAMES

__all__ = [
    "ACTIONS", "FAMILIES", "ALLOWED", "POLICY_FAMILIES", "RULE_FAMILIES",
    "RULE_SECTIONS", "VENDORS", "Config", "PolicyConfig", "IPv4Policy",
    "IPv6Policy", "MacPolicy", "SecretsPolicy", "TextPolicy",
    "IdentityPolicy", "PlatformPolicy", "InterfacesPolicy", "VlansPolicy",
    "CircuitsPolicy",
    "CollectionConfig", "VerifyConfig", "CustomRule",
    "ConfigError", "find_config", "DEFAULT_CONFIG_NAMES",
]

DEFAULT_CONFIG_NAMES = ("netredact.toml", ".netredact.toml")

#: what can be done to a selected part of the input
ACTIONS = ("keep", "pseudo", "hash", "redact")

#: the families a rule -- or a bare regex match -- belongs to
FAMILIES = ("secrets", "text", "identity", "platform", "interfaces", "vlans",
            "circuits",
            "hostnames", "domains", "usernames", "emails",
            "ipv4", "ipv6", "macs")

#: legality per family. The only illegal cell is ``pseudo`` on ``secrets``.
ALLOWED: dict[str, tuple[str, ...]] = {f: ACTIONS for f in FAMILIES}
ALLOWED["secrets"] = ("keep", "hash", "redact")

#: the families named directly in ``[policy]``: the four the collect pass
#: learns. Every other family is a table of named rules and has a section of
#: its own, where each rule is a key -- see :data:`RULE_FAMILIES`.
POLICY_FAMILIES = ("hostnames", "domains", "usernames", "emails")

#: legal values for ``vendor``. ``auto`` runs the detector and is the default;
#: naming one only overrides what the report says, since every rule is applied
#: to every file regardless.
#:
#: THE PRINCIPLE, the same one the family sections are built on: the names come
#: from the detector's own hint table (:data:`netredact.vendors.VENDOR_HINTS`)
#: rather than being transcribed here, so the two cannot fall out of step. A
#: vendor in only one of the two lists is either an unreachable config value or
#: an undetectable vendor, and neither can now be written by accident.
#: ``auto`` stays first, and is not a vendor: it is the absence of a choice.
VENDORS = ("auto",) + VENDOR_NAMES

_DOCS = "see docs/configuration.md"


class ConfigError(ValueError):
    """Raised when a configuration file is invalid."""


def _check_action(where: str, family: str, action: object) -> str:
    """Validate one action string for one family. Returns it unchanged."""
    if not isinstance(action, str):
        raise ConfigError(f"{where} must be an action string, got {action!r}")
    if action not in ACTIONS:
        raise ConfigError(
            f"{where}: unknown action {action!r}. "
            f"Expected one of {', '.join(ACTIONS)}")
    allowed = ALLOWED.get(family, ACTIONS)
    if action not in allowed:
        if action == "pseudo" and family == "secrets":
            raise ConfigError(
                f"{where}: pseudo is not available for secrets: use hash for "
                f"an opaque marker, or redact")
        raise ConfigError(
            f"{where}: {action} is not available for {family}: "
            f"use one of {', '.join(allowed)}")
    return action


# ---------------------------------------------------------------------------
# sections
# ---------------------------------------------------------------------------


@dataclass
class PolicyConfig:
    """The families that have no rules.

    ``hostnames``, ``domains``, ``usernames`` and ``emails`` are not found by
    a pattern table: the collect pass reads them off the lines that declare
    them and then substitutes them wherever they appear. There is nothing to
    name per rule, so they take one action each and stay here.

    Every other family is a table of named rules, and each of those has a
    section of its own -- see :func:`_rule_policy`.
    """

    #: device names, discovered by the collect pass
    hostnames: str = "keep"
    domains: str = "keep"
    usernames: str = "keep"
    emails: str = "keep"

    def __post_init__(self) -> None:
        for f in fields(self):
            _check_action(f"[policy] {f.name}", f.name, getattr(self, f.name))

    def action(self, family: str) -> str:
        if family not in POLICY_FAMILIES:
            raise ConfigError(
                f"[policy] has no family {family!r}. "
                f"Expected: {', '.join(POLICY_FAMILIES)}")
        return getattr(self, family)


@dataclass
class IPv4Policy:
    """What happens to IPv4 addresses, per address class.

    ``default`` governs every class; naming a class overrides it for that
    class only, and a class left unset (``None``) inherits ``default``.
    Classes are mutually exclusive and checked most-specific first, so an
    address is governed by exactly one of them. Netmasks and wildcard masks
    are detected structurally and never touched, whatever you set here.
    """

    #: the action for every class not named below
    default: str = "keep"

    loopback: str | None = None        # 127.0.0.0/8
    rfc1918: str | None = None         # 10/8, 172.16/12, 192.168/16
    cgnat: str | None = None           # 100.64.0.0/10
    link_local: str | None = None      # 169.254.0.0/16
    multicast: str | None = None       # 224.0.0.0/4
    documentation: str | None = None   # 192.0.2/24, 198.51.100/24, 203.0.113/24
    benchmark: str | None = None       # 198.18.0.0/15
    reserved: str | None = None        # 0/8, 192.0.0.0/24, 240/4, ...
    #: the address CLASS; the resolvers themselves are well_known_resolvers
    well_known: str | None = None
    other_unicast: str | None = None   # everything else: globally routable

    #: pseudonyms are allocated from these, in order. Only the /24 moves --
    #: the host octet and the prefix length are preserved.
    pool: list[str] = field(default_factory=lambda: [
        "198.18.0.0/15", "100.64.0.0/10"])
    #: public resolvers, treated as the ``well_known`` class above. Keeping
    #: them makes the output far easier to read and identifies nobody.
    well_known_resolvers: list[str] = field(default_factory=lambda: [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
        "149.112.112.112", "208.67.222.222", "208.67.220.220",
        "4.2.2.1", "4.2.2.2",
    ])
    #: extra prefixes never to touch, whatever class they fall into
    keep_networks: list[str] = field(default_factory=list)

    #: the address classes this policy can name, most-specific first
    CLASSES = V4_CLASS_NAMES

    def __post_init__(self) -> None:
        _check_action("[ipv4] default", "ipv4", self.default)
        for klass in self.CLASSES:
            value = getattr(self, klass)
            if value is not None:
                _check_action(f"[ipv4] {klass}", "ipv4", value)

    def action(self, klass: str) -> str:
        """The resolved action for one address class. Never ``None``."""
        if klass not in self.CLASSES:
            raise ConfigError(
                f"unknown IPv4 address class {klass!r}. "
                f"Expected: {', '.join(self.CLASSES)}")
        value = getattr(self, klass)
        return self.default if value is None else value

    def any_active(self) -> bool:
        """True if any address class resolves to something other than keep."""
        return any(self.action(k) != "keep" for k in self.CLASSES)


@dataclass
class IPv6Policy:
    """What happens to IPv6 addresses, per address class. See :class:`IPv4Policy`."""

    default: str = "keep"

    unspecified: str | None = None     # ::/128
    loopback: str | None = None        # ::1/128
    ula: str | None = None             # fc00::/7
    link_local: str | None = None      # fe80::/10
    multicast: str | None = None       # ff00::/8
    documentation: str | None = None   # 2001:db8::/32
    teredo: str | None = None          # 2001::/32
    six_to_four: str | None = None     # 2002::/16
    ipv4_mapped: str | None = None     # ::ffff:0:0/96, 64:ff9b::/96
    #: the address CLASS; the resolvers themselves are well_known_resolvers
    well_known: str | None = None
    other_unicast: str | None = None   # everything else: global unicast

    #: the /64 moves inside this prefix; the interface identifier is preserved
    pool: str = "2001:db8::/32"
    well_known_resolvers: list[str] = field(default_factory=lambda: [
        "2001:4860:4860::8888", "2001:4860:4860::8844",
        "2606:4700:4700::1111", "2606:4700:4700::1001",
    ])
    keep_networks: list[str] = field(default_factory=list)

    CLASSES = V6_CLASS_NAMES

    def __post_init__(self) -> None:
        _check_action("[ipv6] default", "ipv6", self.default)
        for klass in self.CLASSES:
            value = getattr(self, klass)
            if value is not None:
                _check_action(f"[ipv6] {klass}", "ipv6", value)

    def action(self, klass: str) -> str:
        """The resolved action for one address class. Never ``None``."""
        if klass not in self.CLASSES:
            raise ConfigError(
                f"unknown IPv6 address class {klass!r}. "
                f"Expected: {', '.join(self.CLASSES)}")
        value = getattr(self, klass)
        return self.default if value is None else value

    def any_active(self) -> bool:
        """True if any address class resolves to something other than keep."""
        return any(self.action(k) != "keep" for k in self.CLASSES)


@dataclass
class MacPolicy:
    """MAC addresses, in two independent halves.

    ``oui`` is the 24-bit vendor prefix, ``nic`` the 24-bit device half.
    ``redact`` on the ``oui`` writes ``pool``. ``hash`` replaces the whole
    address with one marker, so it is only available by setting both halves
    to ``hash``.
    """

    oui: str = "keep"
    nic: str = "keep"
    #: the OUI written by ``redact`` -- 00:00:5e is IANA-reserved
    pool: str = "00:00:5e"

    def __post_init__(self) -> None:
        _check_action("[macs] oui", "macs", self.oui)
        _check_action("[macs] nic", "macs", self.nic)
        if "hash" in (self.oui, self.nic) and self.oui != self.nic:
            raise ConfigError(
                "macs: hash applies to the whole address, set both oui and "
                "nic to hash")
        if not isinstance(self.pool, str):
            raise ConfigError(f"[macs] pool must be a string, got {self.pool!r}")

    def any_active(self) -> bool:
        return self.oui != "keep" or self.nic != "keep"


def _field(rule: str) -> str:
    """The dataclass field that holds the action for one rule name.

    TOML allows a dash in a bare key and a Python identifier does not, so
    ``[platform] os-version`` is stored on ``PlatformPolicy.os_version``. The
    rule name is the spelling users see everywhere -- in its section, and in
    ``netredact --list-rules`` -- so the translation stops here.
    """
    return rule.replace("-", "_")


def _rule_post_init(self) -> None:
    _check_action(f"[{self.FAMILY}] default", self.FAMILY, self.default)
    for rule in self.RULES:
        value = getattr(self, _field(rule))
        if value is not None:
            _check_action(f"[{self.FAMILY}] {rule}", self.FAMILY, value)


def _rule_action(self, rule: str) -> str:
    """The resolved action for one rule. Never ``None``."""
    if rule not in self.RULES:
        raise ConfigError(
            f"[{self.FAMILY}] has no rule {rule!r}. "
            f"Expected: {', '.join(self.RULES)}")
    value = getattr(self, _field(rule))
    return self.default if value is None else value


def _rule_any_active(self) -> bool:
    """True if any rule resolves to something other than keep."""
    return any(self.action(r) != "keep" for r in self.RULES)


def _rule_policy(family: str, default: str, doc: str) -> type:
    """Build the section class for one rule-named family.

    THE PRINCIPLE: the keys come from the rule table, never from a list
    written out here. A rule added to a family gets a key in its section, a
    line in ``--print-config`` and a cell in the option-matrix sweep, with
    nothing to keep in step by hand -- and no way for the config to fall
    silently out of date with the rules it configures.

    ``default`` governs every rule in the family; naming a rule gives that
    rule its own action, and a rule left unset (``None``) inherits
    ``default``. This is the same shape as ``[ipv4]``, one section down: the
    difference is only that its members are rules rather than a partition of
    a value space.
    """
    names = tuple(info.name for info in rules.RuleCatalogue.builtins().inventory()
                  if info.family == family)
    cls = make_dataclass(
        f"{family.capitalize()}Policy",
        [("default", str, field(default=default))]
        + [(_field(n), "str | None", field(default=None)) for n in names],
        namespace={
            "FAMILY": family,
            "RULES": names,
            "__doc__": doc,
            "__post_init__": _rule_post_init,
            "action": _rule_action,
            "any_active": _rule_any_active,
        },
    )
    cls.__module__ = __name__
    return cls


SecretsPolicy = _rule_policy(
    "secrets", "redact",
    """Passwords, keys, community strings and password hashes, per rule.

    The one family whose ``default`` is not ``keep``: netredact destroys
    credentials unless you tell it otherwise, and that is the whole of the
    default promise. ``pseudo`` is refused here -- the substitute would be an
    HMAC of the real credential.
    """)

TextPolicy = _rule_policy(
    "text", "keep",
    """Descriptions, remarks, banners, login messages, location, contact.

    On a service-provider config this is where the customer names live.
    ``hash`` is usually the right middle ground: ``<DESC-f11e24>`` still tells
    two ports apart without saying whose they are.
    """)

IdentityPolicy = _rule_policy(
    "identity", "keep",
    """Serial numbers, license UDIs, SNMP engine IDs, certificates, SSH keys.

    None of these is a credential, and all of them tie the file to one real
    device. ``default = "hash"`` with ``serial-number = "keep"`` is the vendor
    support case: destroy the identity, keep the one value the case needs.
    """)

PlatformPolicy = _rule_policy(
    "platform", "keep",
    """The hardware model, the software release and the boot image.

    Neither a credential nor an instance identity -- every device off the
    same production line carries it. What it discloses is the attack surface:
    a model plus a release number is a CVE list. Kept by default, because it
    is also the first thing a support desk asks for and the thing a reviewer
    needs in order to judge a config at all.
    """)

InterfacesPolicy = _rule_policy(
    "interfaces", "keep",
    """What a port is called: the ``description`` on an interface.

    The same selector as ``[text] description``, split off by the block it is
    in -- scope traversal lives behind ``RuleCatalogue``. It is a section of
    its own because it is
    the one piece of free text with two incompatible audiences: a TAC case is
    unreadable without the descriptions the topology is written in, and a public
    post is unpublishable with them. ``[text] default = "redact"`` with
    ``[interfaces] default = "keep"`` says that in two lines.
    """)

VlansPolicy = _rule_policy(
    "vlans", "keep",
    """What a VLAN is called: the ``name`` under a ``vlan <id>`` block.

    Not an SVI -- an ``interface Vlan905`` block is ``interfaces``. On a
    service-provider access switch this is frequently a service or customer
    identifier, and it was previously unreachable by any configuration, which
    is why the report had to name VLAN names as something it never touched.

    ``pseudo`` is the action to reach for: a VLAN name is referred to elsewhere
    in the config, so a type-valid ``vlname-f11e24`` keeps it loadable.
    """)

CircuitsPolicy = _rule_policy(
    "circuits", "keep",
    """What a cross-connect or a pseudowire is called.

    Arista's ``patch panel`` names and its ``mpls ldp`` pseudowires. On a
    service-provider edge these are order and customer references -- the
    material a ticket number is made of -- and unlike a description they are
    not free text: the config refers to them by name from more than one place,
    so a connector line and the pseudowire it points at have to come out the
    other side still pointing at each other.

    That is what makes ``pseudo`` the action to reach for, exactly as in
    ``[vlans]``: ``circuit-f11e24`` is type-valid, the file still loads, and
    two mentions of one name still read as one name. ``redact`` is honest but
    collapses every circuit onto one constant, so use it only where the output
    never has to load.
    """)

#: the families whose members are named rules, and so have a section each
RULE_FAMILIES = ("secrets", "text", "identity", "platform",
                 "interfaces", "vlans", "circuits")

#: family -> its section class
RULE_SECTIONS = {"secrets": SecretsPolicy, "text": TextPolicy,
                 "identity": IdentityPolicy, "platform": PlatformPolicy,
                 "interfaces": InterfacesPolicy, "vlans": VlansPolicy,
                 "circuits": CircuitsPolicy}

#: rule name -> the section that rule is set in. Read off the rule table, so a
#: rule refiled between families cannot be pointed at a stale section. One
#: table serves both places that have to answer "where does this rule live?":
#: the ``[overrides]`` migration hints below, and the wrong-section routing in
#: :func:`_misfiled`.
_RULE_HOMES = {info.name: info.family
               for info in rules.RuleCatalogue.builtins().inventory()}


@dataclass
class CustomRule:
    """A user-supplied rule.

    ``pattern`` is a regex. If it has capture groups, the groups are what
    gets acted on and everything outside them is kept. With no groups it is
    treated as the *prefix* -- everything up to and including the keyword
    that introduces the value -- and netredact appends the value matcher
    itself. ``%VAL%`` expands to that value matcher anywhere in the pattern.

    ``family`` decides both the action (via ``[policy]``) and how the
    replacement is rendered.

    ``action`` optionally gives this one rule its own action, the way a key
    in ``[secrets]`` or ``[text]`` does for a built-in one. Left unset, the
    rule takes its family's action.

    ``stanza`` optionally restricts the rule to a JunOS top-level stanza.
    """

    name: str
    pattern: str
    family: str = "secrets"
    action: str | None = None
    stanza: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ConfigError("a custom rule needs a name")
        if not isinstance(self.pattern, str) or not self.pattern:
            raise ConfigError(f"custom rule {self.name!r}: needs a pattern")
        if self.family not in FAMILIES:
            raise ConfigError(
                f"custom rule {self.name!r}: family must be one of "
                f"{', '.join(FAMILIES)}, got {self.family!r}")
        if self.action is not None:
            _check_action(f"custom rule {self.name!r} action", self.family,
                          self.action)


@dataclass
class VerifyConfig:
    """The pass that re-scans the *output* for anything still sensitive."""

    enabled: bool = True
    #: exit non-zero if the verification pass finds anything
    strict: bool = False
    #: names of verification checks to switch off
    disable: list[str] = field(default_factory=list)
    #: extra regexes that should be treated as expected, not as findings
    ignore_patterns: list[str] = field(default_factory=list)


@dataclass
class CollectionConfig:
    """How collector wrappers around a device configuration are handled."""

    rancid_diagnostics: str = "remove"

    def __post_init__(self) -> None:
        if not isinstance(self.rancid_diagnostics, str):
            raise ConfigError("[collection] rancid_diagnostics must be a string")
        if self.rancid_diagnostics not in {"remove", "keep"}:
            raise ConfigError(
                "[collection] rancid_diagnostics: unknown mode "
                f"{self.rancid_diagnostics!r}. Expected one of remove, keep"
            )


@dataclass
class Config:
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    ipv4: IPv4Policy = field(default_factory=IPv4Policy)
    ipv6: IPv6Policy = field(default_factory=IPv6Policy)
    macs: MacPolicy = field(default_factory=MacPolicy)
    #: the seven rule-named families, one section each
    secrets: SecretsPolicy = field(default_factory=SecretsPolicy)
    text: TextPolicy = field(default_factory=TextPolicy)
    identity: IdentityPolicy = field(default_factory=IdentityPolicy)
    platform: PlatformPolicy = field(default_factory=PlatformPolicy)
    interfaces: InterfacesPolicy = field(default_factory=InterfacesPolicy)
    vlans: VlansPolicy = field(default_factory=VlansPolicy)
    circuits: CircuitsPolicy = field(default_factory=CircuitsPolicy)
    #: extra rules of your own
    custom: list[CustomRule] = field(default_factory=list)
    collection: CollectionConfig = field(default_factory=CollectionConfig)
    verify: VerifyConfig = field(default_factory=VerifyConfig)
    #: file holding the HMAC salt, created 0600 if missing. Reuse it to keep
    #: pseudonyms consistent across runs and across devices. It is a
    #: re-identification key -- protect it.
    salt_file: str | None = None
    vendor: str = "auto"
    #: where the configuration came from, for diagnostics
    source: str | None = None

    def __post_init__(self) -> None:
        if self.vendor not in VENDORS:
            raise ConfigError(f"vendor must be one of {VENDORS}, got {self.vendor!r}")
        self.custom = [c if isinstance(c, CustomRule) else CustomRule(**c)
                       for c in self.custom]
        self._validate_custom()

    # -- resolution -------------------------------------------------------
    def action_for_rule(self, rule_name: str) -> str:
        """The action for one named rule.

        There is exactly one place a rule's action can come from: the section
        for its family, which either names the rule or falls back to that
        section's ``default``. A custom rule answers from its own ``action``
        if it set one, else from its family.
        """
        for c in self.custom:
            if c.name == rule_name:
                return c.action or self.action_for(c.family)
        family = self.family_of(rule_name)
        section = RULE_SECTIONS.get(family)
        if section is not None:
            return getattr(self, family).action(rule_name)
        return self.action_for(family)

    def action_for(self, family: str) -> str:
        """The family-level action.

        The four ``[policy]`` families answer from ``[policy]``. The seven
        rule-named families, and ``ipv4`` / ``ipv6``, answer with their
        section's ``default`` -- the per-rule and per-class detail lives in
        :meth:`action_for_rule` and :meth:`IPv4Policy.action`. ``macs`` is
        per-half, so it answers ``keep`` only when both halves are kept, and
        ``pseudo`` (i.e. active, see ``[macs]``) when they differ.
        """
        if family in POLICY_FAMILIES:
            return getattr(self.policy, family)
        if family in RULE_FAMILIES:
            return getattr(self, family).default
        if family == "ipv4":
            return self.ipv4.default
        if family == "ipv6":
            return self.ipv6.default
        if family == "macs":
            if self.macs.oui == self.macs.nic:
                return self.macs.oui
            return "pseudo"
        raise ConfigError(
            f"unknown family {family!r}. Expected: {', '.join(FAMILIES)}")

    def family_of(self, rule_name: str) -> str:
        """The family of a rule, built-in or custom."""
        for c in self.custom:
            if c.name == rule_name:
                return c.family
        family = _RULE_HOMES.get(rule_name)
        if family is None:
            raise ConfigError(
                f"unknown rule name {rule_name!r}. "
                f"See netredact --list-rules")
        return family

    # -- validation -------------------------------------------------------
    def _validate_custom(self) -> None:
        for c in self.custom:
            _check_action(f"custom rule {c.name!r}", c.family,
                          self.action_for_rule(c.name))

    # -- loading ----------------------------------------------------------
    @classmethod
    def load(cls, path: str | os.PathLike | None = None, *,
             search: bool = True) -> Config:
        """Load configuration. With no path, search the standard locations.

        Returns the built-in defaults if nothing is found.
        """
        if path is None and search:
            path = find_config()
        if path is None:
            return cls(source="<defaults>")
        p = Path(path).expanduser()
        try:
            raw = tomllib.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ConfigError(f"no such config file: {p}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{p}: {exc}") from exc
        cfg = cls.from_dict(raw)
        cfg.source = str(p)
        return cfg

    @classmethod
    def from_dict(cls, raw: dict) -> Config:
        _reject_removed(raw)
        known = {f.name for f in fields(cls)} - {"source"}
        unknown = set(raw) - known
        if unknown:
            raise ConfigError(
                f"unknown top-level section(s): {', '.join(sorted(unknown))}. "
                f"Expected: {', '.join(sorted(known))}")
        kwargs: dict = {}
        # read once, up front: a section is checked against the rules this
        # document defines as well as the built-in ones
        custom_names = _custom_names(raw)
        for f in fields(cls):
            if f.name not in raw:
                continue
            value = raw[f.name]
            if f.name == "custom":
                kwargs["custom"] = _build_custom(value)
                continue
            sub = _dataclass_for(f)
            if sub is not None:
                if not isinstance(value, dict):
                    raise ConfigError(f"[{f.name}] must be a table")
                kwargs[f.name] = _build(sub, value, f.name,
                                        kebab=f.name in RULE_FAMILIES,
                                        custom=custom_names)
            else:
                kwargs[f.name] = value
        return cls(**kwargs)

    def salt_path(self) -> Path | None:
        return Path(self.salt_file).expanduser() if self.salt_file else None

    # -- emitting ---------------------------------------------------------
    def to_toml(self) -> str:
        """Render this configuration as a commented TOML document."""
        return _render_toml(self)


def _dataclass_for(f) -> type | None:
    mapping = {
        "policy": PolicyConfig, "ipv4": IPv4Policy, "ipv6": IPv6Policy,
        "macs": MacPolicy, "collection": CollectionConfig,
        "verify": VerifyConfig, **RULE_SECTIONS,
    }
    return mapping.get(f.name)


def _custom_names(raw: dict) -> frozenset[str]:
    """The names the ``[[custom]]`` entries of this document give themselves.

    Read before any section is built, because a custom rule is a rule as far as
    the user is concerned: naming it in ``[secrets]`` is the same filing mistake
    as naming a built-in one in the wrong section, and deserves the same answer.
    """
    value = raw.get("custom")
    if not isinstance(value, list):
        return frozenset()
    return frozenset(item["name"] for item in value
                     if isinstance(item, dict) and isinstance(item.get("name"), str))


def _misfiled(section: str, unknown: set[str],
              custom: frozenset[str]) -> dict[str, str]:
    """Of the keys a section does not have, the ones that are rules elsewhere.

    THE PRINCIPLE: a key that names a real rule is not a typo, it is a filing
    mistake, and the only thing worth saying about it is where that rule lives.
    ``[text] serial-number`` is the reachable-but-wrong case -- the rule exists,
    the action is legal, and the section's own key list answers a question the
    user did not ask. Listing the section's keys is the right answer only for a
    key that names nothing at all.

    The home comes from :data:`_RULE_HOMES`, i.e. from the rule table, so
    refiling a rule between families moves the message with it. A custom rule
    has no section: its action is a key on its own ``[[custom]]`` entry.

    Returns key -> what to say about it, in the user's own spelling.
    """
    out: dict[str, str] = {}
    for key in sorted(unknown):
        rule = key.replace("_", "-")
        home = _RULE_HOMES.get(rule)
        if home is not None and home in RULE_SECTIONS and home != section:
            out[key] = (f"{key} is a rule in [{home}], not in [{section}]: "
                        f"set it as [{home}] {rule}")
        elif rule in custom or key in custom:
            out[key] = (f"{key} is a [[custom]] rule, not a key of "
                        f"[{section}]: give it an action on its own "
                        f"[[custom]] entry")
    return out


def _build(cls: type, raw: dict, section: str, *, kebab: bool = False,
           custom: frozenset[str] = frozenset()):
    """Build one section from its TOML table.

    ``kebab`` is for ``[platform]``, whose keys are rule names: the field is
    ``os_version`` and the key is ``os-version``. Every message here speaks
    the TOML spelling, so a typo is reported in the words the user wrote.

    ``custom`` names the document's own ``[[custom]]`` rules, so that one of
    those named in a family section is routed rather than called unknown.
    """
    spell = (lambda name: name.replace("_", "-")) if kebab else (lambda name: name)
    known = {spell(f.name): f.name for f in fields(cls)}
    unknown = set(raw) - set(known)
    if unknown:
        misfiled = _misfiled(section, unknown, custom)
        lines = [f"[{section}]: {said}" for said in misfiled.values()]
        strays = sorted(unknown - set(misfiled))
        if strays:
            lines.append(
                f"[{section}]: unknown key(s) {', '.join(strays)}. "
                f"Expected: {', '.join(sorted(known))}")
        raise ConfigError("\n".join(lines))
    kwargs = {}
    for key, value in raw.items():
        name = known[key]
        expected = next(f for f in fields(cls) if f.name == name)
        _check_type(section, key, value, expected)
        kwargs[name] = value
    try:
        return cls(**kwargs)
    except TypeError as exc:
        raise ConfigError(f"[{section}]: {exc}") from exc


def _check_type(section: str, key: str, value, f) -> None:
    ann = f.type if isinstance(f.type, str) else str(f.type)
    if ann.startswith("bool") and not isinstance(value, bool):
        raise ConfigError(f"[{section}] {key} must be true or false, got {value!r}")
    if ann.startswith("str") and not isinstance(value, str):
        raise ConfigError(f"[{section}] {key} must be a string, got {value!r}")
    if ann.startswith("list") and not isinstance(value, list):
        raise ConfigError(f"[{section}] {key} must be a list, got {value!r}")


def _build_custom(raw) -> list[CustomRule]:
    if not isinstance(raw, list):
        raise ConfigError(
            "custom rules are a list of tables: use [[custom]] for each one")
    out: list[CustomRule] = []
    for item in raw:
        if isinstance(item, CustomRule):
            out.append(item)
            continue
        if not isinstance(item, dict):
            raise ConfigError(f"[[custom]] entries must be tables, got {item!r}")
        if "mode" in item:
            raise ConfigError(
                "[[custom]] mode was replaced by family (one of "
                f"{', '.join(FAMILIES)}); value / value-kw / rest are now "
                f"expressed in the pattern itself -- {_DOCS}")
        out.append(_build(CustomRule, item, "[custom]"))
    return out


# ---------------------------------------------------------------------------
# migration: keys that used to exist, and where they went
# ---------------------------------------------------------------------------

_REMOVED_SECTIONS = {
    "overrides": "[overrides] is gone: a rule is set in the section for its "
                 "own family, so every rule now has exactly one home. Each "
                 f"key you had moves as follows -- {_DOCS}",
    "redact": f"[redact] was replaced by the family sections; {_DOCS}",
    "scrub": f"[scrub] was replaced by [policy]; {_DOCS}",
    "ips": f"[ips] was replaced by [ipv4] and [ipv6]; {_DOCS}",
}

_REMOVED_KEYS = {
    ("redact", "descriptions"):
        'now [text] default = "keep" | "pseudo" | "hash" | "redact"',
    ("redact", "banners"):
        'now [text] default, or [text] banner = "redact" for banners alone',
    ("redact", "disable"):
        'disabling is an action now: set the section default or the rule '
        'itself to "keep"',
    ("redact", "custom"):
        "now top-level [[custom]] entries, each with a family",
    ("scrub", "ipv4"):
        "now [ipv4] default plus per-class actions (the bool shorthand is gone)",
    ("scrub", "ipv6"):
        "now [ipv6] default plus per-class actions (the bool shorthand is gone)",
    ("scrub", "hostnames"): "now policy.hostnames",
    ("scrub", "domains"): "now policy.domains",
    ("scrub", "usernames"): "now policy.usernames",
    ("scrub", "emails"): "now policy.emails",
    ("scrub", "macs"):
        'now [macs] oui / nic: keep -> oui = nic = "keep"; oui -> nic = '
        '"pseudo"; full -> oui = "redact", nic = "pseudo"',
    ("ips", "pools_v4"): "now [ipv4] pool",
    ("ips", "pool_v6"): "now [ipv6] pool",
    ("ips", "well_known"):
        "now split into [ipv4] well_known_resolvers and [ipv6] "
        "well_known_resolvers",
    ("ips", "keep_networks"):
        "now [ipv4] keep_networks and [ipv6] keep_networks",
}


#: every rule that could have been named in ``[overrides]``, and the section
#: it lives in now. Read off :data:`_RULE_HOMES`, i.e. off the rule table, so a
#: refiled rule cannot be pointed at the wrong section -- and so this hint and
#: the wrong-section routing in :func:`_misfiled` can never disagree.
_REMOVED_KEYS.update({
    ("overrides", name): f"now [{home}] {name}"
    for name, home in _RULE_HOMES.items()
})

#: keys whose *section* survived but which themselves moved. A family that
#: became a section of its own left a hole in ``[policy]``, and landing in the
#: generic "unknown key" message would not say where to look.
_MOVED_KEYS = {
    ("policy", family): f'now [{family}] default, plus one key per rule'
    for family in RULE_FAMILIES
}


def _reject_removed(raw: dict) -> None:
    """Turn an old-style config into a migration message, not a puzzle."""
    for section, message in _REMOVED_SECTIONS.items():
        if section not in raw:
            continue
        lines = [message]
        value = raw[section]
        if isinstance(value, dict):
            for key in value:
                hint = _REMOVED_KEYS.get((section, key))
                if hint:
                    lines.append(f"  {section}.{key}: {hint}")
        raise ConfigError("\n".join(lines))

    moved = [(section, key) for section, key in _MOVED_KEYS
             if isinstance(raw.get(section), dict) and key in raw[section]]
    if moved:
        raise ConfigError("\n".join(
            [f"[{s}] {k}: {_MOVED_KEYS[(s, k)]}" for s, k in sorted(moved)]))


def find_config(start: str | os.PathLike | None = None) -> Path | None:
    """Return the first configuration file found, or None."""
    here = Path(start or Path.cwd())
    for name in DEFAULT_CONFIG_NAMES:
        candidate = here / name
        if candidate.is_file():
            return candidate
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    candidate = base / "netredact" / "config.toml"
    return candidate if candidate.is_file() else None


# ---------------------------------------------------------------------------
# TOML rendering, so `netredact --print-config` emits a real starting point
# ---------------------------------------------------------------------------

_HEADER = [
    "# netredact configuration",
    "#",
    "# Select a part of the config, then choose an action:",
    "#   keep    leave it alone",
    "#   pseudo  a type-valid substitute -- equality preserved, output loads",
    "#   hash    an opaque <PREFIX-tag> marker -- equality preserved",
    "#   redact  a family-appropriate constant -- nothing survives",
    "# pseudo is not available for secrets.",
    "#",
    "# Every key below is set to its default value; commented-out keys show",
    "# the shape of an optional setting.",
    "# Docs: https://github.com/fmcglinn/netredact",
    "",
]

#: what to show for a key whose default is None
_NONE_EXAMPLES = {"salt_file": "~/.config/netredact/salt"}

_TOP_COMMENTS = {
    "salt_file": ("the HMAC salt, created 0600 if missing. Reuse it to keep "
                  "pseudonyms\n# consistent across runs and devices. It is a "
                  "re-identification key -- protect it."),
    "vendor": " | ".join(VENDORS),
}

_POLICY_COMMENTS = {
    "hostnames": "device names, from the collect pass",
    "domains": "domain names and search lists",
    "usernames": "local users, AAA users, JunOS login names",
    "emails": "e-mail addresses, wherever they appear",
}

_IP_COMMENTS = {
    "ipv4": {
        "default": "the action for every class not named below",
        "pool": ("pseudonyms come from these, in order -- only the /24 moves, "
                 "the host\n# octet and the prefix length are preserved"),
        "well_known_resolvers": ("public resolvers; they form the well_known "
                                 "class above"),
        "keep_networks": ("extra prefixes never to touch, whatever class they "
                          "fall into"),
    },
    "ipv6": {
        "default": "the action for every class not named below",
        "pool": ("the /64 moves inside this prefix; the interface identifier "
                 "is preserved"),
        "well_known_resolvers": ("public resolvers; they form the well_known "
                                 "class above"),
        "keep_networks": ("extra prefixes never to touch, whatever class they "
                          "fall into"),
    },
}

#: the header above each family section. The per-rule keys below it carry no
#: gloss of their own: at 49 rules that would bury the guidance, and
#: `netredact --list-rules` says what each one matches.
_SECTION_INTROS = {
    "secrets": [
        "# Passwords, keys, community strings and password hashes. This is",
        "# the one family that acts by default, and the whole of netredact's",
        "# default promise: credentials are destroyed, nothing else is.",
        "# `pseudo` is refused here -- the substitute would be an HMAC of the",
        "# real credential, computable by anyone who can derive it.",
    ],
    "text": [
        "# Descriptions, ACL remarks, banners, login messages, SNMP location",
        "# and contact. On a service-provider config this is where the",
        "# customer names live. `hash` is usually the right middle ground:",
        "# <DESC-f11e24> still tells two ports apart and still correlates the",
        "# same port across files, without saying whose it is.",
    ],
    "identity": [
        "# Serial numbers, license UDIs, SNMP engine IDs, certificates and",
        "# SSH public keys. None is a credential; all of them tie the file to",
        "# one real device. `default = \"hash\"` with `serial-number = \"keep\"`",
        "# is the vendor support case in two lines.",
    ],
    "platform": [
        "# The hardware model, the software release and the boot image.",
        "# Neither a credential nor an instance identity -- every device off",
        "# the same production line carries it. What it discloses is the",
        "# attack surface: a model plus a release number is a CVE list. Kept",
        "# by default, because it is also the first thing a support desk asks",
        "# for and the thing a reviewer needs to judge a config at all.",
    ],
    "interfaces": [
        "# What a port is called: the `description` on an interface, and only",
        "# there -- every other description belongs to `text` above. It is a",
        "# section of its own because it is the one piece of free text with two",
        "# incompatible audiences: a TAC case is unreadable without the",
        "# descriptions your topology is written in, and a public post is",
        "# unpublishable with them. `[text] redact` plus `[interfaces] keep`",
        "# says exactly that.",
    ],
    "vlans": [
        "# What a VLAN is called: the `name` under a `vlan <id>` block. NOT an",
        "# SVI -- an `interface Vlan905` block is an interface, and its",
        "# description belongs to `[interfaces]`. On an access switch a VLAN",
        "# name is frequently a service or customer identifier.",
        "#",
        "# `pseudo` is the one to reach for here: the config refers to a VLAN",
        "# by name elsewhere, so a type-valid `vlname-f11e24` still loads.",
    ],
    "circuits": [
        "# What a cross-connect or a pseudowire is called: Arista `patch panel`",
        "# names, and the pseudowires under `mpls ldp`. On a provider edge",
        "# these are order and customer references -- the stuff a ticket number",
        "# is made of.",
        "#",
        "# Like a VLAN name and unlike a description, these are not free text:",
        "# a `connector` line names a pseudowire that another section defines,",
        "# so both mentions have to survive as the same name. `pseudo` does",
        "# that (`circuit-f11e24`); `redact` collapses every circuit onto one",
        "# constant, so only use it where the output never has to load.",
    ],
}

_MACS_COMMENTS = {
    "oui": "the 24-bit vendor prefix; redact writes `pool`",
    "nic": "the 24-bit device half",
    "pool": "the OUI that redact writes -- 00:00:5e is IANA-reserved",
}

_VERIFY_COMMENTS = {
    "strict": "exit non-zero if the verification pass finds anything",
    "disable": "verification check names to switch off",
    "ignore_patterns": "regexes to treat as expected, not as findings",
}

_COLLECTION_COMMENTS = {
    "rancid_diagnostics": "remove non-configuration command sections from RANCID captures",
}


def _toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, list):
        if not v:
            return "[]"
        inner = ", ".join(_toml_value(x) for x in v)
        return f"[{inner}]" if len(inner) < 70 else (
            "[\n" + "".join(f"  {_toml_value(x)},\n" for x in v) + "]")
    raise TypeError(type(v))


def _block(rows) -> list[str]:
    """Render ``(name, value, comment, commented)`` rows, columns aligned."""
    rows = list(rows)
    width = max((len(name) for name, _, _, _ in rows), default=0)
    rendered = []
    for name, value, comment, commented in rows:
        line = f"{name:{width}} = {_toml_value(value)}"
        rendered.append((f"# {line}" if commented else line, comment))
    pad = max((len(line) for line, comment in rendered if comment), default=0)
    return [f"{line:{pad}}  # {comment}" if comment else line
            for line, comment in rendered]


def _render_policy(policy: PolicyConfig) -> list[str]:
    out = [
        "# The four families that have no rules: the collect pass reads these",
        "# names off the lines that declare them and then substitutes them",
        "# wherever they appear, so there is nothing to name per rule. Every",
        "# other family is a table of rules and has a section of its own.",
        "[policy]",
    ]
    out += _block((f.name, getattr(policy, f.name),
                   _POLICY_COMMENTS.get(f.name), False) for f in fields(policy))
    out.append("")
    return out


def _render_rule_section(family: str, section) -> list[str]:
    """One family section: `default`, then every rule in the family.

    Same shape as an address section one level down -- a `default` plus the
    members it governs -- and for the same reason: it is the only way to say
    "all of this except that one" without spelling out every member.
    """
    out = list(_SECTION_INTROS[family])
    out += [
        "#",
        "# `default` governs every rule; name a rule below to give it its own",
        "# action. The keys are rule names: `netredact --list-rules` says what",
        "# each one matches.",
        f"[{family}]",
    ]
    out += _block([("default", section.default,
                    "the action for every rule not named below", False)])
    out.append("")
    out.append("# Per-rule actions. Commented out means: inherit `default`.")
    out += _block(
        (rule, section.action(rule), None,
         getattr(section, _field(rule)) is None)
        for rule in section.RULES)
    out.append("")
    return out


def _render_ip(name: str, section) -> list[str]:
    label = "IPv4" if name == "ipv4" else "IPv6"
    comments = _IP_COMMENTS[name]
    out = [
        f"# {label} addressing. `default` governs every address class; name a",
        "# class below to give it its own action. Classes are mutually",
        "# exclusive and checked most-specific first, so every address is",
        "# governed by exactly one of them. Netmasks and wildcard masks are",
        "# detected structurally and never touched, whatever you set here.",
        f"[{name}]",
    ]
    classes = section.CLASSES
    scalars = [f.name for f in fields(section)
               if f.name not in classes and f.name != "default"]
    out += _block([("default", section.default, comments["default"], False)])
    out.append("")
    out.append("# Per-class actions. Commented out means: inherit `default`.")
    out += _block(
        (klass, section.default if getattr(section, klass) is None
         else getattr(section, klass), describe(name, klass),
         getattr(section, klass) is None)
        for klass in classes)
    out.append("")
    for key in scalars:
        comment = comments.get(key)
        if comment:
            out.append(f"# {comment}")
        out.append(f"{key} = {_toml_value(getattr(section, key))}")
    out.append("")
    return out


def _render_macs(macs: MacPolicy) -> list[str]:
    out = [
        "# MAC addresses, in two independent halves. hash replaces the whole",
        "# address with one marker, so it is only available by setting both",
        "# halves to hash.",
        "[macs]",
    ]
    out += _block((f.name, getattr(macs, f.name),
                   _MACS_COMMENTS.get(f.name), False) for f in fields(macs))
    out.append("")
    return out


def _render_verify(verify: VerifyConfig) -> list[str]:
    out = [
        "# The pass that re-scans the OUTPUT for anything still sensitive.",
        "[verify]",
    ]
    out += _block((f.name, getattr(verify, f.name),
                   _VERIFY_COMMENTS.get(f.name), False) for f in fields(verify))
    out.append("")
    return out


def _render_collection(collection: CollectionConfig) -> list[str]:
    out = [
        "# Collector wrappers. RANCID captures are detected from strong headers",
        "# or repeated prompts; unknown command sections fail closed.",
        "[collection]",
    ]
    out += _block((f.name, getattr(collection, f.name),
                   _COLLECTION_COMMENTS.get(f.name), False)
                  for f in fields(collection))
    out.append("")
    return out


_CUSTOM_EXAMPLE = [
    "# Extra rules of your own. `pattern` is a regex: if it has capture",
    "# groups, the groups are what gets acted on and everything outside them",
    "# is kept. With no groups it is treated as the PREFIX -- everything up",
    "# to and including the keyword -- and netredact appends the value",
    "# matcher itself. %VAL% expands to that value matcher anywhere in the",
    "# pattern. `family` decides both the action and the rendering.",
    "#",
    "# [[custom]]",
    '# name = "acme-shared-key"',
    "# pattern = '\\s*acme\\s+shared-key\\s+'",
    '# family = "secrets"    # ' + " | ".join(FAMILIES),
    '# action = "redact"     # optional; without it the family decides',
    '# stanza = "snmp"       # optional: a JunOS stanza, or an IOS-style block',
    "#                       # scope: interfaces / vlans / patch-panel",
    "",
]


def _render_toml(cfg: Config) -> str:
    out = list(_HEADER)
    for f in fields(cfg):
        if f.name == "source":
            continue
        value = getattr(cfg, f.name)
        if is_dataclass(value) or isinstance(value, (dict, list)):
            continue
        comment = _TOP_COMMENTS.get(f.name)
        if value is None:
            if comment:
                out.append(f"# {comment}")
            example = _NONE_EXAMPLES.get(f.name, "")
            out.append(f"# {f.name} = {_toml_value(example)}")
        else:
            line = f"{f.name} = {_toml_value(value)}"
            out.append(f"{line}  # {comment}" if comment else line)
    out.append("")
    for family in RULE_FAMILIES:
        out += _render_rule_section(family, getattr(cfg, family))
    out += _render_policy(cfg.policy)
    out += _render_ip("ipv4", cfg.ipv4)
    out += _render_ip("ipv6", cfg.ipv6)
    out += _render_macs(cfg.macs)
    out += _render_collection(cfg.collection)
    out += _render_verify(cfg.verify)
    out += _CUSTOM_EXAMPLE
    return "\n".join(out)
