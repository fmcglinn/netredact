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
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path

from . import rules
from .addresses import V4_CLASS_NAMES, V6_CLASS_NAMES, describe

__all__ = [
    "ACTIONS", "FAMILIES", "ALLOWED", "POLICY_FAMILIES", "VENDORS",
    "Config", "PolicyConfig", "IPv4Policy", "IPv6Policy", "MacPolicy",
    "VerifyConfig", "CustomRule", "ConfigError", "find_config",
    "DEFAULT_CONFIG_NAMES",
]

DEFAULT_CONFIG_NAMES = ("netredact.toml", ".netredact.toml")

#: what can be done to a selected part of the input
ACTIONS = ("keep", "pseudo", "hash", "redact")

#: the families a rule -- or a bare regex match -- belongs to
FAMILIES = ("secrets", "text", "identity",
            "hostnames", "domains", "usernames", "emails",
            "ipv4", "ipv6", "macs")

#: legality per family. The only illegal cell is ``pseudo`` on ``secrets``.
ALLOWED: dict[str, tuple[str, ...]] = {f: ACTIONS for f in FAMILIES}
ALLOWED["secrets"] = ("keep", "hash", "redact")

#: the families named directly in ``[policy]``
POLICY_FAMILIES = ("secrets", "text", "identity",
                   "hostnames", "domains", "usernames", "emails")

VENDORS = ("auto", "cisco", "arista", "juniper")

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
    """What happens to each family of sensitive material.

    ``secrets`` is the only one that is not ``keep`` by default: netredact
    destroys credentials unless you tell it otherwise.
    """

    #: passwords, keys, community strings, password hashes
    secrets: str = "redact"
    #: descriptions, remarks, banners, login messages, location, contact
    text: str = "keep"
    #: serial numbers, UDIs, engine IDs, certificates, SSH public keys
    identity: str = "keep"
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

    ``stanza`` optionally restricts the rule to a JunOS top-level stanza.
    """

    name: str
    pattern: str
    family: str = "secrets"
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
class Config:
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    ipv4: IPv4Policy = field(default_factory=IPv4Policy)
    ipv6: IPv6Policy = field(default_factory=IPv6Policy)
    macs: MacPolicy = field(default_factory=MacPolicy)
    #: per-rule exceptions to [policy]: rule name -> action
    overrides: dict[str, str] = field(default_factory=dict)
    #: extra rules of your own
    custom: list[CustomRule] = field(default_factory=list)
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
        self._validate_overrides()
        self._validate_custom()

    # -- resolution -------------------------------------------------------
    def action_for_rule(self, rule_name: str) -> str:
        """The action for one named rule.

        ``overrides[name]`` if present, else the action of the rule's family.
        """
        if rule_name in self.overrides:
            return self.overrides[rule_name]
        return self.action_for(self.family_of(rule_name))

    def action_for(self, family: str) -> str:
        """The family-level action.

        The seven ``[policy]`` families answer from ``[policy]``. ``ipv4`` /
        ``ipv6`` answer with their ``default`` -- per-class detail lives in
        :meth:`IPv4Policy.action`. ``macs`` is per-half, so it answers
        ``keep`` only when both halves are kept, and ``pseudo`` (i.e. active,
        see ``[macs]``) when they differ.
        """
        if family in POLICY_FAMILIES:
            return getattr(self.policy, family)
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
        try:
            return rules.family_of(rule_name)
        except (KeyError, ValueError) as exc:
            raise ConfigError(
                f"unknown rule name {rule_name!r}. "
                f"See netredact --list-rules") from exc

    # -- validation -------------------------------------------------------
    def _validate_overrides(self) -> None:
        known = set(rules.rule_names()) | {c.name for c in self.custom}
        unknown = sorted(set(self.overrides) - known)
        if unknown:
            raise ConfigError(
                f"[overrides]: unknown rule(s) {', '.join(unknown)}. "
                f"See netredact --list-rules")
        for name, action in self.overrides.items():
            _check_action(f"[overrides] {name}", self.family_of(name), action)

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
        for f in fields(cls):
            if f.name not in raw:
                continue
            value = raw[f.name]
            if f.name == "overrides":
                kwargs["overrides"] = _build_overrides(value)
                continue
            if f.name == "custom":
                kwargs["custom"] = _build_custom(value)
                continue
            sub = _dataclass_for(f)
            if sub is not None:
                if not isinstance(value, dict):
                    raise ConfigError(f"[{f.name}] must be a table")
                kwargs[f.name] = _build(sub, value, f.name)
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
        "macs": MacPolicy, "verify": VerifyConfig,
    }
    return mapping.get(f.name)


def _build(cls: type, raw: dict, section: str):
    known = {f.name for f in fields(cls)}
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(
            f"[{section}]: unknown key(s) {', '.join(sorted(unknown))}. "
            f"Expected: {', '.join(sorted(known))}")
    for key, value in raw.items():
        expected = next(f for f in fields(cls) if f.name == key)
        _check_type(section, key, value, expected)
    try:
        return cls(**raw)
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


def _build_overrides(raw) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise ConfigError("[overrides] must be a table of rule name = action")
    out: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(value, str):
            raise ConfigError(
                f"[overrides] {key} must be an action string "
                f"({' | '.join(ACTIONS)}), got {value!r}")
        out[key] = value
    return out


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
    "redact": f"[redact] was replaced by [policy] and [overrides]; {_DOCS}",
    "scrub": f"[scrub] was replaced by [policy]; {_DOCS}",
    "ips": f"[ips] was replaced by [ipv4] and [ipv6]; {_DOCS}",
}

_REMOVED_KEYS = {
    ("redact", "descriptions"):
        'now policy.text = "keep" | "pseudo" | "hash" | "redact"',
    ("redact", "banners"):
        'now policy.text, or [overrides] banner = "redact" for banners alone',
    ("redact", "disable"):
        'disabling is an action now: set the family in [policy] or the rule '
        'in [overrides] to "keep"',
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
    "vendor": "auto | cisco | arista | juniper",
}

_POLICY_COMMENTS = {
    "secrets": "passwords, keys, community strings, hashes (no pseudo)",
    "text": "descriptions, remarks, banners, login messages, location, contact",
    "identity": "serials, UDIs, engine IDs, certificates, SSH public keys",
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
        "# What happens to each family of sensitive material. Per-rule",
        "# exceptions live in [overrides]; addresses have their own sections.",
        "[policy]",
    ]
    out += _block((f.name, getattr(policy, f.name),
                   _POLICY_COMMENTS.get(f.name), False) for f in fields(policy))
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


def _render_overrides(overrides: dict[str, str]) -> list[str]:
    out = [
        "# Per-rule exceptions to [policy]. The key is a rule name from",
        "# `netredact --list-rules`, the value an action. A rule's family",
        "# still decides how the replacement is rendered.",
        "[overrides]",
    ]
    if overrides:
        out += _block((key, value, None, False) for key, value in overrides.items())
    else:
        out += [
            '# location      = "keep"',
            '# serial-number = "keep"',
            '# banner        = "redact"',
        ]
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
    '# stanza = "snmp"       # optional, JunOS top-level stanza only',
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
    out += _render_policy(cfg.policy)
    out += _render_ip("ipv4", cfg.ipv4)
    out += _render_ip("ipv6", cfg.ipv6)
    out += _render_macs(cfg.macs)
    out += _render_overrides(cfg.overrides)
    out += _render_verify(cfg.verify)
    out += _CUSTOM_EXAMPLE
    return "\n".join(out)
