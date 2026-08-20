"""Substitutions for identifying values: pseudonyms, hash markers, redaction.

Every derived value comes from an HMAC of the original under a per-run salt
(:meth:`Pseudonymiser._h`) -- never from ``random`` or ``secrets``. There is no
``--map-in``, so the salt is the *only* thing that makes a run reproducible:
reuse a salt file and a whole fleet of devices pseudonymises consistently, the
same real IP becoming the same fake IP in every file.

Four actions, one per family (see ``config.ACTIONS``):

``keep``
    returned unchanged and recorded in :attr:`kept`, so the caller can report
    what was left behind
``pseudo``
    a type-valid substitute; equality is preserved and the output still loads
``hash``
    an opaque ``<PREFIX-tag>`` marker; equality is preserved, the value is not
``redact``
    a family-appropriate constant; nothing about the original survives

Structure is preserved wherever it carries meaning and no identity:
  * IPv4 keeps its host octet and prefix length; only the /24 moves
  * IPv6 keeps its interface identifier; only the /64 moves
  * MACs keep their separator style, and the two halves move independently
  * netmasks and wildcard masks are detected and never touched
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from collections import OrderedDict

from .addresses import classify_v4, classify_v6
from .config import FAMILIES, Config

__all__ = ["Pseudonymiser", "PoolExhausted", "is_mask_like", "PREFIX",
           "REDACT_CONST", "REMOVED", "DESC_REMOVED"]


class PoolExhausted(ValueError):
    """A bounded pseudonym space cannot cover the input one-to-one.

    Pseudonyms are a bijection: two real /24s must never land on the same fake
    /24, or the output silently merges two subnets. So when the space runs out
    the only honest thing to do is stop and say so. Subclasses ``ValueError``,
    which the CLI already catches, so it prints as an error rather than a
    traceback.
    """


#: kind -> (what ran out, unit, what to do about it). Kinds absent from this
#: table draw from a hash-shaped space that is effectively unbounded.
_SPACES = {
    "v4net": ("ipv4.pool", "/24 blocks",
              "Widen [ipv4] pool, or set some [ipv4] classes to keep."),
    "v6net": ("ipv6.pool", "/64 prefixes",
              "Widen [ipv6] pool (a shorter prefix holds more /64s), "
              "or set some [ipv6] classes to keep."),
    "mac": ("the MAC NIC space", "NIC halves", 'Set [macs] nic = "keep".'),
    "mac-nic": ("the MAC NIC space", "NIC halves", 'Set [macs] nic = "keep".'),
    "mac-oui": ("the MAC OUI space", "OUI prefixes",
                'Set [macs] oui = "keep" or "redact".'),
}

#: mirrors ``rules.REMOVED`` / ``rules.DESC_REMOVED`` (kept here so this module
#: does not have to import ``rules`` at module scope)
REMOVED = "<REMOVED>"
DESC_REMOVED = "<DESCRIPTION-REMOVED>"

#: family or rule name -> (hash marker prefix, pseudo token prefix).
#: A ``None`` token means ``pseudo`` is either illegal (secrets) or produced by
#: a dedicated generator (names, addresses) rather than a ``token-tag`` string.
PREFIX: dict[str, tuple[str, str | None]] = {
    "secrets": ("SECRET", None),          # None => pseudo illegal
    "text": ("DESC", "desc"),
    "locations": ("DESC", "desc"),
    # an interface description is a description: it renders as one, so a
    # reader of the output learns what was taken out rather than which section
    # took it out. The two families never see the same span -- one is scoped to
    # an interface block and the other is scoped out of it.
    "interfaces": ("DESC", "desc"),
    # the pseudo token is deliberately NOT `vlan`: `VLAN-100` is a plausible
    # real VLAN name, and `is_rendered` would then read it as already
    # sanitised and leave it standing.
    "vlans": ("VLAN", "vlname"),
    # both circuits rules resolve here rather than to a prefix each, and that
    # is load-bearing: the tag is a function of the value, so a pseudowire
    # named on a `connector` line and the same name in the `mpls ldp` section
    # render identically only while the two share one (marker, token) pair.
    # The token is not `patch` or `pseudowire` for the reason `vlans` avoids
    # `vlan`: `pseudowire pseudowire-1a2b3c` reads as a parser error.
    "circuits": ("CIRCUIT", "circuit"),
    "serial-number": ("SERIAL", "SN"),
    "license-udi": ("UDI", "udi"),
    "snmp-engineid": ("EID", "eid"),
    "ssh-public-key": ("KEY", "key"),
    "certificate-block": ("CERT", "cert"),
    "pem-cert": ("CERT", "cert"),
    # platform. The pseudo token is never the rule's own keyword: `version
    # version-1a2b3c` reads as a parser error, `version ver-1a2b3c` does not.
    "hardware-model": ("MODEL", "model"),
    "os-version": ("VERSION", "ver"),
    "software-image": ("IMAGE", "image"),
    "boot-image": ("IMAGE", "image"),
    "hostnames": ("HOST", None), "domains": ("DOMAIN", None),
    "usernames": ("USER", None), "emails": ("EMAIL", None),
    "ipv4": ("IP", None), "ipv6": ("IP6", None), "macs": ("MAC", None),
}

#: family -> the constant ``redact`` leaves behind. Families absent from this
#: table redact to :data:`REMOVED`, except the ``text`` rules listed in
#: :data:`_TEXT_REDACT`.
REDACT_CONST = {
    "ipv4": "192.0.2.0", "ipv6": "2001:db8::",
    "hostnames": "redacted", "domains": "example.invalid",
    "usernames": "user", "emails": "user@example.invalid",
}

#: ``text`` is not uniform: a banner is replaced wholesale, so it takes the
#: generic marker; description-shaped values take the description marker.
_TEXT_REDACT = {"banner": REMOVED}
_TEXT_DEFAULT_REDACT = DESC_REMOVED

#: families whose values are free text, so ``redact`` leaves the description
#: marker rather than the generic one
_DESC_FAMILIES = ("text", "locations", "interfaces")

#: family names, for :meth:`Pseudonymiser._family`. Read off the config's own
#: tuple so a new family cannot be renderable but unknown here.
_FAMILIES = frozenset(FAMILIES)

#: rule -> family for common rule names. Other built-ins fall through to the
#: catalogue inventory; custom rules fall through to ``config.custom``.
_KEY_FAMILY = {
    "description": "text", "acl-remark": "text", "login-message": "text",
    "banner": "text", "contact": "text",
    "location": "locations", "junos-location-body": "locations",
    "interface-description": "interfaces", "vlan-name": "vlans",
    "patch-name": "circuits", "pseudowire-name": "circuits",
    "serial-number": "identity", "license-udi": "identity",
    "snmp-engineid": "identity", "ssh-public-key": "identity",
    "certificate-block": "identity", "pem-cert": "identity",
    "hardware-model": "platform", "os-version": "platform",
    "software-image": "platform", "boot-image": "platform",
}

#: only used if someone renders the ``identity`` or ``platform`` family itself
#: rather than one of its rules; the spec's table is per-rule, so there is no
#: documented marker for the family as a whole.
_FAMILY_FALLBACK = {"identity": ("ID", "id"),
                    "platform": ("PLATFORM", "platform")}

_TAG_RE = "[0-9a-f]{1,6}"

#: family -> regex matching a value this module already produced with `pseudo`
_PSEUDO_RE = {
    "hostnames": r"device-[0-9a-f]{1,6}",
    "usernames": r"user-[0-9a-f]{1,4}",
    "domains": r"(?:d[0-9a-f]{1,4}\.example\.com|example\.(?:com|net|org))",
}
_PSEUDO_RE["emails"] = f"{_PSEUDO_RE['usernames']}@{_PSEUDO_RE['domains']}"

#: family -> constants this module already produced with `redact`
_REDACTED_CONSTS = {
    "secrets": (REMOVED,),
    "circuits": (REMOVED,),
    "identity": (REMOVED,),
    "platform": (REMOVED,),
    "text": (REMOVED, DESC_REMOVED),
    "locations": (REMOVED, DESC_REMOVED),
    "interfaces": (REMOVED, DESC_REMOVED),
    "vlans": (REMOVED,),
    "hostnames": ("redacted",),
    "domains": ("example.invalid",),
    "usernames": ("user",),
    "emails": ("user@example.invalid",),
    "ipv4": ("192.0.2.0",),
    "ipv6": ("2001:db8::",),
    "macs": (),
}


def is_mask_like(v: int) -> bool:
    """True for contiguous netmasks (255.255.255.0) and wildcards (0.0.0.255).

    A 32-bit netmask is 1*0*, so its complement is 2^n - 1; a wildcard is the
    complement of that. Either way ``x & (x + 1) == 0`` for one of the two.
    """
    inv = (~v) & 0xFFFFFFFF
    return (inv & (inv + 1)) == 0 or (v & (v + 1)) == 0


def _hex_digits(text: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", text).lower()


class Pseudonymiser:
    """Applies the configured action to each family.

    Anything whose action is ``keep`` is returned unchanged and recorded in
    :attr:`kept`, so the caller can report what was left behind.
    """

    def __init__(self, salt: bytes, config: Config | None = None):
        self.salt = salt
        self.cfg = config or Config()
        self.cfg.validate()
        self.maps: dict[str, OrderedDict[str, str]] = {}
        self.kept: dict[str, set[str]] = {}
        #: real addresses left in place that fall inside a pseudonym pool --
        #: in the output they are indistinguishable from generated ones
        self.collisions: set[str] = set()
        self._used: dict[str, set[str]] = {}

        v4, v6cfg = self.cfg.ipv4, self.cfg.ipv6
        self._keep_nets = [ipaddress.ip_network(n)
                           for n in list(v4.keep_networks) + list(v6cfg.keep_networks)]
        self._well_known = frozenset(v4.well_known_resolvers) | frozenset(
            v6cfg.well_known_resolvers)
        self._pool_v4 = self._build_v4_pools(v4.pool)
        self._pool_v4_size = sum(n for _, n in self._pool_v4)
        v6 = ipaddress.ip_network(v6cfg.pool)
        if v6.prefixlen > 64:
            raise ValueError(f"ipv6.pool must be /64 or shorter: {v6cfg.pool}")
        self._pool_v6_base = int(v6.network_address)
        self._pool_v6_bits = 64 - v6.prefixlen
        self._pool_nets = [ipaddress.ip_network(c) for c in v4.pool] + [v6]
        #: kind -> how many distinct pseudonyms that space can ever produce.
        #: Known up front, so exhaustion is detected on the allocation that
        #: overruns rather than after a million wasted probes.
        self._capacity = {
            "v4net": self._pool_v4_size,
            "v6net": 1 << self._pool_v6_bits,
            "mac": 1 << 24,          # 24-bit NIC half
            "mac-nic": 1 << 24,
            "mac-oui": 1 << 22,      # 24 bits less the multicast and local bits
        }

    @staticmethod
    def _build_v4_pools(cidrs) -> list[tuple[int, int]]:
        pools = []
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr)
            if net.version != 4:
                raise ValueError(f"ipv4.pool must be IPv4: {cidr}")
            if net.prefixlen > 24:
                raise ValueError(f"ipv4.pool entries must be /24 or shorter: {cidr}")
            pools.append((int(net.network_address), 1 << (24 - net.prefixlen)))
        if not pools:
            raise ValueError("ipv4.pool must not be empty")
        return pools

    # -- plumbing ----------------------------------------------------------
    def _h(self, kind: str, value: str) -> int:
        digest = hmac.new(self.salt, f"{kind}\x00{value}".encode(), hashlib.sha256)
        return int.from_bytes(digest.digest(), "big")

    def tag(self, kind: str, value: str, nibbles: int = 6) -> str:
        return f"{self._h(kind, value):0x}"[:nibbles]

    def _assign(self, kind: str, value: str, gen) -> str:
        table = self.maps.setdefault(kind, OrderedDict())
        if value in table:
            return table[value]
        used = self._used.setdefault(kind, set())
        limit = self._capacity.get(kind, 1_000_000)
        if len(used) >= limit:
            raise PoolExhausted(self._exhausted(kind, limit, len(used) + 1))
        i = 0
        while True:
            candidate = gen(i)
            if candidate not in used:
                break
            i += 1
            if i >= limit:
                raise PoolExhausted(self._exhausted(kind, limit, len(used) + 1))
        table[value] = candidate
        used.add(candidate)
        return candidate

    def _exhausted(self, kind: str, capacity: int, needed: int) -> str:
        what, unit, remedy = _SPACES.get(
            kind, (f"the {kind} pseudonym space", "values",
                   "Report this: a hash-shaped space should not run out."))
        return (f"{what} is exhausted: {capacity} {unit} available, "
                f"at least {needed} needed. {remedy}")

    def _keep(self, category: str, value: str) -> None:
        """Record a value we deliberately left alone, and return None."""
        self.kept.setdefault(category, set()).add(value)
        return None

    def _keep_addr(self, category: str, value: str, addr) -> None:
        """As :meth:`_keep`, but flag addresses that clash with a pool.

        Only a concern once this family is being substituted: a real address
        inside a pseudonym pool cannot be told apart from a generated one.
        """
        pol = self.cfg.ipv4 if addr.version == 4 else self.cfg.ipv6
        if pol.any_active() and any(addr in net for net in self._pool_nets
                                    if net.version == addr.version):
            self.collisions.add(value)
        return self._keep(category, value)

    # -- the render entry point --------------------------------------------
    def _family(self, key: str) -> str:
        """Family for a family name or a rule name."""
        if key in _FAMILIES:
            return key
        fam = _KEY_FAMILY.get(key)
        if fam is not None:
            return fam
        for rule in getattr(self.cfg, "custom", ()):       # user's own rules
            if rule.name == key:
                return rule.family
        try:
            from . import rules
            fam = next(info.family for info in rules.RuleCatalogue.builtins().inventory()
                       if info.name == key)
        except Exception as exc:                       # unknown rule name
            raise ValueError(f"render: unknown key {key!r}") from exc
        if fam not in _FAMILIES:
            raise ValueError(f"render: unknown family {fam!r} for key {key!r}")
        return fam

    def _prefix(self, key: str, family: str) -> tuple[str, str | None]:
        if key in PREFIX:
            return PREFIX[key]
        if family in PREFIX:
            return PREFIX[family]
        return _FAMILY_FALLBACK[family]

    def _redact_const(self, key: str, family: str) -> str:
        if family in REDACT_CONST:
            return REDACT_CONST[family]
        if family in _DESC_FAMILIES:
            return _TEXT_REDACT.get(key, _TEXT_DEFAULT_REDACT)
        return REMOVED

    def is_rendered(self, key: str, value: str) -> bool:
        """True if ``value`` is already one of this key's own renderings.

        This is what makes sanitising sanitised output a no-op: markers,
        redaction constants and generated pseudonyms are all recognised, so a
        second pass leaves them alone instead of substituting a substitute.
        """
        family = self._family(key)
        probe = value.strip()
        if len(probe) > 1 and probe[0] == probe[-1] and probe[0] in "\"'":
            probe = probe[1:-1].strip()
        if not probe:
            return False
        mark, tok = self._prefix(key, family)
        if re.fullmatch(rf"<{mark}-{_TAG_RE}>", probe):
            return True
        if tok and re.fullmatch(rf"{re.escape(tok)}-{_TAG_RE}", probe):
            return True
        pat = _PSEUDO_RE.get(family)
        if pat and re.fullmatch(pat, probe):
            return True
        if probe in _REDACTED_CONSTS.get(family, ()):
            return True
        if family == "ipv6":                     # 2001:0db8:: is 2001:db8::
            try:
                return ipaddress.IPv6Address(probe) == ipaddress.IPv6Address(
                    REDACT_CONST["ipv6"])
            except ValueError:
                return False
        return False

    def render(self, key: str, action: str, value: str) -> str:
        """Replacement text for ``value`` under ``action``.

        ``key`` is a rule name or a family name; ``action`` is one of
        ``keep`` / ``pseudo`` / ``hash`` / ``redact``. This is the single entry
        point the sanitiser uses for every substitution, and it is idempotent:
        a value that already equals one of this key's renderings comes back
        unchanged.

        For ``ipv4`` / ``ipv6`` / ``macs`` the action lives in the config at a
        finer grain than one string -- per address class, and per MAC half --
        so those delegate to :meth:`ipv4` / :meth:`ipv6` / :meth:`mac`, which
        resolve it themselves; the ``action`` argument is only used to skip the
        work entirely when it is ``keep``.
        """
        if action == "keep":
            return value
        if action not in ("pseudo", "hash", "redact"):
            raise ValueError(f"unknown action {action!r}")
        family = self._family(key)
        if self.is_rendered(key, value):
            return value

        if family in ("ipv4", "ipv6", "macs"):
            new = {"ipv4": self.ipv4, "ipv6": self.ipv6,
                   "macs": self.mac}[family](value)
            return value if new is None else new

        mark, tok = self._prefix(key, family)
        if action == "hash":
            return f"<{mark}-{self.tag(mark.lower(), self._tag_value(family, value))}>"
        if action == "redact":
            return self._redact_const(key, family)

        # pseudo
        if family == "secrets":
            raise ValueError("pseudo is not available for secrets: "
                             "use hash for an opaque marker, or redact")
        gen = {"hostnames": self.hostname, "domains": self.domain,
               "usernames": self.username, "emails": self.email}.get(family)
        if gen is not None:
            return gen(value)
        return f"{tok}-{self.tag(mark.lower(), value)}"

    def asn(self, text: str) -> str:
        """Render one ASN, preserving notation, width and allocation class."""
        action = self.cfg.as_numbers.default
        dotted = "." in text
        try:
            if dotted:
                high, low = (int(part) for part in text.split(".", 1))
                if not (0 <= high <= 65535 and 0 <= low <= 65535):
                    return text
                value = high * 65536 + low
            else:
                value = int(text)
        except ValueError:
            return text
        if not 0 <= value <= 0xFFFFFFFF or action == "keep":
            return text
        # Protocol constants and documentation-only ASNs identify nobody.
        if value in {0, 23456, 65535, 0xFFFFFFFF} or 64496 <= value <= 64511 \
                or 65536 <= value <= 65551:
            return text
        if action == "hash":
            return f"<ASN-{self.tag('asn', str(value))}>"
        if action == "redact":
            return REMOVED

        if 64512 <= value <= 65534:
            start, end, namespace = 64512, 65534, "asn-private16"
        elif 4200000000 <= value <= 4294967294:
            start, end, namespace = 4200000000, 4294967294, "asn-private32"
        elif value <= 65535:
            start, end, namespace = 1, 64495, "asn-public16"
        else:
            start, end, namespace = 65552, 4199999999, "asn-public32"
        span = end - start + 1
        seed = self._h(namespace, str(value))

        def gen(i: int) -> str:
            return str(start + ((seed + i) % span))

        rendered = int(self._assign(namespace, str(value), gen))
        if dotted:
            return f"{rendered >> 16}.{rendered & 0xFFFF}"
        return str(rendered)

    @staticmethod
    def _tag_value(family: str, value: str) -> str:
        """Names are matched case-insensitively, so they hash case-folded."""
        if family in ("hostnames", "domains", "usernames", "emails"):
            return value.lower()
        return value

    # -- addresses ---------------------------------------------------------
    def ipv4(self, text: str) -> str | None:
        """Substitute for a dotted quad, or None meaning 'leave it alone'."""
        try:
            addr = ipaddress.IPv4Address(text)
        except ValueError:
            return None
        raw = int(addr)
        if is_mask_like(raw):
            return None
        if any(addr in net for net in self._keep_nets if net.version == 4):
            return None

        klass = classify_v4(text, self._well_known)
        action = self.cfg.ipv4.action(klass)
        if action == "keep":
            return self._keep_addr(f"ipv4.{klass}", text, addr)
        if action == "hash":
            return f"<IP-{self.tag('ip', text)}>"
        if action == "redact":
            return REDACT_CONST["ipv4"]

        host = raw & 0xFF
        net24 = str(ipaddress.IPv4Address(raw & 0xFFFFFF00))
        seed = self._h("v4net", net24)

        def gen(i: int) -> str:
            idx = (seed + i) % self._pool_v4_size
            for base, count in self._pool_v4:
                if idx < count:
                    return str(ipaddress.IPv4Address(base + idx * 256))
                idx -= count
            raise AssertionError("unreachable")

        new24 = self._assign("v4net", net24, gen)
        return str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(new24)) | host))

    def ipv6(self, text: str) -> str | None:
        try:
            addr = ipaddress.IPv6Address(text)
        except ValueError:
            return None
        if any(addr in net for net in self._keep_nets if net.version == 6):
            return None

        klass = classify_v6(addr.compressed, self._well_known)
        action = self.cfg.ipv6.action(klass)
        if action == "keep":
            return self._keep_addr(f"ipv6.{klass}", addr.compressed, addr)
        if action == "hash":
            return f"<IP6-{self.tag('ip6', addr.compressed)}>"
        if action == "redact":
            return REDACT_CONST["ipv6"]

        raw = int(addr)
        iid = raw & ((1 << 64) - 1)
        prefix = str(ipaddress.IPv6Address(raw & ~((1 << 64) - 1)))
        seed = self._h("v6net", prefix)
        span = (1 << self._pool_v6_bits) - 1

        def gen(i: int) -> str:
            sub = (seed + i) & span
            return str(ipaddress.IPv6Address(self._pool_v6_base | (sub << 64)))

        new_prefix = self._assign("v6net", prefix, gen)
        return str(ipaddress.IPv6Address(
            int(ipaddress.IPv6Address(new_prefix)) | iid))

    def mac(self, text: str) -> str | None:
        """Remap a MAC, one half at a time, or None meaning 'leave it alone'.

        ``macs.oui`` and ``macs.nic`` are independent. Keeping the OUI keeps
        the hardware manufacturer, which identifies a vendor but not a device;
        redacting it substitutes ``macs.pool`` (``00:00:5e``, IANA, unmistakably
        synthetic). ``hash`` is the one action that cannot apply to half an
        address, so it is only legal on both halves at once and yields a single
        ``<MAC-tag>`` marker for the whole thing.

        A pseudo OUI keeps the multicast and locally-administered bits of the
        original first octet, so a unicast address stays unicast.
        """
        oui_action = self.cfg.macs.oui
        nic_action = self.cfg.macs.nic
        digits = _hex_digits(text)

        if "hash" in (oui_action, nic_action):
            if oui_action != nic_action:
                raise ValueError("macs: hash applies to the whole address, "
                                 "set both oui and nic to hash")
            return f"<MAC-{self.tag('mac', digits)}>"
        if oui_action == "keep" and nic_action == "keep":
            return self._keep("mac", digits)

        pool = _hex_digits(self.cfg.macs.pool)[:6]
        if oui_action == "redact" and digits[:6] == pool:
            # already carries the redact prefix: leave it so a re-run is a no-op
            return self._keep("mac", digits)

        if oui_action == "keep":
            prefix = digits[:6]
        elif oui_action == "redact":
            prefix = pool
        else:                                       # pseudo
            real = int(digits[:6], 16)
            seed = self._h("mac-oui", digits[:6]) & 0x3FFFFF

            def oui_gen(i: int, real=real, seed=seed) -> str:
                # 22 free bits: the first octet's top 6, plus octets 2 and 3.
                # The multicast and local bits are copied from the original, so
                # a unicast address stays unicast -- and stepping `i` walks the
                # free bits exactly once, which is what makes the space bounded.
                c = (seed + i) & 0x3FFFFF
                v = ((c >> 16) << 18) | (real & 0x030000) | (c & 0xFFFF)
                return f"{v:06x}"

            prefix = self._assign("mac-oui", digits[:6], oui_gen)

        if nic_action == "keep":
            nic = digits[6:]
        elif nic_action == "redact":
            nic = "000000"
        else:                                       # pseudo
            # kind depends on whether the OUI survived, so that today's
            # `oui` and `full` modes keep producing exactly what they did
            kind = "mac-nic" if oui_action == "keep" else "mac"
            seed = self._h(kind, digits) & 0xFFFFFF
            nic = self._assign(kind, digits,
                               lambda i, seed=seed: f"{(seed + i) & 0xFFFFFF:06x}")

        new = prefix + nic
        if "." in text:
            return ".".join(new[i:i + 4] for i in (0, 4, 8))
        if "-" in text:
            if len(text.split("-")) == 3:
                return "-".join(new[i:i + 4] for i in (0, 4, 8))
            return "-".join(new[i:i + 2] for i in range(0, 12, 2))
        if ":" not in text:
            return new
        return ":".join(new[i:i + 2] for i in range(0, 12, 2))

    # -- names -------------------------------------------------------------
    def hostname(self, name: str) -> str:
        key = name.lower()
        return self._assign(
            "hostname", key,
            lambda i: f"device-{self.tag('hostname', key + '#' + str(i))}")

    def username(self, name: str) -> str:
        key = name.lower()
        return self._assign(
            "username", key,
            lambda i: f"user-{self.tag('username', key + '#' + str(i), 4)}")

    def domain(self, name: str) -> str:
        key = name.lower()
        tlds = ("example.com", "example.net", "example.org")
        table = self.maps.setdefault("domain", OrderedDict())

        def gen(i: int) -> str:
            if i == 0 and len(table) < len(tlds):
                return tlds[len(table)]
            return f"d{self.tag('domain', key + '#' + str(i), 4)}.example.com"

        return self._assign("domain", key, gen)

    def email(self, addr: str) -> str:
        local, _, dom = addr.partition("@")
        # only reached when the emails action is `pseudo`, so both halves always
        # move -- the domain half of an address is identifying in its own right
        dom_new = self.domain(dom) if dom else "example.com"
        return f"{self.username(local)}@{dom_new}"
