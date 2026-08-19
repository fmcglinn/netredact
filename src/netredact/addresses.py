"""Address classification.

Every address is put into exactly one class, so a configuration option can
name a class without ambiguity. The classes are checked most-specific first
and are mutually exclusive -- there is deliberately no ``rfc5735`` class,
because RFC 5735 is a *set* of these ranges and a single toggle for it would
overlap ``rfc1918``, ``loopback``, ``multicast`` and others.

``other_unicast`` is the fall-through: globally routable space, which for an
operator means the addresses that WHOIS maps back to you.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

__all__ = [
    "V4_CLASSES", "V6_CLASSES", "V4_CLASS_NAMES", "V6_CLASS_NAMES",
    "classify_v4", "classify_v6", "describe",
]

# (class name, prefixes, RFC, one-line description) -- most specific first
V4_CLASSES: tuple[tuple[str, tuple[str, ...], str, str], ...] = (
    ("loopback",      ("127.0.0.0/8",), "RFC 1122", "loopback"),
    ("rfc1918",       ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
     "RFC 1918", "private unicast"),
    ("cgnat",         ("100.64.0.0/10",), "RFC 6598", "carrier-grade NAT / shared address space"),
    ("link_local",    ("169.254.0.0/16",), "RFC 3927", "link-local"),
    ("multicast",     ("224.0.0.0/4",), "RFC 5771", "multicast"),
    ("documentation", ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"),
     "RFC 5737", "documentation / TEST-NET"),
    ("benchmark",     ("198.18.0.0/15",), "RFC 2544", "benchmark testing"),
    ("reserved",      ("0.0.0.0/8", "192.0.0.0/24", "192.88.99.0/24",
                       "240.0.0.0/4", "255.255.255.255/32"),
     "RFC 6890", "other reserved / special-purpose"),
    # other_unicast is the fall-through, not a prefix list
)

V6_CLASSES: tuple[tuple[str, tuple[str, ...], str, str], ...] = (
    ("unspecified",   ("::/128",), "RFC 4291", "the unspecified address"),
    ("loopback",      ("::1/128",), "RFC 4291", "loopback"),
    ("ula",           ("fc00::/7",), "RFC 4193", "unique local address"),
    ("link_local",    ("fe80::/10",), "RFC 4291", "link-local"),
    ("multicast",     ("ff00::/8",), "RFC 4291", "multicast"),
    ("documentation", ("2001:db8::/32",), "RFC 3849", "documentation"),
    ("teredo",        ("2001::/32",), "RFC 4380", "Teredo tunnelling"),
    ("six_to_four",   ("2002::/16",), "RFC 3056", "6to4"),
    ("ipv4_mapped",   ("::ffff:0:0/96", "64:ff9b::/96"),
     "RFC 4291", "IPv4-mapped and NAT64"),
    # other_unicast is the fall-through
)

OTHER = "other_unicast"
WELL_KNOWN = "well_known"

V4_CLASS_NAMES = tuple(n for n, *_ in V4_CLASSES) + (WELL_KNOWN, OTHER)
V6_CLASS_NAMES = tuple(n for n, *_ in V6_CLASSES) + (WELL_KNOWN, OTHER)

_V4_NETS = tuple((name, tuple(ipaddress.ip_network(p) for p in prefixes))
                 for name, prefixes, _, _ in V4_CLASSES)
_V6_NETS = tuple((name, tuple(ipaddress.ip_network(p) for p in prefixes))
                 for name, prefixes, _, _ in V6_CLASSES)

_DESCRIPTIONS = {
    ("ipv4", name): f"{desc} ({rfc}: {', '.join(prefixes)})"
    for name, prefixes, rfc, desc in V4_CLASSES
} | {
    ("ipv6", name): f"{desc} ({rfc}: {', '.join(prefixes)})"
    for name, prefixes, rfc, desc in V6_CLASSES
} | {
    ("ipv4", OTHER): "globally routable space -- the addresses WHOIS maps to you",
    ("ipv6", OTHER): "global unicast -- the addresses WHOIS maps to you",
    ("ipv4", WELL_KNOWN): "public resolvers listed in well_known_resolvers",
    ("ipv6", WELL_KNOWN): "public resolvers listed in well_known_resolvers",
}


def describe(family: str, name: str) -> str:
    """Human-readable description of a class, for --print-config comments."""
    return _DESCRIPTIONS.get((family, name), name)


@lru_cache(maxsize=8192)
def classify_v4(text: str, well_known: frozenset[str] = frozenset()) -> str:
    addr = ipaddress.IPv4Address(text)
    for name, nets in _V4_NETS:
        if any(addr in net for net in nets):
            return name
    return WELL_KNOWN if text in well_known else OTHER


@lru_cache(maxsize=8192)
def classify_v6(text: str, well_known: frozenset[str] = frozenset()) -> str:
    addr = ipaddress.IPv6Address(text)
    for name, nets in _V6_NETS:
        if any(addr in net for net in nets):
            return name
    return WELL_KNOWN if addr.compressed in well_known else OTHER
