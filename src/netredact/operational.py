"""Typed operational identifiers behind one transformation interface."""

from __future__ import annotations

import re
from collections import Counter
from ipaddress import ip_address

from .config import OperationalNamesPolicy

_PREFIX = {
    "acl-firewall-filter": ("ACL", "acl"),
    "route-map": ("ROUTE-MAP", "route-map"),
    "prefix-list": ("PREFIX-LIST", "prefix-list"),
    "policy-statement": ("POLICY", "policy"),
    "vrf": ("VRF", "vrf"),
    "peer-group": ("PEER-GROUP", "peer-group"),
}

_RESERVED_VRFS = {"default", "global", "none"}


class OperationalNames:
    """Transform supported declarations and references without global search."""

    def __init__(self, policy: OperationalNamesPolicy, pseudonymiser):
        self.policy = policy
        self.p = pseudonymiser
        self.counts: Counter = Counter()
        self.kept_counts: Counter = Counter()
        self.handled: set[str] = set()
        self._brace_depth = 0
        self._term_parents: list[tuple[int, str, str]] = []

    def _render(self, kind: str, value: str, *, term: bool = False,
                context: str = "") -> str:
        action = self.policy.action(kind)
        if action == "keep":
            self.kept_counts[kind] += 1
            return value
        marker, token = _PREFIX[kind]
        if term:
            marker += "-TERM"
            token += "-term"
        if (value == "<REMOVED>"
                or re.fullmatch(rf"{re.escape(token)}-[0-9a-f]{{6}}", value, re.I)
                or re.fullmatch(rf"<{re.escape(marker)}-[0-9a-f]{{6}}>", value,
                                re.I)):
            return value
        self.counts[kind] += 1
        if action == "redact":
            self.handled.add("<removed>")
            return "<REMOVED>"
        tag_value = f"{context.lower()}\0{value.lower()}" if term else value.lower()
        tag = self.p.tag(marker.lower(), tag_value)
        rendered = f"<{marker}-{tag}>" if action == "hash" else f"{token}-{tag}"
        self.handled.add(rendered.lower())
        return rendered

    @staticmethod
    def _replace_group(line: str, pattern: str, callback, *, flags=re.I) -> str:
        regex = re.compile(pattern, flags)
        return regex.sub(lambda m: m.group(1) + callback(m.group(2)), line)

    def line(self, line: str) -> str:
        original = line
        parent = None
        match = re.search(r"\bpolicy-statement\s+(\S+)\s*\{", original, re.I)
        if match:
            parent = ("policy-statement", match.group(1))
        else:
            match = re.match(r"\s*filter\s+(\S+)\s*\{", original, re.I)
            if match:
                parent = ("acl-firewall-filter", match.group(1))
        active_parent = self._term_parents[-1][1:] if self._term_parents else None
        if active_parent:
            parent_kind, parent_name = active_parent
            line = re.sub(
                r"^(\s*term\s+)(\S+)(?=\s*\{)",
                lambda m: m.group(1) + self._render(
                    parent_kind, m.group(2), term=True, context=parent_name),
                line, flags=re.I)
        # ACLs and JunOS firewall filters, including their term names.
        acl = "acl-firewall-filter"
        patterns = (
            r"(\b(?:ip|ipv6|mac)\s+access-list\s+(?:(?:standard|extended)\s+)?)(\S+)",
            r"(\b(?:ip\s+)?access-group\s+)(\S+)",
            r"(\b(?:traffic-filter|access-class)\s+)(\S+)",
            r"(\bfirewall\s+family\s+\S+\s+filter\s+)(\S+)",
            r"(\bfilter\s+(?:input|output)\s+)(\S+)",
            r"(\bfilter\s+)(\S+)(?=\s*\{)",
        )
        for pat in patterns:
            line = self._replace_group(line, pat, lambda value: self._render(acl, value))
        line = re.sub(
            r"(\bfirewall\s+family\s+\S+\s+filter\s+)(\S+)(\s+term\s+)(\S+)",
            lambda m: m.group(1) + m.group(2) + m.group(3)
            + self._render(acl, m.group(4), term=True, context=m.group(2)), line,
            flags=re.I)

        # Route maps and prefix lists.
        line = self._replace_group(
            line, r"(\broute-map\s+)(\S+)",
            lambda value: self._render("route-map", value))
        for pat in (
            r"(\b(?:ip|ipv6)\s+prefix-list\s+)(\S+)",
            r"(\b(?:match\s+(?:ip|ipv6)\s+address\s+|neighbor\s+\S+\s+)prefix-list\s+)(\S+)",
            r"(\bpolicy-options\s+prefix-list\s+)(\S+)",
            r"(\bprefix-list(?:-filter)?\s+)(\S+)",
        ):
            line = self._replace_group(
                line, pat, lambda value: self._render("prefix-list", value))

        # JunOS policy names and their local term names.
        line = self._replace_group(
            line, r"(\bpolicy-statement\s+)(\S+)",
            lambda value: self._render("policy-statement", value))
        line = re.sub(
            r"(\bpolicy-statement\s+)(\S+)(\s+term\s+)(\S+)",
            lambda m: m.group(1) + m.group(2) + m.group(3) + self._render(
                "policy-statement", m.group(4), term=True, context=m.group(2)),
            line, flags=re.I)
        line = self._replace_group(
            line, r"((?<![\w-])(?:import|export|vrf-import|vrf-export)\s+)(?!\[)(\S+)",
            lambda value: self._render("policy-statement", value))
        line = re.sub(
            r"((?<![\w-])(?:import|export|vrf-import|vrf-export)\s+\[)([^]]+)(\])",
            lambda m: m.group(1) + re.sub(
                r"\S+", lambda n: self._render("policy-statement", n.group(0)),
                m.group(2)) + m.group(3), line, flags=re.I)

        # VRF/routing-instance names. Reserved built-ins remain structural.
        def vrf(value: str) -> str:
            return value if value.lower() in _RESERVED_VRFS else self._render("vrf", value)
        for pat in (
            r"(\bvrf\s+(?:(?:instance|definition|forwarding|member)\s+)?)(\S+)",
            r"(\bip\s+vrf\s+)(\S+)",
            r"(\brouting-instances?\s+)(\S+)",
        ):
            line = self._replace_group(line, pat, vrf)

        # BGP peer-group/group declarations and references.
        for pat in (
            r"(\bneighbor\s+)([^\s]+)(?=\s+peer\s+group\s*$)",
            r"(\bneighbor\s+\S+\s+peer\s+group\s+)(\S+)",
            r"(\bneighbor\s+\S+\s+peer-group\s+)(\S+)",
            r"(\bprotocols\s+bgp\s+group\s+)(\S+)",
        ):
            line = self._replace_group(
                line, pat, lambda value: self._render("peer-group", value))

        def peer_operand(value: str) -> str:
            try:
                ip_address(value.split("%", 1)[0])
            except ValueError:
                return self._render("peer-group", value)
            return value

        # Within IOS/EOS BGP grammar, a non-address neighbor operand names a
        # peer group. This covers address-family references such as activate,
        # route-map, maximum-routes, and aigp-session.
        line = self._replace_group(
            line,
            r"(\bneighbor\s+)(\S+)(?!\S)(?!\s+peer\s+group\s+\S+)",
            peer_operand)
        opens, closes = original.count("{"), original.count("}")
        if parent and opens:
            self._term_parents.append((self._brace_depth + opens, *parent))
        self._brace_depth += opens - closes
        while self._term_parents and self._brace_depth < self._term_parents[-1][0]:
            self._term_parents.pop()
        return line


class AsNumbers:
    """Transform ASNs only in explicit ASN-valued grammar."""

    _ONE = re.compile(
        r"(?P<prefix>\b(?:router\s+bgp|remote-as|local-as|autonomous-system)\s+)"
        r"(?P<value>\d+(?:\.\d+)?)\b", re.I)
    _PATH = re.compile(r"(?P<prefix>\bas-path\s+prepend\s+)(?P<values>[\d. ]+)", re.I)

    def __init__(self, policy, pseudonymiser):
        self.policy = policy
        self.p = pseudonymiser
        self.counts: Counter = Counter()
        self.kept_counts: Counter = Counter()
        self.handled: set[str] = set()

    def _replace(self, value: str) -> str:
        new = self.p.asn(value)
        if new == value:
            self.kept_counts["as-numbers"] += 1
        else:
            self.counts["as-numbers"] += 1
            self.handled.add(new.lower())
        return new

    def line(self, line: str) -> str:
        line = self._ONE.sub(
            lambda m: m.group("prefix") + self._replace(m.group("value")), line)

        def path(m):
            values = re.sub(r"\d+(?:\.\d+)?", lambda n: self._replace(n.group(0)),
                            m.group("values"))
            return m.group("prefix") + values

        return self._PATH.sub(path, line)
