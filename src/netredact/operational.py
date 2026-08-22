"""Typed operational identifiers behind one transformation interface."""

from __future__ import annotations

import re
from collections import Counter
from ipaddress import ip_address

from .config import OperationalNamesPolicy
from .rules import fortios_scope, fortios_scopes, routeros_scope

_PREFIX = {
    "acl-firewall-filter": ("ACL", "acl"),
    "route-map": ("ROUTE-MAP", "route-map"),
    "prefix-list": ("PREFIX-LIST", "prefix-list"),
    "policy-statement": ("POLICY", "policy"),
    "vrf": ("VRF", "vrf"),
    "peer-group": ("PEER-GROUP", "peer-group"),
    "label-switched-path": ("LSP", "lsp"),
    "configuration-group": ("CONFIG-GROUP", "config-group"),
    # RouterOS routing-filter chains. The token is not `chain`: a bare
    # `chain-1a2b3c` is a plausible real chain name, and `_render` would then
    # read its own output back as an already-sanitised value and leave a real
    # one standing -- the reason `vlans` avoids `vlan` too.
    "routing-filter-chain": ("FILTER-CHAIN", "filter-chain"),
    # FortiOS interface names. The token is short on purpose: FortiOS caps an
    # interface name at 15 characters, and `pseudo` is only worth having if the
    # substitute still LOADS -- `fos-if-a1b2c3` is 13. `fos-if` is also not a
    # name anyone would choose, which is what `_render` needs in order to read
    # its own output back without mistaking a real name for one of its own.
    "fortios-interface": ("FOS-IF", "fos-if"),
}

_RESERVED_VRFS = {"default", "global", "none"}

#: FortiOS interface names that are the platform's and not the operator's: the
#: factory ports, the pseudo-interfaces, and the wildcard. Structural, exactly
#: as :data:`_RESERVED_VRFS` is -- `set srcintf "any"` means every interface and
#: substituting it would change what the policy does, and a `port1` is the
#: FortiOS spelling of the interface NUMBERING this tool promises never to
#: scrub. What is left is what an operator typed, which is where a customer name
#: reaches an interface.
_FORTIOS_SYSTEM_INTERFACES = re.compile(
    r"any|port\d+|wan\d*|internal\d*|dmz\d*|mgmt\d*|ha\d*|lan\d*|modem"
    r"|fortilink|virtual-wan-link|npu\d*_vlink\d*|vsys_\w+"
    r"|(?:ssl|l2t|naf)\.\w+", re.I)

#: keys whose value is an interface name wherever they appear. Each of these
#: names an interface and nothing else, which is what lets them go unscoped.
_FORTIOS_INTERFACE_REFS = (
    r"srcintf|dstintf|interface|extintf|associated-interface"
    r"|outgoing-interface|src-interface|dst-interface")


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
        #: brace depth at which a `groups {` block names its groups, if inside one
        self._group_block_depth: int | None = None
        #: the RouterOS section, tracked here for the same reason brace depth is:
        #: :meth:`line` sees every line in file order, so it can carry the state
        #: a scoped declaration needs without the caller passing it in. A bare
        #: `chain=` is a routing-filter chain under `/routing filter rule` and a
        #: firewall chain under `/ip firewall filter`, where `input`, `forward`
        #: and `srcnat` are RouterOS's own and substituting one breaks the file.
        self._ros_section: tuple[str, ...] = ()
        #: the FortiOS `config` path stack, tracked here for the same reason.
        #: An `edit` name is an interface under `config system interface` and a
        #: policy id under `config firewall policy`, and only the stack says
        #: which.
        self._fos_stack: tuple[str, ...] = ()

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

    @staticmethod
    def _replace_values(line: str, pattern: str, callback, *, flags=re.I) -> str:
        """Substitute EVERY value after a keyword, not just the first.

        FortiOS writes a list as a run of quoted tokens on one line -- `set
        srcintf "port2" "port3"` -- and a keyword rule that took only the first
        would leave the second naming an interface that no longer exists, which
        is a configuration that does not load. The same argument :data:`_PAIRS`
        makes for being searched rather than matched.
        """
        def one(match: re.Match) -> str:
            values = re.sub(r'"[^"]*"|\S+',
                            lambda token: callback(token.group(0)),
                            match.group(2))
            return match.group(1) + values + match.group(3)

        return re.sub(pattern, one, line, flags=flags)

    def line(self, line: str) -> str:
        original = line
        self._ros_section = routeros_scope(line, self._ros_section)

        # RouterOS routing-filter chains. The declaration is `chain=` and it is
        # scoped, because `chain=` is also firewall grammar; the references are
        # the BGP connection's `input.filter=` / `output.filter-chain=` and their
        # abbreviated `.filter=` / `.filter-chain=` forms, which name a filter
        # chain and nothing else, so they need no scope.
        #
        # One TYPE carries both, which is the point: the tag is a function of the
        # value, so a chain named in `/routing filter rule` and the same name on
        # a `/routing bgp connection` render identically. Two types could be
        # given two actions and the file would no longer load -- the same
        # argument `pseudowire-name` makes for being one rule.
        def chain(value: str) -> str:
            return self._render("routing-filter-chain", value)

        if "routing-filter-rules" in self._ros_section:
            line = self._replace_group(
                line, r"((?<![-\w])chain=)([^\s;]+)", chain)
        line = self._replace_group(
            line,
            r"((?:(?:input|output)\.|(?<![-\w])\.)(?:filter|filter-chain)=)"
            r"([^\s;]+)",
            chain)

        # FortiOS interface names. ONE type carries the `edit` declaration and
        # every reference, which is the whole point: the tag is a function of
        # the value, so an interface declared under `config system interface`
        # and named by a `set srcintf` in a firewall policy render identically
        # and the file still loads. Two types could be given two actions, and
        # then it would not -- the argument `pseudowire-name` and
        # `routing-filter-chain` both make for being one rule.
        #
        # THE RISK, stated plainly because it is the reason this type defaults
        # to `keep`: coverage here is a list of reference spellings, and a
        # spelling not on it leaves a reference pointing at an interface that no
        # longer exists. The keys below are the ones FortiOS uses; a `set
        # member` outside the four interface sections is an ADDRESS group and is
        # deliberately not one of them.
        self._fos_stack = fortios_scope(line, self._fos_stack)
        fos = fortios_scopes(self._fos_stack)

        def interface(value: str) -> str:
            bare = value.strip('"')
            if not bare or _FORTIOS_SYSTEM_INTERFACES.fullmatch(bare):
                return value
            rendered = self._render("fortios-interface", bare)
            return f'"{rendered}"' if value.startswith('"') else rendered

        if "fortios-interface-names" in fos:
            # the declaration, and the member list of a zone or an aggregate
            for pat in (r'^(\s*edit\s+)("[^"]*"|\S+)(\s*)$',
                        r'^(\s*set\s+member\s+)(.*?)(\s*)$'):
                line = self._replace_values(line, pat, interface)
        if "fortios-route-device" in fos:
            # `set device` is an interface on a static route and something else
            # elsewhere, so it is scoped where the keys below are not
            line = self._replace_values(
                line, r"^(\s*set\s+device\s+)(.*?)(\s*)$", interface)
        line = self._replace_values(
            line,
            rf"^(\s*set\s+(?:{_FORTIOS_INTERFACE_REFS})\s+)(.*?)(\s*)$",
            interface)

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

        # JunOS MPLS LSP names. The keyword carries the name in both
        # syntaxes and at any depth, so a declaration inside a configuration
        # group is the same match as one under `protocols mpls`. `lsp-next-hop`
        # is guarded against `-`, so a p2mp tree name -- a namespace of its own,
        # and not this type -- is left alone.
        for pat in (
            r"(\blabel-switched-path\s+)([^\s{};]+)",
            r"((?<![\w-])lsp-next-hop\s+)([^\s{};]+)",
        ):
            line = self._replace_group(
                line, pat,
                lambda value: self._render("label-switched-path", value))

        # JunOS configuration groups. In `set` form the name follows the
        # keyword; in brace form `groups {` opens a block whose direct children
        # ARE the names, which is why the declaration needs the depth and not
        # just the line. `apply-groups` and `apply-groups-except` reference a
        # group from any hierarchy level, in a bare or a bracketed list form.
        if (self._group_block_depth is not None
                and self._brace_depth < self._group_block_depth):
            self._group_block_depth = None            # the block has closed
        if self._brace_depth == self._group_block_depth:
            line = re.sub(
                r"^(\s*)([^\s{};]+)(?=\s*\{)",
                lambda m: m.group(1) + self._render("configuration-group",
                                                    m.group(2)),
                line)
        group_patterns = (
            r"^(\s*(?:(?:set|delete|deactivate|activate)\s+)?groups\s+)"
            r"([^\s{};]+)",
            r"((?<![\w-])apply-groups(?:-except)?\s+)(?!\[)([^\s{};]+)",
        )
        for pat in group_patterns:
            line = self._replace_group(
                line, pat,
                lambda value: self._render("configuration-group", value))
        line = re.sub(
            r"((?<![\w-])apply-groups(?:-except)?\s+\[)([^]]+)(\])",
            lambda m: m.group(1) + re.sub(
                r"[^\s{};]+",
                lambda n: self._render("configuration-group", n.group(0)),
                m.group(2)) + m.group(3), line, flags=re.I)

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
        if opens and re.match(r"\s*groups\s*\{", original, re.I):
            self._group_block_depth = self._brace_depth + opens
        self._brace_depth += opens - closes
        while self._term_parents and self._brace_depth < self._term_parents[-1][0]:
            self._term_parents.pop()
        return line


class AsNumbers:
    """Transform ASNs only in explicit ASN-valued grammar."""

    _ONE = re.compile(
        r"(?P<prefix>\b(?:router\s+bgp|remote-as|local-as|autonomous-system)\s+)"
        r"(?P<value>\d+(?:\.\d+)?)\b", re.I)
    #: RouterOS writes an ASN as a ``key=value`` pair, and RouterOS 7 abbreviates
    #: a nested property to a leading dot: ``/routing bgp connection add
    #: as=65501 ... remote.address=... .as=65500``, where that ``.as=`` is
    #: ``remote.as=``. :attr:`_ONE` requires whitespace after the keyword, so it
    #: reaches none of these -- not even the ``remote-as=`` that RouterOS 6
    #: wrote, whose keyword it does know.
    #:
    #: The ``as`` key is a bare two-letter word, so the boundary in front of it
    #: is the whole safety margin: a character that is neither a word character
    #: nor a hyphen nor a dot, or the start of the line. Without it every key
    #: that merely ENDS in those letters -- ``alias=``, ``class=``, ``bias=`` --
    #: would have its value read as an autonomous system number.
    _ROS = re.compile(
        r"(?P<prefix>(?:^|[\s.])(?:(?:local|remote)[-.])?as=)"
        r"(?P<value>\d+(?:\.\d+)?)(?![\w.])", re.I)
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
        for pat in (self._ONE, self._ROS):
            line = pat.sub(
                lambda m: m.group("prefix") + self._replace(m.group("value")),
                line)

        def path(m):
            values = re.sub(r"\d+(?:\.\d+)?", lambda n: self._replace(n.group(0)),
                            m.group("values"))
            return m.group("prefix") + values

        return self._PATH.sub(path, line)


def asn_candidates(line: str) -> list[str]:
    """Every ASN :class:`AsNumbers` would act on in ``line``.

    Exported so the verifier asks the question the transformation answers,
    rather than keeping a second list of grammars: one that had drifted would
    either report an ASN the rule had already handled, or -- the direction that
    matters -- stay silent about one the rule never reached. ``as-number-left``
    knew none of the RouterOS spellings until this was shared.
    """
    out: list[str] = []
    for pat in (AsNumbers._ONE, AsNumbers._ROS):
        out.extend(match.group("value") for match in pat.finditer(line))
    for match in AsNumbers._PATH.finditer(line):
        out.extend(re.findall(r"\d+(?:\.\d+)?", match.group("values")))
    return out
