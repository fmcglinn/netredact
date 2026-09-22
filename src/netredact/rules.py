"""The rule tables.

A rule *selects* a part of a config; it never decides what happens to it. The
action -- ``keep`` / ``pseudo`` / ``hash`` / ``redact`` -- comes from the policy
in ``config.py``, resolved per rule via the rule's **family**. So this module
answers two questions only: *where is the interesting text* and *what kind of
thing is it*.

Shapes of a rule
----------------
A keyword rule is normally described by the *prefix* that introduces the
interesting value -- everything up to and including the keyword. The value
matcher is appended here, centrally, by :func:`_compile`, so a rule never has
to spell out how to match a quoted string, a JunOS ``;`` terminator or a
trailing ``## SECRET-DATA`` comment. That rationale still holds for the prefix
path: write the prefix, get quoting, terminators and the brace guard for free.

A rule that needs more control writes its own capture groups, and then **the
groups are the targets**: every captured group is a span the action applies to,
and everything outside the groups is kept verbatim. ``%VAL%`` (:data:`VAL_MACRO`)
expands to :data:`VAL_GROUP` -- the capturing spelling of :data:`VAL` -- so a
hand-written or user-supplied pattern can borrow the value matcher and still
count as having said where the value is.

There is no ``mode`` field any more:

* ``value`` / ``rest``  -> a prefix (zero groups), or an explicit pattern whose
  one group is the value; the old ``rest`` shape is spelled out by :func:`_rest`,
  which keeps the JunOS terminator and ``##`` comment *outside* the group.
* ``value-kw``          -> retired. It is now a negative lookahead over
  :data:`JUNOS_KEYWORDS` (plus bare digits) baked into the pattern, so a
  structural keyword is never mistaken for the value.
* ``snmp-host``         -> the only named ``handler``; the target group is the
  token region of an ``snmp-server host`` line, which the handler walks so the
  known keywords survive and only the community / v3 user is acted on.

Matched once, or searched
-------------------------
A keyword rule is normally *matched*: once per line, from the start. That is
enough where a keyword can only introduce one value on a line, which is true of
every hierarchical grammar. It is not true of RouterOS, where one command
carries many ``key=value`` pairs and two of them can belong to the same rule --
so :data:`_PAIRS` is *searched*, like the shape rules in :data:`_BLOB`, and
every pair is found. Searched rules honour scope exactly as matched ones do; the
difference is the traversal and nothing else.

Scope: the block a line is inside
---------------------------------
Some material is only recognisable from the block that encloses it. A bare
``name CUST000000000123`` is a VLAN name under ``vlan 905`` and a route-map
name under ``route-map``, and the line itself cannot tell you which. So a rule
can name the block it needs (``stanza``) or the blocks it must stay out of
(:data:`_OUTSIDE`), and the sanitiser tracks four kinds of block under one set
of names:

* a JunOS brace stanza -- ``interfaces { … }`` -- from the stanza stack;
* an IOS-style block -- ``interface Gi0/0`` and the indented lines under it --
  from :data:`_BLOCK_SCOPES`;
* a RouterOS ``/export`` section -- ``/snmp community`` and every ``add`` /
  ``set`` line after it -- from :data:`_ROUTEROS_SCOPES`;
* a FortiOS block -- ``config system snmp community`` … ``end`` -- from
  :class:`FortiBlocks` and :data:`_FORTI_SCOPES`.

The names are JunOS's own wherever the dialects share the block, so one rule
covers them all: an IOS ``interface`` block, a RouterOS ``/interface
ethernet`` section and a FortiOS ``config system interface`` block are all
scope ``interfaces``, a ``vlan 905`` block is scope ``vlans``, and a FortiOS
``config system snmp community`` block is scope ``snmp`` alongside the JunOS
``snmp { … }`` stanza. A JunOS ``set`` line carries its scope on the line
itself (:data:`_SET_SCOPE`), so ``set interfaces xe-0/0/0 description …`` is
inside ``interfaces`` too, and ``/export terse`` does the same thing with its
``/``-prefixed path. A block only one vendor has keeps its own name --
``patch-panel``, ``snmp-community``, ``system-identity``, ``system-admin``.

Wrapped lines
-------------
``/export`` wraps a long RouterOS command with a trailing ``\\`` and continues
it on the next line, so a single logical command can arrive as three physical
ones. :func:`join_continuations` undoes that before any rule runs; the reason
it has to is spelled out there, and it is the same reason a block body or a
banner may collapse: the line count of the output is not promised, the safety
of it is.

Scope is also how a vendor-specific rule is confined, and there is no other
mechanism for it. :data:`_RULE_VENDORS` labels the dialect a rule was written
for, but nothing consults it when matching: a rule is held off another
vendor's file by needing a block that vendor's grammar cannot open, which is
evidence in the file rather than a guess about the file. The reasoning is at
:data:`_RULE_VENDORS`.

``RuleCatalogue`` is the sole interface for rule inventory and traversal.
Executable rule forms, scope state and multiline handling stay private to its
implementation; callers see immutable ``RuleInfo`` and logical ``RuleHit``
values only.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

__all__ = [
    "REMOVED", "DESC_REMOVED", "RuleInfo", "RuleHit",
    "RuleReplacement", "RuleCatalogue", "FortiBlocks",
    "HOSTNAME_PATS", "DOMAIN_PATS", "USERNAME_PATS",
    "SCOPED_HOSTNAME_PATS", "SCOPED_USERNAME_PATS", "SCOPED_NAME_PATS",
    "join_continuations", "routeros_scope",
    "IPV4_RE", "IPV6_RE", "MAC_RE", "BARE_MAC_CONTEXT_RE", "EMAIL_RE",
]

REMOVED = "<REMOVED>"
DESC_REMOVED = "<DESCRIPTION-REMOVED>"

#: RANCID writes these comments where the device denied access to a value.
#: They are evidence that the credential is already absent, not values whose
#: opening ``/*`` token should be replaced.
RANCID_SENTINEL = r"/\*\s*(?:ACCESS-DENIED|SECRET-DATA)\s*\*/"

#: a value: a quoted string, or a run of non-space non-semicolon characters
VAL = rf'(?!(?:{RANCID_SENTINEL}))(?:(?:"[^"]*")|(?:\'[^\']*\')|[^\s;]+)'
#: what a custom / built-in pattern writes to borrow ``VAL``. It expands to a
#: *capturing* group: a pattern that spells out ``%VAL%`` has said where the
#: value is, so it must take the explicit-groups path. Expanding it
#: non-capturing left ``...shared-key\s+%VAL%`` with zero groups, so the prefix
#: path appended a second value matcher and ``hunter2`` became ``hunter<REMOVED>``.
VAL_MACRO = "%VAL%"
#: the capturing spelling of :data:`VAL`, substituted for :data:`VAL_MACRO`
VAL_GROUP = rf"""((?!(?:{RANCID_SENTINEL}))(?:"[^"]*"|'[^']*'|[^\s;]+))"""
#: a Huawei quoted value.
#:
#: Huawei escapes an embedded double quote by DOUBLING it, so ``password-auth
#: "%NwOntPass""H^9a...%"`` is ONE value with a quote in the middle of it.
#: :data:`VAL`, whose ``"[^"]*"`` closes at the first quote it meets, took
#: ``"%NwOntPass"`` and wrote a marker over that much -- leaving the rest of
#: the credential on the line next to a placeholder saying it had been dealt
#: with, which is the half-redacted line this project treats as worse than a
#: plain miss.
#:
#: ``(?:[^"]|"")*`` consumes the doubled pair as a unit instead. The two
#: branches cannot both match the same character, so the alternation is
#: unambiguous and the star cannot backtrack catastrophically; and because a
#: closing quote is only recognised where a doubled pair is not, ``"A" hex "B"``
#: is still two values and not one.
HUAWEI_QUOTED = r'"(?:[^"]|"")*"'

#: a Huawei value: the quoted form above, or a bare run to whitespace.
#:
#: Written out rather than borrowed from :data:`VAL`, and the difference is the
#: semicolon. ``VAL`` stops at one, because in JunOS a ``;`` terminates the
#: statement -- but Huawei's grammar has no such terminator and its cipher
#: blobs are arbitrary punctuation, ``snmp-agent community read
#: $5;,WML.z{R;N[7IgJZ@KpE6T/Wn|"zV}`Dv.TW9Ba8R>'IN/$`` among them. Borrowing
#: ``VAL`` there would have taken ``$5`` and left the community string.
HUAWEI_VAL = rf'(?:{HUAWEI_QUOTED}|\S+)'

#: encoding / algorithm hints that sit between the keyword and the secret.
#: ``enc`` is FortiOS's marker on a stored credential -- ``set password ENC
#: <blob>``. Without it here the blob was not the value, ``ENC`` was: the line
#: came out as ``set password <SECRET-...> <blob>``, reading as handled with the
#: credential still on it.
#:
#: It lives here rather than in the FortiOS rule for a second reason:
#: ``verify.VTOK`` is derived from this table. The rules and the credential
#: check have to agree on what may stand between a keyword and its placeholder,
#: or ``set password ENC "<REMOVED>"`` is reported as a leak by the very check
#: that exists to catch leaks.
ENC = (r"(?:\d+|sha512|sha256|sha1|md5|encrypted|enc|clear|ascii|ascii-text|"
       r"hex|hexadecimal|plain-text)")

#: a RUN of those hints, because several commands stack two of them. Cisco's
#: autonomous-AP ``wpa-psk {ascii|hex} [0|7] <key>`` is the plain case: an
#: encoding *format* and an encoding *type*, in that order, before the secret.
#: Admitting only one consumed the type as if it were the key and emitted a
#: marker over it, so the line read as handled while the credential stayed in
#: cleartext -- and ``--strict`` exited 0. Each repetition must end in
#: ``\s+``, so the final token can never be eaten: ``password 0 12345678``
#: still yields ``12345678``, not nothing.
ENC_RUN = rf"(?:{ENC}\s+)*"

#: A value is never a brace-only token: ``location {`` opens a JunOS stanza,
#: it does not carry a location. Eating the brace unbalanced the config and
#: left the address inside the stanza untouched.
NOT_BRACE = r"(?![{}\s]*$)"

#: tokens that are JunOS grammar, not secrets, after an authentication-key
JUNOS_KEYWORDS = {
    "type", "value", "md5", "sha1", "sha256", "key", "ascii-text",
    "hexadecimal", "plain-text", "authentication", "algorithm", "start-time",
}

#: tokens that follow a *key id* on IOS-style lines and are grammar, not
#: secrets, e.g. ``ntp server 10.0.0.1 key 5 prefer`` -- ``5`` is the key id
#: and ``prefer`` is a keyword, so the line holds no secret at all.
IOS_KEYWORDS = {
    "prefer", "source", "source-interface", "version", "minpoll", "maxpoll",
    "iburst", "burst", "vrf", "timeout", "retransmit", "port", "auth-port",
    "acct-port", "single-connection", "nat", "dynamic", "informs", "inform",
    "traps", "trap", "udp-port",
}

#: the base64 of an SSH public key's own type-string header, which is what
#: makes a blob recognisable with no algorithm token in front of it: `ssh-rsa`
#: and `ssh-dss` are 7 bytes, `ssh-ed25519` 11, `ecdsa-sha2-*` 19. Shared with
#: the ``ssh-key-left`` check, so the rule and the check cannot disagree.
SSH_KEY_SIG = r"AAAA(?:B3Nza|C3Nza|E2Vj)"

#: keywords on an `snmp-server host` line, so only the community is hit
SNMP_HOST_KEYWORDS = {
    "vrf", "informs", "inform", "traps", "trap", "version", "1", "2c", "3",
    "auth", "noauth", "priv", "udp-port", "source-interface",
}


@dataclass(frozen=True)
class _Rule:
    name: str
    regex: re.Pattern
    family: str
    targets: tuple[int, ...]     # capture-group indices to act on
    #: the block this rule needs to be inside: a JunOS stanza name, or a name
    #: from :data:`_BLOCK_SCOPES` for an IOS-style block. None means anywhere.
    stanza: str | None = None
    #: blocks this rule must NOT be inside, because a scoped rule owns that
    #: material instead -- see :data:`_OUTSIDE`
    outside: tuple[str, ...] = ()
    custom: bool = False
    handler: str | None = None   # "snmp-host" only; else None
    #: ADVISORY ONLY: the dialect this rule's grammar comes from, or None for
    #: a rule that is unlabelled. Nothing in the sanitiser reads it, and no
    #: rule is ever skipped because of it -- see :data:`_RULE_VENDORS`.
    vendor: str | None = None


@dataclass(frozen=True)
class RuleInfo:
    """Stable, non-executable description of a rule.

    Callers that report or configure rules should consume this view rather
    than learning which internal representation happens to execute the rule.
    """

    name: str
    family: str
    vendor: str | None
    custom: bool
    required_scope: str | None
    excluded_scopes: tuple[str, ...]
    pattern: str
    end_pattern: str | None = None


@dataclass(frozen=True)
class RuleHit:
    """One value selected by the catalogue during transformation."""

    name: str
    family: str
    value: str


@dataclass(frozen=True)
class RuleReplacement:
    """The caller's decision for a selected value.

    ``active`` distinguishes an inactive (kept) banner, whose body remains
    ordinary input, from an active banner whose already-rendered body is left
    unchanged.  Other rule forms treat both decisions as no replacement.
    """

    text: str | None = None
    active: bool = True

    @classmethod
    def keep(cls) -> RuleReplacement:
        return cls(active=False)

    @classmethod
    def unchanged(cls) -> RuleReplacement:
        return cls(active=True)

    @classmethod
    def with_text(cls, text: str) -> RuleReplacement:
        return cls(text=text, active=True)


# ---------------------------------------------------------------------------
# pattern helpers
# ---------------------------------------------------------------------------

def _alt_order(word: str) -> tuple[int, str]:
    """Order for a regex alternation built from a *set*.

    Longest first, because a short keyword must not shadow a longer one that
    starts with it (``lata`` before ``latitude`` would swallow the match).
    Alphabetical breaks ties, because set iteration order varies with
    ``PYTHONHASHSEED`` and the compiled pattern text is rendered into
    ``docs/rules.md`` -- an unordered alternation makes the docs irreproducible
    and ``gen_docs.py --check`` flake between processes.
    """
    return (-len(word), word)


def _not_keyword(words, enc: str | None = ENC, digits: bool = False) -> str:
    """A lookahead asserting the value is not a bare grammar keyword.

    The optional encoding hint is *inside* the assertion on purpose. Without
    that, ``key 5 prefer`` would simply backtrack -- give up ``5`` as the hint,
    take ``5`` as the secret -- and destroy nothing useful while still losing
    the key id. Covering both alignments makes the whole rule decline the line.
    """
    alts = sorted(words, key=_alt_order)
    if digits:
        alts.append(r"\d+")
    kw = "(?:" + "|".join(alts) + r")(?![-\w])"
    if enc is None:
        return rf"(?!{kw})"
    return rf"(?!(?:{enc}\s+)?{kw})"


#: keys JunOS allows inside a `system { location { ... } }` stanza, in
#: :func:`_alt_order` so `latitude` is not shadowed by `lata`
_JUNOS_LOCATION_KEYS = "|".join(sorted((
    "altitude", "building", "country-code", "floor", "hcoord", "lata",
    "latitude", "longitude", "npa-nxx", "postal-code", "rack", "room",
    "street-address", "vcoord",
), key=_alt_order))


#: keys that introduce a hardware model. The rule requires a ``:`` or ``=``
#: after them, and that separator is the whole safety margin: every one of
#: these words is also a configuration keyword -- ``platform qos ...``,
#: Arista's ``service routing protocols model multi-agent`` -- and none of
#: those carries one. Written out rather than sorted from a set, because the
#: alternation text is rendered into ``docs/rules.md`` and has to be stable.
_MODEL_KEYS = (r"hardware(?:\s+(?:model|version|revision))?"
               r"|model(?:\s+(?:number|name))?"
               r"|chassis(?:\s+type)?"
               r"|product(?:\s+id)?"
               r"|platform|pid")

#: keys that introduce a software release or image, with the value separated
#: by a colon *or* just a space. Cisco writes ``System image file is
#: "flash:..."`` with no colon at all, so ``is`` belongs to the key rather
#: than to the separator.
_IMAGE_KEYS = (r"software\s+image\s+version"
               r"|system\s+image\s+file(?:\s+is)?"
               r"|(?:software|firmware|image|junos|eos|os)\s+version")

#: the same, for keys that are a bare product name -- JunOS ``show version``
#: prints ``Junos: 20.4R3.8``. A colon is required here and the space form is
#: refused, because a bare ``eos`` or ``junos`` followed by a space is far too
#: little evidence to rewrite a line on.
_IMAGE_COLON_KEYS = r"junos|eos"


#: a ``description`` line, in every dialect: IOS / EOS / NX-OS bare, JunOS
#: ``description "…";``, JunOS ``set … description …`` and FortiOS
#: ``set description …`` / ``set comments …``.
#:
#: THE PRINCIPLE: which rule owns a description is decided by its **scope**, not
#: by its pattern. Inside an interface it is ``interface-description`` in the
#: ``interfaces`` family; everywhere else -- a VRF, a policy-map, a peer group --
#: it is ``description`` in ``text``. One selector, split in two by
#: :data:`_OUTSIDE`, so the two can never both act on the same line and no
#: description falls between them.
#:
#: The path after ``set`` is optional because FortiOS has none: its grammar is
#: ``set <attribute> <value>`` and the block supplies the context that JunOS
#: writes out.
#:
#: ``comments`` is FortiOS's own spelling of the same field, and it deliberately
#: does NOT get the wildcard path that ``description`` has. ``comment`` is an
#: ordinary word: through ``set\s+\S.*?\s`` it matched the tail of ``set system
#: scripts … checksum sha-256 <digest> comment <hex>``, which handed a long hex
#: run to the ``text`` family and blinded ``long-hex-left`` to it. The
#: keyword has to be the whole line, or the first token after ``set``.
_DESCRIPTION = (r"\s*(?:(?:set\s+(?:\S.*?\s)?)?description"
                r"|(?:set\s+)?comments?)\s+")

#: FortiOS credential attributes, for the one grammar shape they all share:
#: ``set <attribute> <value>``, with the *block* rather than the line saying
#: what the value belongs to. So one alternation reaches an admin password, an
#: IPsec pre-shared key, an SNMPv3 auth secret and a WiFi passphrase alike,
#: and there is no per-block pattern to keep in step with FortiOS's tables.
#:
#: The keyword has to be the FIRST token after ``set``, and that is the whole
#: guard on the two ordinary words in the list. ``secret`` and ``key`` are
#: keywords in half the dialects, but ``set secret …`` with nothing between is
#: FortiOS's shape and not JunOS's -- a JunOS ``set`` line always carries the
#: hierarchy first, which is what ``bare-secret`` and ``quoted-key`` read.
#: Longest first (see :func:`_alt_order`), so ``passwd`` cannot shadow
#: ``password``; written out rather than sorted from a set because the
#: alternation text is rendered into ``docs/rules.md``.
_FORTIOS_SECRET_KEYS = (r"passphrase|ppk-secret|psksecret|auth-pwd|password"
                        r"|priv-pwd|api-key|passwd|secret|key")

#: FortiOS's whole platform header: ``#config-version=FGVM64-7.4.4-FW-build2662
#: -240514:opmode=0:vdom=0:user=admin``. Like Arista's ``! device:`` line it
#: carries values of several kinds -- a model, a release, a build, and the name
#: of the administrator who saved the file -- introduced by position alone, so
#: each is reached by a branch on the rule that owns that kind of value rather
#: than by a rule for the line.
_FORTIOS_HEADER = r"^#config-version="

#: RouterOS's ``description``, and the same principle: which rule owns a
#: ``comment=`` is decided by its scope. Inside a RouterOS ``/interface …``
#: section it is ``interface-comment`` in ``interfaces``; everywhere else -- a
#: firewall rule, a DHCP lease, an address list -- it is ``comment`` in
#: ``text``. Split in two by :data:`_OUTSIDE`, so the two can never both act on
#: the same pair and no comment falls between them. Both live in :data:`_PAIRS`.
_COMMENT = r'(?<![-\w])comment=%VAL%'

#: everything up to the opening bracket of Arista's ``show running-config``
#: header, ``! device: agg-sw-02 (DCS-7280SR-48C6-M, EOS-4.32.1F)``. The two
#: values inside the brackets are introduced by no keyword at all -- position
#: is their only grammar -- so each is reached by a second branch on the rule
#: that owns that kind of value, rather than by a rule of its own. The
#: hostname in front is left alone here: it belongs to ``hostnames``, which
#: learns it from :data:`HOSTNAME_PATS` and substitutes it everywhere.
_EOS_HEADER = r"^\s*!\s*device:\s*\S+\s*\("

def _rest(prefix: str) -> str:
    """The whole remainder of the line is the value (the old ``rest`` mode)."""
    return rf"^{prefix}{NOT_BRACE}(.+?)(?:\s*;\s*(?:##.*)?)?$"


def _alt(*shapes: str) -> str:
    """One rule, several shapes, each with its own capture group.

    A branch that did not take part in the match reports a span of ``-1`` and
    is skipped by :meth:`Sanitiser._spans`, so exactly the group that matched
    is the target.
    """
    return "(?:" + "|".join(shapes) + ")"


def _compile(pattern: str, flags: int = re.I) -> tuple[re.Pattern, tuple[int, ...]]:
    """Compile a rule pattern, returning ``(regex, targets)``.

    ``%VAL%`` expands first. A pattern that captures is used as written and
    every group is a target. A pattern that captures nothing is a prefix: the
    value matcher, the brace guard and the trailing context are appended here.
    """
    p = pattern.replace(VAL_MACRO, VAL_GROUP)
    if re.compile(p).groups:
        rx = re.compile(p, flags)
        return rx, tuple(range(1, rx.groups + 1))
    rx = re.compile(rf"^({p}){NOT_BRACE}({VAL})(.*)$", flags)
    return rx, (2,)


# ---------------------------------------------------------------------------
# keyword rules: (name, pattern, family, required JunOS stanza)
# ---------------------------------------------------------------------------

_BUILTIN: list[tuple[str, str, str, str | None]] = [
    # ---- enable / user credentials -------------------------------------
    ("enable-secret", rf"\s*enable\s+(?:secret|password)\s+(?:level\s+\d+\s+)?{ENC_RUN}", "secrets", None),
    ("username-secret", rf"\s*username\s+\S+\s+(?:\S+\s+)*?(?:password|secret)\s+{ENC_RUN}", "secrets", None),
    # Neither of these takes the ADJACENT `set <key>` form, and deliberately:
    # `set password ENC …` and `set secret ENC …` are FortiOS, and
    # `fortios-secret` owns them. Two rules matching one span would splice
    # twice, and the second would hash the first's marker. What is left here is
    # the hierarchical form -- a bare `password` line under `line vty`, and the
    # JunOS path form `set system tacplus-server 10.0.0.1 secret X`, which
    # always has a token between `set` and the keyword.
    ("bare-password", rf"\s*(?:password|passwd)\s+{ENC_RUN}", "secrets", None),
    ("bare-secret", rf"\s*(?:set\s+\S.*?\s)?secret\s+{ENC_RUN}", "secrets", None),
    # `authentication password <secret>` mid-line: `bare-password` is anchored,
    # so it only sees the hierarchical form. JunOS subscriber management puts
    # the same credential at the end of a long `set` path. The `authentication`
    # qualifier is what keeps the unanchored form off `no password` and
    # `service password-encryption`.
    ("authentication-password",
     rf".*\bauthentication\s+password\s+{ENC_RUN}", "secrets", None),

    # ---- AAA / shared keys ----------------------------------------------
    ("encoded-key",
     r".*\bkey\s+"
     + _not_keyword(IOS_KEYWORDS, enc=r"(?:0|7|8|encrypted)")
     + r"(?:0|7|8|encrypted)\s+", "secrets", None),
    ("aaa-server-key",
     r".*\b(?:tacacs|radius|ldap|server-private|server)\b.*?\bkey\s+"
     + _not_keyword(IOS_KEYWORDS)
     + rf"{ENC_RUN}", "secrets", None),
    ("quoted-key", r"\s*(?:set\s+\S.*?\s)?key\s+(?=\")", "secrets", None),
    ("key-string", rf"\s*key-string\s+{ENC_RUN}", "secrets", None),
    ("key-hash", r"\s*(?:key-hash|hash)\s+\S+\s+", "secrets", None),
    ("license-entitlement-key", r"\s*(?:set\s+system\s+)?license\s+keys\s+key\s+", "secrets", None),

    # ---- SNMP -------------------------------------------------------------
    ("snmp-community", r"\s*(?:snmp-server|set\s+snmp)\s+community\s+", "secrets", None),
    ("junos-community", r"\s*community\s+", "secrets", "snmp"),
    # the target group is the token region; the handler walks it so the known
    # keywords survive and only the community / v3 user name is acted on
    ("snmp-host", r"^\s*snmp-server\s+host\s+\S+\s+(.*)$", "secrets", None),
    ("snmp-v3-auth", r".*\bauth\s+(?:md5|sha\d*)\s+", "secrets", None),
    ("snmp-v3-priv", r".*\bpriv\s+(?:(?:aes(?:\s+\d+)?|des|3des)\s+)?", "secrets", None),
    ("snmp-engineid", r"\s*snmp-server\s+engineID\s+\S+\s+", "identity", None),

    # ---- crypto / VPN -----------------------------------------------------
    ("isakmp-key", rf"\s*crypto\s+isakmp\s+key\s+{ENC_RUN}", "secrets", None),
    ("pre-shared-key", rf".*\bpre-shared-key\s+(?:address\s+\S+\s+)?(?:key\s+)?{ENC_RUN}", "secrets", None),
    ("auth-key",
     r"\s*(?:set\s+\S.*?\s)?(?:authentication-key|encryption-key)\s+"
     + _not_keyword(JUNOS_KEYWORDS, digits=True)
     + rf"{ENC_RUN}", "secrets", None),

    # ---- routing / redundancy protocol authentication ---------------------
    ("message-digest-key", rf".*\bmessage-digest-key\s+\d+\s+md5\s+{ENC_RUN}", "secrets", None),
    ("bgp-neighbor-password", rf".*\bneighbor\s+\S+\s+password\s+{ENC_RUN}", "secrets", None),
    ("hsrp-vrrp-auth", rf"\s*(?:standby\s+\d+\s+|vrrp\s+\d+\s+)?authentication\s+(?:text|md5\s+key-string|md5\s+key-chain)\s+{ENC_RUN}", "secrets", None),
    ("isis-password",
     # `area-password` / `domain-password` / `lsp-password` are the IS-IS
     # authentication commands; `isis password <key>` is the interface-level
     # form and is spelled with a space, not a hyphen.
     rf"\s*(?:(?:lsp|area|domain)-password|isis\s+password)\s+{ENC_RUN}", "secrets", None),
    ("ntp-auth-key", r"\s*ntp\s+authentication-key\s+\d+\s+\S+\s+", "secrets", None),

    # ---- PPP / L2 / wireless ---------------------------------------------
    ("ppp-credential", rf"\s*ppp\s+(?:chap|pap|eap)\s+(?:password|secret|sent-username\s+\S+\s+password)\s+{ENC_RUN}", "secrets", None),
    ("wpa-psk", rf".*\bwpa-psk\s+{ENC_RUN}", "secrets", None),
    ("ftp-password", rf"\s*ip\s+(?:ftp|tftp|http\s+client)\s+password\s+{ENC_RUN}", "secrets", None),

    # ---- RouterOS ---------------------------------------------------------
    # The `key=value` credentials are not here: one command line can carry two
    # pairs belonging to one rule, so they are searched rather than matched --
    # see :data:`_PAIRS`. This one is a header comment and can only occur once.
    #
    # RouterOS's licence identifier, under both the names it goes by: the
    # `/export` header writes `# software id = ` on some versions and platforms
    # and `# system id = ` on others, and `/system license print` writes
    # `system-id:`. They are one value with one meaning, so they are one rule --
    # naming only the first spelling let the second leave the tool untouched.
    #
    # Licence-tied to one device, not to a production line: two routers of the
    # same model never share one. So `identity`, not `platform`.
    #
    # The `[:=]` is the safety margin, exactly as it is for `hardware-model`:
    # `system-id` is also an IS-IS and FabricPath keyword, and neither of those
    # carries a separator.
    ("routeros-license-id",
     r"\s*#?\s*(?:software|system)[-\s]id\s*[:=]\s*", "identity", None),

    # ---- FortiOS: the keys `fortios-secret` cannot name --------------------
    # `fortios-secret` below is a LIST of attribute names, which is the right
    # shape for the ones FortiOS has always had. These two are for the ones it
    # has not: the marker and the qualifier are evidence in the line itself, so
    # a key nobody has written down is still covered.
    #
    # `ENC` is FortiOS's own marker that what follows is a stored credential,
    # whatever the attribute is called, so `fortios-encrypted` needs no list at
    # all. `fortios-credential-key` is the qualified spelling without the
    # marker -- `group-password`, `key-passphrase`, `password2` -- which is
    # what a typed or templated configuration carries where a backup carries
    # `ENC`. A qualified key name is still that key, exactly as it is on
    # RouterOS (`ipsec-secret=`, `authentication-password=`).
    #
    # All three are disjoint by construction, and that is load-bearing rather
    # than tidy: two rules matching one span would splice twice, and the second
    # would hash the first's marker -- `set password <SECRET-a1b2c3>` hashed
    # AGAIN into `set password <SECRET-9f8e7d>`, counted twice and traceable to
    # nothing. The lookahead holds both off `_FORTIOS_SECRET_KEYS`, and
    # `(?!ENC\s)` holds the second off the first.
    #
    # The `\d*\s+` after the credential word keeps `fortios-credential-key`
    # off the knobs: `set password2 <secret>` is a real second credential,
    # while `set password-policy status enable` and `set password-expire 5`
    # have a HYPHEN there, and admitting a hyphenated suffix would have
    # redacted `status` and `5` and broken both. The key sits IMMEDIATELY after
    # `set` in both, which is what holds them off JunOS -- there a credential
    # is always at the end of a path, never adjacent.
    ("fortios-encrypted",
     rf"\s*set\s+(?!(?:{_FORTIOS_SECRET_KEYS})\s)[\w-]+\s+ENC\s+",
     "secrets", None),
    ("fortios-credential-key",
     rf"\s*set\s+(?!(?:{_FORTIOS_SECRET_KEYS})\s)"
     r"[\w-]*(?:password|passwd|pwd|secret|passphrase)\d*\s+(?!ENC\s)",
     "secrets", None),
    # A LABEL `set name`: operator free text, and on a provider config a
    # customer and an order reference. Scoped to `object-labels` and not to a
    # whole section, for the reason set out at :data:`_FORTI_SCOPES` -- a name
    # the configuration REFERENCES cannot be acted on by a rule that only sees
    # the declaration. `fortios-snmp-community` is the same selector one scope
    # over, and :data:`_OUTSIDE` is not needed because no block opens both.
    ("fortios-object-name", r"\s*set\s+name\s+", "text", "object-labels"),

    # ---- Huawei MA5600T / MA5800 (GPON OLT) --------------------------------
    # THE CREDENTIALS ARE NOT REACHED THROUGH THEIR QUOTING, and that is the
    # whole design of this group. `display current-configuration` writes an
    # ONT's stored password as a cipher blob inside double quotes -- but the
    # blob is emitted RAW, so its own punctuation routinely includes a bare
    # `"`:
    #
    #     password-auth "%#%#NwOntPass...>w{R8{cPeRqD%F&"=q;sJ-:[>rH%#%#"
    #
    # There are eight quotes on that line and six of them are payload. Any
    # rule that closed the value at a quote closed it in the middle of the
    # credential and wrote a marker over the first fragment, which is the
    # half-redacted line this project treats as worse than a plain miss.
    #
    # What IS reliable is the command's own grammar. `ont add` puts the
    # credentials between `password-auth` and the `omci` that introduces the
    # profile ids, so the region between those two keywords is the target and
    # the quotes inside it are never consulted. `hex` gets its own group
    # rather than being swallowed with the rest: it is a second rendering of
    # the same credential, and keeping the keyword visible is what says so.
    #
    # The second branch is the one that keeps this fail-safe. A Huawei capture
    # wraps at the width of the collecting session, and where a wrap lands
    # inside a blob whose embedded quotes defeat :func:`_quote_open` the
    # joiner declines it (see :data:`_HUAWEI_WRAPPED`) and the line arrives
    # here with no `omci` on it at all. Rather than decline the line and leave
    # a password on it, the fallback takes everything from `password-auth` to
    # the end: blunter than the first branch, and the bluntness is the point.
    ("huawei-ont-credential",
     _alt(r"^\s*ont\s+(?:add|confirm|modify)\s.*?\bpassword-auth\s+"
          r"(\S.*?)(?:\s+hex\s+(\S.*?))?(?=\s+omci(?![-\w]))",
          r"^\s*ont\s+(?:add|confirm|modify)\s.*?\bpassword-auth\s+(\S.*?)\s*$"),
     "secrets", None),
    # The MA5600T local user table. `terminal user name <flag> <user>
    # *<cipher>* <level> <created> <modified> <creator> <id> "<desc>"`, where
    # the cipher is delimited by `*` and everything between the delimiters is
    # payload -- `*[4JJE5U**BAW5;JF`U_X-Q^=!*` has two of them inside it, so
    # the blob has to be taken to the LAST `*` and not the next one.
    #
    # Three branches, in decreasing confidence:
    #
    # * the whole command is on the line, so the trailing grammar -- a level
    #   digit and a `yyyy:mm:dd:hh:mm:ss` stamp -- says exactly where the
    #   cipher ends, and the creation times, the creator and the account's
    #   description all survive.
    # * the line was wrapped and the trailing grammar is on the next one, so
    #   there is nothing to anchor against and everything from the `*` goes.
    # * the wrap fell INSIDE the cipher, so the remainder arrives as a line of
    #   its own with the blob's tail on the front of it. The lookahead is the
    #   evidence and it is a strong one: a token ending in `*`, then a level
    #   and two colon-separated timestamps, is this command's tail and no
    #   other dialect writes anything like it.
    ("huawei-terminal-user",
     _alt(r"^\s*terminal\s+user\s+name\s+\S+\s+\S+\s+(\*.*\*)"
          r"(?=\s+\d+\s+\d{4}:\d{2}:)",
          r"^\s*terminal\s+user\s+name\s+\S+\s+\S+\s+(\*.*?)\s*$",
          r"^(\S*\*)(?=\s+\d+\s+\d{4}:\d{2}:\d{2}:\d{2}:\d{2}:\d{2}\s)"),
     "secrets", None),
    # An SNMP community, under both the grammars Huawei states one in. The
    # value is taken with `\S+` rather than `%VAL%` because `VAL` stops at a
    # `;` -- the JunOS statement terminator, which Huawei's grammar does not
    # have -- and a Huawei cipher blob carries semicolons freely: `snmp-agent
    # community read $5;,WML.z{R;N[7IgJZ@...$` would have handed over `$5` and
    # left the community string on the line.
    #
    # `snmp-agent` rather than `snmp-server`, which is what keeps this off the
    # IOS-style rule and that one off this: `snmp-community` above wants
    # `snmp-server` or `set snmp`, so each spelling has exactly one owner.
    ("huawei-snmp-community",
     _alt(r"^\s*snmp-agent\s+community\s+(?:read|write)\s+"
          r"(?:(?:cipher|simple)\s+)?(\S+)",
          r"^\s*snmp-agent\s+target-host\s+.*?\bsecurityname\s+(\S+)"),
     "secrets", None),
    # SNMPv3, where Huawei spells out what Cisco writes as `auth md5 X` /
    # `priv aes 128 X`. `snmp-v3-auth` and `snmp-v3-priv` want the bare words,
    # so the `-mode` suffix is what gives this rule the line and those two the
    # IOS one.
    ("huawei-snmp-usm",
     r"^\s*snmp-agent\s.*?\b(?:authentication|privacy)-mode\s+"
     r"(?:md5|sha\d*|sha2-\d+|aes\d*|des\d*|3des)\s+(\S+)", "secrets", None),
    # The engine id, and `identity` for the same reason Cisco's is: it names
    # this one box and nothing else, and it is a 24-character hex run, so
    # `long-hex-left` reported it on every capture until a rule owned it. A
    # rule the shape checks can be blinded to is the whole difference between
    # "kept on purpose" and "missed".
    ("huawei-snmp-engineid",
     r"\s*snmp-agent\s+local-engineid\s+", "identity", None),
    # The ONT's serial number. `identity`, alongside `serial-number`: it is
    # the hardware serial of one subscriber's terminal, so `pseudo` is the
    # action to reach for -- an `ont confirm` elsewhere in the file names the
    # same ONT, and a pseudonym keeps the two reading as one ONT.
    #
    # Reached with `%VAL%` rather than the grammar anchor the credentials
    # need, because this value is the one on an `ont add` line that is NOT a
    # cipher blob: it is `48575443` -- "HWTC" -- and eight more hex digits.
    ("huawei-ont-serial",
     r"^\s*ont\s+(?:add|confirm|modify)\s.*?\bsn-auth\s+%VAL%",
     "identity", None),
    # What an ONT and a service port are called, which on this box is the
    # subscriber: `desc "ORD-772311, TransitCo Ltd - SME, 300M"`
    # carries an order reference, a customer and the bandwidth they bought.
    #
    # `interfaces` and not `text`, for the reason `fortios-interface-alias` is
    # `interfaces`: it is the label a reviewer reads the topology by, and a
    # provider needs the ports to stay distinguishable from each other.
    #
    # Both take the REST of the line, and both are safe to: `desc` is the last
    # field of `ont add` and `description` the last field of `service-port
    # desc`, so there is no following keyword for an embedded quote to hide.
    ("huawei-ont-desc",
     r"^\s*ont\s+(?:add|confirm|modify)\s.*?\bdesc\s+(\S.*?)\s*$",
     "interfaces", None),
    # `service-port desc <n> description "..."` is the subscriber's, and `port
    # desc <f>/<s>/<p> description "..."` is the uplink's -- one grammar, so
    # one rule, and one action for both.
    ("huawei-port-desc",
     r"^\s*(?:service-)?port\s+desc\s+\S+\s+description\s+(\S.*?)\s*$",
     "interfaces", None),
    # `rack info 0 description "NW-RACK-01" name "NW-RACK-01"
    # manufactured-name "Huawei"`. The cabinet a chassis stands in, which is a
    # place -- so
    # `locations`, alongside the `snmp location` this box states four lines
    # further down. `manufactured-name` is deliberately left: it says
    # "Huawei", which the whole file already does.
    ("huawei-rack-info",
     r"^\s*rack\s+info\s+\d+\s+description\s+%VAL%(?:\s+name\s+%VAL%)?",
     "locations", None),
    # The names of the profiles a subscriber is provisioned against -- a line
    # profile, a service profile, a DBA profile, a traffic table. `text`, and
    # safe to act on, because the configuration refers to every one of them by
    # its NUMBER and never by its name: `ont-lineprofile-id 305`,
    # `traffic-table index 45`. A name nothing points at is a label, which is
    # the same argument `object-labels` makes on RouterOS and FortiOS.
    #
    # `(?:\S+\s+)*?` rather than `.*?`: whole tokens only, so the keyword has
    # to be a word of the command and cannot be found inside a value.
    ("huawei-profile-name",
     r"\s*(?:\S+\s+)*?profile-name\s+", "text", None),
    ("huawei-traffic-table-name",
     r"\s*traffic\s+table\s+\S+\s+index\s+\d+\s+name\s+", "text", None),
    # The MSTP region, which on a provider's access ring is named after the
    # site it stands in -- `region-name manila`.
    ("huawei-region-name", r"\s*region-name\s+", "text", None),

    # ---- Juniper specifics -------------------------------------------------
    ("junos-password", r".*\b(?:encrypted-password|plain-text-password-value)\s+", "secrets", None),
    # The digest a script file is pinned to. NOT a credential, but a 64-char hex
    # run, so the shape checks reported it. `identity` is where it belongs: a
    # checksum ties the file to one exact script, and those checks go blind to
    # it only when the policy keeps identity (verify.SHAPE_BLIND_FAMILIES).
    # The algorithm token is JunOS's own grammar, and requiring it keeps the
    # unanchored prefix off another dialect's bare `checksum` knob.
    ("script-checksum",
     r".*\bchecksum\s+(?:md5|sha-?1|sha-?256|sha-?512)\s+", "identity", None),

    # ---- FortiOS specifics -------------------------------------------------
    # ONE rule for every FortiOS credential, because they are all one grammar:
    # see :data:`_FORTIOS_SECRET_KEYS` for why the keyword has to be the first
    # token after `set`, and `ENC` for why the encoding hint is shared.
    ("fortios-secret",
     rf"\s*set\s+(?:{_FORTIOS_SECRET_KEYS})\s+{ENC_RUN}", "secrets", None),
    # An SNMP community, and the one FortiOS rule that scope alone can confine:
    # `set name` is everywhere in FortiOS -- a firewall policy, an address
    # object, an admin profile all have one -- and only inside a `config system
    # snmp community` block is the name a credential. So the gate is the block,
    # which is evidence in the file, and the shape carries nothing on its own.
    ("fortios-snmp-community", r"\s*set\s+name\s+", "secrets", "snmp"),
    # What a FortiOS port is called. `alias` is the interfaces family for the
    # same reason `description` is: it is the label a reviewer reads the
    # topology by, and on a service-provider box it carries the customer.
    # Scoped to `interfaces`, so the `set alias` in `config system global` --
    # which is the device's own name -- is left to the hostname collection.
    ("fortios-interface-alias", r"\s*set\s+alias\s+", "interfaces", "interfaces"),

    # ---- vendor unlocks ----------------------------------------------------
    # Arista `service unsupported-transceiver <label> <authorization-code>`:
    # the code is TAC-issued credential material, and the label is operator
    # free text that in practice carries a customer / project name and dates.
    # The second token is optional, but the bare Cisco IOS `service
    # unsupported-transceiver` (no arguments) must not match at all.
    ("unsupported-transceiver",
     rf"^\s*service\s+unsupported-transceiver\s+{NOT_BRACE}%VAL%(?:\s+%VAL%)?\s*$",
     "secrets", None),

    # ---- platform: what the box is and what it runs -----------------------
    # Model, software release and boot image. Not a credential, and not an
    # instance identity either -- every device off the same production line
    # shares it. It is the attack surface: a model plus a release number is a
    # CVE list, and a fleet-wide version is a fleet-wide one. Kept by default,
    # because it is also the first thing a support engineer asks for and the
    # thing a reviewer needs in order to read the config at all.
    #
    # These lines are also where the VENDOR DETECTOR gets its best evidence,
    # which is why detection reads the input and never the output; see
    # ``vendors.py``.
    #
    # Arista's `! device: <name> (<model>, <release>)` header carries three
    # values of three different kinds on one line. It gets no rule of its own:
    # a rule carries ONE family and ONE action, so a rule for the whole header
    # would put the model and the release beyond the reach of
    # `[platform] os-version` and `[platform] hardware-model`. Each of those
    # two rules reads the header itself instead, and the hostname stays with
    # `hostnames`.
    # `[!#]?` rather than `!?`: the comment leader is `!` in IOS-style grammars
    # and `#` in JunOS and RouterOS, and the RouterOS `/export` header writes
    # `# model = RB4011iGS+`. Admitting both here rather than adding a second
    # rule keeps one model rule with one action, which is what `[platform]
    # hardware-model = "keep"` has to mean on every dialect.
    ("hardware-model",
     _alt(_rest(rf"\s*[!#]?\s*(?:{_MODEL_KEYS})\s*[:=]\s*"),
          # the Arista header, up to the last comma inside the brackets
          rf"{_EOS_HEADER}([^)]+),",
          # the FortiOS header: the model is everything before the first `-`
          # that a dotted release follows, so `FGVM64` and `FWF-60E` both work
          rf"{_FORTIOS_HEADER}([\w-]+?)-(?=\d+\.\d)",
          # Huawei's own version marker, `[MA5600V800R013: 3910]`, which sits
          # in the configuration as a section header of its own. Like the
          # Arista and FortiOS headers it states a model and a release with
          # nothing but position to introduce them, so each is a branch on the
          # rule that owns that kind of value.
          r"^\s*\[(MA\d+[A-Z]*)(?=V\d+R\d+)",
          # A board part number -- `board add 0/0 H805GPFD`. A branch and not
          # a rule of its own, because `[platform] hardware-model = "keep"`
          # has to mean one thing on every dialect and a line card is a
          # hardware model. `board add standby` names no part and cannot
          # match: the slot is required.
          r"^\s*board\s+add\s+\d+/\d+\s+(\S+)",
          # and the same part numbers again in the `display board` table a
          # RANCID capture keeps as a comment above the configuration. Left
          # out, the model was destroyed where the device configures it and
          # kept twelve lines higher up where the device reports it -- which
          # is not a policy anybody asked for. `H` and three digits is the
          # whole of Huawei's part-number shape and the slot number in front
          # is what keeps the branch off the rest of the table.
          r"^\s*!\s+\d+\s+(H\d{3}[A-Z0-9]+)(?![-\w])"), "platform", None),
    ("os-version",
     _alt(_rest(r"\s*(?:set\s+)?version\s+(?=\d)"),
          # the Arista header, the token after the last comma
          rf"{_EOS_HEADER}[^)]+,\s*([^\s,)]+)\s*\)\s*$",
          # RouterOS writes the release in the `/export` provenance comment and
          # nowhere else: `# 2026-08-19 10:22:33 by RouterOS 7.15.3`. A third
          # branch rather than a rule of its own, for the reason the Arista
          # header has branches: the release is the release, and one rule means
          # one action for it. `by RouterOS` itself survives, which is what
          # keeps the detector working on redacted output -- see `vendors.py`.
          r"^\s*#.*\bby\s+RouterOS\s+%VAL%\s*$",
          # the FortiOS header: the release, its firmware kind and its build,
          # up to the `:` that starts `opmode=`. `.*?` rather than a character
          # class for the model in front, because `hardware-model` is an
          # earlier rule and has already replaced it by the time this one
          # looks -- a class that could not span `<REMOVED>` left the release
          # behind whenever the model was acted on and the release was not.
          rf"{_FORTIOS_HEADER}.*?-(\d+\.\d[^\s:]*)",
          # `#buildno=` and `#branch_pt=`, the same release stated again on
          # their own lines
          r"^\s*#(?:buildno|branch_pt)=(\S+)\s*$",
          # Huawei's `[MA5600V800R013: 3910]`. `.*?` for the model in front
          # for the reason the FortiOS branch needs one: `hardware-model` is
          # an earlier rule and has already replaced it by the time this one
          # looks, so a pattern that could not span `<REMOVED>` left the
          # release behind on exactly the files where the model was acted on.
          r"^\s*\[.*?(V\d+R\d+[\w.]*)"), "platform", None),
    ("software-image",
     _rest(rf"\s*!?\s*(?:(?:{_IMAGE_KEYS})(?:\s*[:=]\s*|\s+)"
           rf"|(?:{_IMAGE_COLON_KEYS})\s*[:=]\s*)"), "platform", None),
    ("boot-image", _rest(r"\s*!?\s*boot\s+system\s+"), "platform", None),

    # ---- free text ---------------------------------------------------------
    # location / contact are text, not secrets: they leak an org and a site,
    # not a credential. NOT_BRACE keeps `location {` a stanza opener.
    # The second branch of each is RouterOS's `key=value` spelling of the same
    # field -- `/snmp` `set location="…" contact="…"`. It is a branch and not a
    # rule of its own so that one action governs the field whatever grammar
    # wrote it, and it is unanchored because `/export terse` puts the section
    # path in front of the command.
    # The bare ``set`` form in the first branch is FortiOS's -- ``set location
    # "…"`` under `config system snmp sysinfo`, where the block carries the
    # `snmp` that JunOS spells out on the line; it is safe unqualified because
    # NOT_BRACE refuses a stanza opener and no dialect uses `location` or
    # `contact` as a command keyword. `contact-info` is FortiOS's spelling of
    # the contact field.
    ("location",
     _alt(_rest(r"\s*(?:set\s+(?:snmp\s+)?|snmp-server\s+"
                r"|snmp-agent\s+sys-info\s+)?location\s+"),
          r".*(?<![-\w])location=%VAL%"), "locations", None),
    ("contact",
     _alt(_rest(r"\s*(?:set\s+(?:snmp\s+)?|snmp-server\s+"
                r"|snmp-agent\s+sys-info\s+)?contact(?:-info)?\s+"),
          r".*(?<![-\w])contact=%VAL%"), "text", None),
    # the body of a JunOS `location { ... }` stanza: the keys carry the street
    # address the `location` rule itself must not eat (it is a stanza opener,
    # not a value). Stanza-scoped, so a `building` line elsewhere is untouched.
    ("junos-location-body",
     _alt(_rest(rf"\s*set\s+system\s+location\s+(?:{_JUNOS_LOCATION_KEYS})\s+"),
          _rest(rf"\s*(?:{_JUNOS_LOCATION_KEYS})\s+")),
     "locations", "location"),
    ("description", _rest(_DESCRIPTION), "text", None),
    ("acl-remark", _rest(r"\s*remark\s+"), "text", None),
    ("login-message",
     _rest(r"\s*(?:set\s+system\s+login\s+)?(?:message|announcement)\s+"), "text", None),

    # ---- what a port and a VLAN are called ---------------------------------
    # Both of these are only recognisable from the block they sit in, so both
    # are scoped: see _BLOCK_SCOPES. They are families of their own rather than
    # part of `text` because they are the two places a customer name reaches
    # material that has to survive -- a reviewer needs the ports to stay
    # distinguishable, a VLAN name is a value the config elsewhere refers to,
    # and a support case needs the descriptions the topology is written in.
    ("interface-description", _rest(_DESCRIPTION), "interfaces", "interfaces"),
    # `vlan 905` / `name CUST000000000123`, and the one-line Catalyst
    # vlan-database form `vlan 905 name CUST000000000123`. NOT an SVI: an
    # `interface Vlan905` block is scope `interfaces`, so its own description
    # belongs to the rule above and it has no `name` line at all.
    ("vlan-name", r"\s*(?:vlan\s+\d+\s+)?name\s+", "vlans", "vlans"),

    # ---- what a cross-connect and a pseudowire are called -------------------
    # Arista's `patch panel` and its `mpls ldp` -> `pseudowires` section. These
    # names are NOT free text, which is why they are `circuits` and not `text`:
    # the config refers to them BY NAME from more than one place, so the
    # substitution has to preserve the equality relation. `pseudo` is the
    # action to reach for -- a type-valid `circuit-f11e24` still loads, and two
    # mentions of one name still read as one name.
    #
    # `patch <name>` is scoped to the block it sits in, and that scope is the
    # whole reason the rule is harmless on another vendor's file: `patch` is an
    # ordinary word, but no grammar except Arista's opens a `patch panel` block
    # for a line to be inside. That is a gate on evidence in the file rather
    # than on a guess about the file -- which is also why there is no vendor
    # gate; see :data:`_RULE_VENDORS`.
    #
    # The `panel` lookahead is not redundant with the scope. An IOS-style block
    # header is inside its own block (see ``Sanitiser._enter``), so without it
    # the rule reads `panel` off the `patch panel` line as a patch name. The
    # leading `\s+` is the second guard: the header is at column zero and a
    # patch is always indented under it.
    ("patch-name", r"\s+patch\s+(?!panel(?![-\w]))", "circuits", "patch-panel"),
    # ONE rule, three values, and therefore ONE action -- which is the point of
    # writing it as two branches rather than two rules. The `connector` line
    # REFERENCES a pseudowire that the `mpls ldp` section DEFINES, and a file
    # with one of the pair substituted and the other kept does not load. Two
    # rules could be given two actions; two branches of one rule cannot.
    ("pseudowire-name",
     _alt(r"^\s*connector\s+\d+\s+pseudowire\s+ldp\s+%VAL%"
          r"(?:\s+alternate\s+%VAL%)?\s*$",
          # the definition, always nested under `pseudowires`. The leading
          # indent and NOT_BRACE are what keep this branch off a column-zero
          # `pseudowire` line in some other dialect. `pseudowires` itself
          # cannot match: `\s+` has to follow the keyword, and there an `s`
          # does.
          rf"^\s+pseudowire\s+{NOT_BRACE}%VAL%\s*$"),
     "circuits", None),
]

#: the start of a RouterOS key name: a word boundary that a hyphen does not
#: satisfy, then any hyphenated qualifiers in front of the keyword itself.
#:
#: RouterOS puts a qualifier there freely and means the same field by it --
#: ``ipsec-secret=``, ``authentication-password=``, ``wpa2-pre-shared-key=`` --
#: and the key still carries the credential whatever the prefix says. Written
#: once because getting it wrong is silent in the worst direction: the
#: ``(?<![-\w])`` guard on a bare ``secret=`` did not merely fail to help,
#: it actively REFUSED ``ipsec-secret=`` and left an L2TP/IPsec secret in the
#: output.
#:
#: It is deliberately NOT used in front of ``name=`` or ``comment=``, where the
#: guard exists precisely to reject the qualified form: ``default-name=ether1``
#: is a selector naming a factory default, not a name anyone chose, and
#: ``ipsec-secret`` is a secret while ``default-name`` is not a name. That
#: asymmetry is the whole reason this is a named constant rather than something
#: repeated per rule.
_ROS_KEY = r"(?<![-\w])(?:[a-z\d]+-)*"

#: RouterOS ``key=value`` rules: ``(name, pattern, family, scope)``, the same
#: shape as :data:`_BUILTIN`.
#:
#: These are SEARCHED rather than matched, and that is the difference that
#: matters. RouterOS spells every argument as a ``key=value`` pair on an ``add``
#: / ``set`` command, so one command carries many pairs -- and more than one of
#: them can belong to the same rule: a wireless security profile routinely sets
#: ``wpa-pre-shared-key=`` and ``wpa2-pre-shared-key=`` on one line. An ordinary
#: rule is matched once per line, so a greedy ``.*`` prefix took the LAST pair,
#: redacted it, and left the first passphrase standing next to a marker that
#: said the line had been dealt with. Searching finds every pair, which is what
#: the shape rules in :data:`_BLOB` have always done and for the same reason.
#:
#: The ``=`` is what keeps these off the space-form rules in :data:`_BUILTIN`
#: and those off these: ``bare-password`` wants ``password\s+``, so it never
#: sees ``password=``, and ``pre-shared-key`` wants ``pre-shared-key\s+``, so
#: the space form and the ``=`` form are claimed by exactly one owner each. The
#: ``(?<![-\w])`` guard in :data:`_ROS_KEY` is the other half of it: without it
#: ``default-name=`` would be read as a ``name=``, because a hyphen is a word
#: boundary.
_PAIRS: list[tuple[str, str, str, str | None]] = [
    ("routeros-password",
     rf'{_ROS_KEY}(?:password|passphrase)=%VAL%', "secrets", None),
    ("routeros-secret", rf'{_ROS_KEY}secret=%VAL%', "secrets", None),
    # `pre-?shared` because RouterOS uses both spellings of one field: wireless
    # writes `wpa2-pre-shared-key=` and WireGuard writes `preshared-key=`, with
    # no hyphen inside the word. Missing the second left a WireGuard peer's PSK
    # in the output.
    ("routeros-pre-shared-key",
     rf'{_ROS_KEY}pre-?shared-key=%VAL%', "secrets", None),
    # A WireGuard interface's own key. It is 44 characters of base64, so
    # `long-base64-left` reported it -- loudly, but a reported credential is
    # still a credential in the file, and only a rule can destroy it.
    ("routeros-private-key", rf'{_ROS_KEY}private-key=%VAL%', "secrets", None),
    # `/routing ospf interface-template auth-key=`, and the RIP and BGP forms of
    # the same field. Spelled out rather than reached with a generic `key=`,
    # because a generic one would ALSO claim `public-key=`, `private-key=` and
    # `pre-shared-key=` -- and `public-key=` is `identity`, so two rules with two
    # families would be fighting over one span. `auth=md5` and `auth-id=1` on the
    # same line are a method and an index, and the `-key` is what tells them
    # apart.
    ("routeros-auth-key",
     r'(?<![-\w])auth(?:entication)?-key=%VAL%', "secrets", None),
    # The other half of a WireGuard pair, and NOT a credential: a public key is
    # published on purpose. It is `identity` for exactly the reason
    # `ssh-public-key` is -- it ties the file to one real device or peer, and the
    # shape checks cannot tell an authorised key from a leaked one, so a kept one
    # has to be a rule they can be blinded to rather than an unexplained base64
    # run that fails `--strict`.
    ("routeros-public-key", rf'{_ROS_KEY}public-key=%VAL%', "identity", None),
    # A community string, and ONLY inside `/snmp community`. Everywhere else in
    # a RouterOS export `name=` is an interface, a firewall rule, a bridge or a
    # DHCP pool, and the line itself cannot tell you which -- the section is the
    # whole of the evidence. This is also the rule that made the searched path
    # learn about scope at all; see ``RuleCatalogue._line``.
    ("routeros-snmp-community", r'(?<![-\w])name=%VAL%', "secrets",
     "snmp-community"),
    # A LABEL `name=`: operator free text, and on a provider config a customer
    # and an order reference -- `name="Cust: 4G - Quantum - BPI000000562604"` on
    # a BGP connection. So it is split by scope the same way `description` and
    # `comment` are, and into the same two families: inside a RouterOS
    # `/interface …` section it is `routeros-peer-name` in `interfaces`,
    # everywhere else it is `routeros-object-name` in `text`. :data:`_OUTSIDE`
    # keeps them disjoint.
    #
    # Both are scoped to `object-labels` rather than to whole sections, and that
    # narrowness is the whole point: see :data:`_ROUTEROS_SCOPES` for why only
    # some sections open it. A `name=` the configuration REFERENCES cannot be
    # acted on by a rule that only sees the declaration.
    ("routeros-peer-name", r'(?<![-\w])name=%VAL%', "interfaces",
     "wireguard-peers"),
    ("routeros-object-name", r'(?<![-\w])name=%VAL%', "text", "object-labels"),
    # RouterOS's `description`, split by scope in exactly the same way and for
    # exactly the same reason: on an interface it is a port label a reviewer
    # needs, on a firewall rule or a DHCP lease it is ordinary free text. One
    # selector, two rules, made disjoint by :data:`_OUTSIDE`.
    ("comment", _COMMENT, "text", None),
    ("interface-comment", _COMMENT, "interfaces", "interfaces"),
]

#: rule -> the blocks it must not fire inside, because a scoped rule of its own
#: owns that material there. Each pair is exhaustive and disjoint by
#: construction: every description is matched by exactly one of
#: ``interface-description`` and ``description``, every RouterOS ``comment=`` by
#: exactly one of ``interface-comment`` and ``comment``.
_OUTSIDE: dict[str, tuple[str, ...]] = {
    "description": ("interfaces",),
    "comment": ("interfaces",),
    "routeros-object-name": ("interfaces",),
}

#: rule -> the dialect its grammar comes from. **ADVISORY ONLY.** Nothing in
#: ``sanitise.py`` reads this, and no rule is ever skipped because of it.
#:
#: THE PRINCIPLE, and the reason this is a label rather than a gate: a rule is
#: confined by evidence -- the shape of the line, and the block the line is
#: inside -- and never by a guess about the file it came from. Vendor detection
#: is a whole-file heuristic over exactly the material the ``platform`` family
#: exists to delete (see ``vendors.py``), and it answers ``unknown`` for the
#: input a redaction tool is most often handed: a pasted fragment with no
#: header on it. A rule that fired only when the detector agreed would skip
#: credential rules on a misread file, silently, and ``--strict`` would still
#: exit 0 -- a fail-open path in a tool whose whole promise is fail-safe. So
#: ``patch-name`` is kept off a JunOS file by requiring a ``patch panel`` block
#: to be inside, which that grammar cannot produce, and not by asking what
#: vendor the file is.
#:
#: What the table is for: grouping ``--list-rules`` and ``docs/rules.md``, and
#: naming the dialect a test fixture has to be written in. Only rules whose
#: vendor the pattern itself already asserts are listed. Absence is not a claim
#: of portability -- it means unlabelled.
_RULE_VENDORS: dict[str, str] = {
    "fortios-interface-alias": "fortinet",
    "fortios-secret": "fortinet",
    "fortios-snmp-community": "fortinet",
    "junos-community": "juniper",
    "junos-location-body": "juniper",
    "junos-password": "juniper",
    "junos-type9": "juniper",
    "patch-name": "arista",
    "pseudowire-name": "arista",
    "unsupported-transceiver": "arista",
    # RouterOS grammar: a `key=value` pair, or the `/export` header comment.
    # `comment` and `interface-comment` are here for the `=` in the pattern,
    # the same way `junos-community` is here for the JunOS `community X { … }`
    # shape -- not because either is skipped on another vendor's file.
    "comment": "mikrotik",
    "interface-comment": "mikrotik",
    "routeros-auth-key": "mikrotik",
    "routeros-object-name": "mikrotik",
    "routeros-password": "mikrotik",
    "routeros-peer-name": "mikrotik",
    "routeros-pre-shared-key": "mikrotik",
    "routeros-private-key": "mikrotik",
    "routeros-public-key": "mikrotik",
    "routeros-secret": "mikrotik",
    "routeros-snmp-community": "mikrotik",
    "routeros-license-id": "mikrotik",
    # FortiOS grammar: the `ENC` marker, the qualified credential key, and a
    # `set name` whose meaning only the `config` block it sits in supplies.
    "fortios-credential-key": "fortinet",
    "fortios-encrypted": "fortinet",
    "fortios-object-name": "fortinet",
    # Huawei MA5600T / MA5800 grammar: `ont add`, `terminal user name`,
    # `snmp-agent`, `service-port desc`, and the `%#%#` cipher delimiter.
    # Labels, as every entry here is -- each of these rules is held to the
    # dialect by the command keyword its pattern names, which is evidence in
    # the line and not a guess about the file.
    "huawei-cipher": "huawei",
    "huawei-ont-credential": "huawei",
    "huawei-ont-desc": "huawei",
    "huawei-ont-serial": "huawei",
    "huawei-profile-name": "huawei",
    "huawei-region-name": "huawei",
    "huawei-port-desc": "huawei",
    "huawei-rack-info": "huawei",
    "huawei-snmp-community": "huawei",
    "huawei-snmp-engineid": "huawei",
    "huawei-snmp-usm": "huawei",
    "huawei-terminal-user": "huawei",
    "huawei-traffic-table-name": "huawei",
}

#: rules whose value needs a code path rather than a plain span replacement
_HANDLERS = {"snmp-host": "snmp-host"}

_COMPILED: dict[str, tuple[re.Pattern, tuple[int, ...]]] = {
    name: _compile(pattern) for name, pattern, _family, _stanza in _BUILTIN
}

#: the banner rule: name and family here, delimiter state machine in sanitise
_BANNER_RE = re.compile(r"^\s*banner\s+([\w-]+)\s+(.*)$", re.I)
_BANNER_RULE = ("banner", "text")


# ---------------------------------------------------------------------------
# secret-shaped material, wherever it appears in a line
# ---------------------------------------------------------------------------

#: (name, pattern, family, flags) -- searched anywhere in the line, so the
#: context stays *outside* the groups instead of being rebuilt by a template.
_BLOB: list[tuple[str, str, str, int]] = [
    ("junos-type9", r'(\$9\$[^\s";]+)', "secrets", 0),
    # Huawei's cipher, which is SELF-DELIMITING and therefore recognisable
    # with no keyword in front of it at all: `%#%#` opens the blob and `%#%#`
    # closes it, and nothing else in any dialect writes that sequence. That is
    # what makes it a shape rule rather than a keyword one -- the same
    # argument `junos-type9` makes for `$9$`.
    #
    # It earns its place by reaching the blobs a keyword cannot. A Huawei
    # capture wraps mid-value, and where the wrap defeats the joiner the tail
    # of an ONT password arrives as a line of its own with no `password-auth`
    # anywhere on it; searched rather than matched, this finds the fragment
    # where it lies. `[^\s"]` for the payload, because the payload's own
    # punctuation includes bare quotes -- see `huawei-ont-credential` -- but
    # never whitespace, so a blob cannot run past the token it is in.
    ("huawei-cipher", r'(%#%#[^\s]*?%#%#)', "secrets", 0),
    ("crypt-hash", r'(\$(?:1|2[abxy]?|5|6|y)\$[^\s";]+)', "secrets", 0),
    # two shapes, because the algorithm token is not always glued to the blob:
    # IOS `key-hash ssh-rsa <fingerprint> <blob>` puts the fingerprint between
    # them, so the second branch recognises the blob by its own header instead.
    ("ssh-public-key",
     _alt(r'(?:\b(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-[\w-]+)\s+'
          r'|\bssh-known-hosts\s+host\s+\S+\s+(?:rsa|dsa|ecdsa|ed25519)-key\s+)'
          r'("?AAAA[0-9A-Za-z+/=]+"?)',
          rf'("?{SSH_KEY_SIG}[0-9A-Za-z+/=]*"?)'),
     "identity", 0),
    # atomic header: the optional colon must not be handed back as the value,
    # so a bare `! License UDI:` heading with no data on it never matches
    ("license-udi", r"^\s*!?\s*(?>License\s+UDI:?\s*)(.+)$", "identity", re.I),
    # `[!#]?` for the same reason as `hardware-model`: RouterOS's `/export`
    # header writes `# serial number = HEA08XXXXXX`, and one serial rule with
    # one action has to reach it too.
    # `(?:set\s+)?` is FortiOS, which writes `set serial-number "FGT60FTK…"`
    # under `config system central-management` and on an HA peer. Adjacent, for
    # the reason `bare-password` is: FortiOS puts nothing between `set` and the
    # key it is setting.
    ("serial-number",
     r"^\s*[!#]?\s*(?:set\s+)?(?:System\s+)?[Ss]erial[-\s]*(?:[Nn]umber)?"
     r"\s*[:=]?\s+(\S+.*)$",
     "identity", 0),
]

def _blob_rules() -> list[_Rule]:
    out = []
    for name, pattern, family, flags in _BLOB:
        regex, targets = _compile(pattern, flags)
        out.append(_Rule(name=name, regex=regex, family=family, targets=targets,
                        vendor=_RULE_VENDORS.get(name)))
    return out


def _pair_rules() -> list[_Rule]:
    """Compile :data:`_PAIRS`, which unlike :data:`_BLOB` carry scope.

    A ``key=value`` rule is a keyword rule that happens to need searching, so it
    keeps everything a keyword rule has -- the block it must be inside, the
    blocks it must stay out of -- and only the traversal differs.
    """
    out = []
    for name, pattern, family, stanza in _PAIRS:
        regex, targets = _compile(pattern)
        out.append(_Rule(name=name, regex=regex, family=family, targets=targets,
                         stanza=stanza, outside=_OUTSIDE.get(name, ()),
                         vendor=_RULE_VENDORS.get(name)))
    return out


#: everything the catalogue *searches* rather than matches. The pair rules come
#: FIRST: a `password=$9$…` is a credential before it is a JunOS blob, and that
#: is the order the two had when one of them was an ordinary rule.
_SEARCHED_RULES: list[_Rule] = _pair_rules() + _blob_rules()

#: opaque multi-line blocks: (start, end, name, family). The body is the target.
_BLOCK_STARTS = (
    (re.compile(r"^\s*certificate\s+(?:self-signed|ca)?\s*\S*\s*(?:nvram:\S+)?\s*$", re.I),
     re.compile(r"^\s*quit\s*$", re.I), "certificate-block", "identity"),
    (re.compile(r"^\s*key-string\s*$", re.I),
     re.compile(r"^\s*quit\s*$", re.I), "key-string-block", "secrets"),
    # pem-block split: private keys and DH parameters are secrets, a
    # certificate is public material that only identifies the device
    (re.compile(r"-----BEGIN [A-Z0-9 ]*(?:KEY|PARAMETERS)-----"),
     re.compile(r"-----END [A-Z0-9 ]*(?:KEY|PARAMETERS)-----"), "pem-key", "secrets"),
    (re.compile(r"-----BEGIN [A-Z0-9 ]*CERTIFICATE-----"),
     re.compile(r"-----END [A-Z0-9 ]*CERTIFICATE-----"), "pem-cert", "identity"),
)

#: retained for docs and callers that want the three description-ish rules by
#: name; they are ordinary ``text`` rules and go through the normal path.
DESCRIPTION_RULES = [
    (name, _COMPILED[name][0])
    for name in ("description", "acl-remark", "login-message")
]

def _build_rules(custom=()) -> list[_Rule]:
    """Compile the keyword rule set.

    ``custom`` is a list of ``CustomRule`` appended after the built-ins. There
    is no ``disable`` argument: ``keep`` is an action, so a rule the policy
    keeps still matches and still gets counted.
    """
    rules = [
        _Rule(name=name, regex=_COMPILED[name][0], family=family,
             targets=_COMPILED[name][1], stanza=stanza,
             outside=_OUTSIDE.get(name, ()), handler=_HANDLERS.get(name),
             vendor=_RULE_VENDORS.get(name))
        for name, _pattern, family, stanza in _BUILTIN
    ]
    for c in custom:
        try:
            regex, targets = _compile(c.pattern)
        except (re.error, OverflowError) as exc:
            raise ValueError(f"custom rule {c.name!r}: bad regex: {exc}") from exc
        rules.append(_Rule(name=c.name, regex=regex,
                          family=getattr(c, "family", "secrets") or "secrets",
                          targets=targets, stanza=getattr(c, "stanza", None),
                          custom=True))
    return rules


@dataclass(frozen=True)
class RuleCatalogue:
    """All rule forms behind one immutable execution and reporting interface."""

    _ordinary: tuple[_Rule, ...]
    _searched: tuple[_Rule, ...]
    _blocks: tuple[tuple[re.Pattern, re.Pattern, str, str], ...]

    @classmethod
    def builtins(cls) -> RuleCatalogue:
        return cls(tuple(_build_rules()), tuple(_SEARCHED_RULES),
                   tuple(_BLOCK_STARTS))

    def configured(self, custom=()) -> RuleCatalogue:
        """Return a catalogue with custom rules appended to ordinary rules."""
        custom = tuple(custom)
        if not custom:
            return self
        existing = {r.name for r in self._ordinary + self._searched}
        existing.update(name for _start, _end, name, _family in self._blocks)
        existing.add(_BANNER_RULE[0])
        seen: set[str] = set()
        for item in custom:
            if item.name in existing or item.name in seen:
                raise ValueError(f"custom rule {item.name!r}: duplicate rule name")
            seen.add(item.name)
        compiled = tuple(_build_rules(custom)[-len(custom):])
        return type(self)(self._ordinary + compiled, self._searched, self._blocks)

    def inventory(self) -> tuple[RuleInfo, ...]:
        """Every rule in report order, without executable representations."""
        # `_PAIRS` is included so the generated docs print the pattern as it is
        # written, `%VAL%` and all, rather than the expanded capturing group
        source_patterns = {name: pattern for name, pattern, _family, _scope
                           in _BUILTIN + _PAIRS}
        ordinary = tuple(
            RuleInfo(r.name, r.family, r.vendor, r.custom, r.stanza, r.outside,
                     source_patterns.get(r.name, r.regex.pattern))
            for r in self._ordinary if not r.custom
        )
        custom = tuple(
            RuleInfo(r.name, r.family, r.vendor, True, r.stanza, r.outside,
                     r.regex.pattern)
            for r in self._ordinary if r.custom
        )
        banner = (RuleInfo(_BANNER_RULE[0], _BANNER_RULE[1], None, False, None,
                           (), _BANNER_RE.pattern),)
        searched = tuple(
            RuleInfo(r.name, r.family, r.vendor, r.custom, r.stanza, r.outside,
                     source_patterns.get(r.name, r.regex.pattern))
            for r in self._searched
        )
        blocks = tuple(
            RuleInfo(name, family, _RULE_VENDORS.get(name), False, None, (),
                     start.pattern, end.pattern)
            for start, end, name, family in self._blocks
        )
        return ordinary + banner + searched + blocks + custom

    @staticmethod
    def _decision(value: RuleReplacement) -> RuleReplacement:
        if not isinstance(value, RuleReplacement):
            raise TypeError("rule replacement callback must return RuleReplacement")
        return value

    @staticmethod
    def _spans(rule: _Rule, match: re.Match) -> list[tuple[int, int, str]]:
        spans: list[tuple[int, int, str]] = []
        for index in rule.targets:
            start, end = match.span(index)
            value = match.group(index)
            if start < 0 or not value or not value.strip():
                continue
            if spans and start < spans[-1][1]:
                continue
            spans.append((start, end, value))
        return spans

    @staticmethod
    def _scope(rule: _Rule, inside: tuple[str, ...]) -> bool:
        return (not rule.stanza or rule.stanza in inside) and not any(
            scope in inside for scope in rule.outside)

    def _splice(self, rule: _Rule, match: re.Match, text: str,
                replace: Callable[[RuleHit], RuleReplacement]) -> str:
        for start, end, selected in reversed(self._spans(rule, match)):
            quote = (selected[0] if len(selected) > 1
                     and selected[0] == selected[-1]
                     and selected[0] in "\"'" else "")
            value = selected[1:-1] if quote else selected
            if rule.handler == "snmp-host":
                tokens, out, index = value.split(), [], 0
                while index < len(tokens):
                    token = tokens[index]
                    if token.lower() in SNMP_HOST_KEYWORDS:
                        out.append(token)
                        index += 1
                        continue
                    decision = self._decision(replace(
                        RuleHit(rule.name, rule.family, token)))
                    out.append(token if decision.text is None else decision.text)
                    out.extend(tokens[index + 1:])
                    break
                replacement = " ".join(out)
            else:
                decision = self._decision(replace(
                    RuleHit(rule.name, rule.family, value)))
                if decision.text is None:
                    continue
                replacement = decision.text
            if quote:
                replacement = f"{quote}{replacement}{quote}"
            text = f"{text[:start]}{replacement}{text[end:]}"
        return text

    def _line(self, text: str, inside: tuple[str, ...],
              replace: Callable[[RuleHit], RuleReplacement]) -> str:
        for rule in self._ordinary:
            if not self._scope(rule, inside):
                continue
            match = rule.regex.match(text)
            if match:
                text = self._splice(rule, match, text, replace)
        # Scope reached this path with `routeros-snmp-community`: a RouterOS
        # `name=` is a community string under `/snmp community` and an object
        # name everywhere else, so a searched rule needs the block it is inside
        # exactly as a matched one does. The shape rules in `_BLOB` name no
        # scope, so this was inert until then.
        for rule in self._searched:
            if not self._scope(rule, inside):
                continue
            for match in reversed(list(rule.regex.finditer(text))):
                text = self._splice(rule, match, text, replace)
        return text

    def transform(self, lines: Iterable[str], *,
                  replace: Callable[[RuleHit], RuleReplacement],
                  finish_line: Callable[[str], str] = lambda line: line,
                  ) -> list[str]:
        """Transform rules in their canonical order, including scoped state."""
        source = join_continuations(line.rstrip("\n") for line in lines)
        out: list[str] = []
        stanza: list[str] = []
        forti = FortiBlocks()
        ios_block: str | None = None
        ros_section: tuple[str, ...] = ()
        index = 0
        while index < len(source):
            raw = source[index]
            if raw.strip() and not raw[:1].isspace():
                ios_block = next((name for name, pat in _BLOCK_SCOPES
                                  if pat.match(raw)), None)
            # the section line is inside the section it opens, exactly as an
            # IOS-style block header is inside its own block -- and it has to
            # be, or a `/export terse` line would never be inside anything
            ros_section = routeros_scope(raw, ros_section)
            set_match = _SET_SCOPE.match(raw)
            if re.match(r"\s*set\s+system\s+location\b", raw, re.I):
                line_scope = ("location",)
            else:
                line_scope = (set_match.group(1).lower(),) if set_match else ()
            inside = (tuple(stanza) + ((ios_block,) if ios_block else ())
                      + ros_section + forti.scopes() + line_scope)

            block = next(((start, end, name, family)
                          for start, end, name, family in self._blocks
                          if start.search(raw)), None)
            if block:
                _start, end, name, family = block
                out.append(raw)
                body: list[str] = []
                index += 1
                while index < len(source) and not end.search(source[index]):
                    body.append(source[index])
                    index += 1
                value = "\n".join(body).strip()
                decision = self._decision(replace(RuleHit(name, family, value))) \
                    if value else RuleReplacement.unchanged()
                if decision.text is None:
                    out.extend(body)
                else:
                    indent = next((line[:len(line) - len(line.lstrip())]
                                   for line in body if line.strip()), "")
                    out.append(f"{indent or '  '}{decision.text}")
                if index < len(source):
                    out.append(source[index])
                index += 1
                continue

            banner = _BANNER_RE.match(raw)
            if banner:
                kind, rest = banner.group(1), banner.group(2)
                stripped = rest.strip()
                if stripped:
                    if len(stripped) <= 2 and not stripped[0].isalnum():
                        delim, body, close = stripped, [], None
                        cursor = index + 1
                        while cursor < len(source):
                            if delim in source[cursor]:
                                close = cursor
                                break
                            body.append(source[cursor])
                            cursor += 1
                        value = "\n".join(body).strip()
                        decision = self._decision(replace(
                            RuleHit(_BANNER_RULE[0], _BANNER_RULE[1], value)))
                        if decision.active:
                            out.append(f"banner {kind} {delim}")
                            out.extend(body if decision.text is None else [decision.text])
                            if close is not None:
                                out.append(delim)
                            index = (close + 1) if close is not None else len(source)
                            continue
                    else:
                        delim = stripped[0]
                        closing = stripped.find(delim, 1)
                        if closing >= 0:
                            body = stripped[1:closing]
                            decision = self._decision(replace(
                                RuleHit(_BANNER_RULE[0], _BANNER_RULE[1], body)))
                            if decision.active:
                                out.append(raw if decision.text is None else
                                           f"banner {kind} {delim}{decision.text}{delim}")
                                index += 1
                                continue
            out.append(finish_line(self._line(raw, inside, replace)))
            # Fed here rather than at the top of the loop, alongside the JunOS
            # stanza stack and for the same reason: a banner body is consumed
            # by the branch above and never reaches this point, so a `config
            # system global` inside a banner cannot open a block.
            forti.feed(raw)
            stanza_match = _STANZA_OPEN.match(raw)
            if stanza_match:
                stanza.append(stanza_match.group(1).lower())
            elif _STANZA_CLOSE.match(raw) and stanza:
                stanza.pop()
            index += 1
        return out

    def verification_view(self, lines: Iterable[str], *,
                          blind: Callable[[RuleInfo], bool]) -> list[str]:
        """Return line-aligned text with selected rule values blanked out.

        ``transform`` may emit fewer lines than it was given -- a collapsed
        block body, a banner, a joined RouterOS wrap -- and this view has to
        stay line-for-line with its own input, because ``verify`` zips the two
        together. So each of those is neutralised before ``transform`` sees it:
        a multi-line body is masked line by line below, and a wrap is already
        undone, since the caller normalises with :func:`join_continuations`
        first and joining twice is joining once.
        """
        selected = {info.name for info in self.inventory() if blind(info)}

        def mask(hit: RuleHit) -> RuleReplacement:
            if hit.name not in selected:
                return RuleReplacement.keep()
            if not hit.value:
                return RuleReplacement.unchanged()
            return RuleReplacement.with_text(" " * len(hit.value))

        # _Rule values retain their length. Multi-line bodies are exceptional:
        # transform can collapse an active body, so mask them line by line.
        source = [line.rstrip("\n") for line in lines]
        masked = list(source)
        block_names = {name for _s, _e, name, _f in self._blocks} & selected
        for start, end, name, _family in self._blocks:
            if name not in block_names:
                continue
            active = False
            for index, line in enumerate(source):
                if not active and start.search(line):
                    active = True
                elif active and end.search(line):
                    active = False
                elif active:
                    masked[index] = " " * len(line)
        if _BANNER_RULE[0] in selected:
            delim: str | None = None
            for index, line in enumerate(source):
                if delim is not None:
                    if delim in line:
                        delim = None
                    else:
                        masked[index] = " " * len(line)
                    continue
                match = _BANNER_RE.match(line)
                if not match:
                    continue
                stripped = match.group(2).strip()
                if (stripped and len(stripped) <= 2
                        and not stripped[0].isalnum()):
                    delim = stripped
        return self.transform(masked, replace=mask)


# ---------------------------------------------------------------------------
# identity sources
# ---------------------------------------------------------------------------

HOSTNAME_PATS = (
    # the optional `set` is FortiOS's `set hostname "FGT-EDGE-01"`; the quotes
    # come off in the collect pass, which strips them from every name source
    # `sysname` is Huawei's and H3C's spelling of the same command. A third
    # alternative here rather than a pattern of its own, so one collector
    # learns the device's name whichever dialect states it.
    re.compile(r"^\s*(?:set\s+)?(?:hostname|switchname|sysname)\s+(\S+)", re.I),
    re.compile(r"^\s*(?:set\s+system\s+)?host-name\s+(\S+?);?\s*$", re.I),
    re.compile(r"^\s*!\s*device:\s*(\S+)", re.I),
)
DOMAIN_PATS = (
    re.compile(r"^\s*ip\s+domain[-\s]name\s+(?:vrf\s+\S+\s+)?(\S+)", re.I),
    re.compile(r"^\s*(?:set\s+system\s+)?domain-name\s+(\S+?);?\s*$", re.I),
    re.compile(r"^\s*dns\s+domain\s+(\S+)", re.I),
    re.compile(r"^\s*(?:set\s+system\s+)?domain-search\s+\[?\s*([^\];]+)", re.I),
)
USERNAME_PATS = (
    re.compile(r"^\s*username\s+(\S+)", re.I),
    re.compile(r"^\s*set\s+system\s+login\s+user\s+(\S+)", re.I),
    re.compile(r"^\s*user\s+(\S+)\s*\{", re.I),
    re.compile(r"^\s*snmp-server\s+user\s+(\S+)", re.I),
    re.compile(r"^\s*!\s*Last configuration change.*?\bby\s+(\S+)", re.I),
    re.compile(r"^\s*##\s*Last changed:.*?\bby\s+(\S+)", re.I),
    # FortiOS names the administrator who saved the file in its own header,
    # `#config-version=…:vdom=0:user=fgtadmin`. The `platform` rules act on the
    # model and the release earlier on that line and leave this untouched,
    # which is the split the two families are for.
    re.compile(r"^#config-version=.*[:\s]user=(\S+)", re.I),
    # Huawei's local user table, `terminal user name <flag> <user> *<cipher>*
    # ...`. The account name is the SECOND token after `name`, not the first:
    # the device writes a flag of its own there -- `buildrun_new_password`,
    # `history_password` -- and reading that as the account would have
    # substituted a device keyword everywhere and missed every real login.
    # Anchoring on the flag's shape is what tells the two apart, and a flag
    # spelled some other way means this collector declines the line rather
    # than guessing at which token is the name.
    re.compile(r"^\s*terminal\s+user\s+name\s+[\w-]*password\s+(\S+)", re.I),
    # and the same accounts again where the SSH server lists them
    re.compile(r"^\s*ssh\s+user\s+(\S+)", re.I),
)

#: identity declarations that only the enclosing block makes recognisable:
#: ``(scope, pattern, family)``, matched by the collect pass against a line
#: inside that block. FortiOS is why this exists. Its grammar names an entry
#: with ``edit "<id>"`` whatever the entry is, so the same line is an account
#: name under ``config system admin`` and an interface name under ``config
#: system interface`` -- the pattern cannot tell, and only the block can.
#:
#: These go to the collect pass rather than to a rule because a name is
#: referenced elsewhere in the file: an admin's name is in the header, a local
#: user's is in a group. Collecting it substitutes every mention with the one
#: pseudonym, which a per-line rule cannot do.
_FORTI_EDIT = re.compile(r'^\s*edit\s+"([^"]+)"\s*$', re.I)
SCOPED_NAME_PATS = (
    ("system-admin", _FORTI_EDIT, "usernames"),
    ("system-api-user", _FORTI_EDIT, "usernames"),
    ("user-local", _FORTI_EDIT, "usernames"),
    ("snmp-user", _FORTI_EDIT, "usernames"),
    # FortiOS's `config system global` alias is a second name for the device
    # itself, and usually the site it stands in. An alias inside `config system
    # interface` is a port label instead, and belongs to the `interfaces`
    # family -- see `fortios-interface-alias`.
    ("system-global", re.compile(r"^\s*set\s+alias\s+(\S+)", re.I), "hostnames"),
)

#: A name only the enclosing section identifies, and the sections that identify
#: it: ``(scopes, pattern)``, read by the collect pass the same way the flat
#: tables above are. RouterOS spells all four of these ``name=`` -- the device's
#: own name, a login, a PPPoE subscriber's account and an interface -- so the
#: line carries no evidence at all and the section carries all of it. That is
#: the collect-pass half of what :data:`_ROUTEROS_SCOPES` does for the rules,
#: and it is a table rather than an extra pattern for the same reason a scoped
#: rule is a scoped rule: an unscoped ``name=`` would substitute every interface
#: name in the file as if it were the hostname.
SCOPED_HOSTNAME_PATS = (
    (("system-identity",), re.compile(r'(?<![-\w])name=("[^"]*"|\S+)', re.I)),
)
#: a PPPoE / L2TP account name is a customer's login, so ``/ppp secret`` names
#: are usernames and not hostnames
SCOPED_USERNAME_PATS = (
    (("user", "ppp-secret"),
     re.compile(r'(?<![-\w])name=("[^"]*"|\S+)', re.I)),
)

IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")
IPV6_RE = re.compile(
    r"(?<![\w:.])("
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)"
    r")(?![\w:.])"
)
MAC_RE = re.compile(
    r"(?<![\w.:-])("
    r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}"
    r"|[0-9A-Fa-f]{4}(?:-[0-9A-Fa-f]{4}){2}"
    r"|(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
    r"|(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}"
    r")(?![\w.:-])"
)
BARE_MAC_CONTEXT_RE = re.compile(
    r"(?P<prefix>\b(?:mac-address|mac\s+address|hardware-address)\s+)"
    r"(?P<value>[0-9A-Fa-f]{12})(?![0-9A-Fa-f])", re.I)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")

_STANZA_OPEN = re.compile(r"^\s*([\w-]+)[^{}]*\{\s*$")
_STANZA_CLOSE = re.compile(r"^\s*\}\s*$")

#: IOS / EOS / NX-OS block headers, and the scope each opens: ``(scope, regex)``.
#: A block is a line at column zero plus the indented lines under it, so these
#: are matched against unindented lines only and any other unindented line ends
#: the block -- including the bare ``!`` Cisco and Arista separate them with.
#:
#: The names are JunOS's own stanza names, deliberately: a rule then says
#: ``interfaces`` once and reaches an IOS ``interface Gi0/0`` block, a JunOS
#: ``interfaces { … }`` stanza and a ``set interfaces …`` line alike.
#:
#: ``vlan`` needs a digit after it, which is the whole safety margin: it makes
#: ``vlan 905`` and ``vlan 300,301`` blocks while leaving the commands that
#: merely start with the word -- ``vlan internal allocation policy ascending``,
#: ``vlan configuration 905`` -- outside any scope. ``interface Vlan905`` is
#: scope ``interfaces``: an SVI is a port, not a VLAN definition.
_BLOCK_SCOPES = (
    ("interfaces", re.compile(r"^interface\s+\S", re.I)),
    ("vlans", re.compile(r"^vlan\s+(?:\d|database\b)", re.I)),
    # Arista's L2 cross-connects. This is the one scope whose name is not
    # JunOS's, because JunOS has no equivalent block to share it with. It is
    # what makes `patch-name` inert on every other dialect: a rule that has to
    # be inside a `patch panel` block cannot fire on a grammar that has none.
    # Note that the header is inside its own block, so `patch-name` still needs
    # its own `panel` lookahead.
    ("patch-panel", re.compile(r"^patch\s+panel\b", re.I)),
)

#: a JunOS ``set`` line, whose scope is the word after ``set`` and lasts for
#: that line only -- ``set interfaces xe-0/0/0 description …`` is inside
#: ``interfaces`` without any enclosing block to be inside of.
_SET_SCOPE = re.compile(r"\s*set\s+([\w-]+)\b", re.I)

#: a RouterOS ``/export`` section path: a ``/``-prefixed word path at column
#: zero. ``/export`` writes the path on a line of its own and the ``add`` /
#: ``set`` commands under it; ``/export terse`` repeats the whole path on every
#: command line instead. Both forms answer the same question, so both go through
#: this one recogniser -- the terse form being the RouterOS analogue of
#: :data:`_SET_SCOPE`, a scope carried on the line rather than by a block.
#:
#: Column zero and the word-path shape are the guard. A base64 body line can
#: begin with ``/``, and it must not be able to open a section: it has no space
#: in it, so its whole run has to spell a section path exactly before any scope
#: below will match it.
_ROUTEROS_SECTION = re.compile(r"^/([a-z][\w-]*(?:\s+[a-z][\w-]*)*)")

#: a RouterOS section path -> the scopes it opens, longest path first, because
#: ``/snmp community`` is not ``/snmp``.
#:
#: The naming follows the rule set out above :data:`_BLOCK_SCOPES`: where both
#: dialects have the block the name is JunOS's own, so ONE rule reaches every
#: dialect -- a ``/interface ethernet`` section is scope ``interfaces`` exactly
#: as an ``interface Gi0/0`` block and an ``interfaces { … }`` stanza are. A
#: section only RouterOS has keeps its own name.
#:
#: A section opens SEVERAL scopes where the paths nest, because that is what the
#: path says: ``/interface wireguard peers`` is inside ``/interface``, so a
#: peer's ``comment=`` is an interface comment while its ``name=`` is a rule of
#: its own. Listing the general scope alongside the specific one is what lets
#: the two coexist instead of the longest match hiding the shorter.
#:
#: Those own-name sections are not decoration. ``name=`` is a community string
#: under ``/snmp community``, a login under ``/user`` and ``/ppp secret``, the
#: device's own name under ``/system identity``, a free-text label under
#: ``/interface wireguard peers`` and ``/routing bgp connection``, and a
#: referenced object name everywhere else. The line is identical in all of them,
#: so the section is the only evidence there is -- which is exactly the argument
#: for scope in the first place, and exactly why none of this is a vendor gate:
#: a file with no ``/user`` section in it cannot reach the rules and the
#: collectors that need one.
#:
#: ``object-labels`` is the one scope named for a PROPERTY rather than a block,
#: and it earns that: it marks the sections whose ``name=`` is a label nothing
#: else refers to. That distinction cannot be read off the line, off the key, or
#: even off the value -- only off which section it is in, and it is the
#: difference between a rule that is safe and one that breaks the file. An
#: interface, a bridge, a BGP template, an OSPF area or an address list is
#: named so that another line can point at it (``interface=ether1-transit``,
#: ``area=backbone-v2``): acting on such a declaration alone would break the
#: configuration AND leak the value through every reference that kept it. A
#: WireGuard peer and a BGP connection are pointed at by nothing.
#:
#: So this list is deliberately short, and it is the guard rather than a
#: convenience. Adding a section to it is a claim that nothing in the grammar
#: references that section's ``name=`` -- and the way to cover one that IS
#: referenced is to carry the references in the same rule, as
#: ``pseudowire-name`` does, not to add it here.
_ROUTEROS_SCOPES = (
    (("wireguard-peers", "object-labels", "interfaces"),
     re.compile(r"interface\s+wireguard\s+peers(?![\w-])", re.I)),
    (("bgp-connections", "object-labels"),
     re.compile(r"routing\s+bgp\s+connection(?![\w-])", re.I)),
    # `chain=` names a routing-filter chain here and a FIREWALL chain under
    # `/ip firewall …`, where `input`, `forward` and `srcnat` are RouterOS's own
    # names and substituting one breaks the file. Read by `OperationalNames`.
    (("routing-filter-rules",),
     re.compile(r"routing\s+filter\s+rule(?![\w-])", re.I)),
    (("snmp-community", "snmp"),
     re.compile(r"snmp\s+community(?![\w-])", re.I)),
    (("system-identity",), re.compile(r"system\s+identity(?![\w-])", re.I)),
    (("ppp-secret",), re.compile(r"ppp\s+secret(?![\w-])", re.I)),
    (("interfaces",), re.compile(r"interface(?![\w-])", re.I)),
    (("snmp",), re.compile(r"snmp(?![\w-])", re.I)),
    (("user",), re.compile(r"user(?![\w-])", re.I)),
)


def routeros_scope(line: str, current: tuple[str, ...]) -> tuple[str, ...]:
    """The RouterOS section scopes in force after ``line``.

    A ``/``-prefixed line always REPLACES the section, even when its path is one
    no scope names: an ``/ip address`` header has to end the ``/user`` section,
    or the next ``name=`` would still be read as a login. Any other line leaves
    the section as it found it.
    """
    match = _ROUTEROS_SECTION.match(line)
    if not match:
        return current
    path = match.group(1)
    return next((scopes for scopes, pat in _ROUTEROS_SCOPES if pat.match(path)),
                ())


#: the opening line of a wrapped RouterOS command: an ``add`` / ``set`` /
#: ``remove`` at column zero -- optionally behind a ``/export terse`` path --
#: whose last character is a backslash.
#:
#: That command word is the whole of the evidence, and it is needed. A trailing
#: backslash is not line-continuation syntax in IOS or JunOS, but it is
#: perfectly ordinary in an ASCII-art banner body, and joining those would
#: mangle a banner. So a line has to be spelled like a RouterOS command before
#: its backslash is read as one, which is evidence in the file rather than a
#: guess about the file -- the same standard scope is held to.
_ROUTEROS_WRAPPED = re.compile(
    r"^(?:/[a-z][\w-]*(?:\s+[a-z][\w-]*)*\s+)?(?:add|set|remove)\s+\S.*\\$",
    re.I)


#: the opening line of a Huawei command whose quoted value a capture split.
#:
#: ``display current-configuration`` wraps its output at the width of the
#: session that collected it, and the wrap is INVISIBLE: there is no
#: continuation character, the break can fall anywhere -- between tokens,
#: inside a token, inside a credential -- and the remainder arrives at column
#: zero on the next physical line. Most of those breaks fall on a space and
#: cost nothing (``cbs 640000 pir `` / ``43008 pbs 2713600``: two halves of a
#: rate, neither of them sensitive). The ones that matter fall inside a quoted
#: value, and there they are the half-redacted line this project treats as
#: worse than a plain miss -- a customer name, or the tail of an ONT password,
#: carried past every rule that could recognise it.
#:
#: So the evidence is assembled from three things at once, and each one is
#: load-bearing:
#:
#: * the line is spelled like one of the Huawei commands that carries a quoted
#:   value. That is the standard :data:`_ROUTEROS_WRAPPED` is held to and it is
#:   needed for the same reason: an unbalanced quote is perfectly ordinary in
#:   an ASCII-art banner body, and joining one would mangle a banner.
#: * the line is still UNFINISHED at its end -- see
#:   :func:`_huawei_unfinished`. A line that finished was never wrapped.
#: * the next line is at column zero while this one is indented. Every command
#:   inside a ``[...-config]`` section is indented and no wrap remainder is,
#:   which is what stops a COMPLETE command from swallowing the one after it:
#:   ``terminal user name history_password root *J$1a$...v616"0f!'...$*$*``
#:   carries a lone quote inside its cipher blob, and nothing else about it
#:   says it is unfinished.
_HUAWEI_WRAPPED = re.compile(
    r"^\s+(?:ont(?:-(?:line|srv)profile)?|terminal|service-port|traffic"
    r"|dba-profile|vlan)\s", re.I)

#: a line of Huawei's own structure rather than a wrap remainder: a
#: ``[section]`` marker, the ``<sub-section>`` under it, the ``#`` that
#: separates two, a RANCID comment, and the ``return`` that ends the file.
_HUAWEI_STRUCTURE = re.compile(r"[\[#!<]|return\s*$")


def _quote_open(text: str) -> bool:
    """Is ``text`` still inside a double-quoted Huawei value at its end?

    Quotes are counted rather than matched, because that is all the grammar
    offers -- and the doubled pair is why this cannot be ``count('"') % 2``.
    Inside a value ``""`` is one escaped quote and closes nothing
    (:data:`HUAWEI_QUOTED` reads it the same way); outside one it is an empty
    value that opens and closes. Reading a trailing ``"A""`` as an escape
    therefore errs towards "still open", which is the direction that joins a
    line instead of abandoning half a credential on it.
    """
    inside = False
    index = 0
    while index < len(text):
        if text[index] != '"':
            index += 1
            continue
        if inside and text[index:index + 2] == '""':
            index += 2
            continue
        inside = not inside
        index += 1
    return inside


#: an ``ont add`` / ``ont confirm`` that has stated a credential, and the
#: profile id such a command cannot end without. Between them they are the
#: second way of seeing that a line was wrapped, and the ONLY way of seeing it
#: where the credential is a ``%#%#`` blob.
#:
#: Quote counting is not enough there, and the reason is the blob: its payload
#: carries bare quotes (see ``huawei-ont-credential``), so a wrap that falls
#: inside one lands on a line whose quotes happen to BALANCE. Twelve ONT
#: passwords on one real capture were left half-destroyed that way -- the
#: opening fragment redacted by the rule's fallback branch, the tail sitting on
#: the next line with `huawei-cipher-left` reporting it and nothing able to act
#: on it.
#:
#: The grammar has no such ambiguity. `ont add` names both the line profile
#: and the SERVICE profile it provisions against, always and in that order, so
#: a line that has reached `password-auth` and not `ont-srvprofile-id` is
#: unfinished whatever its quotes say.
#:
#: It has to be the second of the two. Stopping at `ont-lineprofile-id` joined
#: the credential back together and then left a THIRD fragment --
#: `ont-srvprofile-id 110 desc "Northwind Retail Group, 100M"` -- standing on
#: its own, where no rule can see it: `huawei-ont-desc` needs the `ont add`
#: that is now two lines above it, so twenty-five customer names survived a
#: run that destroyed every credential in the file.
#:
#: `ont modify` is deliberately absent: it has short forms that legitimately
#: end before either profile, and a command that may end early is no evidence
#: at all.
_HUAWEI_ONT_AUTH = re.compile(
    r"^\s+ont\s+(?:add|confirm)\s.*\bpassword-auth\s", re.I)
_HUAWEI_ONT_PROFILE = re.compile(r"\bont-srvprofile-id(?![-\w])", re.I)


def _huawei_unfinished(line: str) -> bool:
    """Does ``line`` end in the middle of a Huawei command?"""
    return (_quote_open(line)
            or (bool(_HUAWEI_ONT_AUTH.match(line))
                and not _HUAWEI_ONT_PROFILE.search(line)))


def _huawei_remainder(line: str) -> bool:
    """Is ``line`` the remainder of a wrapped Huawei command?"""
    return bool(line) and not line[:1].isspace() and not _HUAWEI_STRUCTURE.match(line)


def join_continuations(lines: Iterable[str]) -> list[str]:
    r"""Join every wrapped command into one logical line.

    TWO dialects wrap, and they are undone here together because both have to
    be undone in the same place -- before any rule runs, and in the one
    function ``verify`` normalises its own input with.

    RouterOS marks its wraps and Huawei does not, so the two halves of this
    function look nothing alike; what they share is the failure they prevent.

    ``/export`` wraps a long command with a trailing ``\\`` and continues it,
    indented, on the next line. Rules see one line at a time, so a wrap would
    carry the tail of a value past every rule that could recognise it: given
    ``wpa2-pre-shared-key="Winter Harbour \``, the value matcher cannot close
    the quote, so it takes the opening fragment, a marker is written over that
    much, and the rest of the passphrase leaves the tool on the next line with
    ``--strict`` reporting success. A half-redacted line reads as a finished
    one, which is worse than a plain miss -- so the wrap is undone BEFORE any
    rule runs.

    The ``\``, the newline and the continuation's indent are removed and the two
    halves are concatenated with NOTHING between them. That is what RouterOS
    itself does with them, and the "nothing" is load-bearing: ``/export`` wraps
    at whatever column it runs out of room at, which is regularly in the middle
    of a token and even in the middle of a word inside a quoted string --

        rule="if (dst == 0.0.0.0/0) {set bgp-path-\
            prepend 1; accept}

    is one ``bgp-path-prepend``, and ``set bgp-large-communities orig\`` +
    ``in-inband-mgmt`` is one ``origin-inband-mgmt``. Joining those with a space
    does not merely reformat the file, it corrupts it: the keyword becomes
    ``bgp-path- prepend`` and the list name becomes two words. Where a separator
    IS wanted the export has already put it before the backslash, so keeping the
    line up to the backslash verbatim -- trailing space and all -- is both
    necessary and sufficient.

    (This function first assumed a wrap always fell on a token boundary. It does
    not, and nothing in a config says it does; the assumption came from the
    shapes that happened to be in front of it.)

    Huawei writes no marker whatsoever. ``display current-configuration``
    wraps at the width of the session that collected it, so the break is a bare
    newline in the middle of whatever it landed on and the remainder starts at
    column zero:

         ont add 0 0 sn-auth "48575443AAAA0001" ... ont-srvprofile-id 110 desc "
        Bob's Bakery Pty Ltd, 50M"

    is ONE command, and read as two it hands the rule a description that is the
    empty string and leaves the customer on a line no rule can recognise. So a
    Huawei line is joined on the three pieces of evidence set out at
    :data:`_HUAWEI_WRAPPED`, and nothing goes between the halves here either --
    the wrap fell inside a value, and a value has no separator in it.

    The line count therefore changes, as it already can where a block body or a
    banner collapses.

    Idempotent in both dialects, by different arguments. Nothing in the result
    ends in ``\``, so the RouterOS half cannot fire twice. The Huawei half can
    still see an unfinished line in its own output -- a cipher blob with an odd
    number of quotes in it reads as unfinished however often it is joined -- and
    what settles that one is the OTHER half of the evidence: a joined line is
    followed by whatever followed the last remainder, which is a section
    marker, a ``#``, or an indented command, and none of those is a remainder.
    That is what lets ``verify`` normalise its own input the same way and stay
    line-for-line with what :meth:`RuleCatalogue.transform` produced.
    """
    source = list(lines)
    out: list[str] = []
    index = 0
    while index < len(source):
        line = source[index]
        # Huawei first, because its recogniser is the narrower of the two: a
        # RouterOS wrap is a trailing backslash, which no Huawei command line
        # here can end in, so the order costs nothing and reads better.
        if (_HUAWEI_WRAPPED.match(line) and _huawei_unfinished(line)
                and index + 1 < len(source)
                and _huawei_remainder(source[index + 1])):
            index += 1
            # Keep joining while the value is still open: a description long
            # enough to wrap once can wrap twice, and the ONT credentials in a
            # `%#%#...%#%#` config regularly do.
            while True:
                line += source[index]
                index += 1
                if not (_huawei_unfinished(line) and index < len(source)
                        and _huawei_remainder(source[index])):
                    break
            out.append(line)
            continue
        # a trailing backslash on the last line of a file continues nothing, so
        # it is a character of the value and stays exactly where it is
        if not (_ROUTEROS_WRAPPED.match(line) and index + 1 < len(source)):
            out.append(line)
            index += 1
            continue
        # the backslash goes and NOTHING replaces it: whatever separator the
        # wrap needs, the export already wrote before it. Only the continuation's
        # leading indent is dropped, and the backslash is taken off before the
        # indent is, so a space the export put in front of the backslash on a
        # continuation line survives too.
        parts = [line[:-1]]
        index += 1
        while index < len(source):
            nxt = source[index]
            index += 1
            if nxt.endswith("\\") and index < len(source):
                parts.append(nxt[:-1].lstrip())
                continue
            parts.append(nxt.lstrip())
            break
        out.append("".join(parts))
    return out


# ---------------------------------------------------------------------------
# the FortiOS block, which is the third shape of block netredact tracks
# ---------------------------------------------------------------------------
#
# FortiOS nests ``config <path>`` … ``end``, with ``edit <id>`` … ``next``
# inside. Only the ``config`` / ``end`` pair is tracked: the path is what says
# what the material is, and ``edit`` merely numbers the entries under it. That
# also means a nested ``config hosts`` inside an ``edit`` cannot unbalance the
# stack, because ``next`` is not a closer of anything we count.
#
# The line shape is the guard against this grammar firing on another dialect's
# file: the whole line has to be ``config`` plus bare words. A JunOS stanza
# ends in ``{``, a JunOS ``set`` line does not start with ``config``, and an
# IOS-style block header is a command -- none of them can produce it. The bare
# ``end`` that closes a block is a word an IOS running-config also ends with,
# which is harmless: with nothing on the stack it pops nothing.

#: ``config system snmp community``, and nothing that merely starts that way
#: Anything after ``config`` is the path, deliberately. This began as a word
#: path, and that was wrong, because the two ways of being wrong are NOT
#: symmetric:
#:
#: * A header the pattern does not recognise is pushed as an unnamed block only
#:   if it is recognised as a header AT ALL -- and a word path refused ``config
#:   system replacemsg auth "auth-password-page"``, whose path ends in a quoted
#:   argument. Nothing was pushed, but its ``end`` still popped, so what it
#:   closed was the section AROUND it: the enclosing ``config system snmp
#:   community`` ended early, the ``set name`` after it was no longer in the
#:   block that makes it a community string, and the community survived. A LEAK.
#: * A line wrongly taken for a header is pushed and never popped, so scopes
#:   reach further than they should. That over-applies a rule; it cannot leave a
#:   secret in the file.
#:
#: A redaction tool takes the second, so the recogniser asks only what FortiOS
#: itself asks -- the line begins with the word ``config`` -- and a shape nobody
#: has thought of yet still keeps the stack balanced. ``config-register 0x2102``
#: is not this: a hyphen follows the word, not whitespace. A banner body cannot
#: reach here, because :meth:`RuleCatalogue.transform` consumes a banner whole
#: before the next line is scoped.
_FORTI_CONFIG = re.compile(r"^\s*config\s+(\S.*?)\s*$", re.I)
_FORTI_END = re.compile(r"^\s*end\s*$", re.I)

#: FortiOS ``config`` paths and the scope each opens, most specific first --
#: the first match wins, as with :data:`_BLOCK_SCOPES`. A path with no entry
#: here opens an unnamed block: it still has to be tracked, or its ``end``
#: would close somebody else's.
#:
#: The names are JunOS's own wherever both grammars have the block, which is
#: what lets ONE rule reach three dialects: ``config system interface`` is
#: scope ``interfaces``, so ``interface-description`` covers a FortiOS ``set
#: description`` with nothing added, and ``config system snmp community`` is
#: scope ``snmp`` alongside the JunOS ``snmp { … }`` stanza. The rest are
#: FortiOS's own blocks and keep FortiOS's names.
#: A path opens SEVERAL scopes where one block answers more than one question:
#: ``config system interface`` is ``interfaces`` -- so ``interface-description``
#: reaches a FortiOS ``set description`` with nothing added -- and it is also
#: ``fortios-interface-names``, which is what says the ``edit`` on it names an
#: interface. Listing both is what lets the two coexist instead of the first
#: hiding the second.
#:
#: ``fortios-interface-names`` marks the four blocks whose ``edit`` name and
#: ``set member`` list are INTERFACE names: an interface, a zone, a
#: switch-interface and a virtual-switch are all things a ``set srcintf`` can
#: point at. It has to be a scope and not an unscoped pattern, because ``set
#: member`` is also how a ``config firewall addrgrp`` lists ADDRESS objects, and
#: giving one of those an interface's tag would break the file.
#:
#: ``object-labels`` carries the same claim it does on RouterOS: that nothing in
#: the grammar REFERENCES that block's name. A firewall policy is addressed by
#: its ``edit <id>`` and never by its ``set name``. An interface is the
#: counter-example and is deliberately absent -- ``edit "port1"`` is pointed at
#: by ``set srcintf "port1"`` from every policy in the file, which is why
#: interface names are an ``[operational-names]`` type that carries the
#: references too, and not a rule that sees only the declaration.
_FORTI_SCOPES = (
    ("snmp-user", re.compile(r"system\s+snmp\s+user", re.I)),
    # `snmp-community` alongside `snmp`, because `config system snmp sysinfo`
    # is `snmp` too and a `set name` there is not a community string
    (("snmp-community", "snmp"), re.compile(r"system\s+snmp\s+community", re.I)),
    ("snmp", re.compile(r"system\s+snmp(?:\s+\S+)?", re.I)),
    (("interfaces", "fortios-interface-names"),
     re.compile(r"system\s+interface", re.I)),
    ("fortios-interface-names",
     re.compile(r"system\s+(?:zone|switch-interface|virtual-switch)", re.I)),
    ("fortios-route-device", re.compile(r"router\s+static6?", re.I)),
    ("object-labels", re.compile(r"firewall\s+policy", re.I)),
    ("system-global", re.compile(r"system\s+global", re.I)),
    ("system-admin", re.compile(r"system\s+admin", re.I)),
    ("system-api-user", re.compile(r"system\s+api-user", re.I)),
    ("user-local", re.compile(r"user\s+local", re.I)),
)


class FortiBlocks:
    """The FortiOS ``config <path>`` … ``end`` stack, one line at a time.

    Stateful and fed in file order, so the caller asks :meth:`scopes` *before*
    :meth:`feed` and a ``config`` line is therefore NOT inside the block it
    opens -- unlike an IOS-style block header, whose own line is inside its
    block and which is why ``patch-name`` needs a lookahead of its own.

    Two callers share it, and that is the point: the sanitiser needs the scope
    to confine a rule, and the collect pass needs it to know that an ``edit``
    id is an account name rather than an interface name. Duplicating the state
    machine would let the two disagree about where a block ends.
    """

    __slots__ = ("_stack",)

    def __init__(self) -> None:
        self._stack: list[tuple[str, ...]] = []

    def scopes(self) -> tuple[str, ...]:
        """Every scope in force, outermost first and deduplicated.

        The union over the whole stack, because a nested block has not left the
        one that opened it: a ``config hosts`` inside an ``edit`` inside
        ``config system snmp community`` is still inside the community.
        """
        out: list[str] = []
        for names in self._stack:
            out.extend(name for name in names if name not in out)
        return tuple(out)

    def feed(self, line: str) -> None:
        match = _FORTI_CONFIG.match(line)
        if match:
            path = match.group(1)
            names = next((n for n, pat in _FORTI_SCOPES if pat.fullmatch(path)),
                         ())
            self._stack.append((names,) if isinstance(names, str) else names)
        elif _FORTI_END.match(line) and self._stack:
            self._stack.pop()
