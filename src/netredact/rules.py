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

Scope: the block a line is inside
---------------------------------
Some material is only recognisable from the block that encloses it. A bare
``name CUST000000000123`` is a VLAN name under ``vlan 905`` and a route-map
name under ``route-map``, and the line itself cannot tell you which. So a rule
can name the block it needs (``stanza``) or the blocks it must stay out of
(:data:`_OUTSIDE`), and the sanitiser tracks three kinds of block under one set
of names:

* a JunOS brace stanza -- ``interfaces { … }`` -- from the stanza stack;
* an IOS-style block -- ``interface Gi0/0`` and the indented lines under it --
  from :data:`_BLOCK_SCOPES`;
* a FortiOS block -- ``config system snmp community`` … ``end`` -- from
  :class:`FortiBlocks` and :data:`_FORTI_SCOPES`.

The names are JunOS's own wherever the dialects share the block, so one rule
covers them all: an IOS ``interface`` block and a FortiOS ``config system
interface`` block are both scope ``interfaces``, a ``vlan 905`` block is scope
``vlans``, and a FortiOS ``config system snmp community`` block is scope
``snmp`` alongside the JunOS ``snmp { … }`` stanza. A JunOS ``set`` line
carries its scope on the line itself (:data:`_SET_SCOPE`), so ``set interfaces
xe-0/0/0 description …`` is inside ``interfaces`` too. A block only one vendor
has keeps its own name -- ``patch-panel``, ``system-admin``.

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
    "HOSTNAME_PATS", "DOMAIN_PATS", "USERNAME_PATS", "SCOPED_NAME_PATS",
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
#: encoding / algorithm hints that sit between the keyword and the secret.
#: ``enc`` is FortiOS's, and it is here rather than in the FortiOS rule for one
#: reason: ``verify.VTOK`` is derived from this table. The rules and the
#: credential check have to agree on what may stand between a keyword and its
#: placeholder, or ``set password ENC "<REMOVED>"`` is reported as a leak by
#: the very check that exists to catch the leaks -- and every FortiOS
#: credential line fails ``--strict`` after being correctly dealt with.
ENC = (r"(?:\d+|sha512|sha256|sha1|md5|encrypted|enc|clear|ascii|ascii-text|hex|"
       r"hexadecimal|plain-text)")

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
    ("hardware-model",
     _alt(_rest(rf"\s*!?\s*(?:{_MODEL_KEYS})\s*[:=]\s*"),
          # the Arista header, up to the last comma inside the brackets
          rf"{_EOS_HEADER}([^)]+),",
          # the FortiOS header: the model is everything before the first `-`
          # that a dotted release follows, so `FGVM64` and `FWF-60E` both work
          rf"{_FORTIOS_HEADER}([\w-]+?)-(?=\d+\.\d)"), "platform", None),
    ("os-version",
     _alt(_rest(r"\s*(?:set\s+)?version\s+(?=\d)"),
          # the Arista header, the token after the last comma
          rf"{_EOS_HEADER}[^)]+,\s*([^\s,)]+)\s*\)\s*$",
          # the FortiOS header: the release, its firmware kind and its build,
          # up to the `:` that starts `opmode=`. `.*?` rather than a character
          # class for the model in front, because `hardware-model` is an
          # earlier rule and has already replaced it by the time this one
          # looks -- a class that could not span `<REMOVED>` left the release
          # behind whenever the model was acted on and the release was not.
          rf"{_FORTIOS_HEADER}.*?-(\d+\.\d[^\s:]*)",
          # `#buildno=` and `#branch_pt=`, the same release stated again on
          # their own lines
          r"^\s*#(?:buildno|branch_pt)=(\S+)\s*$"), "platform", None),
    ("software-image",
     _rest(rf"\s*!?\s*(?:(?:{_IMAGE_KEYS})(?:\s*[:=]\s*|\s+)"
           rf"|(?:{_IMAGE_COLON_KEYS})\s*[:=]\s*)"), "platform", None),
    ("boot-image", _rest(r"\s*!?\s*boot\s+system\s+"), "platform", None),

    # ---- free text ---------------------------------------------------------
    # location / contact are text, not secrets: they leak an org and a site,
    # not a credential. NOT_BRACE keeps `location {` a stanza opener.
    # The bare ``set`` form is FortiOS's -- ``set location "…"`` under `config
    # system snmp sysinfo`, where the block carries the `snmp` that JunOS
    # spells out on the line. It is safe unqualified for the same reason the
    # unprefixed form is: NOT_BRACE refuses a stanza opener, and no dialect
    # uses `location` or `contact` as a command keyword.
    ("location", _rest(r"\s*(?:set\s+(?:snmp\s+)?|snmp-server\s+)?location\s+"), "locations", None),
    # `contact-info` is FortiOS's spelling of the same field.
    ("contact", _rest(r"\s*(?:set\s+(?:snmp\s+)?|snmp-server\s+)?contact(?:-info)?\s+"), "text", None),
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

#: rule -> the blocks it must not fire inside, because a scoped rule of its own
#: owns that material there. The pair is exhaustive and disjoint by
#: construction: every description is matched by exactly one of
#: ``interface-description`` and ``description``.
_OUTSIDE: dict[str, tuple[str, ...]] = {
    "description": ("interfaces",),
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
    ("serial-number",
     r"^\s*!?\s*(?:System\s+)?[Ss]erial\s*(?:[Nn]umber)?\s*[:=]?\s+(\S+.*)$",
     "identity", 0),
]

def _blob_rules() -> list[_Rule]:
    out = []
    for name, pattern, family, flags in _BLOB:
        regex, targets = _compile(pattern, flags)
        out.append(_Rule(name=name, regex=regex, family=family, targets=targets,
                        vendor=_RULE_VENDORS.get(name)))
    return out


_BLOB_RULES: list[_Rule] = _blob_rules()

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
        return cls(tuple(_build_rules()), tuple(_BLOB_RULES), tuple(_BLOCK_STARTS))

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
        source_patterns = {name: pattern for name, pattern, _family, _scope
                           in _BUILTIN}
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
                     r.regex.pattern)
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
        for rule in self._searched:
            for match in reversed(list(rule.regex.finditer(text))):
                text = self._splice(rule, match, text, replace)
        return text

    def transform(self, lines: Iterable[str], *,
                  replace: Callable[[RuleHit], RuleReplacement],
                  finish_line: Callable[[str], str] = lambda line: line,
                  ) -> list[str]:
        """Transform rules in their canonical order, including scoped state."""
        source = [line.rstrip("\n") for line in lines]
        out: list[str] = []
        stanza: list[str] = []
        forti = FortiBlocks()
        ios_block: str | None = None
        index = 0
        while index < len(source):
            raw = source[index]
            if raw.strip() and not raw[:1].isspace():
                ios_block = next((name for name, pat in _BLOCK_SCOPES
                                  if pat.match(raw)), None)
            set_match = _SET_SCOPE.match(raw)
            if re.match(r"\s*set\s+system\s+location\b", raw, re.I):
                line_scope = ("location",)
            else:
                line_scope = (set_match.group(1).lower(),) if set_match else ()
            inside = (tuple(stanza) + ((ios_block,) if ios_block else ())
                      + forti.scopes() + line_scope)

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
        """Return line-aligned text with selected rule values blanked out."""
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
    re.compile(r"^\s*(?:set\s+)?(?:hostname|switchname)\s+(\S+)", re.I),
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
_FORTI_CONFIG = re.compile(r"^\s*config\s+([\w-]+(?:\s+[\w-]+)*)\s*$", re.I)
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
_FORTI_SCOPES = (
    ("interfaces", re.compile(r"system\s+interface", re.I)),
    ("snmp-user", re.compile(r"system\s+snmp\s+user", re.I)),
    ("snmp", re.compile(r"system\s+snmp(?:\s+\S+)?", re.I)),
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
        self._stack: list[str | None] = []

    def scopes(self) -> tuple[str, ...]:
        return tuple(name for name in self._stack if name)

    def feed(self, line: str) -> None:
        match = _FORTI_CONFIG.match(line)
        if match:
            path = match.group(1)
            self._stack.append(next((name for name, pat in _FORTI_SCOPES
                                     if pat.fullmatch(path)), None))
        elif _FORTI_END.match(line) and self._stack:
            self._stack.pop()
