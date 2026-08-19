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

Collections
-----------
* :func:`build_rules` -- line rules, matched with ``regex.match()`` from the
  start of the line.
* :data:`BLOB_RULES`  -- secret-shaped material anywhere in a line, searched
  (``finditer``), not anchored. Same :class:`Rule` contract: groups are targets.
* :data:`BLOCK_STARTS` -- multi-line blocks; the body between start and end is
  the target.
* :data:`BANNER_RE`   -- the ``banner`` rule, driven by the delimiter state
  machine in ``sanitise.py`` rather than by a target group.

Together these carry all 45 named rules; :func:`rule_names` lists them in
report order and :func:`family_of` maps each to its family.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "REMOVED", "DESC_REMOVED", "Rule", "build_rules", "rule_names", "family_of",
    "BUILTIN", "BLOB_RULES", "BLOCK_STARTS", "DESCRIPTION_RULES", "BANNER_RE",
    "HOSTNAME_PATS", "DOMAIN_PATS", "USERNAME_PATS",
    "IPV4_RE", "IPV6_RE", "MAC_RE", "EMAIL_RE",
    "SNMP_HOST_KEYWORDS", "JUNOS_KEYWORDS", "IOS_KEYWORDS",
    "STANZA_OPEN", "STANZA_CLOSE", "ENC", "VAL", "VAL_MACRO", "VAL_GROUP",
]

REMOVED = "<REMOVED>"
DESC_REMOVED = "<DESCRIPTION-REMOVED>"

#: a value: a quoted string, or a run of non-space non-semicolon characters
VAL = r'(?:"[^"]*"|\'[^\']*\'|[^\s;]+)'
#: what a custom / built-in pattern writes to borrow ``VAL``. It expands to a
#: *capturing* group: a pattern that spells out ``%VAL%`` has said where the
#: value is, so it must take the explicit-groups path. Expanding it
#: non-capturing left ``...shared-key\s+%VAL%`` with zero groups, so the prefix
#: path appended a second value matcher and ``hunter2`` became ``hunter<REMOVED>``.
VAL_MACRO = "%VAL%"
#: the capturing spelling of :data:`VAL`, substituted for :data:`VAL_MACRO`
VAL_GROUP = r"""("[^"]*"|'[^']*'|[^\s;]+)"""
#: encoding / algorithm hints that sit between the keyword and the secret
ENC = (r"(?:\d+|sha512|sha256|sha1|md5|encrypted|clear|ascii|ascii-text|hex|"
       r"hexadecimal|plain-text)")

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

#: keywords on an `snmp-server host` line, so only the community is hit
SNMP_HOST_KEYWORDS = {
    "vrf", "informs", "inform", "traps", "trap", "version", "1", "2c", "3",
    "auth", "noauth", "priv", "udp-port", "source-interface",
}


@dataclass(frozen=True)
class Rule:
    name: str
    regex: re.Pattern
    family: str
    targets: tuple[int, ...]     # capture-group indices to act on
    stanza: str | None = None
    custom: bool = False
    handler: str | None = None   # "snmp-host" only; else None


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


def _rest(prefix: str) -> str:
    """The whole remainder of the line is the value (the old ``rest`` mode)."""
    return rf"^{prefix}{NOT_BRACE}(.+?)(?:\s*;\s*(?:##.*)?)?$"


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

BUILTIN: list[tuple[str, str, str, str | None]] = [
    # ---- enable / user credentials -------------------------------------
    ("enable-secret", rf"\s*enable\s+(?:secret|password)\s+(?:level\s+\d+\s+)?(?:{ENC}\s+)?", "secrets", None),
    ("username-secret", rf"\s*username\s+\S+\s+(?:\S+\s+)*?(?:password|secret)\s+(?:{ENC}\s+)?", "secrets", None),
    ("bare-password", rf"\s*(?:password|passwd)\s+(?:{ENC}\s+)?", "secrets", None),
    ("bare-secret", rf"\s*(?:set\s+\S.*?\s)?secret\s+(?:{ENC}\s+)?", "secrets", None),

    # ---- AAA / shared keys ----------------------------------------------
    ("encoded-key",
     r".*\bkey\s+"
     + _not_keyword(IOS_KEYWORDS, enc=r"(?:0|7|8|encrypted)")
     + r"(?:0|7|8|encrypted)\s+", "secrets", None),
    ("aaa-server-key",
     r".*\b(?:tacacs|radius|ldap|server-private|server)\b.*?\bkey\s+"
     + _not_keyword(IOS_KEYWORDS)
     + rf"(?:{ENC}\s+)?", "secrets", None),
    ("quoted-key", r"\s*(?:set\s+\S.*?\s)?key\s+(?=\")", "secrets", None),
    ("key-string", rf"\s*key-string\s+(?:{ENC}\s+)?", "secrets", None),
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
    ("isakmp-key", rf"\s*crypto\s+isakmp\s+key\s+(?:{ENC}\s+)?", "secrets", None),
    ("pre-shared-key", rf".*\bpre-shared-key\s+(?:address\s+\S+\s+)?(?:key\s+)?(?:{ENC}\s+)?", "secrets", None),
    ("auth-key",
     r"\s*(?:set\s+\S.*?\s)?(?:authentication-key|encryption-key)\s+"
     + _not_keyword(JUNOS_KEYWORDS, digits=True)
     + rf"(?:{ENC}\s+)?", "secrets", None),

    # ---- routing / redundancy protocol authentication ---------------------
    ("message-digest-key", rf".*\bmessage-digest-key\s+\d+\s+md5\s+(?:{ENC}\s+)?", "secrets", None),
    ("bgp-neighbor-password", rf".*\bneighbor\s+\S+\s+password\s+(?:{ENC}\s+)?", "secrets", None),
    ("hsrp-vrrp-auth", rf"\s*(?:standby\s+\d+\s+|vrrp\s+\d+\s+)?authentication\s+(?:text|md5\s+key-string|md5\s+key-chain)\s+(?:{ENC}\s+)?", "secrets", None),
    ("isis-password", rf"\s*(?:lsp|area|domain)-password\s+(?:{ENC}\s+)?", "secrets", None),
    ("ntp-auth-key", r"\s*ntp\s+authentication-key\s+\d+\s+\S+\s+", "secrets", None),

    # ---- PPP / L2 / wireless ---------------------------------------------
    ("ppp-credential", rf"\s*ppp\s+(?:chap|pap|eap)\s+(?:password|secret|sent-username\s+\S+\s+password)\s+(?:{ENC}\s+)?", "secrets", None),
    ("wpa-psk", rf".*\bwpa-psk\s+(?:{ENC}\s+)?", "secrets", None),
    ("ftp-password", rf"\s*ip\s+(?:ftp|tftp|http\s+client)\s+password\s+(?:{ENC}\s+)?", "secrets", None),

    # ---- Juniper specifics -------------------------------------------------
    ("junos-password", r".*\b(?:encrypted-password|plain-text-password-value)\s+", "secrets", None),

    # ---- vendor unlocks ----------------------------------------------------
    # Arista `service unsupported-transceiver <label> <authorization-code>`:
    # the code is TAC-issued credential material, and the label is operator
    # free text that in practice carries a customer / project name and dates.
    # The second token is optional, but the bare Cisco IOS `service
    # unsupported-transceiver` (no arguments) must not match at all.
    ("unsupported-transceiver",
     rf"^\s*service\s+unsupported-transceiver\s+{NOT_BRACE}%VAL%(?:\s+%VAL%)?\s*$",
     "secrets", None),

    # ---- free text ---------------------------------------------------------
    # location / contact are text, not secrets: they leak an org and a site,
    # not a credential. NOT_BRACE keeps `location {` a stanza opener.
    ("location", _rest(r"\s*(?:set\s+snmp\s+|snmp-server\s+)?location\s+"), "text", None),
    ("contact", _rest(r"\s*(?:set\s+snmp\s+|snmp-server\s+)?contact\s+"), "text", None),
    # the body of a JunOS `location { ... }` stanza: the keys carry the street
    # address the `location` rule itself must not eat (it is a stanza opener,
    # not a value). Stanza-scoped, so a `building` line elsewhere is untouched.
    ("junos-location-body",
     _rest(rf"\s*(?:{_JUNOS_LOCATION_KEYS})\s+"), "text", "location"),
    ("description", _rest(r"\s*(?:set\s+\S.*?\s)?description\s+"), "text", None),
    ("acl-remark", _rest(r"\s*remark\s+"), "text", None),
    ("login-message",
     _rest(r"\s*(?:set\s+system\s+login\s+)?(?:message|announcement)\s+"), "text", None),
]

#: rules whose value needs a code path rather than a plain span replacement
_HANDLERS = {"snmp-host": "snmp-host"}

_COMPILED: dict[str, tuple[re.Pattern, tuple[int, ...]]] = {
    name: _compile(pattern) for name, pattern, _family, _stanza in BUILTIN
}

#: the banner rule: name and family here, delimiter state machine in sanitise
BANNER_RE = re.compile(r"^\s*banner\s+([\w-]+)\s+(.*)$", re.I)
BANNER_RULE = ("banner", "text")


# ---------------------------------------------------------------------------
# secret-shaped material, wherever it appears in a line
# ---------------------------------------------------------------------------

#: (name, pattern, family, flags) -- searched anywhere in the line, so the
#: context stays *outside* the groups instead of being rebuilt by a template.
_BLOB: list[tuple[str, str, str, int]] = [
    ("junos-type9", r'(\$9\$[^\s";]+)', "secrets", 0),
    ("crypt-hash", r'(\$(?:1|2[abxy]?|5|6|y)\$[^\s";]+)', "secrets", 0),
    ("ssh-public-key",
     r'\b(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-[\w-]+)\s+("?AAAA[0-9A-Za-z+/=]+"?)',
     "identity", 0),
    # atomic header: the optional colon must not be handed back as the value,
    # so a bare `! License UDI:` heading with no data on it never matches
    ("license-udi", r"^\s*!?\s*(?>License\s+UDI:?\s*)(.+)$", "identity", re.I),
    ("serial-number",
     r"^\s*!?\s*(?:System\s+)?[Ss]erial\s*(?:[Nn]umber)?\s*[:=]?\s+(\S+.*)$",
     "identity", 0),
]

def _blob_rules() -> list[Rule]:
    out = []
    for name, pattern, family, flags in _BLOB:
        regex, targets = _compile(pattern, flags)
        out.append(Rule(name=name, regex=regex, family=family, targets=targets))
    return out


BLOB_RULES: list[Rule] = _blob_rules()

#: opaque multi-line blocks: (start, end, name, family). The body is the target.
BLOCK_STARTS = (
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

def _registry() -> dict[str, str]:
    """name -> family for every named rule, in report order."""
    reg = {name: family for name, _pattern, family, _stanza in BUILTIN}
    reg[BANNER_RULE[0]] = BANNER_RULE[1]
    reg.update({r.name: r.family for r in BLOB_RULES})
    reg.update({name: family for _start, _end, name, family in BLOCK_STARTS})
    return reg


_FAMILY: dict[str, str] = _registry()


def rule_names() -> list[str]:
    """Every built-in rule name, in report order."""
    return list(_FAMILY)


def family_of(name: str) -> str:
    """The family a built-in rule belongs to.

    Raises ``KeyError`` for an unknown name; custom rules carry their own
    family on the ``CustomRule`` and are never registered here.
    """
    try:
        return _FAMILY[name]
    except KeyError:
        raise KeyError(f"unknown rule: {name!r}") from None


def build_rules(custom=()) -> list[Rule]:
    """Compile the keyword rule set.

    ``custom`` is a list of ``CustomRule`` appended after the built-ins. There
    is no ``disable`` argument: ``keep`` is an action, so a rule the policy
    keeps still matches and still gets counted.
    """
    rules = [
        Rule(name=name, regex=_COMPILED[name][0], family=family,
             targets=_COMPILED[name][1], stanza=stanza,
             handler=_HANDLERS.get(name))
        for name, _pattern, family, stanza in BUILTIN
    ]
    for c in custom:
        try:
            regex, targets = _compile(c.pattern)
        except re.error as exc:
            raise ValueError(f"custom rule {c.name!r}: bad regex: {exc}") from exc
        rules.append(Rule(name=c.name, regex=regex,
                          family=getattr(c, "family", "secrets") or "secrets",
                          targets=targets, stanza=getattr(c, "stanza", None),
                          custom=True))
    return rules


# ---------------------------------------------------------------------------
# identity sources
# ---------------------------------------------------------------------------

HOSTNAME_PATS = (
    re.compile(r"^\s*(?:hostname|switchname)\s+(\S+)", re.I),
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
    r"|(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
    r"|(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}"
    r")(?![\w.:-])"
)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")

STANZA_OPEN = re.compile(r"^\s*([\w-]+)[^{}]*\{\s*$")
STANZA_CLOSE = re.compile(r"^\s*\}\s*$")
