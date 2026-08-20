"""Every configuration option, against every value it accepts.

THE PRINCIPLE, which is what makes this file worth its length: the assertions
are *contracts*, not expected strings. A cell of the matrix does not say "this
becomes ``<HOST-a99da0>``" -- that is :mod:`test_actions`' job, and it pins one
value per family. A cell here says what the action promises:

===========  ================================================================
``keep``     the value is still there, byte for byte
``pseudo``   the value is gone, the replacement is type-valid, and equal
             inputs still map to equal outputs
``hash``     the value is gone and a ``<PREFIX-tag>`` marker stands in its place
``redact``   the value is gone and the family's constant stands in its place
===========  ================================================================

So a new family, class or action is covered the moment it exists, and
:func:`test_the_matrix_covers_every_option` fails until it is.

The dimensions are read from the code's own tuples -- ``ACTIONS``,
``POLICY_FAMILIES``, ``RULE_FAMILIES``, ``RULE_SECTIONS``,
``V4_CLASS_NAMES``, ``V6_CLASS_NAMES``, ``VENDORS``, ``VENDOR_HINTS``, the
dataclass fields -- and never transcribed, because a transcribed list is a list
that goes stale without anything failing.
"""

import ipaddress
import re
from dataclasses import fields

import pytest

from netredact import Config, RuleCatalogue, sanitise_text
from netredact.addresses import V4_CLASS_NAMES, V6_CLASS_NAMES
from netredact.config import (
    ACTIONS,
    ALLOWED,
    POLICY_FAMILIES,
    RULE_FAMILIES,
    RULE_SECTIONS,
    VENDORS,
    IPv4Policy,
    IPv6Policy,
    MacPolicy,
    PolicyConfig,
    VerifyConfig,
)
from netredact.pseudonymise import DESC_REMOVED, REDACT_CONST, REMOVED
from netredact.vendors import VENDOR_HINTS

from .conftest import SALT, policy, section

_RULES = RuleCatalogue.builtins().inventory()


def rule_names():
    return [info.name for info in _RULES]


def family_of(name):
    return next(info.family for info in _RULES if info.name == name)

#: any ``<PREFIX-tag>`` marker, whichever family produced it
MARKER_RE = re.compile(r"<[A-Z0-9-]+-[0-9a-f]{1,6}>")


# ---------------------------------------------------------------------------
# [policy] and the family sections: every family, every action it allows
# ---------------------------------------------------------------------------

#: family -> (a line the rules match, the sensitive value inside it)
#:
#: Each line is the narrowest one that reaches its family and nothing else --
#: ``snmp-server contact`` would reach ``emails`` too, but it is also the
#: ``contact`` rule in ``text``, and then the sweep would be testing two
#: families at once. For a family with a section, this is what its ``default``
#: is judged on; the per-rule keys are swept separately below.
POLICY_SAMPLE = {
    "secrets":   (" enable secret 5 $1$abc$0123456789abcdefghij\n",
                  "$1$abc$0123456789abcdefghij"),
    "text":      (" description a plain description\n", "a plain description"),
    "identity":  ("! Serial Number: FDO1234ABCD\n", "FDO1234ABCD"),
    "platform":  ("version 15.7\n", "15.7"),
    # the two scoped families need the block that scopes them, so their sample
    # is two lines: the header is what tells the sanitiser where it is
    "interfaces": ("interface GigabitEthernet0/1\n description a port note\n",
                   "a port note"),
    "vlans":     ("vlan 905\n name CUST000000000123\n", "CUST000000000123"),
    # scoped the same way, on the block only Arista opens
    "circuits":  ("patch panel\n   patch acme_ORD000000111222\n",
                  "acme_ORD000000111222"),
    "hostnames": ("hostname core-rtr-01\n", "core-rtr-01"),
    "domains":   ("ip domain-name northwind.test\n", "northwind.test"),
    "usernames": ("username netops privilege 15\n", "netops"),
    "emails":    ("! owner noc@northwind.test\n", "noc@northwind.test"),
}

#: the constants ``redact`` may leave behind, by family
REDACT_EXPECTED = {
    "secrets": (REMOVED,),
    "text": (REMOVED, DESC_REMOVED),
    "identity": (REMOVED,),
    "platform": (REMOVED,),
    "interfaces": (DESC_REMOVED,),
    "vlans": (REMOVED,),
    "circuits": (REMOVED,),
    "hostnames": (REDACT_CONST["hostnames"],),
    "domains": (REDACT_CONST["domains"],),
    "usernames": (REDACT_CONST["usernames"],),
    "emails": (REDACT_CONST["emails"],),
}

#: every family that takes one action: the four in ``[policy]``, and the
#: ``default`` of every family that has a section
POLICY_CELLS = [(family, action)
                for family in POLICY_FAMILIES + RULE_FAMILIES
                for action in ALLOWED[family]]


@pytest.mark.parametrize("family,action", POLICY_CELLS,
                         ids=[f"{f}-{a}" for f, a in POLICY_CELLS])
def test_every_policy_family_honours_every_action(family, action):
    text, value = POLICY_SAMPLE[family]
    out = sanitise_text(text, policy(**{family: action}), salt=SALT).text

    if action == "keep":
        assert value in out
        return

    assert value not in out, f"{family}={action} left the value behind"
    if action == "hash":
        assert MARKER_RE.search(out), out
    elif action == "redact":
        assert any(c in out for c in REDACT_EXPECTED[family]), out
    else:                                   # pseudo
        assert out.strip() and out != text
        again = sanitise_text(text, policy(**{family: action}), salt=SALT).text
        assert again == out, "pseudo broke the equality relation"


# ---------------------------------------------------------------------------
# [ipv4] / [ipv6]: `default`, then every class, on every action
# ---------------------------------------------------------------------------

#: class -> an address in it that is not mask-like, because masks are exempt
#: from every action by design (0.0.0.0 and 255.255.255.255 are both masks, so
#: neither can stand for its class here)
V4_SAMPLE = {
    "loopback": "127.0.0.1",
    "rfc1918": "10.20.30.1",
    "cgnat": "100.64.0.1",
    "link_local": "169.254.0.1",
    "multicast": "224.0.0.5",
    "documentation": "203.0.113.10",
    "benchmark": "198.18.0.1",
    "reserved": "240.0.0.1",
    "well_known": "8.8.8.8",
    "other_unicast": "128.66.16.130",
}

V6_SAMPLE = {
    "unspecified": "::",
    "loopback": "::1",
    "ula": "fd00::1",
    "link_local": "fe80::1",
    "multicast": "ff02::5",
    "documentation": "2001:db8::1",
    "teredo": "2001::1",
    "six_to_four": "2002::1",
    "ipv4_mapped": "64:ff9b::1",
    "well_known": "2001:4860:4860::8888",
    "other_unicast": "3fff:16::1",
}


def _v4_pool(klass: str) -> list[str]:
    """A pool that cannot overlap the class under test.

    Pseudonymising an address into the range it already came from is a
    collision, not a replacement, so the benchmark class -- which is where the
    default pool lives -- has to allocate somewhere else.
    """
    return ["100.64.0.0/10"] if klass == "benchmark" else ["198.18.0.0/15"]


def _v6_pool(klass: str) -> str:
    return "3fff:f000::/32" if klass == "documentation" else "2001:db8::/32"


V4_CELLS = [(k, a) for k in V4_CLASS_NAMES for a in ACTIONS]
V6_CELLS = [(k, a) for k in V6_CLASS_NAMES for a in ACTIONS]


def _address_contract(sample: str, action: str, out: str, family: str) -> None:
    """Judge the replacement as an address, never as a substring.

    ``::`` and ``::1`` are substrings of every IPv6 address there is, so
    ``sample not in out`` would call a correct replacement a leak -- the
    unspecified address pseudonymised to ``2001:db8:10f4:d45d::`` still
    "contains" ``::``. Comparing parsed addresses also makes the check immune
    to how the address was spelled.
    """
    token = out.split()[-1]
    if action == "hash":
        assert MARKER_RE.fullmatch(token), out
        return
    got = ipaddress.ip_address(token)
    original = ipaddress.ip_address(sample)
    if action == "keep":
        assert got == original, out
    elif action == "redact":
        assert got == ipaddress.ip_address(REDACT_CONST[family]), out
    else:                                   # pseudo
        assert got != original, out
        assert got.version == original.version, out


@pytest.mark.parametrize("klass,action", V4_CELLS,
                         ids=[f"{k}-{a}" for k, a in V4_CELLS])
def test_every_ipv4_class_honours_every_action(klass, action):
    cfg = Config()
    cfg.ipv4.default = "keep"
    setattr(cfg.ipv4, klass, action)
    cfg.ipv4.pool = _v4_pool(klass)
    sample = V4_SAMPLE[klass]
    out = sanitise_text(f"! peer {sample}\n", cfg, salt=SALT).text
    _address_contract(sample, action, out, "ipv4")


@pytest.mark.parametrize("klass,action", V6_CELLS,
                         ids=[f"{k}-{a}" for k, a in V6_CELLS])
def test_every_ipv6_class_honours_every_action(klass, action):
    cfg = Config()
    cfg.ipv6.default = "keep"
    setattr(cfg.ipv6, klass, action)
    cfg.ipv6.pool = _v6_pool(klass)
    sample = V6_SAMPLE[klass]
    out = sanitise_text(f"! peer {sample}\n", cfg, salt=SALT).text
    _address_contract(sample, action, out, "ipv6")


@pytest.mark.parametrize("action", ACTIONS)
def test_the_address_default_reaches_a_class_that_is_not_named(action):
    """`default` is the whole point of the class model: it must reach them all."""
    cfg = Config()
    cfg.ipv4.default = action
    cfg.ipv4.pool = ["198.18.0.0/15"]
    cfg.ipv6.default = action
    v4, v6 = sanitise_text("! peer 128.66.16.130\n! peer 3fff:16::1\n",
                           cfg, salt=SALT).text.splitlines()
    _address_contract("128.66.16.130", action, v4, "ipv4")
    _address_contract("3fff:16::1", action, v6, "ipv6")


@pytest.mark.parametrize("klass", [k for k in V4_CLASS_NAMES
                                  if k != "other_unicast"])
def test_naming_one_ipv4_class_leaves_the_others_alone(klass):
    """A class is a selector: acting on one must not act on any other."""
    cfg = Config()
    cfg.ipv4.default = "keep"
    setattr(cfg.ipv4, klass, "hash")
    cfg.ipv4.pool = _v4_pool(klass)
    out = sanitise_text(f"! a {V4_SAMPLE[klass]} b 128.66.16.130\n",
                        cfg, salt=SALT).text
    assert "128.66.16.130" in out, f"{klass} bled into other_unicast"


# ---------------------------------------------------------------------------
# [macs]: two halves, and the rule that `hash` takes both
# ---------------------------------------------------------------------------

MAC_LINE = " mac-address 0011.2233.4455\n"
MAC_VALUE = "0011.2233.4455"

#: every legal (oui, nic) pair. ``hash`` replaces the whole address, so it is
#: legal only as both halves at once -- which is a config error otherwise, and
#: therefore part of the matrix rather than an omission from it.
MAC_PAIRS = [(o, n) for o in ("keep", "pseudo", "redact")
             for n in ("keep", "pseudo", "redact")] + [("hash", "hash")]


@pytest.mark.parametrize("oui,nic", MAC_PAIRS,
                         ids=[f"oui={o}-nic={n}" for o, n in MAC_PAIRS])
def test_every_legal_mac_half_combination(oui, nic):
    cfg = Config()
    cfg.macs.oui, cfg.macs.nic = oui, nic
    out = sanitise_text(MAC_LINE, cfg, salt=SALT).text

    if oui == nic == "keep":
        assert MAC_VALUE in out
    elif oui == nic == "hash":
        assert MAC_VALUE not in out and MARKER_RE.search(out), out
    else:
        assert MAC_VALUE not in out, out
        if oui == "redact":
            # the pool is written in the vendor's own notation, so compare the
            # hex digits rather than the punctuation: `00:00:5e` reaches a
            # Cisco-style address as `0000.5e..`
            pool_hex = re.sub(r"[^0-9a-f]", "", cfg.macs.pool.lower())
            got_hex = re.sub(r"[^0-9a-f]", "",
                             out.split()[-1].lower())
            assert got_hex.startswith(pool_hex), out


@pytest.mark.parametrize("half", ["oui", "nic"])
def test_hash_on_one_mac_half_is_rejected(half):
    """`hash` names the whole address, so half of one is a config error."""
    with pytest.raises(ValueError, match="set both oui and nic to hash"):
        MacPolicy(**{half: "hash"})


# ---------------------------------------------------------------------------
# the per-rule keys of the family sections
# ---------------------------------------------------------------------------
#
# The `default` of each section is swept above, on the family sample. What is
# left to prove here is the OTHER axis: that naming one rule gives that rule
# its own action and leaves the rest of the family on `default`. One
# representative rule per family carries that -- the mechanism is shared, it
# is generated once by `_rule_policy`, so proving it once per generated class
# is proof for every key. `platform` is swept rule by rule as well, because
# its four rules are four different line shapes and that is the family the
# shapes were written for.

#: family -> (rule, a line only that rule reaches, the value inside it)
RULE_SAMPLE = {
    "secrets": ("snmp-community", "snmp-server community s3cr3t ro\n", "s3cr3t"),
    "text": ("acl-remark", " remark a plain remark\n", "a plain remark"),
    "identity": ("serial-number", "! Serial Number: FDO1234ABCD\n", "FDO1234ABCD"),
    "platform": ("os-version", "version 15.7\n", "15.7"),
    "interfaces": ("interface-description",
                   "interface GigabitEthernet0/1\n description a port note\n",
                   "a port note"),
    "vlans": ("vlan-name", "vlan 905\n name CUST000000000123\n",
              "CUST000000000123"),
    "circuits": ("patch-name", "patch panel\n   patch acme_ORD000000111222\n",
                 "acme_ORD000000111222"),
}

RULE_CELLS = [(f, a) for f in RULE_FAMILIES for a in ALLOWED[f] if a != "keep"]


@pytest.mark.parametrize("family,action", RULE_CELLS,
                         ids=[f"{f}-{a}" for f, a in RULE_CELLS])
def test_naming_one_rule_opts_it_out_of_the_section_default(family, action):
    """The rule named acts; the rest of the family stays on `default`."""
    rule, text, value = RULE_SAMPLE[family]
    cfg = section(family, "keep", **{rule: action})
    out = sanitise_text(text, cfg, salt=SALT).text
    assert value not in out, f"[{family}] {rule}={action} left the value behind"
    assert cfg.action_for_rule(rule) == action
    assert all(cfg.action_for_rule(r) == "keep"
               for r in RULE_SECTIONS[family].RULES if r != rule)


@pytest.mark.parametrize("family", RULE_FAMILIES)
def test_a_rule_left_unset_inherits_the_section_default(family):
    rule, text, value = RULE_SAMPLE[family]
    cfg = section(family, "redact", **{rule: "keep"})
    assert cfg.action_for_rule(rule) == "keep"
    assert all(cfg.action_for_rule(r) == "redact"
               for r in RULE_SECTIONS[family].RULES if r != rule)
    assert cfg.platform.any_active() if family == "platform" else True
    assert value in sanitise_text(text, cfg, salt=SALT).text


#: rule -> (a line only that rule reaches, the value inside it). Only
#: `platform` is swept this finely: see the note at the top of this block.
PLATFORM_SAMPLE = {
    "hardware-model": ("Model Number : WS-C3850-48P\n", "WS-C3850-48P"),
    "os-version": ("version 15.7\n", "15.7"),
    "software-image": ("Software image version: 4.32.1F\n", "4.32.1F"),
    "boot-image": ("boot system flash:img.bin\n", "flash:img.bin"),
}

PLATFORM_CELLS = [(r, a) for r in RULE_SECTIONS["platform"].RULES
                  for a in ALLOWED["platform"]]


@pytest.mark.parametrize("rule,action", PLATFORM_CELLS,
                         ids=[f"{r}-{a}" for r, a in PLATFORM_CELLS])
def test_every_platform_rule_honours_every_action(rule, action):
    text, value = PLATFORM_SAMPLE[rule]
    cfg = section("platform", "keep", **{rule: action})
    out = sanitise_text(text, cfg, salt=SALT).text

    if action == "keep":
        assert value in out
        return
    assert value not in out, f"[platform] {rule}={action} left the value behind"
    if action == "hash":
        assert MARKER_RE.search(out), out
    elif action == "redact":
        assert REMOVED in out, out
    else:                                   # pseudo
        assert out.strip() and out != text
        assert sanitise_text(text, cfg, salt=SALT).text == out


def test_every_platform_rule_has_a_representative_sample():
    """A rule with no sample is a rule the sweep silently skips."""
    assert set(PLATFORM_SAMPLE) == set(RULE_SECTIONS["platform"].RULES)


@pytest.mark.parametrize("family", RULE_FAMILIES)
def test_a_section_names_exactly_its_family_rules(family):
    """The anti-drift check: the keys come from the rule table, both ways.

    `declared` walks the generated dataclass; `covered` walks the rule table.
    A rule added to a family with no key in its section, or a key that names
    no rule, fails here rather than being silently unreachable.
    """
    declared = {f.name for f in fields(RULE_SECTIONS[family])} - {"default"}
    covered = {name.replace("-", "_") for name in rule_names()
               if family_of(name) == family}
    assert declared == covered


def test_an_unknown_rule_in_a_section_is_rejected():
    with pytest.raises(ValueError, match="has no rule"):
        Config().platform.action("no-such-rule")


# ---------------------------------------------------------------------------
# the scalar options: vendor, and the [verify] switches
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vendor", VENDORS)
def test_every_vendor_value_is_accepted_and_reported(vendor, cisco):
    cfg = Config(vendor=vendor)
    result = sanitise_text(cisco, cfg, salt=SALT)
    assert result.text
    assert result.vendor


def test_an_unknown_vendor_is_rejected():
    with pytest.raises(ValueError, match="vendor"):
        Config(vendor="nortel")


def test_the_vendor_values_are_exactly_the_vendors_the_detector_knows():
    """The anti-drift check for vendor identity, and it belongs here.

    ``test_platform.py`` asserts what ``detect_vendor`` answers; this file
    asserts what the configuration surface *is*, and this is a claim about the
    surface: the sweep above parametrises over ``VENDORS``, so a vendor missing
    from it is a vendor nothing tests, and a vendor in it with no hints behind
    it is a value you can set and netredact can never arrive at on its own.

    ``VENDORS`` is now built from ``VENDOR_HINTS`` (see
    ``config.VENDORS``), so this cannot fail by accident -- it fails if someone
    unpicks that derivation and starts transcribing the list again.
    """
    assert set(VENDORS) - {"auto"} == {name for name, _ in VENDOR_HINTS}
    # Config.__post_init__ tests membership and this file parametrises over it,
    # so the shape matters as much as the contents
    assert isinstance(VENDORS, tuple)
    assert all(isinstance(v, str) for v in VENDORS)
    assert VENDORS[0] == "auto", "auto is the default, and reads first"


@pytest.mark.parametrize("enabled", [True, False])
def test_verify_enabled_switches_the_pass_on_and_off(enabled):
    cfg = policy(secrets="keep")
    cfg.verify.enabled = enabled
    result = sanitise_text(" enable secret 5 $1$abc$def\n", cfg, salt=SALT)
    assert bool(result.findings) is enabled


@pytest.mark.parametrize("strict", [True, False])
def test_verify_strict_is_carried_on_the_config(strict):
    cfg = Config()
    cfg.verify.strict = strict
    assert cfg.verify.strict is strict


# ---------------------------------------------------------------------------
# the completeness meta-test: the part that stops this file going stale
# ---------------------------------------------------------------------------

#: options that are not enums, so they take value tests rather than a sweep of
#: actions. Named here so that adding one to the config is a deliberate act.
NON_ENUM_OPTIONS = {
    "policy": set(),
    "secrets": set(), "text": set(), "identity": set(), "platform": set(),
    "interfaces": set(), "vlans": set(), "circuits": set(),
    "ipv4": {"pool", "well_known_resolvers", "keep_networks"},
    "ipv6": {"pool", "well_known_resolvers", "keep_networks"},
    "macs": {"pool"},
    "verify": {"disable", "ignore_patterns"},
}


def _rule_keys(family: str) -> set[str]:
    """Every key a family section carries, read off the rule table."""
    return {"default"} | {n.replace("-", "_") for n in rule_names()
                          if family_of(n) == family}


@pytest.mark.parametrize("section,cls,covered", [
    ("policy", PolicyConfig, set(POLICY_FAMILIES)),
    ("secrets", RULE_SECTIONS["secrets"], _rule_keys("secrets")),
    ("text", RULE_SECTIONS["text"], _rule_keys("text")),
    ("identity", RULE_SECTIONS["identity"], _rule_keys("identity")),
    ("platform", RULE_SECTIONS["platform"], _rule_keys("platform")),
    ("interfaces", RULE_SECTIONS["interfaces"], _rule_keys("interfaces")),
    ("vlans", RULE_SECTIONS["vlans"], _rule_keys("vlans")),
    ("circuits", RULE_SECTIONS["circuits"], _rule_keys("circuits")),
    ("ipv4", IPv4Policy, {k for k, _ in V4_CELLS} | {"default"}),
    ("ipv6", IPv6Policy, {k for k, _ in V6_CELLS} | {"default"}),
    ("macs", MacPolicy, {"oui", "nic"}),
    ("verify", VerifyConfig, {"enabled", "strict"}),
])
def test_the_matrix_covers_every_option(section, cls, covered):
    """Add an option to the config and this fails until the sweep reaches it."""
    declared = {f.name for f in fields(cls)} - NON_ENUM_OPTIONS[section]
    assert declared == covered, (
        f"[{section}] options not in the matrix: {sorted(declared - covered)}; "
        f"in the matrix but not on the config: {sorted(covered - declared)}")


def test_the_matrix_covers_every_action():
    """Add a fifth action and this fails until every sweep reaches it."""
    for family in POLICY_FAMILIES:
        exercised = {a for f, a in POLICY_CELLS if f == family}
        assert exercised == set(ALLOWED[family]), family
    assert {a for _, a in V4_CELLS} == set(ACTIONS)
    assert {a for _, a in V6_CELLS} == set(ACTIONS)
    assert {a for pair in MAC_PAIRS for a in pair} == set(ACTIONS)
    for rule in RULE_SECTIONS["platform"].RULES:
        exercised = {a for r, a in PLATFORM_CELLS if r == rule}
        assert exercised == set(ALLOWED["platform"]), rule


def test_every_address_class_has_a_representative_sample():
    """A class with no sample is a class the sweep silently skips."""
    assert set(V4_SAMPLE) == set(V4_CLASS_NAMES)
    assert set(V6_SAMPLE) == set(V6_CLASS_NAMES)
