"""The rule catalogue: one interface for metadata and traversal."""

import ipaddress
from collections import Counter

import pytest

from netredact import FAMILIES, Config, CustomRule, RuleCatalogue, RuleReplacement
from netredact import rules as R
from netredact.addresses import V4_CLASS_NAMES, V6_CLASS_NAMES
from netredact.pseudonymise import is_mask_like


def inventory(custom=()):
    return RuleCatalogue.builtins().configured(custom).inventory()


def test_inventory_is_immutable_and_rule_names_are_unique():
    rules = inventory()
    assert isinstance(rules, tuple)
    assert len({info.name for info in rules}) == len(rules)
    with pytest.raises(AttributeError):
        rules[0].name = "changed"


def test_every_rule_has_the_expected_family():
    counts = Counter(info.family for info in inventory())
    assert counts == {"secrets": 48, "text": 11, "locations": 3,
                      "identity": 11, "platform": 4,
                      "interfaces": 6, "vlans": 1, "circuits": 2}
    assert set(counts) <= set(FAMILIES)


@pytest.mark.parametrize("name,family", [
    ("enable-secret", "secrets"), ("junos-type9", "secrets"),
    ("pem-key", "secrets"), ("location", "locations"), ("banner", "text"),
    ("snmp-engineid", "identity"), ("ssh-public-key", "identity"),
    ("pem-cert", "identity"), ("hardware-model", "platform"),
    ("interface-description", "interfaces"), ("vlan-name", "vlans"),
    ("patch-name", "circuits"), ("pseudowire-name", "circuits"),
    ("huawei-ont-credential", "secrets"), ("huawei-cipher", "secrets"),
    ("huawei-ont-serial", "identity"), ("huawei-snmp-engineid", "identity"),
    ("huawei-ont-desc", "interfaces"), ("huawei-profile-name", "text"),
])
def test_inventory_names_each_rules_family(name, family):
    assert next(info.family for info in inventory() if info.name == name) == family


def test_rule_names_never_collide_with_an_address_class():
    classes = set(V4_CLASS_NAMES) | set(V6_CLASS_NAMES)
    assert classes.isdisjoint({info.name for info in inventory()})


def test_inventory_carries_descriptive_metadata():
    rules = {info.name: info for info in inventory()}
    assert rules["interface-description"].required_scope == "interfaces"
    assert rules["description"].excluded_scopes == ("interfaces",)
    assert rules["interface-comment"].required_scope == "interfaces"
    assert rules["comment"].excluded_scopes == ("interfaces",)
    assert rules["patch-name"].vendor == "arista"
    assert rules["routeros-snmp-community"].vendor == "mikrotik"
    assert rules["huawei-ont-credential"].vendor == "huawei"
    assert rules["routeros-snmp-community"].required_scope == "snmp-community"
    assert rules["enable-secret"].vendor is None
    assert rules["pem-key"].end_pattern
    assert rules["enable-secret"].pattern


def test_configured_catalogue_merges_custom_rules_without_mutating_builtins():
    builtins = RuleCatalogue.builtins()
    custom = CustomRule(name="acme-key", pattern=r"\s*acme\s+key\s+")
    configured = builtins.configured([custom])
    assert configured.inventory()[-1].name == "acme-key"
    assert configured.inventory()[-1].custom
    assert "acme-key" not in {info.name for info in builtins.inventory()}


def test_configured_catalogue_rejects_duplicate_names():
    with pytest.raises(ValueError, match="duplicate rule name"):
        RuleCatalogue.builtins().configured([
            CustomRule(name="banner", pattern=r"banner\s+")])


@pytest.mark.parametrize("pattern,line,values", [
    (r"\s*acme\s+key\s+", "acme key hunter2 trailing", ["hunter2"]),
    (r"^\s*acme\s+(\S+)\s+(\S+)$", "acme one two", ["one", "two"]),
    (r"\s*acme\s+key\s+%VAL%", 'acme key "two words"', ["two words"]),
])
def test_custom_pattern_forms_are_hidden_behind_transform(pattern, line, values):
    catalogue = RuleCatalogue.builtins().configured([
        CustomRule(name="acme", pattern=pattern)])
    seen = []

    def replace(hit):
        if hit.name == "acme":
            seen.append(hit.value)
        return RuleReplacement.keep()

    catalogue.transform([line], replace=replace)
    assert sorted(seen) == sorted(values)


def test_transform_owns_scope_order_and_structural_splicing():
    hits = []

    def replace(hit):
        hits.append((hit.name, hit.value))
        return RuleReplacement.with_text(f"<{hit.name}>")

    output = RuleCatalogue.builtins().transform([
        "interface Gi0/0", " description customer edge",
        "username admin secret hunter2", 'key "$9$abcd";',
    ], replace=replace, finish_line=lambda line: line + "!")
    assert output == ["interface Gi0/0!", " description <interface-description>!",
                      "username admin secret <username-secret>!",
                      'key "<quoted-key>";!']
    assert ("description", "customer edge") not in hits


def test_transform_hides_snmp_host_token_selection():
    seen = []

    def replace(hit):
        seen.append((hit.name, hit.value))
        return RuleReplacement.with_text("MASKED")

    out = RuleCatalogue.builtins().transform(
        ["snmp-server host 10.0.0.1 version 2c public"], replace=replace)
    assert out == ["snmp-server host 10.0.0.1 version 2c MASKED"]
    assert ("snmp-host", "public") in seen


def test_kept_banner_falls_through_but_active_unchanged_banner_does_not():
    catalogue = RuleCatalogue.builtins()
    lines = ["banner motd ^C", "password hunter2", "^C"]
    kept = catalogue.transform(
        lines, replace=lambda hit: (RuleReplacement.keep() if hit.name == "banner"
                                    else RuleReplacement.with_text("MASKED")))
    active = catalogue.transform(
        lines, replace=lambda hit: (RuleReplacement.unchanged() if hit.name == "banner"
                                    else RuleReplacement.with_text("MASKED")))
    assert kept == ["banner motd ^C", "password MASKED", "^C"]
    assert active == lines


def test_verification_view_preserves_alignment_and_masks_multiline_bodies():
    catalogue = RuleCatalogue.builtins()
    pem = ["-----BEGIN RSA PRIVATE KEY-----", "payload", "-----END RSA PRIVATE KEY-----"]
    view = catalogue.verification_view(pem, blind=lambda info: info.name == "pem-key")
    assert view == [pem[0], " " * len(pem[1]), pem[2]]
    banner = ["banner motd ^C", "sensitive words", "^C"]
    view = catalogue.verification_view(
        banner, blind=lambda info: info.name == "banner")
    assert view == [banner[0], " " * len(banner[1]), banner[2]]


#: one wrapped RouterOS command, spread over three physical lines
WRAPPED = ["/interface wireless security-profiles",
           "add name=guest-wifi \\",
           '    wpa2-pre-shared-key="Winter Harbour \\',
           '    Lantern 77"']


def test_transform_joins_a_wrapped_command_before_any_rule_sees_it():
    hits = []

    def replace(hit):
        hits.append((hit.name, hit.value))
        return RuleReplacement.with_text("MASKED")

    out = RuleCatalogue.builtins().transform(WRAPPED, replace=replace)
    assert out == ["/interface wireless security-profiles",
                   'add name=guest-wifi wpa2-pre-shared-key="MASKED"']
    # the whole quoted value, not the fragment the first physical line carried
    assert ("routeros-pre-shared-key", "Winter Harbour Lantern 77") in hits


def test_joining_is_idempotent_so_verification_stays_line_aligned():
    """`verify` normalises its own input this way and then zips the view
    against it, so joining twice has to be joining once."""
    once = R.join_continuations(WRAPPED)
    assert R.join_continuations(once) == once
    view = RuleCatalogue.builtins().verification_view(
        once, blind=lambda info: True)
    assert len(view) == len(once)


def test_a_wrapped_line_at_the_end_of_a_file_continues_nothing():
    """There is no next line, so the backslash is a character of the value."""
    lines = ["add name=x comment=y \\"]
    assert R.join_continuations(lines) == lines


#: (wrapped source, the one logical line it is)
#:
#: `/export` wraps at whatever column it runs out of room at, NOT at a token
#: boundary -- these are real shapes from a `/routing filter` section. Every
#: wrap case here once joined with a space, which did not merely reformat the
#: file: it corrupted it. `bgp-path- prepend` is not a keyword and
#: `orig in-inband-mgmt` is not a list name, so the output no longer loaded.
#: The bug survived a full suite because every case written before this was a
#: token boundary, where a space happens to be right.
ARBITRARY_WRAPS = [
    # mid-token, inside a quoted string
    (['add chain=to-corp rule="if (dst == 0.0.0.0/0) {set bgp-path-\\',
      '    prepend 1; accept}"'],
     'add chain=to-corp rule="if (dst == 0.0.0.0/0) {set bgp-path-prepend 1; '
     'accept}"'),
    # mid-WORD, inside a quoted string
    (['add chain=from-oob rule="set bgp-large-communities orig\\',
      '    in-inband-mgmt;"'],
     'add chain=from-oob rule="set bgp-large-communities origin-inband-mgmt;"'),
    # immediately after the `=`, with no space to preserve
    (["set chain=block-default rule=\\", '    "if (dst == 0.0.0.0/0) {reject}"'],
     'set chain=block-default rule="if (dst == 0.0.0.0/0) {reject}"'),
    # a separator the export DID write survives, because the line up to the
    # backslash is kept verbatim
    (["add name=corp-wifi \\", "    wpa2-pre-shared-key=hunter2"],
     "add name=corp-wifi wpa2-pre-shared-key=hunter2"),
    # a literal `\n` escape is content, and no space may appear in front of it
    (['add rule="set bgp-local-pref 100;\\', "    \\naccept\""],
     'add rule="set bgp-local-pref 100;\\naccept"'),
]


@pytest.mark.parametrize("source,joined", ARBITRARY_WRAPS,
                         ids=range(len(ARBITRARY_WRAPS)))
def test_a_wrap_is_undone_with_nothing_in_its_place(source, joined):
    """Whatever separator the wrap needs, the export wrote it before the
    backslash -- so the two halves are concatenated, never spaced."""
    assert R.join_continuations(source) == [joined]


def test_masks_are_never_a_rule_target():
    assert R.IPV4_RE.fullmatch("255.255.255.0")

    def mask(text: str) -> bool:
        return is_mask_like(int(ipaddress.IPv4Address(text)))

    assert mask("255.255.255.0") and mask("0.0.0.255") and mask("0.0.0.0")
    assert not mask("10.20.30.1")


def test_configuration_has_no_legacy_descriptions_section():
    assert not hasattr(Config(), "descriptions")


# ---------------------------------------------------------------------------
# Huawei wraps, which carry no marker at all. `display current-configuration`
# breaks at the width of the collecting session and the remainder arrives at
# column zero, so the evidence has to be assembled from the command keyword,
# an unclosed quoted value and that column-zero remainder together -- see
# `rules._HUAWEI_WRAPPED`. Each piece is here because dropping it either
# abandons half a credential or swallows the next command whole.
# ---------------------------------------------------------------------------

#: (source lines, the one logical line they are) -- real shapes from an OLT
#: capture, with the values replaced
HUAWEI_WRAPS = [
    # the common case: the break lands immediately after `desc "`, because
    # everything in front of it is a fixed-width prefix
    ([' ont add 0 0 sn-auth "48575443AAAA0001" password-auth "%YQ%" omci desc "',
      'Bob\'s Bakery Pty Ltd, 50M"'],
     ' ont add 0 0 sn-auth "48575443AAAA0001" password-auth "%YQ%" omci desc '
     '"Bob\'s Bakery Pty Ltd, 50M"'),
    # the break lands INSIDE a cipher blob, which is the case that leaves a
    # credential in the output if it is not joined
    ([' ont add 0 1 sn-auth "4857544" password-auth "%#%#NwOntPass%F&"=q;s',
      'Z![l;4wuBEAcXQBS15%#%#" omci ont-lineprofile-id 305'],
     ' ont add 0 1 sn-auth "4857544" password-auth "%#%#NwOntPass%F&"=q;s'
     'Z![l;4wuBEAcXQBS15%#%#" omci ont-lineprofile-id 305'),
    # and twice over, because a value long enough to wrap once can wrap again.
    # A remainder is at column zero -- that is what distinguishes it from the
    # next command, every one of which is indented.
    ([' service-port desc 2 description "ORD-11223, Bob\'s ',
      'Bakery Pty Ltd - ',
      'L2, 50M"'],
     ' service-port desc 2 description "ORD-11223, Bob\'s Bakery Pty Ltd - '
     'L2, 50M"'),
]


@pytest.mark.parametrize("source,joined", HUAWEI_WRAPS,
                         ids=range(len(HUAWEI_WRAPS)))
def test_a_huawei_wrap_is_undone_with_nothing_in_its_place(source, joined):
    """The break fell inside a value, and a value has no separator in it."""
    assert R.join_continuations(source) == [joined]


def test_an_ont_command_is_unfinished_until_it_names_its_service_profile():
    """The second way of seeing a wrap, and the only one that works on a
    `%#%#` credential: those blobs carry bare quotes, so a wrap inside one can
    land on a line whose quotes BALANCE. `ont add` always names both profiles,
    so the grammar says the line is unfinished when the quotes cannot.

    It has to be the SECOND profile. Stopping at `ont-lineprofile-id` joined
    the credential back together and left a third fragment -- carrying the
    customer -- standing on its own, where `huawei-ont-desc` cannot see it.
    """
    # six quotes on the first line and four of them payload, so the count
    # BALANCES and `_quote_open` sees a finished line. Only the grammar does
    # not.
    source = [' ont add 1 0 sn-auth "4857" password-auth "%#%#Pa"ss"q;%#%#" omci ',
              'ont-lineprofile-id 310 ',
              'ont-srvprofile-id 110 desc "Northwind Retail Group, 100M" ']
    assert not R._quote_open(source[0])
    assert R.join_continuations(source) == [
        ' ont add 1 0 sn-auth "4857" password-auth "%#%#Pa"ss"q;%#%#" omci '
        'ont-lineprofile-id 310 '
        'ont-srvprofile-id 110 desc "Northwind Retail Group, 100M" ']

    # and the point of joining it: both values are now reachable
    hits = []

    def replace(hit):
        hits.append(hit.name)
        return RuleReplacement.with_text("MASKED")

    RuleCatalogue.builtins().transform(source, replace=replace)
    assert "huawei-ont-credential" in hits and "huawei-ont-desc" in hits


def test_a_complete_huawei_command_never_swallows_the_next_one():
    """A Huawei cipher blob carries arbitrary punctuation, bare quotes
    included, so an odd quote count is NOT on its own evidence that the line
    was wrapped. The indent is what settles it: every command inside a
    `[...-config]` section is indented and no wrap remainder is."""
    source = [' terminal user name history_password root *J$1a$oSXP"0f!$*$*',
              ' traffic table ip index 40 name "biz-20m-up" cir 5120']
    assert R.join_continuations(source) == source


def test_a_huawei_wrap_is_not_joined_across_the_files_own_structure():
    """`#` separates two sections and `[...]` opens one. Neither is the
    remainder of anything, whatever the line above it left open."""
    for following in ("#", "[vlan-config]", "  <gpon-0/1>", "!"):
        source = [' ont add 0 0 sn-auth "4857" desc "', following]
        assert R.join_continuations(source) == source


def test_another_dialect_is_never_joined_on_an_unbalanced_quote():
    """The command keyword is the guard, and it is needed: an unbalanced quote
    is perfectly ordinary in a banner body, and joining one would mangle it."""
    source = ['banner motd ^', '  Welcome to "ACME', '^']
    assert R.join_continuations(source) == source


def test_huawei_joining_is_idempotent_so_verification_stays_line_aligned():
    source = HUAWEI_WRAPS[0][0]
    once = R.join_continuations(source)
    assert R.join_continuations(once) == once
    view = RuleCatalogue.builtins().verification_view(
        once, blind=lambda info: True)
    assert len(view) == len(once)
