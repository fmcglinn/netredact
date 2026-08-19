"""The rule table: what it selects, and which family it says the material is."""

import ipaddress
import re
from collections import Counter

import pytest

from netredact import FAMILIES, Config, CustomRule, build_rules, family_of, rule_names
from netredact import rules as R
from netredact.addresses import V4_CLASS_NAMES, V6_CLASS_NAMES
from netredact.pseudonymise import is_mask_like


def test_there_are_forty_five_uniquely_named_rules():
    names = rule_names()
    assert len(names) == 45
    assert len(set(names)) == 45


def test_every_rule_has_a_family_and_the_split_is_as_designed():
    names = rule_names()
    counts = Counter(family_of(name) for name in names)
    assert counts == {"secrets": 32, "text": 7, "identity": 6}
    assert set(counts) <= set(FAMILIES)


def test_family_of_rejects_an_unknown_name():
    with pytest.raises(KeyError, match="unknown rule"):
        family_of("no-such-rule")


@pytest.mark.parametrize("name,family", [
    ("enable-secret", "secrets"),
    ("snmp-community", "secrets"),
    ("license-entitlement-key", "secrets"),
    ("junos-type9", "secrets"),
    ("crypt-hash", "secrets"),
    ("key-string-block", "secrets"),
    ("pem-key", "secrets"),
    ("unsupported-transceiver", "secrets"),
    # refiled out of secrets: free text, not credentials
    ("location", "text"),
    ("contact", "text"),
    ("junos-location-body", "text"),
    ("description", "text"),
    ("acl-remark", "text"),
    ("login-message", "text"),
    ("banner", "text"),
    # refiled into identity: they identify a device, they are not secrets
    ("snmp-engineid", "identity"),
    ("ssh-public-key", "identity"),
    ("serial-number", "identity"),
    ("license-udi", "identity"),
    ("certificate-block", "identity"),
    ("pem-cert", "identity"),
])
def test_rule_families(name, family):
    assert family_of(name) == family


def test_pem_block_is_split_into_a_key_and_a_certificate_half():
    blocks = {name: (start, end) for start, end, name, _f in R.BLOCK_STARTS}
    assert set(blocks) >= {"pem-key", "pem-cert"}
    key_start = blocks["pem-key"][0]
    cert_start = blocks["pem-cert"][0]
    assert key_start.search("-----BEGIN RSA PRIVATE KEY-----")
    assert key_start.search("-----BEGIN DH PARAMETERS-----")
    assert not key_start.search("-----BEGIN CERTIFICATE-----")
    assert cert_start.search("-----BEGIN CERTIFICATE-----")
    assert not cert_start.search("-----BEGIN RSA PRIVATE KEY-----")


def test_rule_names_never_collide_with_an_address_class():
    """[overrides] is flat, so a rule name must be unambiguous."""
    classes = set(V4_CLASS_NAMES) | set(V6_CLASS_NAMES)
    assert classes.isdisjoint(set(rule_names()))


# -- pattern compilation ----------------------------------------------------

def test_build_rules_takes_no_disable_argument():
    """`keep` is an action, so a rule is never removed from the table."""
    with pytest.raises(TypeError):
        build_rules(disable=["location"])


def test_build_rules_appends_custom_rules_after_the_builtins():
    custom = CustomRule(name="acme-key", pattern=r"\s*acme\s+key\s+", family="secrets")
    built = build_rules([custom])
    assert [r.name for r in built[:-1]] == [n for n, *_ in R.BUILTIN]
    assert built[-1].name == "acme-key"
    assert built[-1].custom is True


def test_a_pattern_with_no_groups_is_a_prefix():
    """The value matcher, the brace guard and the tail are appended centrally."""
    rule = build_rules([CustomRule(name="p", pattern=r"\s*acme\s+key\s+")])[-1]
    assert rule.targets == (2,)
    m = rule.regex.match("acme key hunter2 trailing")
    assert m.group(2) == "hunter2"


def test_a_pattern_with_groups_declares_its_own_targets():
    rule = build_rules([CustomRule(name="g", pattern=r"^\s*acme\s+(\S+)\s+(\S+)$")])[-1]
    assert rule.targets == (1, 2)
    m = rule.regex.match("acme one two")
    assert (m.group(1), m.group(2)) == ("one", "two")


def test_val_macro_expands_to_a_capturing_value_matcher():
    rule = build_rules([CustomRule(name="v", pattern=r"\s*acme\s+key\s+%VAL%")])[-1]
    assert R.VAL_MACRO not in rule.regex.pattern
    assert rule.targets == (1,), "%VAL% must count as declaring the target"
    assert rule.regex.match("acme key hunter2").group(1) == "hunter2"
    assert rule.regex.match('acme key "two words"').group(1) == '"two words"'


def test_every_builtin_rule_has_at_least_one_target():
    for rule in build_rules():
        assert rule.targets, rule.name
        assert rule.regex.groups >= max(rule.targets), rule.name


def test_only_snmp_host_has_a_handler():
    handlers = {r.name: r.handler for r in build_rules() if r.handler}
    assert handlers == {"snmp-host": "snmp-host"}


def test_stanza_scoped_rules():
    stanzas = {r.name: r.stanza for r in build_rules() if r.stanza}
    assert stanzas == {"junos-community": "snmp", "junos-location-body": "location"}


def test_junos_keywords_are_exported_and_used_as_a_negative_lookahead():
    assert "ascii-text" in R.JUNOS_KEYWORDS
    assert "prefer" in R.IOS_KEYWORDS
    rule = next(r for r in build_rules() if r.name == "auth-key")
    assert rule.regex.match('authentication-key "$9$abc"')
    assert not rule.regex.match("authentication-key type md5")


def test_blob_rules_capture_the_secret_and_not_the_context():
    blobs = {r.name: r for r in R.BLOB_RULES}
    m = blobs["ssh-public-key"].regex.search(
        "username x ssh-key ssh-rsa AAAAB3NzaC1yc2EAAAA rest")
    assert m.group(1) == "AAAAB3NzaC1yc2EAAAA"
    assert "ssh-rsa" not in m.group(1)
    m = blobs["junos-type9"].regex.search('key "$9$abcdEFGH";')
    assert m.group(1) == "$9$abcdEFGH"


def test_a_bare_license_udi_heading_is_not_a_match():
    """The optional colon is atomic, so a heading with no data never matches."""
    udi = next(r for r in R.BLOB_RULES if r.name == "license-udi")
    assert not udi.regex.search("! License UDI:")
    assert udi.regex.search("! License UDI: PID:ISR4331/K9,SN:FDO1234ABCD")


def test_description_rules_are_ordinary_text_rules():
    """_descriptions() is gone: they go through the normal path."""
    assert not hasattr(Config(), "descriptions")
    names = {name for name, _rx in R.DESCRIPTION_RULES}
    assert names == {"description", "acl-remark", "login-message"}
    assert all(family_of(n) == "text" for n in names)


def test_masks_are_never_a_rule_target():
    """Netmasks are structural: no rule may claim one."""
    assert R.IPV4_RE.fullmatch("255.255.255.0")     # it is still an address shape

    def mask(text: str) -> bool:
        return is_mask_like(int(ipaddress.IPv4Address(text)))

    assert mask("255.255.255.0") and mask("0.0.0.255") and mask("0.0.0.0")
    assert not mask("10.20.30.1")


def test_stanza_open_and_close_recognise_junos_braces():
    assert R.STANZA_OPEN.match("system {").group(1) == "system"
    assert R.STANZA_OPEN.match("    location {").group(1) == "location"
    assert R.STANZA_CLOSE.match("}")
    assert not R.STANZA_OPEN.match("location Level 5, 500 Example St")


def test_banner_regex_captures_the_kind_and_the_rest():
    m = R.BANNER_RE.match("banner motd ^C")
    assert m.group(1) == "motd" and m.group(2) == "^C"
    assert R.BANNER_RULE == ("banner", "text")


def test_val_matches_quotes_and_stops_at_a_junos_terminator():
    assert re.fullmatch(R.VAL, '"two words"')
    assert re.fullmatch(R.VAL, "'two words'")
    assert re.match(R.VAL, "value;").group(0) == "value"
