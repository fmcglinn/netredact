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
    assert counts == {"secrets": 33, "text": 5, "locations": 2,
                      "identity": 7, "platform": 4,
                      "interfaces": 1, "vlans": 1, "circuits": 2}
    assert set(counts) <= set(FAMILIES)


@pytest.mark.parametrize("name,family", [
    ("enable-secret", "secrets"), ("junos-type9", "secrets"),
    ("pem-key", "secrets"), ("location", "locations"), ("banner", "text"),
    ("snmp-engineid", "identity"), ("ssh-public-key", "identity"),
    ("pem-cert", "identity"), ("hardware-model", "platform"),
    ("interface-description", "interfaces"), ("vlan-name", "vlans"),
    ("patch-name", "circuits"), ("pseudowire-name", "circuits"),
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
    assert rules["patch-name"].vendor == "arista"
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


def test_masks_are_never_a_rule_target():
    assert R.IPV4_RE.fullmatch("255.255.255.0")

    def mask(text: str) -> bool:
        return is_mask_like(int(ipaddress.IPv4Address(text)))

    assert mask("255.255.255.0") and mask("0.0.0.255") and mask("0.0.0.0")
    assert not mask("10.20.30.1")


def test_configuration_has_no_legacy_descriptions_section():
    assert not hasattr(Config(), "descriptions")
