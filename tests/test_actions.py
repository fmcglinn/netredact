"""The four actions: what each one leaves behind, and for which family.

The rendering table in ``docs/design/actions-model.md`` is a contract -- other
tools read the markers -- so it is asserted literally.
"""

import pytest

from netredact import Config, Pseudonymiser, Result, sanitise_text
from netredact.config import RULE_FAMILIES
from netredact.pseudonymise import PREFIX, REDACT_CONST

from .conftest import SALT, policy, section

#: (key, pseudo, hash, redact) -- ``None`` means the cell is illegal.
#: Tags are the HMAC of the value under conftest.SALT, so they are fixed.
TABLE = [
    ("secrets",           None,                    "<SECRET-ced7b7>", "<REMOVED>"),
    ("description",       "desc-3cc015",           "<DESC-3cc015>",   "<DESCRIPTION-REMOVED>"),
    # an interface description is a description: the marker says what was taken
    # out, not which section took it out
    ("interface-description", "desc-3cc015",        "<DESC-3cc015>",   "<DESCRIPTION-REMOVED>"),
    # the pseudo token is `vlname`, never `vlan`: `VLAN-100` is a plausible real
    # VLAN name and would then read as already sanitised
    ("vlan-name",         "vlname-7ae0e1",         "<VLAN-7ae0e1>",   "<REMOVED>"),
    # the two circuits rules render IDENTICALLY from one value, and that is a
    # contract rather than a coincidence: a pseudowire named on a `connector`
    # line and defined under `mpls ldp` is found by different branches, and the
    # output only loads while both come out as the same name. Give either rule
    # a prefix of its own and these two rows stop matching.
    ("patch-name",        "circuit-7ed66c",        "<CIRCUIT-7ed66c>", "<REMOVED>"),
    ("pseudowire-name",   "circuit-7ed66c",        "<CIRCUIT-7ed66c>", "<REMOVED>"),
    ("acl-remark",        "desc-3cc015",           "<DESC-3cc015>",   "<DESCRIPTION-REMOVED>"),
    ("login-message",     "desc-3cc015",           "<DESC-3cc015>",   "<DESCRIPTION-REMOVED>"),
    ("location",          "desc-3cc015",           "<DESC-3cc015>",   "<DESCRIPTION-REMOVED>"),
    ("contact",           "desc-3cc015",           "<DESC-3cc015>",   "<DESCRIPTION-REMOVED>"),
    # a banner is replaced wholesale, so it takes the generic marker
    ("banner",            "desc-3cc015",           "<DESC-3cc015>",   "<REMOVED>"),
    ("serial-number",     "SN-79f13d",             "<SERIAL-79f13d>", "<REMOVED>"),
    ("license-udi",       "udi-f071fd",            "<UDI-f071fd>",    "<REMOVED>"),
    ("snmp-engineid",     "eid-7fcad6",            "<EID-7fcad6>",    "<REMOVED>"),
    ("ssh-public-key",    "key-e80962",            "<KEY-e80962>",    "<REMOVED>"),
    ("certificate-block", "cert-810f13",           "<CERT-810f13>",   "<REMOVED>"),
    ("pem-cert",          "cert-bda017",           "<CERT-bda017>",   "<REMOVED>"),
    ("hostnames",         "device-9d04bf",         "<HOST-a99da0>",   "redacted"),
    ("domains",           "example.com",           "<DOMAIN-71c499>", "example.invalid"),
    ("usernames",         "user-ca31",             "<USER-10c8cc>",   "user"),
    ("emails",            "user-ac24@example.com", "<EMAIL-dcd1ad>",  "user@example.invalid"),
]

#: the value each key above is rendered from
VALUE = {
    "secrets": "hunter2",
    "description": "a description", "acl-remark": "a description",
    "interface-description": "a description", "vlan-name": "ACME-CORP-DATA",
    "patch-name": "acme_ORD000000111222",
    "pseudowire-name": "acme_ORD000000111222",
    "login-message": "a description", "location": "a description",
    "contact": "a description", "banner": "a description",
    "serial-number": "FDO123", "license-udi": "PID:X,SN:Y",
    "snmp-engineid": "800000090300AABB", "ssh-public-key": "AAAAB3Nza...",
    "certificate-block": "3082...", "pem-cert": "MIIB...",
    "hostnames": "core-rtr-01", "domains": "northwind.test",
    "usernames": "netops", "emails": "noc@northwind.test",
}


@pytest.fixture
def p():
    return Pseudonymiser(SALT, Config())


@pytest.mark.parametrize("key,pseudo,hashed,redacted", TABLE,
                         ids=[row[0] for row in TABLE])
def test_rendering_table(p, key, pseudo, hashed, redacted):
    value = VALUE[key]
    assert p.render(key, "keep", value) == value
    assert p.render(key, "hash", value) == hashed
    assert p.render(key, "redact", value) == redacted
    if pseudo is None:
        with pytest.raises(ValueError, match="pseudo is not available for secrets"):
            p.render(key, "pseudo", value)
    else:
        assert p.render(key, "pseudo", value) == pseudo


@pytest.mark.parametrize("key", ["key-string-block", "pem-key", "enable-secret",
                                 "snmp-community", "junos-type9"])
def test_every_secrets_rule_renders_as_a_secret(p, key):
    assert p.render(key, "hash", "hunter2").startswith("<SECRET-")
    assert p.render(key, "redact", "hunter2") == "<REMOVED>"
    with pytest.raises(ValueError, match="pseudo is not available for secrets"):
        p.render(key, "pseudo", "hunter2")


def test_redact_constants_are_the_rfc_reserved_ones():
    assert REDACT_CONST == {"ipv4": "192.0.2.0", "ipv6": "2001:db8::",
                            "hostnames": "redacted", "domains": "example.invalid",
                            "usernames": "user", "emails": "user@example.invalid"}
    assert PREFIX["secrets"] == ("SECRET", None)


def test_render_rejects_an_unknown_action(p):
    with pytest.raises(ValueError, match="unknown action"):
        p.render("description", "delete", "x")


def test_render_rejects_an_unknown_key(p):
    with pytest.raises(ValueError, match="unknown key"):
        p.render("no-such-rule", "hash", "x")


def test_hash_and_pseudo_preserve_the_equality_relation(p):
    for action in ("pseudo", "hash"):
        a = p.render("description", action, "same text")
        b = p.render("description", action, "same text")
        c = p.render("description", action, "other text")
        assert a == b and a != c


def test_redact_destroys_the_equality_relation(p):
    a = p.render("description", "redact", "same text")
    c = p.render("description", "redact", "other text")
    assert a == c


def test_addresses_and_macs_render_per_class_and_per_half():
    cfg = Config()
    cfg.ipv4.default = "hash"
    cfg.ipv6.default = "redact"
    cfg.macs.oui = cfg.macs.nic = "hash"
    p = Pseudonymiser(SALT, cfg)
    assert p.render("ipv4", "hash", "128.66.16.130").startswith("<IP-")
    assert p.render("ipv6", "redact", "3fff:16::1") == "2001:db8::"
    assert p.render("macs", "hash", "0011.2233.4455").startswith("<MAC-")


# -- end to end -------------------------------------------------------------

#: free text that is NOT on an interface: a VRF description, an ACL remark and
#: an SNMP location. The description deliberately sits under `vrf definition`
#: rather than an interface -- inside an interface block it belongs to the
#: `interfaces` family, which is the point of IFACE_TEXT below.
TEXTY = ('vrf definition CUST\n description UPLINK TO ACME PTY LTD\n'
         ' remark allow noc\nsnmp-server location Level 5 Example St\n')

#: the same description, on a port
IFACE_TEXT = 'interface Gi0/0\n description UPLINK TO ACME PTY LTD\n'

#: a VLAN name, which is only a VLAN name because of the line above it
VLAN_TEXT = 'vlan 905\n name ACME-CORP-DATA\n'


@pytest.mark.parametrize("action,expected", [
    ("keep", "UPLINK TO ACME PTY LTD"),
    ("pseudo", "description desc-"),
    ("hash", "description <DESC-"),
    ("redact", "description <DESCRIPTION-REMOVED>"),
])
def test_text_family_end_to_end(action, expected):
    out = sanitise_text(TEXTY, policy(text=action), salt=SALT).text
    assert expected in out
    if action != "keep":
        assert "ACME" not in out


@pytest.mark.parametrize("action,expected", [
    ("keep", "UPLINK TO ACME PTY LTD"),
    ("pseudo", "description desc-"),
    ("hash", "description <DESC-"),
    ("redact", "description <DESCRIPTION-REMOVED>"),
])
def test_interfaces_family_end_to_end(action, expected):
    """An interface description renders as a description: same markers, own key."""
    out = sanitise_text(IFACE_TEXT, policy(interfaces=action), salt=SALT).text
    assert expected in out
    if action != "keep":
        assert "ACME" not in out


@pytest.mark.parametrize("action,expected", [
    ("keep", "name ACME-CORP-DATA"),
    ("pseudo", "name vlname-"),
    ("hash", "name <VLAN-"),
    ("redact", "name <REMOVED>"),
])
def test_vlans_family_end_to_end(action, expected):
    out = sanitise_text(VLAN_TEXT, policy(vlans=action), salt=SALT).text
    assert expected in out
    assert "vlan 905" in out, "the VLAN id is structure, not a name"
    if action != "keep":
        assert "ACME" not in out


def test_the_two_description_families_never_both_act():
    """One selector, split by scope: each description is claimed exactly once."""
    both = policy(text="redact", interfaces="hash")
    result = sanitise_text(TEXTY + IFACE_TEXT, both, salt=SALT)
    lines = result.text.splitlines()
    assert lines[1] == " description <DESCRIPTION-REMOVED>"      # the VRF one
    assert lines[-1].startswith(" description <DESC-")           # the port one
    assert result.counts["description"] == 1
    assert result.counts["interface-description"] == 1


@pytest.mark.parametrize("action,expected", [
    ("keep", "AAAAB3NzaC1yc2EAAAADAQABAAABgQDLongKeyMaterialHere1234567890"),
    ("pseudo", "ssh-rsa key-"),
    ("hash", "ssh-rsa <KEY-"),
    ("redact", "ssh-rsa <REMOVED>"),
])
def test_identity_family_end_to_end(arista, action, expected):
    out = sanitise_text(arista, policy(identity=action), salt=SALT).text
    assert expected in out


@pytest.mark.parametrize("action,expected", [
    ("keep", "enable secret 5 $1$mERr$M6KsMCsLPnvvKmnZkH3xF/"),
    ("hash", "enable secret 5 <SECRET-"),
    ("redact", "enable secret 5 <REMOVED>"),
])
def test_secrets_family_end_to_end(cisco, action, expected):
    out = sanitise_text(cisco, policy(secrets=action), salt=SALT).text
    assert expected in out


def test_a_kept_rule_is_still_counted(cisco):
    """The report promises a count of what was left, so keep still matches."""
    result = sanitise_text(cisco, Config(), salt=SALT)
    assert result.kept_counts["interface-description"] == 2
    assert result.kept_counts["location"] == 1
    assert result.kept_counts["certificate-block"] == 1
    assert result.counts["enable-secret"] == 2
    assert "interface-description" not in result.counts


# -- Result -----------------------------------------------------------------

def test_result_fields(cisco):
    result = sanitise_text(cisco, Config(), salt=SALT)
    assert isinstance(result, Result)
    assert result.text and result.vendor == "cisco"
    assert result.counts and result.kept_counts
    assert result.kept and isinstance(result.policy_summary, str)
    assert result.families["description"] == "text"
    assert result.families["ipv4"] == "ipv4"
    assert result.collisions == set()
    assert result.findings == []
    assert result.mapping == {}                    # nothing was pseudonymised
    assert result.lines == result.text.splitlines()
    assert result.redactions == sum(result.counts.values())


def test_kept_descriptions_is_gone(cisco):
    result = sanitise_text(cisco, Config(), salt=SALT)
    assert not hasattr(result, "kept_descriptions")


def test_redactions_counts_only_destroyed_material(cisco):
    """Pseudonymised addresses and names are substitutions, not destructions."""
    cfg = policy(hostnames="pseudo", domains="pseudo")
    cfg.ipv4.default = "pseudo"
    cfg.ipv4.pool = ["198.18.0.0/15"]
    result = sanitise_text(cisco, cfg, salt=SALT)
    assert result.counts["ipv4"] > 0 and result.counts["hostnames"] > 0
    assert result.redactions == sum(
        n for k, n in result.counts.items()
        if result.families[k] in RULE_FAMILIES)


def test_policy_summary_names_what_acts():
    assert sanitise_text("hostname x\n", Config(),
                         salt=SALT).policy_summary == \
        "secrets=redact, everything else kept"
    cfg = policy(secrets="keep")
    assert sanitise_text("hostname x\n", cfg,
                         salt=SALT).policy_summary == "everything kept"
    cfg = policy(text="hash")
    cfg.ipv4.default = "pseudo"
    cfg.macs.oui = "redact"
    cfg.macs.nic = "pseudo"
    summary = sanitise_text("hostname x\n", cfg, salt=SALT).policy_summary
    assert "secrets=redact" in summary and "text=hash" in summary
    assert "ipv4=pseudo" in summary and "macs=redact/pseudo" in summary
    assert "everything else kept" in summary


def test_policy_summary_reports_a_mixed_address_policy():
    cfg = Config()
    cfg.ipv4.default = "keep"
    cfg.ipv4.other_unicast = "pseudo"
    summary = sanitise_text("hostname x\n", cfg, salt=SALT).policy_summary
    assert "ipv4=keep (per class)" in summary


def test_policy_summary_reports_a_mixed_family_as_per_rule():
    """A family whose rules disagree cannot be named by one action."""
    cfg = section("text", "redact", banner="keep")
    summary = sanitise_text("hostname x\n", cfg, salt=SALT).policy_summary
    assert "text=redact (per rule)" in summary


# -- idempotence ------------------------------------------------------------

def _every_family(action: str) -> Config:
    cfg = policy(hostnames=action, domains=action, usernames=action,
                 emails=action,
                 **{family: action for family in RULE_FAMILIES})
    cfg.ipv4.default = action
    cfg.ipv6.default = action
    cfg.macs.oui = cfg.macs.nic = action
    return cfg


@pytest.mark.parametrize("action", ["hash", "redact"])
@pytest.mark.parametrize("name", ["cisco.cfg", "arista.cfg", "juniper.cfg",
                                  "edge.cfg", "edge-junos.cfg", "qk.cfg"])
def test_sanitising_sanitised_output_is_a_no_op(fixtures, name, action):
    cfg = _every_family(action)
    once = sanitise_text((fixtures / name).read_text(), cfg, salt=SALT).text
    assert sanitise_text(once, cfg, salt=SALT).text == once


def test_pseudo_addresses_deliberately_remap_on_a_second_pass(cisco):
    """Not a bug: the default pool includes real CGNAT space.

    Treating a pool address as 'already done' would leak a real 100.64/10
    address, so a pool address is re-mapped like any other. Everything whose
    pseudonym is recognisable -- names, descriptions, certificates -- is stable.
    """
    cfg = policy(text="pseudo", identity="pseudo", hostnames="pseudo",
                 domains="pseudo", usernames="pseudo", emails="pseudo")
    cfg.ipv4.default = "pseudo"
    cfg.ipv6.default = "pseudo"
    once = sanitise_text(cisco, cfg, salt=SALT).text
    twice = sanitise_text(once, cfg, salt=SALT).text
    assert twice != once
    changed = {a for a, b in zip(once.splitlines(), twice.splitlines(),
                                 strict=True) if a != b}
    assert changed, "expected the address lines to move"
    # every difference is an address; nothing else re-renders
    import re
    assert all(re.search(r"\d+\.\d+\.\d+\.\d+|[0-9a-f]{1,4}:", line)
               for line in changed)
    for stable in ("desc-", "device-", "example.com", "cert-", "user-"):
        assert once.count(stable) == twice.count(stable), stable


def test_a_marker_is_never_re_marked():
    p = Pseudonymiser(SALT, Config())
    for key, value in (("secrets", "<SECRET-abc123>"),
                       ("description", "<DESC-abc123>"),
                       ("description", "<DESCRIPTION-REMOVED>"),
                       ("description", "desc-abc123"),
                       ("patch-name", "<REMOVED>"),
                       ("pseudowire-name", "<REMOVED>"),
                       ("serial-number", "<REMOVED>"),
                       ("hostnames", "device-abc123"),
                       ("hostnames", "redacted"),
                       ("domains", "example.invalid"),
                       ("usernames", "user-ab12"),
                       ("ipv6", "2001:0db8::")):
        assert p.is_rendered(key, value), (key, value)
        for action in ("hash", "redact"):
            assert p.render(key, action, value) == value


def test_a_quoted_marker_is_also_recognised():
    p = Pseudonymiser(SALT, Config())
    assert p.is_rendered("secrets", '"<REMOVED>"')
