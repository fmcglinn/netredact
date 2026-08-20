"""End-to-end coverage for opt-in privacy controls."""

import pytest

from netredact import Config, sanitise_text
from netredact.config import ConfigError
from netredact.verify import verify

SALT = b"deterministic-test-salt-do-not-use-in-anger"


def test_locations_are_an_independent_policy_family():
    cfg = Config.from_dict({"locations": {"default": "redact"}})
    text = (
        "snmp-server location Northwind DC1\n"
        "set system location building GNC\n"
        "set system location floor 4\n"
    )

    result = sanitise_text(text, cfg, salt=SALT)

    assert "Northwind" not in result.text
    assert "GNC" not in result.text
    assert "location <DESCRIPTION-REMOVED>" in result.text
    assert "building <DESCRIPTION-REMOVED>" in result.text


def test_old_text_location_key_reports_its_new_home():
    with pytest.raises(ConfigError, match=r"location is a rule in \[locations\]"):
        Config.from_dict({"text": {"location": "redact"}})


def test_operational_names_act_per_type_and_terms_inherit_parent_action():
    cfg = Config.from_dict({
        "operational-names": {
            "default": "keep",
            "acl-firewall-filter": "pseudo",
            "policy-statement": "pseudo",
        }
    })
    text = (
        "ip access-list extended CUSTOMER-IN\n"
        " ip access-group CUSTOMER-IN in\n"
        "set firewall family inet filter EDGE-IN term allow-customer then accept\n"
        "set policy-options policy-statement CUSTOMER-EXPORT term send-customer then accept\n"
        "set protocols bgp group TRANSIT export CUSTOMER-EXPORT\n"
        "route-map CUSTOMER-EXPORT permit 10\n"
    )

    result = sanitise_text(text, cfg, salt=SALT)

    assert "CUSTOMER-IN" not in result.text
    assert result.lines[0].split()[-1] == result.lines[1].split()[2]
    assert "EDGE-IN" not in result.text
    assert "allow-customer" not in result.text
    assert "CUSTOMER-EXPORT" in result.text  # route-map remains independently kept
    policy_lines = [line for line in result.lines if "policy-" in line]
    assert len(policy_lines) == 2
    assert "send-customer" not in result.text


def test_every_operational_name_type_has_an_independent_option():
    cfg = Config.from_dict({
        "operational-names": {
            "acl-firewall-filter": "hash",
            "route-map": "hash",
            "prefix-list": "hash",
            "policy-statement": "hash",
            "vrf": "hash",
            "peer-group": "hash",
        }
    })

    assert cfg.operational_names.action("acl-firewall-filter") == "hash"
    assert cfg.operational_names.action("route-map") == "hash"
    assert cfg.operational_names.action("prefix-list") == "hash"
    assert cfg.operational_names.action("policy-statement") == "hash"
    assert cfg.operational_names.action("vrf") == "hash"
    assert cfg.operational_names.action("peer-group") == "hash"


def test_as_numbers_are_consistent_and_preserve_notation_and_class():
    cfg = Config.from_dict({"as-numbers": {"default": "pseudo"}})
    text = (
        "router bgp 64513\n"
        " neighbor 192.0.2.1 remote-as 64513\n"
        " neighbor 192.0.2.2 local-as 2.1\n"
        " set as-path prepend 64513 131073 64513\n"
        " set community 64513:100 additive\n"
    )

    result = sanitise_text(text, cfg, salt=SALT)
    lines = result.lines
    mapped_private = lines[0].split()[-1]

    assert mapped_private != "64513"
    assert mapped_private == lines[1].split()[-1] == lines[3].split()[-1]
    assert 64512 <= int(mapped_private) <= 65534
    mapped_dotted = lines[2].split()[-1]
    assert "." in mapped_dotted
    high, low = (int(part) for part in mapped_dotted.split("."))
    mapped_plain = int(lines[3].split()[4])
    assert mapped_plain != 131073
    assert high * 65536 + low == mapped_plain
    assert "64513:100" in lines[4]  # communities are deliberately out of scope


def test_reserved_as_numbers_remain_protocol_constants():
    cfg = Config.from_dict({"as-numbers": {"default": "pseudo"}})
    result = sanitise_text(
        "neighbor 192.0.2.1 remote-as 23456\n", cfg, salt=SALT)
    assert result.text.endswith("remote-as 23456\n")


@pytest.mark.parametrize("source", [
    "aabb-ccdd-eeff",
    "aa-bb-cc-dd-ee-ff",
])
def test_unambiguous_mac_spellings_are_processed_globally(source):
    cfg = Config.from_dict({"macs": {"oui": "redact", "nic": "pseudo"}})
    result = sanitise_text(f"permit host {source}\n", cfg, salt=SALT)
    assert source not in result.text
    assert not result.findings


def test_bare_mac_is_processed_only_in_mac_grammar():
    cfg = Config.from_dict({"macs": {"oui": "redact", "nic": "pseudo"}})
    result = sanitise_text(
        "mac-address aabbccddeeff\nserial aabbccddeeff\n", cfg, salt=SALT)
    assert "mac-address aabbccddeeff" not in result.text
    assert "serial aabbccddeeff" in result.text


def test_mac_verification_flags_a_recognisable_survivor_when_policy_acts():
    cfg = Config.from_dict({"macs": {"oui": "redact", "nic": "pseudo"}})
    findings = verify(["permit host aa-bb-cc-dd-ee-ff"], cfg)
    assert [(finding.line, finding.check) for finding in findings] == [
        (1, "mac-left")
    ]


@pytest.mark.parametrize(("raw", "config", "check"), [
    ("route-map CUSTOMER permit 10",
     {"operational-names": {"route-map": "pseudo"}}, "operational-name-left"),
    ("neighbor 192.0.2.1 remote-as 64513",
     {"as-numbers": {"default": "pseudo"}}, "as-number-left"),
    ("snmp-server location Northwind DC1",
     {"locations": {"default": "redact"}}, "location-left"),
])
def test_strict_verification_catches_new_policy_survivors(raw, config, check):
    findings = verify([raw], Config.from_dict(config))
    assert check in {finding.check for finding in findings}


def test_new_policy_outputs_pass_their_own_verification():
    cfg = Config.from_dict({
        "operational-names": {"default": "pseudo"},
        "as-numbers": {"default": "pseudo"},
        "locations": {"default": "redact"},
    })
    result = sanitise_text(
        "route-map CUSTOMER permit 10\n"
        "neighbor PEERS peer group\n"
        "neighbor 192.0.2.1 remote-as 64513\n"
        "snmp-server location Northwind DC1\n",
        cfg, salt=SALT)
    assert result.findings == []


def test_peer_group_references_in_address_family_are_actioned():
    cfg = Config.from_dict({
        "operational-names": {"peer-group": "pseudo"},
        "ipv4": {"default": "hash"},
    })
    text = (
        "address-family ipv4\n"
        "  neighbor TRANSIT-CORE activate\n"
        "  neighbor TRANSIT-CORE route-map IMPORT-POLICY in\n"
        "  neighbor MGMT-PEERS maximum-routes 0\n"
        "  neighbor iBGP activate\n"
        "  neighbor 192.0.2.1 activate\n"
        "  neighbor 2001:db8::1 activate\n"
        "  neighbor 192.0.2.2 peer group iBGP\n"
        "  neighbor edge-router.example.test peer group EXTERNAL\n"
    )

    result = sanitise_text(text, cfg, salt=SALT)

    lines = result.text.splitlines()
    assert lines[1].startswith("  neighbor peer-group-")
    assert lines[2].split()[1] == lines[1].split()[1]
    assert lines[3].startswith("  neighbor peer-group-")
    assert lines[4].startswith("  neighbor peer-group-")
    assert lines[5].startswith("  neighbor <IP-")
    assert lines[6] == "  neighbor 2001:db8::1 activate"
    assert lines[7].startswith("  neighbor <IP-")
    assert " peer group peer-group-" in lines[7]
    assert lines[8].startswith("  neighbor edge-router.example.test peer group peer-group-")


def test_junos_brace_terms_inherit_their_parent_type_and_policy_lists_match():
    cfg = Config.from_dict({"operational-names": {
        "acl-firewall-filter": "pseudo",
        "policy-statement": "pseudo",
    }})
    text = (
        "policy-options {\n"
        "  policy-statement CUSTOMER-OUT {\n"
        "    term customer-routes {\n"
        "    }\n"
        "  }\n"
        "}\n"
        "set protocols bgp group EDGE export [ CUSTOMER-OUT SAFE-OUT ]\n"
        "firewall {\n"
        "  filter CUSTOMER-IN {\n"
        "    term customer-traffic {\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    result = sanitise_text(text, cfg, salt=SALT)
    for original in ("CUSTOMER-OUT", "SAFE-OUT", "customer-routes",
                     "CUSTOMER-IN", "customer-traffic"):
        assert original not in result.text


def test_equal_term_names_under_different_policies_do_not_create_false_links():
    cfg = Config.from_dict({"operational-names": {"policy-statement": "pseudo"}})
    result = sanitise_text(
        "set policy-options policy-statement CUSTOMER-A term accept then accept\n"
        "set policy-options policy-statement CUSTOMER-B term accept then accept\n",
        cfg, salt=SALT)
    terms = [line.split(" term ")[1].split()[0] for line in result.lines]
    assert terms[0] != terms[1]


def test_operational_name_output_is_idempotent():
    cfg = Config.from_dict({"operational-names": {"default": "pseudo"}})
    text = (
        "ip prefix-list CUSTOMER permit 192.0.2.0/24\n"
        "route-map CUSTOMER permit 10\n"
        "set policy-options policy-statement CUSTOMER term accept then accept\n"
    )
    once = sanitise_text(text, cfg, salt=SALT).text
    twice = sanitise_text(once, cfg, salt=SALT).text
    assert twice == once


def test_verification_covers_brace_terms_and_structured_location_bodies():
    cfg = Config.from_dict({
        "operational-names": {"policy-statement": "pseudo"},
        "locations": {"location": "keep", "junos-location-body": "redact"},
    })
    lines = [
        "policy-options {",
        "  policy-statement CUSTOMER {",
        "    term customer-routes {",
        "    }",
        "  }",
        "}",
        "system {",
        "  location {",
        '    building "Northwind DC1";',
        "  }",
        "}",
    ]
    checks = {finding.check for finding in verify(lines, cfg)}
    assert checks == {"operational-name-left", "location-left"}
