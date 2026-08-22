"""End-to-end coverage for opt-in privacy controls."""

import re

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
            "label-switched-path": "hash",
            "configuration-group": "hash",
        }
    })

    assert cfg.operational_names.action("acl-firewall-filter") == "hash"
    assert cfg.operational_names.action("route-map") == "hash"
    assert cfg.operational_names.action("prefix-list") == "hash"
    assert cfg.operational_names.action("policy-statement") == "hash"
    assert cfg.operational_names.action("vrf") == "hash"
    assert cfg.operational_names.action("peer-group") == "hash"
    assert cfg.operational_names.action("label-switched-path") == "hash"
    assert cfg.operational_names.action("configuration-group") == "hash"


def test_lsp_names_are_one_type_inside_and_outside_a_configuration_group():
    """The keyword carries the name, so nesting is not part of the selector.

    An LSP declared under `groups`, one declared under `protocols mpls` and a
    `lsp-next-hop` that refers to it are the same name in three places, and a
    config that still loads needs all three to move together.
    """
    cfg = Config.from_dict(
        {"operational-names": {"label-switched-path": "pseudo"}})
    text = (
        "set groups rise-mpls-lsp-automation protocols mpls "
        "label-switched-path gncg-cor1_to_rcbc-agr1-1 apply-groups mpls-autobandwidth\n"
        "set groups rise-mpls-lsp-automation protocols mpls "
        "label-switched-path gncg-cor1_to_rcbc-agr1-1 to 10.255.0.1\n"
        "set protocols mpls label-switched-path gncg-cor1_to_rcbc-agr1-1 bandwidth 100m\n"
        "set protocols mpls static-label-switched-path STATIC-IN ingress\n"
        "set routing-options static route 10.9.0.0/16 "
        "lsp-next-hop gncg-cor1_to_rcbc-agr1-1\n"
    )

    result = sanitise_text(text, cfg, salt=SALT)
    lines = result.lines

    def named(line: str) -> str:
        words = line.split()
        return words[words.index("label-switched-path") + 1]

    assert "gncg-cor1_to_rcbc-agr1-1" not in result.text
    names = {named(line) for line in lines[:3]}
    assert len(names) == 1                      # group and `protocols mpls` agree
    name = names.pop()
    assert name.startswith("lsp-")
    assert lines[4].split()[-1] == name         # and the reference follows it
    assert "STATIC-IN" not in lines[3]
    assert result.findings == []


def test_lsp_names_are_transformed_in_the_curly_brace_syntax_too():
    cfg = Config.from_dict(
        {"operational-names": {"label-switched-path": "hash"}})
    text = (
        "protocols {\n"
        "    mpls {\n"
        "        label-switched-path gncg-cor1_to_rcbc-agr1-1 {\n"
        "            to 10.255.0.1;\n"
        "        }\n"
        "        label-switched-path-template autobw {\n"
        "        }\n"
        "    }\n"
        "}\n"
    )

    result = sanitise_text(text, cfg, salt=SALT)

    assert "gncg-cor1_to_rcbc-agr1-1" not in result.text
    assert re.search(r"label-switched-path <LSP-[0-9a-f]{6}> \{", result.text)
    # the template statement names a template, not an LSP
    assert "label-switched-path-template autobw {" in result.text
    assert result.findings == []


def test_lsp_action_leaves_the_namespaces_next_to_it_alone():
    """A named path and a p2mp tree are their own namespaces, not LSP names."""
    cfg = Config.from_dict(
        {"operational-names": {"label-switched-path": "redact"}})
    text = (
        "set protocols mpls path VIA-CORE2 10.255.0.2 strict\n"
        "set protocols mpls label-switched-path GNC-TO-RCBC primary VIA-CORE2\n"
        "set routing-options static route 232.1.1.1/32 p2mp-lsp-next-hop TREE-A\n"
    )

    result = sanitise_text(text, cfg, salt=SALT)

    assert "GNC-TO-RCBC" not in result.text
    assert result.text.count("VIA-CORE2") == 2
    assert "TREE-A" in result.text


def test_lsp_names_are_kept_by_default(edge_junos):
    result = sanitise_text(edge_junos, Config(), salt=SALT)
    assert "lab-rtr-01_to_core-rtr-07" in result.text
    assert result.kept_counts["label-switched-path"] == 4


def test_configuration_group_names_are_one_type_in_both_syntaxes():
    """A `set groups` name, a `groups {` block name and every reference agree.

    In `set` form the keyword carries the name. In brace form `groups {` opens
    a block whose direct children are the names, so the declaration is selected
    by depth -- and the arbitrary configuration nested below it is not.
    """
    cfg = Config.from_dict(
        {"operational-names": {"configuration-group": "pseudo"}})
    text = (
        "set groups mpls-defaults protocols mpls optimize-timer 300\n"
        "set apply-groups [ mpls-defaults re0 ]\n"
        "set apply-groups-except re1-only\n"
        "set interfaces ge-0/0/0 apply-groups mpls-defaults\n"
        "groups {\n"
        "    mpls-defaults {\n"
        "        protocols {\n"
        "            mpls {\n"
        "                optimize-timer 300;\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "}\n"
        "apply-groups [ mpls-defaults ];\n"
    )

    result = sanitise_text(text, cfg, salt=SALT)
    lines = result.lines

    assert "mpls-defaults" not in result.text
    assert "re0" not in result.text
    assert "re1-only" not in result.text
    name = lines[0].split()[2]
    assert name.startswith("config-group-")
    assert lines[1].split()[3] == name              # the bracketed list form
    assert lines[3].split()[-1] == name             # a reference lower down
    assert lines[5].strip() == f"{name} {{"         # the brace-form declaration
    assert lines[13] == f"apply-groups [ {name} ];"
    # the hierarchy nested under a group is configuration, not a group name
    assert "        protocols {" in result.text
    assert "            mpls {" in result.text
    assert "                optimize-timer 300;" in result.text
    assert result.findings == []


def test_a_configuration_group_and_a_bgp_peer_group_are_different_types():
    cfg = Config.from_dict({"operational-names": {
        "configuration-group": "pseudo", "peer-group": "keep"}})
    text = "set groups edge-defaults protocols bgp group TRANSIT-CORE hold-time 30\n"

    result = sanitise_text(text, cfg, salt=SALT)

    assert "edge-defaults" not in result.text
    assert "group TRANSIT-CORE" in result.text
    assert result.counts["configuration-group"] == 1
    assert result.kept_counts["peer-group"] == 1


def test_object_group_is_not_a_configuration_group():
    """`groups` is selected as a JunOS statement, not as a word."""
    cfg = Config.from_dict(
        {"operational-names": {"configuration-group": "redact"}})
    text = (
        "object-group network SERVERS\n"
        " description customer groups for site A\n"
    )

    result = sanitise_text(text, cfg, salt=SALT)

    assert result.text == text
    assert result.counts["configuration-group"] == 0


def test_configuration_groups_are_kept_by_default(juniper, edge_junos):
    for text, occurrences in ((juniper, "mpls-defaults"),
                              (edge_junos, "mpls-lsp-automation")):
        result = sanitise_text(text, Config(), salt=SALT)
        assert occurrences in result.text
        assert result.kept_counts["configuration-group"] > 0


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


# ---------------------------------------------------------------------------
# RouterOS spells an ASN as a `key=value` pair, and RouterOS 7 abbreviates a
# nested property to a leading dot -- `.as=65500` is `remote.as=`. The
# space-form patterns reached none of them, not even the `remote-as=` whose
# keyword they already knew, so an explicit `as-numbers` policy was silently
# doing nothing on a RouterOS file.
# ---------------------------------------------------------------------------

ROS_BGP = (
    "/routing bgp connection\n"
    "add as=65501 disabled=no local.address=128.66.20.1 .role=ebgp "
    "remote.address=128.66.20.2 .as=65500 routing-table=main\n"
    "add remote-as=65502 local.as=65501\n"
)


def test_routeros_asn_spellings_are_all_reached():
    cfg = Config.from_dict({"as-numbers": {"default": "pseudo"}})
    result = sanitise_text(ROS_BGP, cfg, salt=SALT)
    for original in ("65501", "65500", "65502"):
        assert original not in result.text, result.text
    assert result.counts["as-numbers"] == 4
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_a_routeros_asn_keeps_the_equality_relation_across_spellings():
    """`as=65501` and `local.as=65501` are one ASN written two ways."""
    cfg = Config.from_dict({"as-numbers": {"default": "pseudo"}})
    out = sanitise_text(ROS_BGP, cfg, salt=SALT).text
    first = out.splitlines()[1].split("as=")[1].split()[0]
    last = out.splitlines()[2].split("local.as=")[1].strip()
    assert first == last, out


@pytest.mark.parametrize("key", ["alias", "class", "bias"])
def test_a_key_that_merely_ends_in_as_is_not_an_asn(key):
    """The boundary in front of the bare `as` key is the whole safety margin."""
    cfg = Config.from_dict({"as-numbers": {"default": "pseudo"}})
    line = f"add {key}=64512 comment=nothing\n"
    result = sanitise_text(line, cfg, salt=SALT)
    assert result.text == line
    assert not result.counts["as-numbers"]


def test_the_verifier_knows_the_same_asn_grammars_as_the_rule():
    """A check with its own list of grammars stays silent about exactly what
    the rule never reached, which is the failure mode worth preventing."""
    from netredact.operational import asn_candidates

    assert asn_candidates("add as=65501 .as=65500") == ["65501", "65500"]
    assert asn_candidates("add alias=64512") == []
    cfg = Config.from_dict({"as-numbers": {"default": "pseudo"}})
    cfg.verify.disable = []
    # a surviving RouterOS ASN is now reported rather than passed over
    assert "as-number-left" in {
        f.check for f in verify(["add as=65501"], cfg)}


# ---------------------------------------------------------------------------
# RouterOS routing-filter chains. The declaration is `chain=` in `/routing
# filter rule`; the references are a BGP connection's `input.filter=` and
# `output.filter-chain=` and their abbreviated `.filter=` / `.filter-chain=`
# forms. One TYPE carries both, so the two can never be given two actions and
# left pointing at nothing.
# ---------------------------------------------------------------------------

ROS_CHAINS = (
    "/routing filter rule\n"
    "add chain=to-corp-1 disabled=no rule=accept\n"
    "add chain=from-corp-1 disabled=no rule=accept\n"
    "/ip firewall filter\n"
    "add action=accept chain=input comment=noc\n"
    "add action=jump chain=forward jump-target=mychain\n"
    "/routing bgp connection\n"
    "add input.filter=from-corp-1 output.filter-chain=to-corp-1 name=peer-1\n"
    "add input.allow-as=1 .filter=from-corp-1 .filter-chain=to-corp-1\n"
)


def chains(action: str = "pseudo") -> Config:
    return Config.from_dict(
        {"operational-names": {"routing-filter-chain": action}})


def test_a_filter_chain_and_every_reference_to_it_render_alike():
    """THE contract: the tag is a function of the value, so a chain named in
    one section and used in another still name the same thing afterwards."""
    out = sanitise_text(ROS_CHAINS, chains(), salt=SALT).text
    declared = [ln.split("chain=")[1].split()[0] for ln in out.splitlines()
                if ln.startswith("add chain=")]
    assert all(name.startswith("filter-chain-") for name in declared), out
    # `from-corp-1` is declared once and referenced twice, all three alike
    from_corp = declared[1]
    assert out.count(f"input.filter={from_corp}") == 1
    assert out.count(f".filter={from_corp}") == 2      # `input.filter=` too
    to_corp = declared[0]
    assert out.count(f"output.filter-chain={to_corp}") == 1
    assert out.count(f".filter-chain={to_corp}") == 2


def test_a_firewall_chain_is_not_a_routing_filter_chain():
    """`input`, `forward` and `srcnat` are RouterOS's own firewall chain names,
    and substituting one breaks the file. The section is the only evidence."""
    out = sanitise_text(ROS_CHAINS, chains("redact"), salt=SALT).text
    assert "chain=input" in out
    assert "chain=forward" in out
    assert "jump-target=mychain" in out


def test_allow_as_is_a_count_and_not_a_chain_or_an_asn():
    cfg = Config.from_dict({"operational-names": {"routing-filter-chain": "redact"},
                            "as-numbers": {"default": "pseudo"}})
    assert "input.allow-as=1" in sanitise_text(ROS_CHAINS, cfg, salt=SALT).text


@pytest.mark.parametrize("action", ["keep", "pseudo", "hash", "redact"])
def test_a_filter_chain_honours_every_action(action):
    result = sanitise_text(ROS_CHAINS, chains(action), salt=SALT)
    if action == "keep":
        assert "chain=to-corp-1" in result.text
        assert result.kept_counts["routing-filter-chain"] == 6
    else:
        assert "to-corp-1" not in result.text and "from-corp-1" not in result.text
        assert result.counts["routing-filter-chain"] == 6
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_a_surviving_filter_chain_is_reported_when_the_type_acts():
    from netredact.verify import verify

    assert "operational-name-left" in {
        f.check for f in verify(["add input.filter=from-corp-1"], chains())}


# ---------------------------------------------------------------------------
# FortiOS interface names. The same contract every operational name has, and
# the one where getting it wrong is most visible: an interface is pointed at
# from every firewall policy, static route and VPN in the file, so a
# declaration acted on alone leaves the configuration unloadable AND leaks the
# value through every reference that kept it.
#
# It is one TYPE carrying both halves for exactly that reason, and it defaults
# to `keep` because coverage here is a list of reference spellings rather than
# a closed grammar.
# ---------------------------------------------------------------------------

FOS_INTERFACES = (
    "config system interface\n"
    '    edit "port1"\n'
    '        set alias "uplink"\n'
    "    next\n"
    '    edit "vl-bobsbakery"\n'
    '        set interface "port1"\n'
    "        set vlanid 220\n"
    "    next\n"
    '    edit "agg-core"\n'
    "        set type aggregate\n"
    '        set member "port3" "vl-bobsbakery"\n'
    "    next\n"
    "end\n"
    "config system zone\n"
    '    edit "CUSTOMER-EDGE"\n'
    '        set interface "vl-bobsbakery"\n'
    "    next\n"
    "end\n"
    "config router static\n"
    "    edit 1\n"
    '        set device "vl-bobsbakery"\n'
    "    next\n"
    "end\n"
    "config firewall addrgrp\n"
    '    edit "grp-bakery"\n'
    '        set member "addr-bakery-lan"\n'
    "    next\n"
    "end\n"
    "config firewall policy\n"
    "    edit 1\n"
    '        set srcintf "CUSTOMER-EDGE" "vl-bobsbakery"\n'
    '        set dstintf "port1"\n'
    "    next\n"
    "    edit 2\n"
    '        set srcintf "any"\n'
    '        set dstintf "vl-bobsbakery"\n'
    "    next\n"
    "end\n"
)


def interfaces(action: str = "pseudo") -> Config:
    return Config.from_dict({"operational-names": {"fortios-interface": action}})


def test_a_fortios_interface_and_every_reference_to_it_render_alike():
    """THE contract: the tag is a function of the value, so the `edit` that
    declares an interface and every key that points at it render identically
    and the file still loads."""
    out = sanitise_text(FOS_INTERFACES, interfaces(), salt=SALT).text
    assert "vl-bobsbakery" not in out, out
    declared = [ln.split('edit "')[1].rstrip('"\n')
                for ln in out.splitlines() if ln.strip().startswith('edit "vl')
                or ln.strip().startswith('edit "fos-if')]
    vlan = next(name for name in declared if name.startswith("fos-if-"))
    # declared once; referenced by member, zone, device, srcintf and dstintf
    assert out.count(vlan) == 6, out


def test_a_factory_port_name_is_structural_and_is_not_substituted():
    """`port1` is the FortiOS spelling of interface NUMBERING, which this tool
    promises never to scrub, and `any` is the wildcard -- substituting it would
    change what the policy does."""
    out = sanitise_text(FOS_INTERFACES, interfaces("redact"), salt=SALT).text
    assert 'set dstintf "port1"' in out
    assert 'set member "port3"' in out
    assert 'set srcintf "any"' in out


def test_an_address_group_member_is_not_an_interface():
    """`set member` names interfaces in a zone and ADDRESSES in an address
    group, and the line is the same line. Substituting one with an interface's
    tag would break the file in the way the scope exists to prevent."""
    out = sanitise_text(FOS_INTERFACES, interfaces("redact"), salt=SALT).text
    assert 'set member "addr-bakery-lan"' in out
    assert 'edit "grp-bakery"' in out


def test_a_zone_name_is_an_interface_name_because_a_policy_points_at_it():
    """`set srcintf` takes a zone as readily as a port, so a zone left standing
    while its references moved -- or the reverse -- is an unloadable file."""
    out = sanitise_text(FOS_INTERFACES, interfaces(), salt=SALT).text
    assert "CUSTOMER-EDGE" not in out


def test_a_multi_valued_interface_list_moves_every_entry():
    """`set srcintf "A" "B"` is one line and two names. A rule that took only
    the first left the second pointing at an interface that no longer exists."""
    out = sanitise_text(FOS_INTERFACES, interfaces(), salt=SALT).text
    line = next(ln for ln in out.splitlines() if "srcintf" in ln and "any" not in ln)
    assert line.count("fos-if-") == 2, line


def test_a_pseudonymous_interface_name_still_fits_fortios():
    """FortiOS caps an interface name at 15 characters. `pseudo` is only worth
    having if what it writes still loads."""
    out = sanitise_text(FOS_INTERFACES, interfaces(), salt=SALT).text
    for name in re.findall(r'"(fos-if-[0-9a-f]+)"', out):
        assert len(name) <= 15, name


@pytest.mark.parametrize("action", ["keep", "pseudo", "hash", "redact"])
def test_a_fortios_interface_honours_every_action(action):
    result = sanitise_text(FOS_INTERFACES, interfaces(action), salt=SALT)
    # nine values: three `edit` declarations (the VLAN, the aggregate and the
    # zone) and six references. `port1`, `port3` and `any` are structural, and
    # the address group's `member` is not an interface at all.
    if action == "keep":
        assert "vl-bobsbakery" in result.text
        assert result.kept_counts["fortios-interface"] == 9
    else:
        assert "vl-bobsbakery" not in result.text
        assert result.counts["fortios-interface"] == 9
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_a_surviving_fortios_interface_is_reported_when_the_type_acts():
    assert verify(FOS_INTERFACES.splitlines(), interfaces()) != []
    assert verify(FOS_INTERFACES.splitlines(), interfaces("keep")) == []


def test_the_type_defaults_to_keep_so_interface_numbering_stays():
    """The report's NOTE says interface numbering is never scrubbed, and a
    type that acted by default would make that untrue."""
    assert Config().operational_names.action("fortios-interface") == "keep"
    assert sanitise_text(FOS_INTERFACES, Config(), salt=SALT).text == FOS_INTERFACES
