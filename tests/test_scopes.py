"""Scope: the block a line is inside, and the two families that need it.

Some material is only recognisable from what encloses it -- a bare ``name`` line
is a VLAN name under ``vlan 905`` and a route-map name under ``route-map``. Two
kinds of block answer that question under one set of names (a JunOS stanza and
an IOS-style block), and these tests hold both halves of the contract:

* the scoped rules act inside their block and nowhere else;
* the generic ``description`` rule and the interface one **partition** the
  descriptions in a file rather than overlapping, so no line is acted on twice
  and none falls between them.

Every value here is invented. A real VLAN name is exactly the kind of string
this tool exists to remove, so none of them appears in the test suite.
"""

import pytest

from netredact import Config, sanitise_text
from netredact import rules as R

from .conftest import SALT, maximal, policy, section

#: one file, every dialect, with a description in five different places and a
#: VLAN name in two. The comment on each line says which rule owns it.
MIXED = """hostname acc-sw-01
!
vlan 905
 name CUST000000000123
!
vlan 300,301
 name SITE-DATA
!
vlan internal allocation policy ascending
!
interface Vlan905
 description an SVI note
 ip address 10.9.5.1 255.255.255.0
!
interface GigabitEthernet1/0/1
 description a port note
 switchport access vlan 905
!
route-map SET-COMM permit 10
 name a route-map name
!
vrf definition CUST
 description a vrf note
!
set interfaces xe-0/0/0 description "a set-form port note"
set vlans V905 description "a set-form vlan note"
interfaces {
    ge-0/0/5 {
        description "a brace-form port note";
    }
}
"""

#: value -> the rule that must claim it
OWNER = {
    "CUST000000000123": "vlan-name",
    "SITE-DATA": "vlan-name",
    "an SVI note": "interface-description",
    "a port note": "interface-description",
    "a set-form port note": "interface-description",
    "a brace-form port note": "interface-description",
    "a vrf note": "description",
    "a set-form vlan note": "description",
}

#: values no rule in these two families may touch, whatever the policy
UNOWNED = ("a route-map name", "vlan 905", "vlan 300,301",
           "vlan internal allocation policy ascending")


@pytest.mark.parametrize("value,rule", sorted(OWNER.items()))
def test_each_value_is_claimed_by_exactly_one_rule(value, rule):
    """Act on that rule alone: the value goes, and only that one does."""
    family = {"vlan-name": "vlans", "interface-description": "interfaces",
              "description": "text"}[rule]
    result = sanitise_text(MIXED, section(family, "keep", **{rule: "redact"}),
                           salt=SALT)
    assert value not in result.text, f"{rule} did not claim {value!r}"
    assert result.counts[rule] == sum(1 for v, r in OWNER.items() if r == rule)
    for other in OWNER:
        if OWNER[other] != rule:
            assert other in result.text, f"{rule} also ate {other!r}"


@pytest.mark.parametrize("value", UNOWNED)
def test_structure_survives_the_strongest_policy(value):
    """A VLAN id, and a `name` line that is not a VLAN's, are structure."""
    assert value in sanitise_text(MIXED, maximal(), salt=SALT).text


def test_the_descriptions_partition_the_file():
    """Between them the two rules claim every description, each exactly once."""
    result = sanitise_text(MIXED, policy(text="hash", interfaces="hash"),
                           salt=SALT)
    descriptions = sum(1 for v, r in OWNER.items()
                       if r in ("description", "interface-description"))
    assert (result.counts["description"]
            + result.counts["interface-description"]) == descriptions
    assert "note" not in result.text, result.text


def test_an_svi_is_an_interface_and_not_a_vlan():
    """`interface Vlan905` is a port. It is also the case the user asked for."""
    out = sanitise_text(MIXED, section("vlans", "redact"), salt=SALT).text
    assert "description an SVI note" in out
    out = sanitise_text(MIXED, section("interfaces", "redact"), salt=SALT).text
    assert "description an SVI note" not in out


def test_a_vlan_name_survives_a_policy_that_destroys_all_free_text():
    """The whole point of a section of its own: the two are independent."""
    out = sanitise_text(MIXED, section("text", "redact"), salt=SALT).text
    assert "name CUST000000000123" in out
    assert "description a port note" in out


# -- the mechanism itself, observed through the catalogue interface --------

def test_catalogue_scope_tracking_is_observable_through_sanitising():
    """IOS blocks, JunOS stanzas and set lines share the interfaces scope."""
    text = ("interface Gi0/0\n"
            " description ios\n"
            "!\n"
            " description outside\n"
            "interfaces {\n"
            " ge-0/0/0 {\n"
            '  description "junos";\n'
            " }\n"
            "}\n"
            'set interfaces xe-0/0/0 description "set-line"\n')
    out = sanitise_text(
        text, policy(text="keep", interfaces="redact"), salt=SALT).text
    assert "ios" not in out
    assert "junos" not in out
    assert "set-line" not in out
    assert "outside" in out


def test_a_banner_body_never_opens_a_block():
    """A banner that mentions an interface must not scope the lines after it."""
    text = ('banner motd ^C\n'
            'interface Gi0/0 is down, call the NOC\n'
            '^C\n'
            ' description a vrf note\n')
    out = sanitise_text(text, section("text", "redact"), salt=SALT).text
    assert "a vrf note" not in out, out


# -- circuits: the Arista patch panel and the LDP pseudowires ---------------
#
# Every identifier below is invented. A real patch or pseudowire name is an
# order reference with a customer in it -- exactly what this family exists to
# remove -- so none of them comes from a real config.

CIRCUITS = """patch panel
   patch acme_ORD000000111222
      connector 1 pseudowire ldp acme_ORD000000111222_1 alternate acme_ORD000000111222_2
      connector 2 interface Port-Channel1.100
   !
!
mpls ldp
   pseudowires
      !
      pseudowire NORTHWIND_XC_LAB1_A9
      pseudowire acme_ORD000000111222_1
!
"""


def test_a_definition_and_its_reference_render_as_the_same_name():
    """THE contract for this family, and the reason `pseudo` is its action.

    `acme_ORD000000111222_1` is *defined* under `mpls ldp` and *referenced*
    from a `connector` line. If the two substitutions disagreed the output
    would not load, so the pseudonym has to be a function of the value and of
    nothing else -- not of which line it was found on.
    """
    out = sanitise_text(CIRCUITS, section("circuits", "pseudo"), salt=SALT).text
    connector = next(ln for ln in out.splitlines() if "connector 1" in ln)
    definition = out.splitlines()[-2]
    primary = connector.split("pseudowire ldp ")[1].split(" alternate ")[0]
    assert primary.startswith("circuit-")
    assert definition.strip() == f"pseudowire {primary}", out
    # ...and the alternate is a different circuit, not a collapsed duplicate
    alternate = connector.split(" alternate ")[1].strip()
    assert alternate.startswith("circuit-") and alternate != primary


def test_one_rule_carries_the_definition_and_the_reference():
    """So they can never be given two actions and left pointing nowhere.

    A `connector` line references a pseudowire another section defines. Two
    rules could be configured apart; two branches of one rule cannot, and this
    is what pins that down.
    """
    info = next(i for i in R.RuleCatalogue.builtins().inventory()
                if i.name == "pseudowire-name")
    assert info.family == "circuits"
    out = sanitise_text(CIRCUITS, policy(circuits="pseudo"), salt=SALT).text
    connector = next(line for line in out.splitlines() if "connector" in line)
    primary = connector.split("pseudowire ldp ")[1].split(" alternate ")[0]
    assert f"pseudowire {primary}" in out


@pytest.mark.parametrize("action,expected", [
    ("keep", "patch acme_ORD000000111222"),
    ("pseudo", "patch circuit-"),
    ("hash", "patch <CIRCUIT-"),
    ("redact", "patch <REMOVED>"),
])
def test_circuits_family_end_to_end(action, expected):
    out = sanitise_text(CIRCUITS, policy(circuits=action), salt=SALT).text
    assert expected in out
    # structure survives whatever the action: the block headers, the connector
    # numbers and the interface a connector points at are not names
    assert "patch panel" in out
    assert "pseudowires" in out
    assert "connector 2 interface Port-Channel1.100" in out
    if action != "keep":
        assert "acme" not in out and "NORTHWIND_XC" not in out


def test_the_patch_panel_header_is_never_read_as_a_patch_name():
    """An IOS-style block header is inside its own block, so `patch panel`
    reaches `patch-name` and has to be refused by the pattern itself."""
    out = sanitise_text(CIRCUITS, section("circuits", "redact"), salt=SALT).text
    assert out.splitlines()[0] == "patch panel"


def test_a_patch_outside_a_patch_panel_block_is_left_alone():
    """The scope is the whole reason this rule is safe on another dialect.

    `patch` is an ordinary word. What confines the rule is that it has to be
    inside a `patch panel` block, and no grammar but Arista's opens one -- so
    the rule is inert on a JunOS file by construction, not by asking a
    detector what vendor the file is.
    """
    junos = ("system {\n"
             "    services {\n"
             "        patch acme_ORD000000111222;\n"
             "    }\n"
             "}\n")
    out = sanitise_text(junos, section("circuits", "redact"), salt=SALT).text
    assert "patch acme_ORD000000111222;" in out, out


def test_a_vendor_label_never_gates_a_rule():
    """A file the detector calls `juniper` still gets the Arista rules.

    This is the fail-open path the advisory-only rule in `RULE_VENDORS` exists
    to prevent: a provider dump can hold two dialects, detection returns one
    answer for the whole file, and gating on it would ship the circuit names.
    """
    from netredact.vendors import detect_vendor

    mixed = ("## Last changed: 2026-02-11 09:14:02 UTC\n"
             "version 21.4R3-S4.9;\n"
             "system {\n"
             "    host-name edge-pe-01;\n"
             "}\n") + CIRCUITS
    assert detect_vendor(mixed) == "juniper"
    result = sanitise_text(mixed, section("circuits", "redact"), salt=SALT)
    assert result.vendor == "juniper"
    assert "acme_ORD000000111222" not in result.text
    assert result.counts["patch-name"] == 1


def test_the_pseudowires_block_header_is_not_a_pseudowire_name():
    """`pseudowires` cannot match: the keyword must be followed by whitespace,
    and there it is followed by an `s`."""
    out = sanitise_text("mpls ldp\n   pseudowires\n",
                        section("circuits", "redact"), salt=SALT)
    assert out.text == "mpls ldp\n   pseudowires\n"
    assert not out.counts


# -- RouterOS: the third kind of block --------------------------------------
#
# A `/`-prefixed line opens a section that lasts until the next one, and
# `/export terse` puts the same path on every command line instead. Both are
# scope, so both go through one mechanism -- and scope is all there is: a
# RouterOS `name=` names the device, a login, a community string or an
# interface depending only on the section above it.

ROUTEROS = """/system identity
set name=hq-rtr-01
/user
add name=netops group=full password=R0uterPass77
/ppp secret
add name=bobs-bakery service=pppoe password=BakeryPPP123
/interface ethernet
set [ find default-name=ether1 ] comment="a port note" name=ether1-transit
/ip firewall filter
add action=accept chain=input comment="a firewall note"
/snmp community
add name=pubR0nly addresses=128.66.16.0/24
/snmp
set contact="noc@northwind.test" location="DC1, 100 Example St"
"""


def test_a_comment_is_owned_by_the_section_it_sits_in():
    """The same split as `description`, and for the same reason: a port label a
    reviewer needs, and free text on a firewall rule that they do not."""
    out = sanitise_text(ROUTEROS, section("interfaces", "redact"), salt=SALT).text
    assert "a port note" not in out
    assert 'comment="a firewall note"' in out

    out = sanitise_text(ROUTEROS, section("text", "redact"), salt=SALT).text
    assert 'comment="a port note"' in out
    assert "a firewall note" not in out


def test_the_comments_partition_the_file():
    """Between them the two rules claim every comment, each exactly once."""
    result = sanitise_text(ROUTEROS, policy(text="hash", interfaces="hash"),
                           salt=SALT)
    assert result.counts["comment"] + result.counts["interface-comment"] == 2
    assert "note" not in result.text, result.text


def test_a_section_lasts_until_the_next_one_and_no_further():
    """`/ip firewall filter` has to END the `/interface ethernet` section, or
    the comment on it would still be read as a port label."""
    result = sanitise_text(ROUTEROS, section("interfaces", "redact"), salt=SALT)
    assert result.counts["interface-comment"] == 1


def test_the_device_name_is_learnt_only_from_system_identity():
    """`name=hq-rtr-01` is a hostname there and an object name everywhere else,
    so an unscoped collector would substitute every interface in the file."""
    result = sanitise_text(ROUTEROS, policy(hostnames="pseudo"), salt=SALT)
    assert "hq-rtr-01" not in result.text
    assert result.mapping["hostname"] == {"hq-rtr-01": "device-23c856"}
    # the section is the whole of the evidence, so nothing else moved
    assert "name=ether1-transit" in result.text
    assert "name=pubR0nly" in result.text or "name=<REMOVED>" in result.text


def test_a_customer_account_is_a_username():
    """`/user` is a login and `/ppp secret` is a subscriber's account. Both are
    usernames -- neither is the device's own name."""
    result = sanitise_text(ROUTEROS, policy(usernames="pseudo"), salt=SALT)
    for value in ("netops", "bobs-bakery"):
        assert value not in result.text
        assert value in result.mapping["username"]
    assert "hq-rtr-01" in result.text, "the device name is not a login"


def test_a_terse_export_scopes_from_the_path_on_the_line():
    """`/export terse` writes one logical line per item with the whole section
    path in front of the command -- the RouterOS analogue of a JunOS `set`
    line, and it has to reach the same scopes."""
    terse = ("/system identity set name=hq-rtr-01\n"
             "/interface ethernet set [ find default-name=ether1 ] "
             'comment="a port note"\n'
             '/ip firewall filter add chain=input comment="a firewall note"\n'
             "/snmp community add name=pubR0nly addresses=128.66.16.0/24\n")
    result = sanitise_text(terse, policy(hostnames="pseudo",
                                         interfaces="redact"), salt=SALT)
    assert "hq-rtr-01" not in result.text
    assert "a port note" not in result.text
    assert 'comment="a firewall note"' in result.text
    assert "pubR0nly" not in result.text          # a community string, redacted
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_a_routeros_scope_cannot_be_reached_by_another_dialect():
    """The scope is what confines these rules, and nothing else is.

    No grammar but RouterOS's opens a `/snmp community` section, so a JunOS
    file cannot reach `routeros-snmp-community` however it spells `name`.
    """
    junos = ("snmp {\n"
             "    community pubR0nly {\n"
             "        name notacommunity;\n"
             "    }\n"
             "}\n")
    result = sanitise_text(junos, Config(), salt=SALT)
    assert "notacommunity" in result.text
    assert not result.counts["routeros-snmp-community"]


def test_a_wrapped_command_keeps_the_scope_of_its_section():
    """The join happens before the rules run, so the logical line is still
    inside the section its first physical line was in."""
    text = ("/interface l2tp-client\n"
            "add connect-to=203.0.113.10 name=l2tp-dr \\\n"
            '    comment="a port note"\n')
    out = sanitise_text(text, section("interfaces", "redact"), salt=SALT).text
    assert "a port note" not in out
    out = sanitise_text(text, section("text", "redact"), salt=SALT).text
    assert 'comment="a port note"' in out


# -- a RouterOS `name=` is four different things ----------------------------
#
# The section decides which, and the peers case is the one where it is free
# text. What makes that safe is exactly what makes the others unsafe: a peer
# name is referenced by nothing, while an interface name is referenced by every
# `interface=` in the file.

WIREGUARD_PEER = (
    "/interface wireguard peers\n"
    "add allowed-address=100.64.254.2/32 interface=wg-4g "
    'name="a peer label" comment="a port note"\n'
    "/interface ethernet\n"
    "set [ find default-name=ether1 ] name=ether1-transit\n"
    "/ip address\n"
    "add address=128.66.18.2/30 interface=ether1-transit\n"
)


@pytest.mark.parametrize("action,expected", [
    ("keep", '"a peer label"'),
    ("pseudo", '"desc-'),
    ("hash", '"<DESC-'),
    ("redact", '"<DESCRIPTION-REMOVED>"'),
])
def test_a_peer_name_follows_the_description_rule(action, expected):
    """It is a label, and on a provider config a customer -- so it belongs to
    the same family as the description on the interface it hangs off."""
    out = sanitise_text(WIREGUARD_PEER, section("interfaces", action),
                        salt=SALT).text
    assert expected in out, out
    if action != "keep":
        assert "a peer label" not in out


#: a label `name=` OUTSIDE any `/interface ...` section, which is the other
#: level of the same split. On a provider config this is where the customer and
#: the order reference live.
BGP_CONNECTION = (
    "/routing bgp connection\n"
    "add as=64512 disabled=no local.address=128.66.20.1 .role=ebgp "
    'name="Cust: 4G - a customer - ORD000000562604" '
    "remote.address=128.66.20.2 .as=64513 routing-table=main\n"
)


@pytest.mark.parametrize("action,expected", [
    ("keep", '"Cust: 4G - a customer - ORD000000562604"'),
    ("pseudo", '"desc-'),
    ("hash", '"<DESC-'),
    ("redact", '"<DESCRIPTION-REMOVED>"'),
])
def test_a_label_name_outside_an_interface_is_text(action, expected):
    out = sanitise_text(BGP_CONNECTION, section("text", action), salt=SALT).text
    assert expected in out, out
    if action != "keep":
        assert "ORD000000562604" not in out


def test_the_two_levels_of_the_name_rule_partition_the_labels():
    """The same split as `description` / `interface-description`, and the same
    contract: between them the two rules claim every label exactly once."""
    text = WIREGUARD_PEER + BGP_CONNECTION
    result = sanitise_text(text, policy(text="hash", interfaces="hash"),
                           salt=SALT)
    assert result.counts["routeros-peer-name"] == 1
    assert result.counts["routeros-object-name"] == 1
    assert "a peer label" not in result.text
    assert "ORD000000562604" not in result.text


def test_neither_level_reaches_a_referenced_name():
    """`object-labels` marks only the sections nothing points at, so acting on
    all free text still leaves an interface, a bridge or an OSPF area alone."""
    text = ("/interface bridge\nadd name=bridge-lan protocol-mode=rstp\n"
            "/routing ospf area\nadd name=backbone-v2 instance=default\n"
            "/routing ospf interface-template\n"
            "add area=backbone-v2 interfaces=bridge-lan\n")
    out = sanitise_text(text, maximal(), salt=SALT).text
    assert "name=bridge-lan" in out and "interfaces=bridge-lan" in out
    assert "name=backbone-v2" in out and "area=backbone-v2" in out


def test_a_referenced_interface_name_is_left_alone():
    """THE reason `routeros-peer-name` is scoped to the peers section.

    `/ip address add interface=ether1-transit` names the `name=` that
    `/interface ethernet` set. Acting on the declaration alone would break the
    file AND leak the value through the reference that kept it, so a `name=`
    outside the peers section is structure until the references move with it.
    """
    out = sanitise_text(WIREGUARD_PEER, maximal(), salt=SALT).text
    assert "name=ether1-transit" in out
    assert "interface=ether1-transit" in out
    assert "interface=wg-4g" in out


def test_a_peer_is_inside_its_own_section_and_inside_interfaces():
    """The paths nest, so the scopes do: the peer's `comment=` is an interface
    comment while its `name=` is a rule of its own."""
    result = sanitise_text(WIREGUARD_PEER, policy(interfaces="hash"), salt=SALT)
    assert result.counts["interface-comment"] == 1
    assert result.counts["routeros-peer-name"] == 1


def test_a_peer_name_is_not_collected_as_a_hostname_or_a_login():
    """`/system identity`, `/user` and `/ppp secret` are the sections that make
    a `name=` an identity. A peers section is not one of them."""
    result = sanitise_text(WIREGUARD_PEER, policy(hostnames="pseudo",
                                                 usernames="pseudo"), salt=SALT)
    assert '"a peer label"' in result.text
    assert not result.mapping.get("hostname")
    assert not result.mapping.get("username")
