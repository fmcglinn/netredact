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

from netredact import Config, Sanitiser, sanitise_text
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


# -- the mechanism itself ---------------------------------------------------

@pytest.mark.parametrize("line,scope", [
    ("interface GigabitEthernet1/0/1", "interfaces"),
    ("interface Vlan905", "interfaces"),
    ("interface Ethernet1", "interfaces"),
    ("vlan 905", "vlans"),
    ("vlan 300,301", "vlans"),
    ("vlan database", "vlans"),
    ("vlan internal allocation policy ascending", None),
    ("vlan configuration 905", None),
    ("interfaces {", None),          # a JunOS stanza, handled by the brace stack
    ("router bgp 64512", None),
    ("!", None),
    ("switchport access vlan 905", None),   # never at column zero in practice
])
def test_which_lines_open_a_block(line, scope):
    got = next((name for name, pat in R.BLOCK_SCOPES if pat.match(line)), None)
    assert got == scope


def test_an_indented_line_stays_in_the_block_and_any_other_ends_it():
    san = Sanitiser(Config(), salt=SALT)
    san._enter("interface Gi0/0")
    assert san.inside == ("interfaces",)
    san._enter(" description still inside")
    assert san.inside == ("interfaces",)
    san._enter("!")
    assert san.inside == ()


def test_a_set_line_carries_its_own_scope_for_one_line_only():
    san = Sanitiser(Config(), salt=SALT)
    san._enter("set interfaces xe-0/0/0 description \"x\"")
    assert san.inside == ("interfaces",)
    san._enter("set snmp community public")
    assert san.inside == ("snmp",)


def test_a_junos_stanza_and_an_ios_block_share_one_set_of_names():
    """One name, both dialects: that is why the IOS scopes are named in plural."""
    san = Sanitiser(Config(), salt=SALT)
    san.stanza = ["interfaces", "ge-0"]
    san._enter('        description "x";')
    assert "interfaces" in san.inside


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
    rules = {r.name: r for r in R.build_rules()}
    assert "pseudowire-name" in rules
    assert R.family_of("pseudowire-name") == "circuits"
    # three target groups: the connector's two, and the definition's one
    assert rules["pseudowire-name"].targets == (1, 2, 3)


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
