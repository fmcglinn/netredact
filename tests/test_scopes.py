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
