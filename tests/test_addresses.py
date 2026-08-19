"""Addresses, names and MACs: the partitioned families.

Each of these has its own section rather than one key in ``[policy]``, because
its members exhaustively partition a value space -- ten IPv4 classes, eleven
IPv6 classes, the two halves of a MAC -- and a ``default`` covers the rest.
"""

import ipaddress
import re

import pytest

from netredact import Config, sanitise_text
from netredact.addresses import V4_CLASS_NAMES, V6_CLASS_NAMES, classify_v4

from .conftest import SALT, addresses, policy


def public_only() -> Config:
    """The common case: move globally-routable space, keep the rest readable."""
    cfg = Config()
    cfg.ipv4.other_unicast = "pseudo"
    cfg.ipv6.other_unicast = "pseudo"
    return cfg


# -- defaults ---------------------------------------------------------------

def test_nothing_but_secrets_moves_by_default(cisco):
    result = sanitise_text(cisco, Config(), salt=SALT)
    for kept in ("128.66.16.130", "hostname core-rtr-01", "northwind.test",
                 "0011.2233.4455", "username netops",
                 "3fff:16:1234:5678::1"):
        assert kept in result.text


def test_kept_addresses_are_reported_by_class(cisco):
    result = sanitise_text(cisco, Config(), salt=SALT)
    assert "128.66.16.130" in result.kept["ipv4.other_unicast"]
    assert "10.20.30.1" in result.kept["ipv4.rfc1918"]
    assert "203.0.113.44" in result.kept["ipv4.documentation"]
    assert "8.8.8.8" in result.kept["ipv4.well_known"]
    assert "224.0.0.0" not in result.kept.get("ipv4.multicast", set())
    assert "core-rtr-01" in result.kept["hostname"]
    assert result.kept_counts["ipv4"] == 14


# -- per-class gating -------------------------------------------------------

def test_only_the_named_class_moves(cisco):
    cfg = Config()
    cfg.ipv4.other_unicast = "pseudo"
    out = sanitise_text(cisco, cfg, salt=SALT).text
    assert "128.66.16.130" not in out        # other_unicast: moved
    assert "10.20.30.1" in out              # rfc1918: inherits keep
    assert "203.0.113.44" in out            # documentation
    assert "8.8.8.8" in out                 # well_known


def test_default_moves_every_class_and_a_named_class_opts_out(cisco):
    """`default` plus one exception -- the composition the old bool could not do."""
    cfg = addresses("pseudo")
    cfg.ipv4.rfc1918 = "keep"
    out = sanitise_text(cisco, cfg, salt=SALT).text
    assert "10.20.30.1" in out
    assert "128.66.16.130" not in out
    assert "8.8.8.8" not in out             # well_known inherits the default


def test_rfc1918_alone_moves_only_private_space(cisco):
    cfg = Config()
    cfg.ipv4.rfc1918 = "pseudo"
    out = sanitise_text(cisco, cfg, salt=SALT).text
    assert "10.20.30.1" not in out
    assert "128.66.16.130" in out


def test_cgnat_is_its_own_class():
    cfg = Config()
    cfg.ipv4.cgnat = "pseudo"
    cfg.ipv4.pool = ["198.18.0.0/15"]           # keep the pool out of the way
    text = " ip address 100.64.5.9 255.255.255.0\n ip address 10.1.1.1 255.255.255.0\n"
    out = sanitise_text(text, cfg, salt=SALT).text
    assert "100.64.5.9" not in out
    assert "10.1.1.1" in out


def test_multicast_is_kept_by_default_and_movable_on_request(edge):
    assert "224.0.0.5" in sanitise_text(edge, public_only(), salt=SALT).text
    cfg = Config()
    cfg.ipv4.multicast = "pseudo"
    assert "224.0.0.5" not in sanitise_text(edge, cfg, salt=SALT).text


def test_well_known_resolvers_form_their_own_class(cisco):
    cfg = Config()
    cfg.ipv4.well_known = "pseudo"
    out = sanitise_text(cisco, cfg, salt=SALT).text
    assert "8.8.8.8" not in out
    assert "128.66.16.130" in out                # other classes untouched


def test_a_resolver_can_be_kept_while_everything_else_moves(cisco):
    cfg = addresses("pseudo")
    cfg.ipv4.well_known = "keep"
    out = sanitise_text(cisco, cfg, salt=SALT).text
    assert "8.8.8.8" in out and "1.1.1.1" in out
    assert "128.66.16.130" not in out


def test_every_class_name_is_reachable_from_the_config():
    cfg = Config()
    for klass in V4_CLASS_NAMES:
        setattr(cfg.ipv4, klass, "hash")
        assert cfg.ipv4.action(klass) == "hash"
    for klass in V6_CLASS_NAMES:
        setattr(cfg.ipv6, klass, "hash")
        assert cfg.ipv6.action(klass) == "hash"


def test_keep_networks_overrides_an_active_class(cisco):
    cfg = addresses("pseudo")
    cfg.ipv4.keep_networks = ["128.66.16.0/24"]
    out = sanitise_text(cisco, cfg, salt=SALT).text
    assert "128.66.16.130" in out
    assert "10.20.30.1" not in out


# -- the four actions on an address -----------------------------------------

@pytest.mark.parametrize("action,check", [
    ("keep", lambda out: "128.66.16.130" in out),
    ("pseudo", lambda out: "198.1" in out and "128.66.16.130" not in out),
    ("hash", lambda out: "<IP-" in out and "128.66.16.130" not in out),
    ("redact", lambda out: "192.0.2.0" in out and "128.66.16.130" not in out),
])
def test_ipv4_actions(action, check):
    cfg = addresses(action)
    out = sanitise_text(" ip address 128.66.16.130 255.255.255.248\n",
                        cfg, salt=SALT).text
    assert check(out), out
    assert "255.255.255.248" in out             # the mask never moves


@pytest.mark.parametrize("action,check", [
    ("keep", lambda out: "3fff:16:1234:5678::1" in out),
    ("pseudo", lambda out: "2001:db8:" in out and "::1/64" in out),
    ("hash", lambda out: "<IP6-" in out),
    ("redact", lambda out: "2001:db8::/64" in out),
])
def test_ipv6_actions(action, check):
    cfg = addresses(action)
    out = sanitise_text(" ipv6 address 3fff:16:1234:5678::1/64\n",
                        cfg, salt=SALT).text
    assert check(out), out


# -- structure preservation -------------------------------------------------

def test_ipv4_pseudonym_preserves_host_octet_and_subnet_relationships(cisco):
    out = sanitise_text(cisco, public_only(), salt=SALT).text
    got = re.findall(r"\b(\d+\.\d+\.\d+)\.(129|130)\b", out)
    assert len({n for n, _ in got}) == 1, got
    assert {h for _, h in got} == {"129", "130"}


def test_ipv4_pseudonyms_land_in_the_configured_pool(cisco):
    cfg = public_only()
    out = sanitise_text(cisco, cfg, salt=SALT).text
    pools = [ipaddress.ip_network(p) for p in cfg.ipv4.pool]
    assert "128.66.16" not in out
    resolvers = frozenset(cfg.ipv4.well_known_resolvers)
    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out):
        if classify_v4(m.group(0), resolvers) == "other_unicast":
            addr = ipaddress.IPv4Address(m.group(0))
            assert any(addr in p for p in pools), m.group(0)


def test_a_narrowed_pool_is_honoured(cisco):
    cfg = public_only()
    cfg.ipv4.pool = ["198.18.0.0/15"]
    out = sanitise_text(cisco, cfg, salt=SALT).text
    assert "100.64." not in out


def test_ipv6_pseudonym_preserves_the_interface_identifier(cisco):
    out = sanitise_text(cisco, public_only(), salt=SALT).text
    assert "3fff:16" not in out
    assert "2001:db8:" in out
    assert "::1/64" in out and "::2 remote-as" in out


def test_ipv6_pool_is_honoured():
    cfg = addresses("pseudo")
    cfg.ipv6.pool = "3fff::/20"
    out = sanitise_text(" ipv6 address 3fff:16:1234:5678::1/64\n",
                        cfg, salt=SALT).text
    addr = ipaddress.IPv6Address(re.search(r"address (\S+)/64", out).group(1))
    assert addr in ipaddress.ip_network("3fff::/20")


# -- MACs -------------------------------------------------------------------

@pytest.mark.parametrize("oui,nic,expected", [
    ("keep", "keep", "mac-address 0011.2233.4455"),
    ("keep", "pseudo", "mac-address 0011."),     # vendor prefix survives
    ("redact", "pseudo", "mac-address 0000.5e"),
    ("redact", "redact", "mac-address 0000.5e00.0000"),
    ("hash", "hash", "mac-address <MAC-"),
])
def test_mac_halves_move_independently(cisco, oui, nic, expected):
    cfg = Config()
    cfg.macs.oui = oui
    cfg.macs.nic = nic
    out = sanitise_text(cisco, cfg, salt=SALT).text
    assert expected in out
    if (oui, nic) != ("keep", "keep"):
        assert "0011.2233.4455" not in out


def test_mac_redact_writes_the_configured_pool_prefix(cisco):
    cfg = Config()
    cfg.macs.oui = "redact"
    cfg.macs.nic = "keep"
    cfg.macs.pool = "02:00:00"
    out = sanitise_text(cisco, cfg, salt=SALT).text
    # the OUI becomes the pool, the kept NIC half is byte-for-byte the original
    assert "mac-address 0200.0033.4455" in out


@pytest.mark.parametrize("text,expected_sep", [
    ("mac-address 0011.2233.4455\n", "."),
    ("mac 00:11:22:33:44:55\n", ":"),
    ("mac 00-11-22-33-44-55\n", "-"),
])
def test_mac_separator_style_is_preserved(text, expected_sep):
    cfg = Config()
    cfg.macs.oui = cfg.macs.nic = "pseudo"
    out = sanitise_text(text, cfg, salt=SALT).text
    new = out.split()[-1]
    assert expected_sep in new
    assert new != text.split()[-1]


def test_a_pseudo_oui_stays_unicast():
    cfg = Config()
    cfg.macs.oui = cfg.macs.nic = "pseudo"
    out = sanitise_text("mac-address 0011.2233.4455\n", cfg, salt=SALT).text
    first = int(out.split()[-1][:2], 16)
    assert first & 0x03 == 0x00              # multicast / local bits preserved


# -- names ------------------------------------------------------------------

def test_hostname_domain_username_and_email_move_together(cisco):
    cfg = policy(hostnames="pseudo", domains="pseudo", usernames="pseudo",
                 emails="pseudo")
    out = sanitise_text(cisco, cfg, salt=SALT).text
    for leak in ("core-rtr-01", "northwind.test", "netops", "noc@northwind.test"):
        assert leak not in out
    assert "hostname device-" in out
    assert "ip domain-name example.com" in out
    assert re.search(r"username user-\w+ privilege", out)


def test_a_name_never_matches_inside_a_longer_word(arista):
    cfg = policy(usernames="pseudo")
    out = sanitise_text(arista, cfg, salt=SALT).text
    assert "role network-admin" in out
    assert "username admin " not in out


def test_the_longest_name_wins(arista):
    """buildbox.northwind.test must not be half-replaced."""
    cfg = policy(domains="pseudo", hostnames="pseudo")
    out = sanitise_text(arista, cfg, salt=SALT).text
    assert "northwind.test" not in out
    assert ".example.com" in out or "example.com" in out


def test_emails_are_reported_as_kept_by_default(cisco):
    result = sanitise_text(cisco, Config(), salt=SALT)
    assert "noc@northwind.test" in result.kept["email"]
    assert result.kept_counts["emails"] >= 1


# -- reproducibility --------------------------------------------------------

def test_same_salt_gives_identical_output(cisco):
    cfg = public_only()
    assert (sanitise_text(cisco, cfg, salt=SALT).text
            == sanitise_text(cisco, cfg, salt=SALT).text)


def test_different_salt_gives_different_pseudonyms(cisco):
    cfg = public_only()
    assert (sanitise_text(cisco, cfg, salt=b"salt-one").text
            != sanitise_text(cisco, cfg, salt=b"salt-two").text)


def test_pseudonyms_are_consistent_across_files(cisco, arista):
    cfg = public_only()
    a = sanitise_text(cisco, cfg, salt=SALT).text
    b = sanitise_text(arista, cfg, salt=SALT).text
    pa = re.search(r"tacacs-server host (\S+)", a).group(1)
    pb = re.search(r"tacacs-server host (\S+)", b).group(1)
    assert pa == pb


def test_mapping_is_exposed_for_reidentification(cisco):
    cfg = policy(hostnames="pseudo")
    result = sanitise_text(cisco, cfg, salt=SALT)
    assert result.mapping["hostname"]["core-rtr-01"].startswith("device-")


def test_hash_and_redact_produce_no_mapping(cisco):
    """There is nothing to map back: the marker is not an allocation."""
    for action in ("hash", "redact"):
        result = sanitise_text(cisco, policy(hostnames=action), salt=SALT)
        assert result.mapping == {}


# -- pool collisions --------------------------------------------------------

def test_pool_collision_is_detected():
    """Real CGNAT space kept in place clashes with the default pool."""
    cfg = Config()
    cfg.ipv4.other_unicast = "pseudo"           # cgnat stays keep
    text = " ip address 100.64.5.9 255.255.255.0\n"
    assert "100.64.5.9" in sanitise_text(text, cfg, salt=SALT).collisions


def test_no_collision_when_the_pool_is_moved():
    cfg = Config()
    cfg.ipv4.other_unicast = "pseudo"
    cfg.ipv4.pool = ["198.18.0.0/15"]
    text = " ip address 100.64.5.9 255.255.255.0\n"
    assert sanitise_text(text, cfg, salt=SALT).collisions == set()


def test_no_collision_when_the_class_itself_acts():
    cfg = Config()
    cfg.ipv4.other_unicast = "pseudo"
    cfg.ipv4.cgnat = "pseudo"                   # it moves, so nothing clashes
    text = " ip address 100.64.5.9 255.255.255.0\n"
    assert sanitise_text(text, cfg, salt=SALT).collisions == set()


def test_no_collision_reported_when_addresses_are_kept():
    text = " ip address 100.64.5.9 255.255.255.0\n"
    assert sanitise_text(text, Config(), salt=SALT).collisions == set()
