"""Things that must survive, or the output stops being a usable config."""

import pytest

from netredact import Config, sanitise_text

from .conftest import SALT, maximal, policy


def test_netmasks_and_wildcards_untouched(edge):
    out = sanitise_text(edge, maximal(), salt=SALT).text
    assert "255.255.255.240" in out
    assert "ip access-group 0.0.0.255 in" in out
    assert "ip route 0.0.0.0 0.0.0.0" in out


@pytest.mark.parametrize("action", ["pseudo", "hash", "redact"])
def test_masks_are_exempt_from_every_address_action(edge, action):
    """Masks are structural, so no action reaches them."""
    cfg = Config()
    cfg.ipv4.default = action
    cfg.ipv4.pool = ["198.18.0.0/15"]
    out = sanitise_text(edge, cfg, salt=SALT).text
    assert "255.255.255.240" in out
    assert "0.0.0.255 in" in out
    assert "ip route 0.0.0.0 0.0.0.0" in out


def test_bgp_communities_survive(edge, edge_junos):
    for text in (edge, edge_junos):
        out = sanitise_text(text, maximal(), salt=SALT).text
        assert "64512:666" in out
    out = sanitise_text(edge_junos, maximal(), salt=SALT).text
    assert "set policy-options community BLACKHOLE members 64512:666" in out
    assert "community LOCAL-PREF-100 members 64512:100;" in out


def test_junos_snmp_community_is_a_secret_but_a_bgp_community_is_not(edge_junos):
    out = sanitise_text(edge_junos, Config(), salt=SALT).text
    assert "set snmp community <REMOVED> authorization read-only" in out
    assert "publicRO" not in out
    assert "BLACKHOLE" in out


def test_junos_terminators_and_quoting_preserved(juniper):
    out = sanitise_text(juniper, Config(), salt=SALT).text
    assert 'encrypted-password "<REMOVED>"; ## SECRET-DATA' in out
    assert 'authentication-key "<REMOVED>"; ## SECRET-DATA' in out
    # the key id and grammar keywords survive, only the value moves
    assert 'authentication-key 1 type md5 value "<REMOVED>";' in out
    assert '\\"' not in out


def test_a_quoted_value_keeps_its_quotes_under_every_action(juniper):
    for action, marker in (("hash", "<SECRET-"), ("redact", "<REMOVED>")):
        cfg = Config()
        cfg.policy.secrets = action
        out = sanitise_text(juniper, cfg, salt=SALT).text
        assert f'encrypted-password "{marker}' in out


def test_junos_braces_stay_balanced(juniper):
    out = sanitise_text(juniper, maximal(), salt=SALT).text
    assert out.count("{") == juniper.count("{")
    assert out.count("}") == juniper.count("}")


def test_key_chain_names_and_crypto_commands_untouched(edge):
    out = sanitise_text(edge, Config(), salt=SALT).text
    assert "key chain OSPF-KC" in out
    assert "\n key 1\n" in out
    assert "crypto key generate rsa modulus 2048" in out
    assert "no service password-recovery" in out
    assert "service password-encryption" in out


def test_quoted_key_rule_does_not_eat_descriptions(qk):
    out = sanitise_text(qk, Config(), salt=SALT).text
    assert 'description "TRANSIT: TransitCo - CID TC-772311"' in out
    assert 'monkey "should this survive"' in out
    assert 'turnkey "nope"' in out
    assert 'key "<REMOVED>"' in out          # the real one still goes


def test_vlan_and_policy_names_untouched(edge):
    out = sanitise_text(edge, maximal(), salt=SALT).text
    assert "name ACME-CORP-DATA" in out
    assert "route-map SET-COMM permit 10" in out


def test_line_count_is_preserved_for_line_rules(cisco):
    """Only blocks and banners collapse; an ordinary line stays one line."""
    result = sanitise_text(cisco, maximal(), salt=SALT)
    # the certificate body (2 lines) and the banner body (2 lines) collapse to
    # one line each
    assert len(result.lines) == len(cisco.splitlines()) - 2


def test_output_ends_with_a_newline(cisco):
    assert sanitise_text(cisco, Config(), salt=SALT).text.endswith("\n")


def test_an_empty_input_produces_no_output():
    result = sanitise_text("", Config(), salt=SALT)
    assert result.text == ""
    assert result.counts == result.kept_counts


def test_a_truncated_block_is_still_acted_on():
    """A file that ends mid-certificate must not leak the body."""
    text = ("crypto pki certificate chain TP\n"
            " certificate self-signed 01\n"
            "  30820330 30820218 A0030201\n")
    result = sanitise_text(text, policy(identity="redact"), salt=SALT)
    assert "30820330" not in result.text
    assert result.counts["certificate-block"] == 1
