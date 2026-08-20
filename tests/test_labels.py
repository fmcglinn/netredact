"""Associated labels are sanitised with the configuration they describe."""

from types import MappingProxyType

import pytest

from netredact import Config, sanitise_text

from .conftest import SALT, policy


def test_labels_are_optional_and_backwards_compatible(cisco):
    before = sanitise_text(cisco, salt=SALT)
    after = sanitise_text(cisco, salt=SALT, labels=None)

    assert after.text == before.text
    assert after.labels == {}
    assert before.labels == {}
    assert after.label_replacements == {}
    assert before.label_replacements == {}


def test_a_hostname_in_a_filename_uses_the_body_pseudonym():
    result = sanitise_text(
        "hostname edge-rtr-01\n",
        policy(hostnames="pseudo"),
        salt=SALT,
        labels={"filename": "BACKUP_edge-RTR-01_running.cfg"},
    )

    pseudonym = result.mapping["hostname"]["edge-rtr-01"]
    assert f"hostname {pseudonym}" in result.text
    assert result.labels == {"filename": f"BACKUP_{pseudonym}_running.cfg"}


def test_label_replacements_expose_only_immutable_rendered_values():
    result = sanitise_text(
        "hostname edge-rtr-01\n",
        policy(hostnames="pseudo"),
        salt=SALT,
        labels={
            "filename": "backup_edge-rtr-01_203.0.113.9.cfg",
            "unmatched": "customer-secret.backup",
        },
    )

    pseudonym = result.mapping["hostname"]["edge-rtr-01"]
    assert result.label_replacements == {
        "filename": {"hostnames": (pseudonym,)},
        "unmatched": {},
    }
    assert "edge-rtr-01" not in repr(result.label_replacements)
    assert "customer-secret" not in repr(result.label_replacements)
    assert isinstance(result.label_replacements, MappingProxyType)
    assert isinstance(result.label_replacements["filename"], MappingProxyType)
    with pytest.raises(TypeError):
        result.label_replacements["filename"]["hostnames"] = ("unsafe",)


def test_label_name_matching_is_longest_first_case_insensitive_and_filename_aware():
    text = """\
hostname Edge-RTR-01.northwind.test
ip domain name northwind.test
username net_ops privilege 15
"""
    cfg = policy(hostnames="pseudo", domains="pseudo", usernames="pseudo")
    result = sanitise_text(
        text,
        cfg,
        salt=SALT,
        labels={
            "display": (
                "EDGE-RTR-01.NORTHWIND.TEST--NORTHWIND.TEST__NET_OPS "
                "knowledge-RTR-01.northwind.testing"
            )
        },
    )

    hostname = result.mapping["hostname"]["edge-rtr-01.northwind.test"]
    domain = result.mapping["domain"]["northwind.test"]
    username = result.mapping["username"]["net_ops"]
    assert result.labels["display"] == (
        f"{hostname}--{domain}__{username} knowledge-RTR-01.northwind.testing"
    )


def test_a_discovered_email_is_transformed_in_an_associated_label():
    result = sanitise_text(
        "snmp-server contact NetOps@northwind.test\n",
        policy(emails="pseudo"),
        salt=SALT,
        labels={"display": "owner: NETOPS@NORTHWIND.TEST"},
    )

    pseudonym = result.mapping["username"]["netops"] + "@" + (
        result.mapping["domain"]["northwind.test"])
    assert result.labels == {"display": f"owner: {pseudonym}"}


def test_a_discovered_email_with_an_ip_domain_is_handled_before_its_address():
    cfg = policy(emails="pseudo")
    cfg.ipv4.default = "pseudo"
    result = sanitise_text(
        "snmp-server contact ops@203.0.113.9\n",
        cfg,
        salt=SALT,
        labels={"display": "owner: OPS@203.0.113.9"},
    )

    body_email = result.text.split()[-1]
    assert result.labels == {"display": f"owner: {body_email}"}


def test_a_discovered_email_does_not_match_inside_another_email_address():
    result = sanitise_text(
        "snmp-server contact ops@example.com\n",
        policy(emails="pseudo"),
        salt=SALT,
        labels={
            "display": "ops@example.com dev.ops@example.com x+ops@example.com",
        },
    )

    pseudonym = result.text.split()[-1]
    assert result.labels == {
        "display": f"{pseudonym} dev.ops@example.com x+ops@example.com",
    }


def test_labels_transform_recognisable_addresses_and_macs_consistently():
    cfg = Config()
    cfg.ipv4.default = "pseudo"
    cfg.ipv6.default = "pseudo"
    cfg.macs.oui = "pseudo"
    cfg.macs.nic = "pseudo"
    text = """\
ip address 203.0.113.9 255.255.255.0
ipv6 address 2001:db8:44::9/64
mac-address 00:11:22:33:44:55
"""
    result = sanitise_text(
        text,
        cfg,
        salt=SALT,
        labels={
            "filename": "203.0.113.9_2001:DB8:44::9_00-11-22-33-44-55.cfg"
        },
    )

    v4, v6, mac = (
        result.text.splitlines()[0].split()[2],
        result.text.splitlines()[1].split()[2].removesuffix("/64"),
        result.text.splitlines()[2].split()[1],
    )
    assert result.labels["filename"] == f"{v4}_{v6}_{mac.replace(':', '-')}.cfg"
    assert result.label_replacements["filename"] == {
        "ipv4": (v4,),
        "ipv6": (v6,),
        "macs": (mac.replace(":", "-"),),
    }


def test_label_actions_include_hash_and_redact():
    cfg = policy(hostnames="hash")
    cfg.ipv4.default = "redact"
    cfg.ipv6.default = "hash"
    cfg.macs.oui = cfg.macs.nic = "hash"
    result = sanitise_text(
        "hostname edge-1\n",
        cfg,
        salt=SALT,
        labels={"display": "EDGE-1 203.0.113.9 2001:db8:44::9 00:11:22:33:44:55"},
    )

    assert result.labels["display"].startswith("<HOST-")
    assert " 192.0.2.0 " in result.labels["display"]
    assert " <IP6-" in result.labels["display"]
    assert " <MAC-" in result.labels["display"]


def test_labels_do_not_change_body_accounting_or_mapping():
    cfg = Config()
    cfg.ipv4.default = "pseudo"
    text = "ip address 203.0.113.9 255.255.255.0\n"
    without = sanitise_text(text, cfg, salt=SALT)
    with_labels = sanitise_text(
        text,
        cfg,
        salt=SALT,
        labels={"filename": "198.51.100.20.cfg"},
    )

    assert with_labels.labels["filename"] != "198.51.100.20.cfg"
    assert with_labels.counts == without.counts
    assert with_labels.kept_counts == without.kept_counts
    assert with_labels.kept == without.kept
    assert with_labels.mapping == without.mapping
    assert with_labels.findings == without.findings
    assert with_labels.collisions == without.collisions


def test_salt_file_is_not_read_or_created_by_sanitise_text(tmp_path):
    salt_path = tmp_path / "library-must-not-touch-this.salt"
    cfg = policy(hostnames="pseudo")
    cfg.salt_file = str(salt_path)

    result = sanitise_text("hostname edge-1\n", cfg)

    assert "hostname device-" in result.text
    assert not salt_path.exists()
