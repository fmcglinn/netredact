"""The library surface: one object in, one Result out."""

from collections import Counter

import pytest

import netredact
from netredact import Config, Pseudonymiser, Sanitiser, provenance, sanitise_text

from .conftest import SALT, policy


def test_the_documented_entry_point_needs_nothing_but_text(cisco):
    result = sanitise_text(cisco)
    assert "enable secret 5 <REMOVED>" in result.text
    assert result.vendor == "cisco"


def test_a_random_salt_differs_between_runs(cisco):
    cfg = policy(hostnames="pseudo")
    assert (sanitise_text(cisco, cfg).text != sanitise_text(cisco, cfg).text)


def test_public_api_is_exported():
    for name in ("Config", "ConfigError", "CustomRule", "CollectionConfig", "PolicyConfig",
                 "IPv4Policy", "IPv6Policy", "MacPolicy", "VerifyConfig",
                 "SecretsPolicy", "TextPolicy", "IdentityPolicy",
                 "PlatformPolicy",
                 "ACTIONS", "FAMILIES", "ALLOWED", "sanitise_text",
                 "Sanitiser", "Result", "RemovedSection", "Pseudonymiser", "detect_vendor",
                 "verify", "Finding", "check_names", "RuleCatalogue",
                 "RuleInfo", "RuleHit", "RuleReplacement", "REMOVED", "find_config",
                 "classify_v4", "classify_v6",
                 "V4_CLASS_NAMES", "V6_CLASS_NAMES"):
        assert name in netredact.__all__, name
        assert hasattr(netredact, name), name


def test_the_two_passes_can_be_driven_directly(cisco):
    """collect() learns the identities, run() rewrites; nothing else is needed."""
    lines = cisco.splitlines()
    san = Sanitiser(policy(hostnames="pseudo"), salt=SALT)
    san.collect(lines)
    assert "core-rtr-01" in san.hostnames
    assert "northwind.test" in san.domains
    assert "netops" in san.usernames
    out = san.run(lines)
    assert any("hostname device-" in line for line in out)
    assert isinstance(san.counts, Counter)
    assert isinstance(san.kept_counts, Counter)


def test_a_pseudonymiser_can_be_shared_between_files(cisco, arista):
    """One Pseudonymiser means one mapping across a whole fleet."""
    cfg = policy(hostnames="pseudo")
    p = Pseudonymiser(SALT, cfg)
    for text in (cisco, arista):
        san = Sanitiser(cfg, salt=SALT, pseudo=p)
        lines = text.splitlines()
        san.collect(lines)
        san.run(lines)
    assert set(p.maps["hostname"]) >= {"core-rtr-01", "agg-sw-02"}
    assert len(set(p.maps["hostname"].values())) == len(p.maps["hostname"])


def test_pseudonymiser_validates_a_mutated_config_before_using_it():
    from netredact import ConfigError

    cfg = Config()
    cfg.ipv4.pool = [7]
    with pytest.raises(ConfigError, match=r"\[ipv4\] pool entries must be strings"):
        Pseudonymiser(SALT, cfg)


def test_config_can_be_built_in_python_without_a_file():
    cfg = Config()
    cfg.text.default = "hash"
    cfg.ipv4.rfc1918 = "pseudo"
    assert cfg.action_for_rule("description") == "hash"
    assert cfg.ipv4.any_active()
    assert cfg.source is None


def test_version_is_exposed():
    assert netredact.__version__ == "0.1.0"


# -- the library never writes to a stream --------------------------------------
#
# Reporting belongs to the CLI. A library that prints is unusable from a web
# handler, a notebook or another CLI, so problems are returned on the Result or
# raised -- never written to stdout or stderr.

def test_sanitising_writes_to_no_stream(cisco, capsys):
    cfg = policy(secrets="keep")           # guarantees findings
    result = sanitise_text(cisco, cfg, salt=SALT)
    assert result.findings, "the fixture must produce findings for this to mean anything"
    out, err = capsys.readouterr()
    assert out == "" and err == ""


def test_a_pool_that_cannot_be_filled_raises_rather_than_prints(capsys):
    from netredact import PoolExhausted
    cfg = Config()
    cfg.ipv4.other_unicast = "pseudo"
    cfg.ipv4.pool = ["192.0.2.0/24"]       # one /24, so room for one subnet
    text = "".join(f" ip address 203.0.{i}.5 255.255.255.0\n" for i in range(8))
    try:
        sanitise_text(text, cfg, salt=SALT)
    except PoolExhausted as exc:
        assert "pool" in str(exc).lower()
    else:
        raise AssertionError("expected PoolExhausted")
    out, err = capsys.readouterr()
    assert out == "" and err == ""


def test_a_bad_config_raises_rather_than_prints(tmp_path, capsys):
    from netredact import ConfigError
    bad = tmp_path / "netredact.toml"
    bad.write_text('[secrets]\ndefault = "obliterate"\n')
    try:
        Config.load(str(bad))
    except ConfigError as exc:
        assert "obliterate" in str(exc)
    else:
        raise AssertionError("expected ConfigError")
    out, err = capsys.readouterr()
    assert out == "" and err == ""


# -- the provenance marker ---------------------------------------------------

def test_sanitise_text_does_not_add_the_marker(cisco):
    """The marker belongs to the file, not the transformation.

    Inserting a line here would break the line-count guarantee, so the caller
    that writes the artefact applies it -- see ``netredact.provenance``.
    """
    result = sanitise_text(cisco, salt=SALT)
    assert provenance.TOKEN not in result.text
    assert len(result.text.splitlines()) == len(cisco.splitlines())
    assert result.already_sanitised is False


def test_marked_input_is_recognised_and_the_marker_never_reaches_the_rules(cisco):
    once = provenance.apply_text(sanitise_text(cisco, salt=SALT).text,
                                 "cisco", netredact.__version__)
    again = sanitise_text(once, salt=SALT)

    assert again.already_sanitised is True
    # stripped, not sanitised: nothing in the marker was counted as a change,
    # and the version number in it was not hashed by the os-version rule
    assert provenance.TOKEN not in again.text
    assert netredact.__version__ in once
    assert again.text == sanitise_text(cisco, salt=SALT).text


def test_applying_the_marker_twice_leaves_one(cisco):
    once = provenance.apply_text(sanitise_text(cisco, salt=SALT).text,
                                 "cisco", netredact.__version__)
    twice = provenance.apply_text(once, "cisco", netredact.__version__)
    assert twice == once
    assert twice.count(provenance.TOKEN) == 1


def test_the_marker_is_a_comment_in_the_grammar_it_lands_in():
    assert provenance.marker_for("juniper", "1.0").startswith("# ")
    for vendor in ("cisco", "arista", "unknown"):
        assert provenance.marker_for(vendor, "1.0").startswith("! ")


def test_the_marker_carries_no_re_identification_material(cisco):
    """Provenance, not a report: the tool and the version, nothing found."""
    line = provenance.marker_for("cisco", netredact.__version__)
    assert netredact.__version__ in line
    for leak in ("192.168", "10.20.30", "core-rtr", "PlainText"):
        assert leak not in line

