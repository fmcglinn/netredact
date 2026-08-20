"""The library surface: one object in, one Result out."""

from collections import Counter

import netredact
from netredact import Config, Pseudonymiser, Sanitiser, sanitise_text

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


def test_config_can_be_built_in_python_without_a_file():
    cfg = Config()
    cfg.text.default = "hash"
    cfg.ipv4.rfc1918 = "pseudo"
    assert cfg.action_for_rule("description") == "hash"
    assert cfg.ipv4.any_active()
    assert cfg.source is None


def test_version_is_exposed():
    assert netredact.__version__.count(".") >= 1


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
