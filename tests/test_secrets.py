"""Every secret in the fixtures must be gone, at default settings.

The default policy is ``secrets = "redact"`` and nothing else, so these tests
are the contract the README states: credentials are destroyed out of the box.
"""

import pytest

from netredact import Config, sanitise_text
from netredact.cli import EXIT_OK, main

from .conftest import SALT, policy, section

# literal secrets planted in the fixtures -- none may survive
PLANTED = [
    "$1$mERr$M6KsMCsLPnvvKmnZkH3xF/", "070C285F4D06", "04480E051A33490E",
    "PlainTextPass123", "121A0C041104", "SuperSecretTacacsKey", "060506324F41",
    "MyPreSharedKey123", "HsrpSecret9", "05080F1C2243", "110A1016141D",
    "pub1icR0", "wr1teMe", "TrapCommunity99", "AuthPass123", "PrivPass456",
    "07230A4B5C", "08351F1B1C4D",
    "$1$xyz1$abcdefghijklmnopqrstu.",
    "$6$Xy1Z$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab.",
    "$6$Ab2C$zyxwvutsrqponmlkjihgfedcba9876543210",
    "070E234F1A0B", "0822455D0A16", "snmpRO", "snmpRW", "TrapPass",
    "12090404011C03162E",
    "$6$abcd$1234567890abcdefghijklmnopqrstuvwxyzABCDEF",
    "$6$wxyz$0987654321zyxwvutsrqponmlkjihgfedcba",
    "$9$abcdEFGH1234", "JUNOS123456", "pubR0nly", "wr1t3Me",
    "$9$ZqWX-ws4aUjq", "$9$OspfKeyBlob99", "$9$PreSharedBlob123",
    "VrrpPass1", "0x1234abcd", "0x5678ef90",
    "$9$SecretBlob", "$6$abc$def123", "$9$Secret", "publicRO", "privRW",
]


@pytest.mark.parametrize("name", ["cisco.cfg", "arista.cfg", "juniper.cfg",
                                  "edge.cfg", "edge-junos.cfg", "qk.cfg"])
def test_no_planted_secret_survives(fixtures, name):
    text = (fixtures / name).read_text()
    out = sanitise_text(text, Config(), salt=SALT).text
    leaked = [s for s in PLANTED if s in text and s in out]
    assert leaked == [], f"{name} leaked: {leaked}"


def test_the_planted_list_is_not_silently_stale(fixtures):
    """A typo in the list above would make every assertion vacuous."""
    all_text = "".join((fixtures / n).read_text()
                       for n in ("cisco.cfg", "arista.cfg", "juniper.cfg",
                                 "edge.cfg", "edge-junos.cfg", "qk.cfg"))
    missing = [s for s in PLANTED if s not in all_text]
    assert missing == [], f"not present in any fixture: {missing}"


@pytest.mark.parametrize("name", ["cisco.cfg", "arista.cfg", "juniper.cfg",
                                  "edge.cfg", "edge-junos.cfg", "qk.cfg"])
def test_verification_is_clean_at_defaults(fixtures, name):
    text = (fixtures / name).read_text()
    result = sanitise_text(text, Config(), salt=SALT)
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_secrets_go_even_though_nothing_else_does(cisco):
    cfg = Config()
    assert cfg.text.default == "keep" and not cfg.ipv4.any_active()
    out = sanitise_text(cisco, cfg, salt=SALT).text
    assert "enable secret 5 <REMOVED>" in out
    assert "snmp-server community <REMOVED> RO MGMT" in out
    assert "128.66.16.130" in out                 # and nothing else moved


def test_inline_encoded_key_is_caught(cisco):
    """server-private ... key 7 <hex> is not on a tacacs/radius line."""
    out = sanitise_text(cisco, Config(), salt=SALT).text
    assert "server-private 203.0.113.44 key 7 <REMOVED>" in out


def test_snmp_host_keeps_its_keywords_and_loses_the_community(cisco):
    out = sanitise_text(cisco, Config(), salt=SALT).text
    assert "snmp-server host 203.0.113.99 version 2c <REMOVED>" in out


def test_snmp_v3_auth_and_priv_are_both_hit(cisco):
    out = sanitise_text(cisco, Config(), salt=SALT).text
    assert ("snmp-server user snmpv3usr NETGRP v3 auth sha <REMOVED> "
            "priv aes 128 <REMOVED>" in out)


def test_certificate_block_is_kept_by_default_and_prints_verbatim(cisco):
    """identity = keep, so the whole body survives -- deliberately."""
    result = sanitise_text(cisco, Config(), salt=SALT)
    assert "30820330 30820218" in result.text
    assert result.kept_counts["certificate-block"] == 1
    assert result.findings == []                 # kept identity is not a miss


@pytest.mark.parametrize("action,expected", [
    ("redact", "<REMOVED>"),
    ("hash", "<CERT-"),
    ("pseudo", "cert-"),
])
def test_certificate_block_acts_once_per_block(cisco, action, expected):
    result = sanitise_text(cisco, policy(identity=action), salt=SALT)
    assert "30820330" not in result.text
    assert expected in result.text
    assert "certificate self-signed 01" in result.text    # structure survives
    assert "  quit" in result.text
    assert result.counts["certificate-block"] == 1        # once, not per line


def test_a_kept_certificate_block_can_be_asked_for_by_name(cisco):
    """[overrides] certificate-block = "keep" prints a whole certificate."""
    cfg = section("identity", "redact", certificate_block="keep")
    result = sanitise_text(cisco, cfg, salt=SALT)
    assert "30820330 30820218" in result.text
    assert result.findings == []


def test_banner_is_counted_once_per_block_not_per_line(cisco):
    result = sanitise_text(cisco, policy(text="redact"), salt=SALT)
    assert "banner motd ^C\n<REMOVED>\n^C" in result.text
    assert "Unauthorised access" not in result.text
    assert result.counts["banner"] == 1


def test_banner_is_kept_by_default_and_counted(cisco):
    result = sanitise_text(cisco, Config(), salt=SALT)
    assert "Unauthorised access to NORTHWIND" in result.text
    assert result.kept_counts["banner"] == 1


def test_banner_can_be_acted_on_alone(cisco):
    """The banner is the one text rule people want on its own."""
    cfg = section("text", "keep", banner="redact")
    out = sanitise_text(cisco, cfg, salt=SALT).text
    assert "Unauthorised access" not in out
    assert "UPLINK TO ACME PTY LTD" in out       # other text still kept


def test_key_string_block_is_a_secret():
    text = "key chain KC\n key 1\n  key-string\n  SecretMaterial\n  quit\n"
    result = sanitise_text(text, Config(), salt=SALT)
    assert "SecretMaterial" not in result.text
    assert result.counts["key-string-block"] == 1


PEM = ("-----BEGIN RSA PRIVATE KEY-----\n"
       "MIIEowIBAAKCAQEAprivatekeymaterialAAAABBBBCCCCDDDDEEEEFFFF0123456789\n"
       "-----END RSA PRIVATE KEY-----\n"
       "-----BEGIN CERTIFICATE-----\n"
       "MIIBcertificatematerialhere\n"
       "-----END CERTIFICATE-----\n")


def test_pem_private_key_is_a_secret_and_a_certificate_is_identity():
    result = sanitise_text(PEM, Config(), salt=SALT)
    assert "privatekeymaterial" not in result.text
    assert result.counts["pem-key"] == 1
    # a certificate is identity, kept by default
    assert "MIIBcertificatematerialhere" in result.text
    assert result.kept_counts["pem-cert"] == 1
    # The BEGIN / END delimiters are deliberately kept -- they are the config's
    # structure, not the secret -- so a block whose body netredact has already
    # destroyed is not a finding. `pem-left` judges the body.
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_a_kept_pem_private_key_still_reports(tmp_path):
    """Keeping it is allowed; passing --strict on it is not."""
    result = sanitise_text(PEM, policy(secrets="keep"), salt=SALT)
    assert "privatekeymaterial" in result.text
    checks = {f.check for f in result.findings}
    assert "pem-left" in checks and "long-base64-left" in checks

    src = tmp_path / "key.cfg"
    src.write_text(PEM)
    conf = tmp_path / "netredact.toml"
    conf.write_text('[secrets]\ndefault = "keep"\n')
    assert main([str(src), "-c", str(conf), "--strict"]) == 2


def test_a_handled_pem_block_exits_zero(tmp_path):
    """The regression the body-based check protects: --strict on a key we killed."""
    src = tmp_path / "key.cfg"
    src.write_text(PEM)
    assert main([str(src), "--strict"]) == EXIT_OK


def test_junos_secrets_keep_their_terminator_and_quoting(juniper):
    out = sanitise_text(juniper, Config(), salt=SALT).text
    assert 'encrypted-password "<REMOVED>"; ## SECRET-DATA' in out
    assert 'authentication-key "<REMOVED>"; ## SECRET-DATA' in out
    assert 'authentication-key 1 type md5 value "<REMOVED>";' in out
    assert '\\"' not in out


def test_secrets_keep_still_leaves_the_credential_findings(cisco):
    """Keeping a secret is allowed; passing --strict silently is not."""
    result = sanitise_text(cisco, policy(secrets="keep"), salt=SALT)
    assert "$1$mERr$M6KsMCsLPnvvKmnZkH3xF/" in result.text
    checks = {f.check for f in result.findings}
    assert "credential-left" in checks
    assert "crypt-hash-left" in checks


# ---------------------------------------------------------------------------
# Multi-qualifier credential lines.
#
# ENC covers the encoding / algorithm hints that sit between a keyword and its
# secret. Several vendor commands stack TWO of them -- Cisco's autonomous-AP
# `wpa-psk {ascii|hex} [0|7] <key>` is the clearest -- and a pattern that
# admits only one consumes the encoding-type flag as if it were the secret.
# That is worse than a miss: it emits a marker, so the line reads as handled
# and `--strict` exits clean over a cleartext credential.
# ---------------------------------------------------------------------------

#: (line, the secret that must not survive)
MULTI_QUALIFIER = [
    (" wpa-psk ascii 0 Tr0ub4dor&3", "Tr0ub4dor&3"),
    (" wpa-psk hex 0 0123456789abcdef", "0123456789abcdef"),
    (" wpa-psk ascii 7 070C285F4D06", "070C285F4D06"),
    (" password ascii 0 PlainWord", "PlainWord"),
    (" key-string ascii 0 KeyStringVal", "KeyStringVal"),
]


@pytest.mark.parametrize("line,secret", MULTI_QUALIFIER)
def test_a_second_encoding_hint_does_not_shield_the_secret(line, secret):
    out = sanitise_text(line + "\n", Config(), salt=SALT).text
    assert secret not in out, f"leaked through a second hint: {out.strip()!r}"


@pytest.mark.parametrize("line,secret", MULTI_QUALIFIER)
def test_a_multi_qualifier_leak_is_never_silent(line, secret):
    """Belt and braces: if the rule ever regresses, verify must still speak.

    The marker is what makes this dangerous -- a half-redacted line looks
    finished. Whatever else changes, the tool must not report success over a
    surviving credential.
    """
    res = sanitise_text(line + "\n", Config(), salt=SALT)
    assert secret not in res.text or res.findings, (
        f"silent leak: {res.text.strip()!r} with no finding")


def test_single_qualifier_lines_are_unchanged_by_the_run():
    """The common one-hint form must keep working exactly as before."""
    for line, secret in [(" password 7 070C285F4D06", "070C285F4D06"),
                         (" enable secret 5 $1$abc$def", "$1$abc$def"),
                         (" key-string 7 0822455D0A16", "0822455D0A16")]:
        out = sanitise_text(line + "\n", Config(), salt=SALT).text
        assert secret not in out, f"regressed: {out.strip()!r}"


def test_a_numeric_secret_is_not_eaten_as_a_hint():
    """`\\d+` is a hint AND a plausible secret; the last token is the secret."""
    out = sanitise_text(" password 0 12345678\n", Config(), salt=SALT).text
    assert "12345678" not in out, out
    assert "password" in out, "the keyword itself must survive"


def test_isis_interface_password_is_a_secret():
    """`isis password X` is the interface-level form; the rule only had the
    `lsp-/area-/domain-password` spellings."""
    out = sanitise_text(" isis password IsisSecret99\n", Config(), salt=SALT).text
    assert "IsisSecret99" not in out, out
