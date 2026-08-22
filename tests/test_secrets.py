"""Every secret in the fixtures must be gone, at default settings.

The default policy is ``secrets = "redact"`` and nothing else, so these tests
are the contract the README states: credentials are destroyed out of the box.
"""

import pytest

from netredact import Config, sanitise_text
from netredact.cli import EXIT_OK, main

from .conftest import FIXTURE_NAMES, SALT, policy, section

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
    "BngRadiusPass77", "AutoConfPass88",
    # FortiOS: every one of these is a `set <attribute> [ENC] <value>` line,
    # which is the one grammar the whole family shares
    "SH2NwEdgeAdminPassEXAMPLEyqe7C3E5xUkAQjV3wIhLZbCxT1QYyqe7C3E5=",
    "AK1FgtBackupPassEXAMPLE9wQwErTy==", "AK1FgtApiKeyEXAMPLEz0982kQ==",
    "snmpNorthwindRO", "AK1SnmpAuthPassEXAMPLE0aQ==",
    "AK1SnmpPrivPassEXAMPLE1bQ==", "NtpSharedSecret123",
    "AK1LocalUserPassEXAMPLE2cQ==", "AK1LdapBindPassEXAMPLE3dQ==",
    "AK1RadiusSecretEXAMPLE4eQ==", "AK1CertKeyPassEXAMPLE5fQ==",
    "MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqEXAMPLEprivatekeymaterial0123456789",
    "AK1PskEXAMPLEsEcReTkEyMaTeRiAl==", "AK1PpkEXAMPLEsEcReT6gQ==",
    "AK1WifiPassphraseEXAMPLE7hQ==", "AK1BgpNeighborPassEXAMPLE8iQ==",
]


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_no_planted_secret_survives(fixtures, name):
    text = (fixtures / name).read_text()
    out = sanitise_text(text, Config(), salt=SALT).text
    leaked = [s for s in PLANTED if s in text and s in out]
    assert leaked == [], f"{name} leaked: {leaked}"


def test_the_planted_list_is_not_silently_stale(fixtures):
    """A typo in the list above would make every assertion vacuous."""
    all_text = "".join((fixtures / n).read_text()
                       for n in FIXTURE_NAMES)
    missing = [s for s in PLANTED if s not in all_text]
    assert missing == [], f"not present in any fixture: {missing}"


@pytest.mark.parametrize("name", FIXTURE_NAMES)
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


# ---------------------------------------------------------------------------
# `authentication password <secret>` in mid-line position. `bare-password` is
# anchored, so it only saw the hierarchical form; JunOS subscriber management
# puts the same credential at the end of a long `set` path, and those lines
# left the tool in cleartext with `--strict` exiting 0.
# ---------------------------------------------------------------------------

#: (line, the secret that must not survive) -- the real JunOS spellings
AUTH_PASSWORD = [
    ("set groups BNG system services dhcp-local-server dual-stack-group BNG"
     " authentication password BngRadiusPass77", "BngRadiusPass77"),
    ("set groups BNG routing-instances <*> system services dhcp-local-server"
     " dual-stack-group BNG authentication password BngRadiusPass77",
     "BngRadiusPass77"),
    ("set groups AUTOCONF interfaces <*> auto-configure stacked-vlan-ranges"
     " authentication password AutoConfPass88", "AutoConfPass88"),
    # the hierarchical form, which `bare-password` already had: still works
    ("            password BngRadiusPass77;", "BngRadiusPass77"),
]


@pytest.mark.parametrize("line,secret", AUTH_PASSWORD, ids=range(len(AUTH_PASSWORD)))
def test_authentication_password_is_a_secret_wherever_it_sits(line, secret):
    result = sanitise_text(line + "\n", Config(), salt=SALT)
    assert secret not in result.text, result.text
    assert "<REMOVED>" in result.text
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_authentication_password_keeps_the_path_that_names_it():
    """The credential goes; the hierarchy it hangs off is structure."""
    line = ("set groups BNG system services dhcp-local-server dual-stack-group"
            " BNG authentication password BngRadiusPass77\n")
    out = sanitise_text(line, Config(), salt=SALT).text
    assert out.strip().endswith("authentication password <REMOVED>")
    assert "dhcp-local-server dual-stack-group BNG" in out


@pytest.mark.parametrize("line", [
    'aaa authentication password-prompt "Password: "',
    "set system login password minimum-length 8",
    "no password",
    "service password-encryption",
])
def test_the_wider_password_match_stays_off_the_knobs(line):
    """`authentication` is the qualifier that keeps the unanchored form honest."""
    result = sanitise_text(line + "\n", Config(), salt=SALT)
    assert result.text.splitlines()[-1] == line, result.text


# ---------------------------------------------------------------------------
# FortiOS. Every credential the platform has is written the same way -- `set
# <attribute> [ENC] <value>`, with the block above saying what the value
# belongs to -- so one rule covers the lot, and what confines it is the shape:
# the keyword has to be the FIRST token after `set`.
#
# That matters because two of the keywords are ordinary words. JunOS puts
# `secret` and `key` at the END of a long `set` path, where `bare-secret` and
# `quoted-key` own them; FortiOS puts them immediately after `set`, where it
# owns nothing else. The collision tests below are the whole justification for
# reading the keywords at all.
# ---------------------------------------------------------------------------

#: (line, the credential that must not survive)
FORTIOS_SECRETS = [
    ("        set password ENC AK1BgpNeighborPassEXAMPLE8iQ==",
     "AK1BgpNeighborPassEXAMPLE8iQ=="),
    ("        set passwd ENC AK1LocalUserPassEXAMPLE2cQ==",
     "AK1LocalUserPassEXAMPLE2cQ=="),
    ("        set psksecret ENC AK1PskEXAMPLEsEcReTkEyMaTeRiAl==",
     "AK1PskEXAMPLEsEcReTkEyMaTeRiAl=="),
    ("        set ppk-secret ENC AK1PpkEXAMPLEsEcReT6gQ==",
     "AK1PpkEXAMPLEsEcReT6gQ=="),
    ("        set auth-pwd ENC AK1SnmpAuthPassEXAMPLE0aQ==",
     "AK1SnmpAuthPassEXAMPLE0aQ=="),
    ("        set priv-pwd ENC AK1SnmpPrivPassEXAMPLE1bQ==",
     "AK1SnmpPrivPassEXAMPLE1bQ=="),
    ("        set passphrase ENC AK1WifiPassphraseEXAMPLE7hQ==",
     "AK1WifiPassphraseEXAMPLE7hQ=="),
    ("        set api-key ENC AK1FgtApiKeyEXAMPLEz0982kQ==",
     "AK1FgtApiKeyEXAMPLEz0982kQ=="),
    ("        set secret ENC AK1RadiusSecretEXAMPLE4eQ==",
     "AK1RadiusSecretEXAMPLE4eQ=="),
    ('            set key "NtpSharedSecret123"', "NtpSharedSecret123"),
]


@pytest.mark.parametrize("line,secret", FORTIOS_SECRETS,
                         ids=[line.split()[1] for line, _ in FORTIOS_SECRETS])
def test_every_fortios_credential_is_one_rule(line, secret):
    """One rule, ten attributes, and the keyword itself always survives."""
    result = sanitise_text(line + "\n", Config(), salt=SALT)
    assert secret not in result.text
    assert result.counts["fortios-secret"] == 1
    assert line.split()[1] in result.text
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_the_fortios_encoding_token_is_not_mistaken_for_the_secret():
    """`ENC` says the value is encrypted; eating it would leave the blob.

    This is the `wpa-psk ascii 0 <key>` lesson in FortiOS spelling: a hint
    consumed as if it were the value emits a marker, so the line reads as
    handled while the credential stays where it was.
    """
    out = sanitise_text("    set password ENC AK1FgtBackupPassEXAMPLE9wQwErTy==\n",
                        Config(), salt=SALT).text
    assert out.strip() == "set password ENC <REMOVED>"


#: (line, the rule that must claim it) -- the shapes another dialect owns, all
#: of which contain a FortiOS credential keyword somewhere on the line
NOT_FORTIOS = [
    ('    key "OspfKey1";', "quoted-key"),
    ("    key-string 7 0822455D0A16", "key-string"),
    ("    server-private 203.0.113.44 key 7 070C285F4D06", "encoded-key"),
    ("set groups BNG system services dhcp-local-server dual-stack-group BNG"
     " authentication password BngRadiusPass77", "authentication-password"),
    ("    radius-server host 128.66.16.21 key SuperSecretTacacsKey",
     "aaa-server-key"),
    ("set snmp community publicRO authorization read-only", "snmp-community"),
    ("    username admin secret sha512 $6$Ab2C$zyxwvutsrq", "username-secret"),
    ("    enable secret 5 $1$abc$def123", "enable-secret"),
]


@pytest.mark.parametrize("line,owner", NOT_FORTIOS,
                         ids=[owner for _line, owner in NOT_FORTIOS])
def test_the_fortios_rule_does_not_poach_another_dialects_line(line, owner):
    """Two rules on one line would count twice and splice twice."""
    result = sanitise_text(line + "\n", Config(), salt=SALT)
    assert result.counts[owner] == 1
    assert result.counts["fortios-secret"] == 0


@pytest.mark.parametrize("line", [
    "    set key-id 7",                       # a key id; the key is elsewhere
    "    set type password",                  # the kind of account
    "    set password-policy enable",
    "    set secondary 203.0.113.54",
    "    set security wpa2-only-personal",
])
def test_a_fortios_knob_is_not_a_credential(line):
    result = sanitise_text(line + "\n", Config(), salt=SALT)
    assert result.text.splitlines()[-1] == line
    assert not result.counts
