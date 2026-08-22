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
    "R0uterPass77", "BackupPass88", "BakeryPPP123", "FabricPPP456",
    "Aut0mnBridge41", "L2tpPass99", "RadiusSecret55", "L2tpIpsecPsk88",
    # both PSK generations on ONE command line, which is why these rules are
    # searched and not matched: a rule that matched once left the first of the
    # two standing next to a marker saying the line had been dealt with
    "OldStonePier19", "NewStonePier23",
    # WireGuard: the interface's own key, and a peer's PSK. The peer's PUBLIC
    # key is deliberately absent from this list -- it is `identity`, kept by
    # default, and destroying it is not what the default promises.
    "bm9ydGh3aW5kLXdnLXByaXZrZXktdGVzdG9ubHktMDE=",
    "bm9ydGh3aW5kLXdnLXBzay10ZXN0b25seS0wMDAwMDM=",
    # the tail of a passphrase RouterOS wrapped onto a second line. It is only
    # reachable at all because the wrap is undone before the rules run: on the
    # first physical line the value matcher cannot close the quote, so without
    # the join a marker lands on the opening fragment and this survives.
    "Lantern 77",
]


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_no_planted_secret_survives(fixtures, name):
    text = (fixtures / name).read_text()
    out = sanitise_text(text, Config(), salt=SALT).text
    leaked = [s for s in PLANTED if s in text and s in out]
    assert leaked == [], f"{name} leaked: {leaked}"


def test_the_planted_list_is_not_silently_stale(fixtures):
    """A typo in the list above would make every assertion vacuous."""
    all_text = "".join((fixtures / n).read_text() for n in FIXTURE_NAMES)
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
# RouterOS. Every argument is a `key=value` pair on an `add` / `set` command,
# so the credential rules are unanchored and the `=` is what tells them apart
# from the space-form rules: `password hunter2` and `password=hunter2` are two
# grammars, and each must be claimed by exactly one owner.
# ---------------------------------------------------------------------------

#: (line, the secret that must not survive)
ROUTEROS_SECRETS = [
    ("/user\nadd name=netops group=full password=R0uterPass77", "R0uterPass77"),
    ("/ppp secret\nadd name=cust service=pppoe password=BakeryPPP123",
     "BakeryPPP123"),
    ("/radius\nadd address=128.66.16.20 secret=RadiusSecret55", "RadiusSecret55"),
    # a qualified spelling of the same field. The guard that keeps `name=` off
    # `default-name=` REFUSED this one, so an L2TP/IPsec secret left the tool.
    ("/interface l2tp-client\nadd connect-to=203.0.113.10 use-ipsec=yes "
     "ipsec-secret=L2tpIpsecPsk88", "L2tpIpsecPsk88"),
    ("/interface wireless security-profiles\n"
     "add name=corp wpa2-pre-shared-key=Aut0mnBridge41", "Aut0mnBridge41"),
    ("/interface wireless security-profiles\n"
     "add name=legacy wpa-pre-shared-key=Aut0mnBridge41", "Aut0mnBridge41"),
    ("/ip ipsec peer\nadd address=203.0.113.10 pre-shared-key=IpsecPsk42",
     "IpsecPsk42"),
    ("/ppp profile\nadd name=pppoe authentication-password=RadiusPass31",
     "RadiusPass31"),
    ("/interface ovpn-client\nadd name=ovpn1 encryption-password=OvpnPass19",
     "OvpnPass19"),
    ("/interface wireless\nset [ find ] passphrase=Passphrase73", "Passphrase73"),
    # WireGuard spells its PSK without the inner hyphen, which the wireless
    # spelling of the rule did not reach
    ("/interface wireguard peers\nadd interface=wg-4g "
     'preshared-key="bm9ydGh3aW5kLXdnLXBzay10ZXN0b25seS0wMDAwMDM="',
     "bm9ydGh3aW5kLXdnLXBzay10ZXN0b25seS0wMDAwMDM="),
    ("/interface wireguard\nadd listen-port=13231 mtu=1420 name=wg-4g "
     'private-key="bm9ydGh3aW5kLXdnLXByaXZrZXktdGVzdG9ubHktMDE="',
     "bm9ydGh3aW5kLXdnLXByaXZrZXktdGVzdG9ubHktMDE="),
]


@pytest.mark.parametrize("text,secret", ROUTEROS_SECRETS,
                         ids=range(len(ROUTEROS_SECRETS)))
def test_a_routeros_key_value_credential_is_destroyed(text, secret):
    result = sanitise_text(text + "\n", Config(), salt=SALT)
    assert secret not in result.text, result.text
    assert "<REMOVED>" in result.text
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_both_psk_generations_on_one_line_are_destroyed():
    """One command, two pairs, one rule -- and the reason these rules are
    searched rather than matched.

    A RouterOS command carries many `key=value` pairs, and a wireless security
    profile routinely sets both PSK generations. A rule that is matched fires
    once per line, so the greedy prefix took the second pair and left the first
    passphrase standing next to a marker that said the line was finished.
    """
    text = ("/interface wireless security-profiles\n"
            "add name=legacy-wifi wpa-pre-shared-key=OldStonePier19 "
            "wpa2-pre-shared-key=NewStonePier23\n")
    result = sanitise_text(text, Config(), salt=SALT)
    assert "OldStonePier19" not in result.text, result.text
    assert "NewStonePier23" not in result.text, result.text
    assert result.counts["routeros-pre-shared-key"] == 2
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


WIREGUARD = (
    "/interface wireguard\n"
    "add listen-port=13231 mtu=1420 name=wg-4g "
    'private-key="bm9ydGh3aW5kLXdnLXByaXZrZXktdGVzdG9ubHktMDE="\n'
    "/interface wireguard peers\n"
    "add allowed-address=10.66.0.2/32 interface=wg-4g "
    'public-key="bm9ydGh3aW5kLXdnLXB1YmtleS10ZXN0b25seS0wMDI="\n'
)


def test_a_wireguard_private_key_is_a_secret_and_the_public_one_is_identity():
    """The two halves of one pair, in two families, and that is the point.

    A private key is a credential and goes by default. A public key is
    published on purpose: it identifies a device or a peer, so it is `identity`
    -- kept by default, and reachable when the policy acts on identity.
    """
    result = sanitise_text(WIREGUARD, Config(), salt=SALT)
    assert 'private-key="<REMOVED>"' in result.text
    assert "bm9ydGh3aW5kLXdnLXByaXZrZXk" not in result.text
    assert "bm9ydGh3aW5kLXdnLXB1YmtleS10ZXN0b25seS0wMDI=" in result.text
    assert result.counts["routeros-private-key"] == 1
    assert result.kept_counts["routeros-public-key"] == 1
    out = sanitise_text(WIREGUARD, policy(identity="redact"), salt=SALT).text
    assert 'public-key="<REMOVED>"' in out


def test_a_kept_wireguard_public_key_is_not_an_unexplained_base64_run():
    """The reason it needs a rule at all rather than nothing.

    44 characters of base64 is exactly what `long-base64-left` looks for, and
    the check cannot tell an authorised key from a leaked one -- so a config
    that kept its peers failed `--strict` until a named `identity` rule claimed
    the span for the check to be blinded to.
    """
    assert sanitise_text(WIREGUARD, Config(), salt=SALT).findings == []
    checks = {f.check for f in
              sanitise_text(WIREGUARD, policy(identity="keep", secrets="keep"),
                            salt=SALT).findings}
    # ...and a KEPT secret is never blinded: the private key still reports
    assert "credential-left" in checks


def test_the_space_form_and_the_equals_form_have_one_owner_each():
    """Two grammars, two rules, and neither may count the other's line."""
    space = sanitise_text(" password 0 SpaceForm1\n", Config(), salt=SALT)
    equals = sanitise_text("add password=EqualsForm1\n", Config(), salt=SALT)
    assert space.counts["bare-password"] == 1
    assert not space.counts["routeros-password"]
    assert equals.counts["routeros-password"] == 1
    assert not equals.counts["bare-password"]


def test_a_routeros_community_string_is_a_secret_only_in_its_own_section():
    """`name=` is the community string under `/snmp community` and an object
    name everywhere else, and the line cannot tell you which."""
    text = ("/snmp community\n"
            "add name=pubR0nly addresses=128.66.16.0/24\n"
            "/interface bridge\n"
            "add name=bridge-lan protocol-mode=rstp\n"
            "/ip firewall address-list\n"
            "add list=noc address=203.0.113.44\n")
    result = sanitise_text(text, Config(), salt=SALT)
    assert "name=<REMOVED>" in result.text
    assert "pubR0nly" not in result.text
    assert "add name=bridge-lan protocol-mode=rstp" in result.text
    assert result.counts["routeros-snmp-community"] == 1


#: (line, what must go, what must stay) -- RouterOS qualifies a key name freely
#: and means the same field by it, so a credential rule has to admit the
#: qualifier while `name=` has to refuse it. That asymmetry is the bug this
#: pins: the guard that keeps `name=` off `default-name=` was also refusing
#: `ipsec-secret=`, so an L2TP/IPsec secret left the tool with `--strict`
#: reporting nothing wrong.
QUALIFIED_KEYS = [
    ("add use-ipsec=yes ipsec-secret=Psk1", "Psk1", "use-ipsec=yes"),
    ("add authentication-password=Pass1", "Pass1", "authentication-password="),
    ("add encryption-password=Pass2", "Pass2", "encryption-password="),
    ("add wpa-pre-shared-key=Psk2", "Psk2", "wpa-pre-shared-key="),
]


@pytest.mark.parametrize("line,gone,kept", QUALIFIED_KEYS,
                         ids=range(len(QUALIFIED_KEYS)))
def test_a_qualified_credential_key_is_still_that_credential(line, gone, kept):
    result = sanitise_text(line + "\n", Config(), salt=SALT)
    assert gone not in result.text, result.text
    assert kept in result.text, "the key itself is grammar and stays"
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_default_name_is_not_read_as_a_name():
    """A hyphen is a word boundary, so the guard in front of `name=` is what
    keeps `[ find default-name=ether1 ]` out of every `name=` rule."""
    text = ("/snmp community\n"
            "set [ find default-name=public ] addresses=128.66.16.0/24\n")
    result = sanitise_text(text, Config(), salt=SALT)
    assert "default-name=public" in result.text
    assert not result.counts


# ---------------------------------------------------------------------------
# Wrapped lines. `/export` breaks a long command with a trailing `\`, and a
# rule sees one line at a time -- so a value split across the wrap would have
# its tail carried past every rule that could recognise it. The marker on the
# opening fragment is what makes that dangerous: the line reads as handled,
# and `--strict` exits 0 over the rest of the passphrase.
# ---------------------------------------------------------------------------

WRAPPED_PSK = ('/interface wireless security-profiles\n'
               'add authentication-types=wpa2-psk name=guest-wifi \\\n'
               '    wpa2-pre-shared-key="Winter Harbour \\\n'
               '    Lantern 77"\n')


def test_a_wrapped_secret_does_not_leak_its_tail():
    result = sanitise_text(WRAPPED_PSK, Config(), salt=SALT)
    assert "Winter Harbour" not in result.text
    assert "Lantern 77" not in result.text
    assert 'wpa2-pre-shared-key="<REMOVED>"' in result.text
    assert result.counts["routeros-pre-shared-key"] == 1
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_a_wrapped_command_is_emitted_unwrapped_and_still_loads():
    """The `\\`, the newline and the continuation's indent become one space,
    which is what RouterOS itself does with them."""
    out = sanitise_text(WRAPPED_PSK, Config(), salt=SALT).text
    assert out.splitlines() == [
        "/interface wireless security-profiles",
        'add authentication-types=wpa2-psk name=guest-wifi '
        'wpa2-pre-shared-key="<REMOVED>"',
    ]
    assert "\\" not in out


def test_a_trailing_backslash_in_another_dialect_is_left_alone():
    """An ASCII-art banner is the case this could have broken: a backslash at
    the end of a line is ordinary there and means nothing in IOS or JunOS, so a
    RouterOS command word has to be present before the wrap is undone."""
    text = ("banner motd ^C\n"
            "  /\\  \\\n"
            " /  \\  \\\n"
            "^C\n"
            "description a plain description \\\n")
    out = sanitise_text(text, Config(), salt=SALT).text
    assert out == text
