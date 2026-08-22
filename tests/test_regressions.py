"""Bugs found while building the actions model. Each one shipped once.

Every test here is a repro that failed on the previous implementation, so the
comment above it says what the wrong output was.
"""

import os
import re

import pytest

from netredact import Config, CustomRule, sanitise_text
from netredact.cli import EXIT_OK, main
from netredact.vendors import detect_vendor

from .conftest import SALT, policy, section

# --------------------------------------------------------------------------
# 1 + 2: `location` used to eat a JunOS stanza opener
# --------------------------------------------------------------------------

JUNOS_LOCATION = """system {
    location {
        building "Level 5, 500 Example St";
        floor 5;
    }
}
"""


@pytest.mark.parametrize("action", ["keep", "pseudo", "hash", "redact"])
def test_a_junos_stanza_opener_is_never_eaten(action):
    """Was: `location {` -> `location <REMOVED>`, unbalancing the config.

    The brace was consumed as the location's value, so the config no longer
    parsed -- and the street address *inside* the stanza survived untouched.
    """
    out = sanitise_text(JUNOS_LOCATION, policy(locations=action), salt=SALT).text
    assert "    location {" in out
    assert out.count("{") == JUNOS_LOCATION.count("{")
    assert out.count("}") == JUNOS_LOCATION.count("}")
    assert "<REMOVED>" not in out


@pytest.mark.parametrize("action,expected", [
    ("pseudo", "desc-"),
    ("hash", "<DESC-"),
    ("redact", "<DESCRIPTION-REMOVED>"),
])
def test_the_stanza_body_is_what_carries_the_address(action, expected):
    """The address the opener must not eat is reached by junos-location-body."""
    result = sanitise_text(JUNOS_LOCATION, policy(locations=action), salt=SALT)
    assert "500 Example St" not in result.text
    assert expected in result.text
    assert result.counts["junos-location-body"] == 2       # building + floor


def test_the_stanza_body_survives_when_text_is_kept():
    result = sanitise_text(JUNOS_LOCATION, Config(), salt=SALT)
    assert "500 Example St" in result.text
    assert result.kept_counts["junos-location-body"] == 2


def test_a_building_line_outside_a_location_stanza_is_untouched():
    """junos-location-body is stanza-scoped, so it is not a global `building`."""
    text = "system {\n    services {\n        building 7;\n    }\n}\n"
    result = sanitise_text(text, policy(locations="redact"), salt=SALT)
    assert "building 7;" in result.text


# --------------------------------------------------------------------------
# 3: keyword-eating on an IOS key-id line
# --------------------------------------------------------------------------

@pytest.mark.parametrize("keyid", ["5", "7"])
def test_a_key_id_line_with_a_trailing_keyword_holds_no_secret(keyid):
    """Was: `ntp server 10.0.0.1 key 5 prefer` -> `... key 5 <REMOVED>`.

    ``ENC`` ate the key id and ``VAL`` grabbed ``prefer``, so the config lost a
    keyword and nothing was protected -- the key id, the only thing on the
    line, was left in place.
    """
    text = f"ntp server 10.0.0.1 key {keyid} prefer\n"
    result = sanitise_text(text, Config(), salt=SALT)
    assert result.text.strip() == text.strip()
    assert "<REMOVED>" not in result.text
    assert result.counts == {}


def test_a_real_key_on_the_same_shape_of_line_still_goes():
    text = "tacacs-server host 10.0.0.3 key 7 121A0C041104\n"
    out = sanitise_text(text, Config(), salt=SALT).text
    assert "121A0C041104" not in out
    assert "key 7 <REMOVED>" in out


@pytest.mark.parametrize("keyword", ["source", "version", "iburst", "vrf"])
def test_other_ios_keywords_are_not_secrets(keyword):
    text = f"ntp server 10.0.0.1 key 5 {keyword}\n"
    assert sanitise_text(text, Config(), salt=SALT).text.strip() == text.strip()


# --------------------------------------------------------------------------
# 4: the %VAL% macro
# --------------------------------------------------------------------------

def _acme(pattern: str) -> Config:
    return Config(custom=[CustomRule(name="acme-shared-key", pattern=pattern,
                                     family="secrets")])


@pytest.mark.parametrize("line,expected", [
    ("acme shared-key hunter2", "acme shared-key <REMOVED>"),
    ('acme shared-key "hunter2 spaced"', 'acme shared-key "<REMOVED>"'),
    ("acme shared-key hunter2;", "acme shared-key <REMOVED>;"),
])
def test_val_macro_redacts_exactly_the_value(line, expected):
    """Was: `hunter2` -> `hunter<REMOVED>`.

    ``%VAL%`` expanded non-capturing, so the pattern still had zero groups and
    the prefix path appended a *second* value matcher inside the first one.
    """
    cfg = _acme(r"\s*acme\s+shared-key\s+%VAL%")
    result = sanitise_text(line + "\n", cfg, salt=SALT)
    assert result.text.strip() == expected
    assert "hunter" not in result.text
    assert result.counts["acme-shared-key"] == 1


def test_the_prefix_form_of_the_same_rule_agrees_with_the_macro_form():
    line = "acme shared-key hunter2\n"
    with_macro = sanitise_text(line, _acme(r"\s*acme\s+shared-key\s+%VAL%"),
                               salt=SALT).text
    as_prefix = sanitise_text(line, _acme(r"\s*acme\s+shared-key\s+"),
                              salt=SALT).text
    assert with_macro == as_prefix == "acme shared-key <REMOVED>\n"


# --------------------------------------------------------------------------
# 5: rule 45, `service unsupported-transceiver`
# --------------------------------------------------------------------------

def test_both_transceiver_tokens_are_redacted():
    """The label is operator free text, the code is TAC-issued material."""
    text = "service unsupported-transceiver ACME-PROJ-2024 A1B2C3D4\n"
    result = sanitise_text(text, Config(), salt=SALT)
    assert result.text.strip() == "service unsupported-transceiver <REMOVED> <REMOVED>"
    assert "ACME-PROJ-2024" not in result.text and "A1B2C3D4" not in result.text
    assert result.counts["unsupported-transceiver"] == 2


@pytest.mark.parametrize("line", [
    "service unsupported-transceiver",
    "service unsupported-transceiver ",
    "service routing protocols model multi-agent",
    "service password-encryption",
])
def test_a_bare_service_line_matches_nothing(line):
    """The Cisco IOS form takes no arguments and carries no secret."""
    result = sanitise_text(line + "\n", Config(), salt=SALT)
    assert result.text.strip() == line.strip()
    assert "unsupported-transceiver" not in result.counts


def test_one_transceiver_token_is_still_redacted():
    text = "service unsupported-transceiver A1B2C3D4\n"
    result = sanitise_text(text, Config(), salt=SALT)
    assert result.text.strip() == "service unsupported-transceiver <REMOVED>"
    assert result.counts["unsupported-transceiver"] == 1


# --------------------------------------------------------------------------
# 6: vendor weighting
# --------------------------------------------------------------------------

def test_a_decisive_hint_outweighs_repeated_weak_ones():
    """Was: `arista` lost to `cisco` because 25 `feature X` lines out-voted the
    one decisive EOS header. Weight is per distinct hint, not per occurrence."""
    text = ("! device: agg-sw-02 (DCS-7280SR-48C6, EOS-4.29.2F)\n"
            + "".join(f"feature x{i}\n" for i in range(26)))
    assert detect_vendor(text) == "arista"
    assert sanitise_text(text, Config(), salt=SALT).vendor == "arista"


@pytest.mark.parametrize("name,vendor", [
    ("cisco.cfg", "cisco"), ("arista.cfg", "arista"),
    ("juniper.cfg", "juniper"), ("edge-junos.cfg", "juniper"),
    ("fortinet.cfg", "fortinet"),
])
def test_the_fixtures_are_detected_correctly(fixtures, name, vendor):
    assert detect_vendor((fixtures / name).read_text()) == vendor


def test_an_explicit_vendor_beats_detection(cisco):
    cfg = Config(vendor="juniper")
    assert sanitise_text(cisco, cfg, salt=SALT).vendor == "juniper"


# --------------------------------------------------------------------------
# 7: the strict invariant
# --------------------------------------------------------------------------

PLAINTEXT = "hostname x\nenable secret 5 PlainTextSecret\n"


def test_keeping_one_rule_still_fails_the_credential_check(tmp_path, capsys):
    """A policy may keep a secret. It may not do so silently.

    This is the whole justification for the secrets-only default: an
    unconditional check asks *is credential-shaped material present*, and no
    configuration can switch that off by keeping the rule.
    """
    cfg = section("secrets", "redact", enable_secret="keep")
    result = sanitise_text(PLAINTEXT, cfg, salt=SALT)
    assert "PlainTextSecret" in result.text
    assert result.kept_counts["enable-secret"] == 1
    assert [f.check for f in result.findings] == ["credential-left"]

    leaky = tmp_path / "leaky.cfg"
    leaky.write_text(PLAINTEXT)
    conf = tmp_path / "netredact.toml"
    conf.write_text('[secrets]\nenable-secret = "keep"\n')
    assert main([str(leaky), "-c", str(conf), "--strict"]) == 2


def test_keeping_the_whole_secrets_family_still_fires_the_checks():
    result = sanitise_text(PLAINTEXT, policy(secrets="keep"), salt=SALT)
    assert "PlainTextSecret" in result.text
    assert [f.check for f in result.findings] == ["credential-left"]


def test_a_kept_secret_is_not_blinded_by_the_shape_exemption():
    """Shape checks are blinded to kept identity/text, never to kept secrets."""
    text = ("hostname x\n"
            "enable secret 5 $6$abcd$1234567890abcdefghijklmnopqrstuvwxyzABCDEF\n")
    result = sanitise_text(text, policy(secrets="keep"), salt=SALT)
    assert "crypt-hash-left" in {f.check for f in result.findings}


def test_junos_access_denied_secret_placeholder_is_already_safe():
    """An inaccessible secret placeholder is not credential material."""
    text = "set secret /* ACCESS-DENIED */;\n"
    result = sanitise_text(text, Config(), salt=SALT)
    assert result.text == text
    assert result.findings == []


@pytest.mark.parametrize("keyword", [
    "authentication-key",
    "privacy-key",
    "encrypted-password",
    "secret",
])
def test_junos_secret_data_placeholder_is_already_safe(keyword):
    """RANCID's inaccessible-value sentinel is not itself a credential."""
    text = f"set protocols bgp group rise-rr {keyword} /* SECRET-DATA */\n"

    result = sanitise_text(text, Config(), salt=SALT)

    assert result.text == text
    assert result.findings == []
    assert not result.counts


# --------------------------------------------------------------------------
# 8: the shape-check exemption, and its deliberate asymmetry
# --------------------------------------------------------------------------

SHAPES = """hostname x
username bob ssh-key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghijklmnopqrstuvwxyz012345
crypto pki certificate chain TP
 certificate self-signed 01
  30820330 30820218 A0030201 02020101 300D0609 2A864886 F70D0101
  05050030 31312F30 2D060355 04031326 494F532D 53656C66 2D536967
  quit
! Serial Number: FDO1234ABCD
snmp-server engineID local 800000090300AABBCCDDEEFF
"""


def test_material_a_rule_was_told_to_keep_is_not_a_finding():
    """At DEFAULT policy identity is kept, so these are decisions, not misses.

    ``kept_counts`` records every one of them. A shape check cannot tell a
    kept authorised key from a leak, so it is blinded to exactly the spans
    the kept rules match.
    """
    result = sanitise_text(SHAPES, Config(), salt=SALT)
    assert result.findings == [], "\n".join(str(f) for f in result.findings)
    for key in ("ssh-public-key", "certificate-block", "serial-number",
                "snmp-engineid"):
        assert result.kept_counts[key] == 1, key


def test_junos_known_host_ed25519_key_is_owned_by_the_identity_rule():
    key = "AAAAC3NzaC1lZDI1NTE5AAAAINNA" * 2
    text = ("set security ssh-known-hosts host \"[100.116.72.74]:2022\" "
            f"ed25519-key {key}\n")

    kept = sanitise_text(text, Config(), salt=SALT)
    assert kept.text == text
    assert kept.kept_counts["ssh-public-key"] == 1
    assert kept.findings == []

    acting = sanitise_text(text, policy(identity="redact"), salt=SALT)
    assert key not in acting.text
    assert acting.counts["ssh-public-key"] == 1
    assert acting.findings == []


def test_the_same_input_exits_zero(tmp_path):
    p = tmp_path / "shapes.cfg"
    p.write_text(SHAPES)
    assert main([str(p), "--strict"]) == EXIT_OK


def test_a_blob_no_rule_covers_still_flags():
    """The asymmetry is the design: only *recognised* kept material is exempt."""
    text = ("hostname x\n"
            "weird-vendor blob QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbg==\n")
    result = sanitise_text(text, Config(), salt=SALT)
    assert [f.check for f in result.findings] == ["long-base64-left"]


#: a synthetic RSA public key: the real `ssh-rsa` header, then filler. Wrapped
#: only to keep the line length honest.
PUBKEY_BLOB = (
    "AAAAB3NzaC1yc2EAAAADAQABAAABAQCfixtureKeyMaterialForTestsOnly0123456789"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefg"
    "hijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZfixture")

#: an IOS `ip ssh pubkey-chain` entry in both of its forms: a key-hash line
#: whose comment is a pasted key blob, and one whose comment is `user@host`
PUBKEY_CHAIN = f"""ip ssh pubkey-chain
  username ordadmin
   key-hash ssh-rsa 0011223344556677889AABBCCDDEEFF0 {PUBKEY_BLOB}
   key-hash ssh-rsa FFEEDDCCBBAA99887766554433221100 root@lab-rtr-01
"""


def test_a_key_blob_is_found_with_its_fingerprint_in_the_way():
    """IOS `key-hash <alg> <fingerprint> <blob>` splits the pair.

    `ssh-public-key` used to require the algorithm token immediately before
    the blob, so the key survived and only `long-base64-left` spoke -- a
    reported miss rather than a decision.
    """
    kept = sanitise_text(PUBKEY_CHAIN, Config(), salt=SALT)
    assert kept.kept_counts["ssh-public-key"] == 1
    assert kept.findings == [], "\n".join(str(f) for f in kept.findings)

    acting = sanitise_text(PUBKEY_CHAIN, policy(identity="hash"), salt=SALT)
    assert PUBKEY_BLOB not in acting.text
    assert "key-hash ssh-rsa <REMOVED> <KEY-" in acting.text
    assert acting.findings == [], "\n".join(str(f) for f in acting.findings)


def test_the_ordinary_glued_form_still_works():
    """The new branch must not displace the shape that already worked."""
    text = "username bob ssh-key ssh-rsa AAAAB3NzaC1yc2Eabcdefghij0123456789\n"
    result = sanitise_text(text, policy(identity="redact"), salt=SALT)
    assert result.counts["ssh-public-key"] == 1
    assert "AAAAB3Nza" not in result.text


def test_a_key_comment_naming_the_device_goes_with_the_hostname():
    """`root@<host>` is free text; the collect pass reaches it via the name."""
    text = "hostname lab-rtr-01\n" + PUBKEY_CHAIN
    out = sanitise_text(text, policy(hostnames="pseudo"), salt=SALT).text
    assert "lab-rtr-01" not in out
    assert "root@device-" in out


def test_the_exemption_lifts_as_soon_as_the_family_acts():
    """With identity acting, an unhandled key shape is a genuine miss again.

    The blob deliberately does NOT start with an SSH type-string header: that
    header is what `ssh-public-key` recognises on its own, so a blob carrying
    one is handled material rather than an unhandled shape.
    """
    text = ("hostname x\n"
            "weird-vendor pubkey ssh-rsa QUJDREVGR0hJSktMTU5PUFFSU1RVVldY\n")
    kept = sanitise_text(text, Config(), salt=SALT)
    assert "ssh-key-left" not in {f.check for f in kept.findings}
    acting = sanitise_text(text, policy(identity="redact"), salt=SALT)
    assert "ssh-key-left" in {f.check for f in acting.findings}


# --------------------------------------------------------------------------
# 9: our own redaction constants must not report themselves
# --------------------------------------------------------------------------

def test_a_redacted_ipv4_does_not_flag_itself():
    """`redact` writes 192.0.2.0, which classifies as `documentation`.

    With every class acting, that constant would otherwise be reported as an
    address the policy failed to move.
    """
    cfg = Config()
    cfg.ipv4.default = "redact"
    result = sanitise_text(" ip address 128.66.16.130 255.255.255.248\n",
                           cfg, salt=SALT)
    assert "192.0.2.0" in result.text
    assert result.findings == []


def test_a_redacted_ipv6_does_not_flag_itself():
    cfg = Config()
    cfg.ipv6.default = "redact"
    result = sanitise_text(" ipv6 address 3fff:16:1234::1/64\n", cfg, salt=SALT)
    assert "2001:db8::" in result.text
    assert result.findings == []


def test_a_pool_address_does_not_flag_itself():
    cfg = Config()
    cfg.ipv4.default = "pseudo"
    result = sanitise_text(" ip address 128.66.16.130 255.255.255.248\n",
                           cfg, salt=SALT)
    assert result.findings == []


# --------------------------------------------------------------------------
# 10: the <SECRET-…> marker must not read as a credential
# --------------------------------------------------------------------------

def test_hashed_secrets_do_not_trip_the_credential_check(cisco):
    """`<SECRET-a1b2c3>` contains the word "secret"."""
    result = sanitise_text(cisco, policy(secrets="hash"), salt=SALT)
    assert "<SECRET-" in result.text
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_every_marker_prefix_is_ignored_by_the_verifier():
    from netredact.pseudonymise import PREFIX
    lines = [f"community <{mark}-a1b2c3> ro" for mark, _tok in PREFIX.values()]
    from netredact import verify
    assert verify(lines, Config()) == []


# --------------------------------------------------------------------------
# 11: a domain used to eat the tail of a hostname declared as an FQDN
# --------------------------------------------------------------------------

FQDN_HOSTNAME = """hostname core-rtr-01.northwind.test
snmp-server contact noc@northwind.test
interface Loopback0
 description peering with core-rtr-01.northwind.test
"""


def test_an_fqdn_hostname_is_replaced_whole():
    """Was: `hostname core-rtr-01.northwind.test` -> `core-rtr-01.example.com`.

    The name patterns were sorted longest-first *within* each family, and
    domains were built before hostnames, so every domain ran before every
    hostname. The short domain -- learned from the e-mail address, never
    declared with `ip domain-name` -- matched inside the FQDN, rewrote its
    tail, and left the device's own name sitting in the output.
    """
    result = sanitise_text(FQDN_HOSTNAME,
                           policy(hostnames="pseudo", domains="pseudo"),
                           salt=SALT)
    assert "core-rtr-01" not in result.text
    assert "northwind.test" not in result.text
    assert result.counts["hostnames"] == 2      # the declaration and the
    assert result.counts["domains"] == 1        # description; then the e-mail


def test_the_domain_is_still_replaced_where_it_stands_alone():
    """The fix reorders the patterns; it does not stop the domain matching."""
    text = "ip domain-name northwind.test\nip name-server 128.66.0.53\n"
    result = sanitise_text(text, policy(domains="pseudo"), salt=SALT)
    assert "northwind.test" not in result.text
    assert result.counts["domains"] == 1


# --------------------------------------------------------------------------
# 12: a two-character username was below the minimum length
# --------------------------------------------------------------------------

SHORT_USER = """! device: agg-sw-02 (DCS-7280SR-48C6, EOS-4.29.2F)
username lg privilege 15 role lg secret sha512 $6$abcd$0123456789
"""


def test_a_two_character_username_is_replaced():
    """Was: `username lg` survived, because the minimum length was 3.

    Two-letter operator accounts are real, and skipping them left a named
    human in a config the policy said to pseudonymise.
    """
    result = sanitise_text(SHORT_USER, policy(usernames="pseudo"), salt=SALT)
    assert "username lg " not in result.text
    assert " role lg " not in result.text
    assert result.counts["usernames"] == 2


def test_the_short_username_gets_one_tag_in_both_places():
    """`username X ... role X` has to stay one name, or the config will not load."""
    out = sanitise_text(SHORT_USER, policy(usernames="pseudo"), salt=SALT).text
    tags = re.findall(r"user-[0-9a-f]+", out)
    assert len(tags) == 2 and tags[0] == tags[1]
    assert f"username {tags[0]} privilege 15 role {tags[0]} secret" in out


def test_a_one_character_name_is_still_left_alone():
    """One character is not worth the collateral: every bare `x` would move."""
    text = "hostname x\ninterface Ethernet1\n description x-connect to y\n"
    result = sanitise_text(text, policy(hostnames="pseudo"), salt=SALT)
    assert result.text == text
    assert "hostnames" not in result.counts


# --------------------------------------------------------------------------
# 13: a closed pipe is the reader saying "enough", not a crash
# --------------------------------------------------------------------------

class _ClosedPipe:
    """Stdout after `| head` has gone away: every write is a broken pipe."""

    def __init__(self, fd: int):
        self._fd = fd

    def write(self, _text):
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self):
        raise BrokenPipeError(32, "Broken pipe")

    def fileno(self):
        return self._fd

    def isatty(self):
        return False


@pytest.fixture
def closed_pipe():
    """A stdout the fix is safe to redirect.

    ``fileno`` has to answer -- argparse asks it whether it may colourise --
    and the fix redirects whatever it answers with, so it answers with a
    private descriptor on the null device rather than the one pytest is
    capturing the session on.
    """
    fd = os.open(os.devnull, os.O_WRONLY)
    try:
        yield _ClosedPipe(fd)
    finally:
        os.close(fd)


def test_a_closed_stdout_is_not_a_traceback(fixtures, monkeypatch, closed_pipe):
    """Was: `netredact cisco.cfg | head` printed a BrokenPipeError traceback.

    The write went straight to ``sys.stdout`` from inside ``main``, so the
    exception escaped to the interpreter -- twice over, because flushing the
    dead stream at shutdown raised again where nothing could catch it.
    """
    monkeypatch.setattr("sys.stdout", closed_pipe)
    assert main([str(fixtures / "cisco.cfg")]) == EXIT_OK


def test_print_config_down_a_closed_pipe_is_also_clean(monkeypatch, closed_pipe):
    """The other writer of bulk output: `netredact --print-config | head`."""
    monkeypatch.setattr("sys.stdout", closed_pipe)
    assert main(["--print-config"]) == EXIT_OK
