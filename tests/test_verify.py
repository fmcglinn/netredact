"""The verification pass: what it always asks, and what the policy gates.

Two kinds of check. The unconditional ones ask *is credential-shaped material
present* and no policy can silence them. The conditional ones ask *was the
scrub you requested applied*, so they only run when the policy asked for
something other than ``keep``.
"""

import pytest

from netredact import Config, check_names, sanitise_text, verify

from .conftest import SALT, policy

UNCONDITIONAL = ("crypt-hash-left", "junos-type9-left", "pem-left",
                 "type7-left", "long-hex-left", "long-base64-left",
                 "credential-left")
CONDITIONAL = ("email-left", "ipv4-left", "ipv6-left", "mac-left",
               "operational-name-left", "as-number-left", "location-left",
               "routeros-header-left")

#: a PEM block is judged by its body, so every case here is a whole block
PEM_BODY = "MIIEowIBAAKCAQEAprivatekeymaterialAAAABBBBCCCCDDDDEEEEFFFF0123456789"
PEM_KEY = ["-----BEGIN RSA PRIVATE KEY-----", PEM_BODY,
           "-----END RSA PRIVATE KEY-----"]
PEM_CERT = ["-----BEGIN CERTIFICATE-----", PEM_BODY,
            "-----END CERTIFICATE-----"]


def test_check_names_lists_every_check():
    names = check_names()
    assert set(UNCONDITIONAL) | {"ssh-key-left"} | set(CONDITIONAL) == set(names)
    assert len(names) == len(set(names))


@pytest.mark.parametrize("lines,check", [
    (["enable secret 5 $1$mERr$M6KsMCsLPnvvKmnZkH3xF/"], "crypt-hash-left"),
    (['authentication-key "$9$abcdEFGH1234";'], "junos-type9-left"),
    (PEM_KEY, "pem-left"),
    (["username x password 7 070C285F4D06"], "type7-left"),
    (["token 0123456789abcdef0123456789abcdef"], "long-hex-left"),
    (["enable secret 5 PlainTextSecret"], "credential-left"),
])
def test_unconditional_checks_fire_at_default_policy(lines, check):
    assert check in {f.check for f in verify(lines, Config())}


@pytest.mark.parametrize("check,line,cfg_key", [
    ("email-left", "snmp-server contact noc@northwind.test", "emails"),
    ("ipv4-left", " ip address 128.66.16.130 255.255.255.248", "ipv4"),
    ("ipv6-left", " ipv6 address 3fff:16::1/64", "ipv6"),
])
def test_conditional_checks_only_run_when_the_family_acts(check, line, cfg_key):
    assert verify([line], Config()) == []            # kept on purpose
    cfg = Config()
    if cfg_key == "emails":
        cfg = policy(emails="pseudo")
    else:
        getattr(cfg, cfg_key).default = "pseudo"
    assert check in {f.check for f in verify([line], cfg)}


def test_ipv4_left_respects_the_per_class_policy():
    cfg = Config()
    cfg.ipv4.rfc1918 = "pseudo"                  # only private space acts
    assert verify([" ip address 128.66.16.130 255.255.255.248"], cfg) == []
    assert verify([" ip address 10.20.30.1 255.255.255.0"], cfg)


def test_ipv4_left_ignores_masks_pools_and_keep_networks():
    cfg = Config()
    cfg.ipv4.default = "pseudo"
    cfg.ipv4.keep_networks = ["128.66.16.0/24"]
    assert verify([" ip address 128.66.16.130 255.255.255.248"], cfg) == []
    assert verify([" ip route 0.0.0.0 0.0.0.0 198.18.5.1"], cfg) == []


def test_identity_gated_checks():
    """A public key is identity: reported only when the policy acts on it."""
    line = "weird-vendor pubkey AAAAB3NzaC1yc2EAAAADAQABAAABgQ"
    assert verify([line], Config()) == []
    assert "ssh-key-left" in {f.check
                              for f in verify([line], policy(identity="hash"))}


def test_per_rule_ssh_action_activates_its_check_when_identity_default_keeps():
    line = "weird-vendor pubkey AAAAB3NzaC1yc2EAAAADAQABAAABgQ"
    cfg = Config()
    cfg.identity.ssh_public_key = "hash"
    assert "ssh-key-left" in {f.check for f in verify([line], cfg)}


def test_a_pem_certificate_is_identity_but_a_pem_key_is_a_secret():
    assert verify(PEM_CERT, Config()) == []               # identity is kept
    assert "pem-left" in {f.check for f in verify(PEM_KEY, Config())}
    assert "pem-left" in {f.check
                          for f in verify(PEM_CERT, policy(identity="redact"))}


def test_per_rule_pem_cert_action_activates_its_check_when_identity_default_keeps():
    cfg = Config()
    cfg.identity.pem_cert = "hash"
    assert "pem-left" in {f.check for f in verify(PEM_CERT, cfg)}


def test_per_rule_certificate_block_action_exposes_a_surviving_body_to_checks():
    lines = ["certificate self-signed 01",
             "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbg==",
             "quit"]
    cfg = Config()
    cfg.identity.certificate_block = "hash"
    assert "long-base64-left" in {f.check for f in verify(lines, cfg)}


@pytest.mark.parametrize("body", ["<REMOVED>", "<SECRET-a1b2c3>"])
def test_a_pem_block_we_have_already_dealt_with_is_not_a_finding(body):
    """The delimiters are structure, not secret: only a real body is a finding.

    Reporting the surviving BEGIN line failed ``--strict`` on a key netredact
    had itself destroyed, which is exactly the case the tool is for.
    """
    assert verify(["-----BEGIN RSA PRIVATE KEY-----", body,
                   "-----END RSA PRIVATE KEY-----"], Config()) == []


def test_an_empty_pem_block_is_not_a_finding():
    assert verify(["-----BEGIN RSA PRIVATE KEY-----",
                   "-----END RSA PRIVATE KEY-----"], Config()) == []


@pytest.mark.parametrize("lines", [
    ["-----BEGIN RSA PRIVATE KEY-----"],                    # truncated: no END
    ["-----BEGIN RSA PRIVATE KEY-----", PEM_BODY],          # payload, no END
])
def test_an_unterminated_pem_block_still_reports(lines):
    """A lone delimiter is a truncated key, not a handled one."""
    assert "pem-left" in {f.check for f in verify(lines, Config())}


def test_disable_switches_a_check_off():
    cfg = Config()
    cfg.verify.disable = ["credential-left"]
    assert verify(["enable secret 5 PlainTextSecret"], cfg) == []


def test_disable_rejects_an_unknown_check_name():
    cfg = Config()
    cfg.verify.disable = ["no-such-check"]
    with pytest.raises(ValueError, match="unknown check"):
        verify(["x"], cfg)


def test_ignore_patterns_teach_it_a_local_shape():
    line = ["asset-tag ACME-ASSET-12345678901234567890123456789012345678901234"]
    assert verify(line, Config())
    cfg = Config()
    cfg.verify.ignore_patterns = [r"\bACME-ASSET-\d+\b"]
    assert verify(line, cfg) == []


@pytest.mark.parametrize("line", [
    "no password",
    "service password-encryption",
    "password-policy min-length 8",
    "key chain OSPF-KC",
    "## SECRET-DATA",
    "set policy-options community BLACKHOLE members 64512:666",
    "match large-community AS64500-EXPORT",
    "community-list 10 permit 64512:100",
    "set community no-export",
])
def test_default_ignores_keep_the_report_readable(line):
    assert verify([line], Config()) == []


def test_verify_can_be_switched_off_entirely(cisco):
    cfg = policy(secrets="keep")
    assert sanitise_text(cisco, cfg, salt=SALT).findings
    cfg.verify.enabled = False
    assert sanitise_text(cisco, cfg, salt=SALT).findings == []


def test_findings_carry_a_line_number_and_the_offending_text():
    findings = verify(["hostname x", "enable secret 5 PlainTextSecret"], Config())
    assert findings[0].line == 2
    assert findings[0].text == "enable secret 5 PlainTextSecret"
    assert str(findings[0]).startswith("L2 [credential-left]")


# ---------------------------------------------------------------------------
# Script checksums: a 64-character hex run that is not a secret. The shape
# checks know a shape, not a meaning, so both reported every one and `--strict`
# failed on a config with no credential left in it. The fix is a rule that
# SELECTS the digest, filed under `identity`: the shape checks go blind to it
# when the policy keeps identity, and it is replaced when it does not.
# ---------------------------------------------------------------------------

#: the JunOS spellings, `set` form and hierarchical form
CHECKSUM_LINES = [
    "set system scripts commit file no-nukes.py checksum sha-256 "
    "45c6397f9b5d450a7ad3ac9608787b3f0d366a1b2c3d4e5f60718293a4b5c6d7e",
    "set system scripts op file login-validator.py checksum sha-256 "
    "36a29be1fb64e5906c6eeae780f0c5520e1f2a3b4c5d6e7f8091a2b3c4d5e6f70",
    "set event-options event-script file snmp-util-smartd.py checksum sha-256 "
    "be8f897a76ac860af81873ff2d4c9f2e5b1a08cc4e7d6f3b9a0c1d2e3f405162",
    "                checksum sha-256 "
    "be8f897a76ac860af81873ff2d4c9f2e5b1a08cc4e7d6f3b9a0c1d2e3f405162;",
]


@pytest.mark.parametrize("line", CHECKSUM_LINES, ids=range(len(CHECKSUM_LINES)))
def test_a_script_checksum_is_never_a_finding(line):
    """Kept at defaults, and not reported -- a kept identity is not a miss."""
    result = sanitise_text(line + "\n", Config(), salt=SALT)
    assert result.text.splitlines()[-1] == line       # identity = keep
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


@pytest.mark.parametrize("action,expected", [
    ("hash", "checksum sha-256 <CKSUM-"),
    ("pseudo", "checksum sha-256 cksum-"),
    ("redact", "checksum sha-256 <REMOVED>"),
])
def test_the_digest_is_reachable_by_the_identity_policy(action, expected):
    line = CHECKSUM_LINES[0] + "\n"
    result = sanitise_text(line, policy(identity=action), salt=SALT)
    assert expected in result.text
    assert "45c6397f" not in result.text
    assert "no-nukes.py" in result.text, "the file name is structure"
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_a_kept_checksum_still_shields_nothing_else_on_the_line():
    """Blinding is per selected value, not per line."""
    line = (CHECKSUM_LINES[0]
            + " comment 0123456789abcdef0123456789abcdef0123456789\n")
    checks = {f.check for f in verify(line.splitlines(), Config())}
    assert "long-hex-left" in checks


def test_the_checksum_rule_wants_the_algorithm_token():
    """A bare `checksum` keyword is a knob in other dialects, not a value."""
    result = sanitise_text("set chassis fpc 0 checksum enable\n", Config(),
                           salt=SALT)
    assert result.counts.get("script-checksum") is None


def test_a_routeros_authentication_method_is_not_a_credential():
    """`wpa-psk` names a method there and a key on a Cisco autonomous AP, and
    the check knows one keyword for both. The `=` is what tells them apart."""
    assert verify(["add authentication-types=wpa-psk,wpa2-psk name=corp"],
                  Config()) == []
    # ...and the Cisco form, where the keyword introduces the key, still fires
    assert "credential-left" in {
        f.check for f in verify([" wpa-psk ascii 0 Tr0ub4dor&3"], Config())}


def test_a_routeros_section_path_is_not_a_surviving_credential():
    """`/ppp secret` names a section, and `/export terse` repeats the whole
    path on every line -- but only up to the command word, so a `secret=` on
    the rest of the line is still judged."""
    assert verify(["/ppp secret add name=cust password=<REMOVED>"],
                  Config()) == []
    assert "credential-left" in {
        f.check for f in verify(["/ip ipsec identity add secret=hunter2"],
                                Config())}


# ---------------------------------------------------------------------------
# FortiOS. `set <key> ENC <blob>` is the marker FortiOS writes in front of a
# stored credential, and the check knows it by that marker rather than by a
# list of keys -- so an SNMPv3 `auth-pwd` and a key no release has invented yet
# are both judged.
#
# Why it is named at all: `long-base64-left` happened to catch these, and a
# check that only knows a shape must never be the only thing between a
# regressed rule and a credential in the output. That is the argument
# `wpa-psk` and `private-key` are already in the keyword list for.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line", [
    "        set auth-pwd ENC MWlJokDb+fAtYJhw/fISq9OwNfsPCVN2HjDKT",
    "        set priv-pwd ENC Zm9ydGluZXQtcHJpdmFjeS1rZXktdGVzdG9u",
    "        set psksecret ENC cHNrc2VjcmV0YmxvYjAxMjM0NTY3ODlhYmM",
    "        set some-future-credential ENC c29tZWZ1dHVyZWNyZWRlbnQ",
    # short enough that no shape check would speak: the marker is all there is
    "        set auth-pwd ENC QUFBQQ",
])
def test_a_kept_fortios_credential_is_always_reported(line):
    assert "credential-left" in {f.check for f in verify([line], Config())}


@pytest.mark.parametrize("line", [
    "        set auth-pwd ENC <REMOVED>",
    '        set auth-pwd ENC "<SECRET-a1b2c3>"',
    "        set password ENC <REMOVED>",
])
def test_a_handled_fortios_credential_is_not_reported(line):
    """`ENC` is one of the tokens allowed between a keyword and its
    placeholder, which it gets for free: `VTOK` is derived from the same hint
    table the rules use, so the two cannot fall out of step."""
    assert verify([line], Config()) == []


def test_the_word_enc_in_kept_free_text_is_not_a_credential():
    """The `set <key>` in front of the marker is the guard, not decoration."""
    assert verify(['    set description "ENC handover, rack 4"'],
                  Config()) == []


@pytest.mark.parametrize("line", [
    # a message TEMPLATE name, which is grammar and not a value. These two were
    # the whole finding list on a real FortiGate backup.
    'config system replacemsg auth "auth-password-page"',
    'config system replacemsg auth "auth-cert-passwd-page"',
    "config system snmp community",
    "config user password-policy",
])
def test_a_fortios_config_header_is_a_section_path_and_not_a_value(line):
    assert verify([line], Config()) == []


def test_a_credential_inside_the_section_is_still_judged():
    """The header is ignored whole; the lines under it are not."""
    assert "credential-left" in {f.check for f in verify(
        ['config system admin', '    set psksecret hunter2'], Config())}


def test_a_fortios_password_policy_knob_is_not_a_credential():
    assert verify(["config system password-policy",
                   "    set status enable"], Config()) == []


# ---------------------------------------------------------------------------
# An empty value is a credential that is ABSENT, not one that survived.
# RouterOS writes an unset key that way -- `auth-key=""` on a `/routing ospf
# interface-template` is an interface with no authentication on it -- and every
# one of them was reported as a line a human had to look at, carrying no
# credential at all. Same judgement `RANCID_SENTINEL` already makes for
# `## SECRET-DATA`: evidence the value is not there beats the keyword that
# introduces it.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line", [
    'add area=backbone-v2 auth-id=1 auth-key="" cost=10 interfaces=vlan4040-1941',
    "add auth-key='' interfaces=ether1",
    'add name=guest wpa2-pre-shared-key=""',
    'set psksecret ""',
    "        set auth-pwd ENC \"\"",
    "  password \"\";",
])
def test_an_empty_credential_is_not_a_surviving_credential(line):
    assert verify([line], Config()) == []


def test_the_rule_leaves_an_empty_value_alone_and_counts_nothing():
    """There is nothing to destroy, so nothing is destroyed and nothing is
    claimed to have been."""
    line = 'add area=backbone-v2 auth-key="" interfaces=ether1\n'
    result = sanitise_text(line, Config(), salt=SALT)
    assert result.text == line
    assert not result.counts
    assert result.findings == []


def test_an_empty_value_ends_only_its_own_match():
    """The danger in this exemption: a line with an empty key AND a real
    credential on it must still be reported. `search` keeps scanning, and this
    is what says so."""
    line = 'add auth-key="" password=hunter2'
    assert "credential-left" in {f.check for f in verify([line], Config())}


def test_a_real_quoted_key_is_still_reported():
    assert "credential-left" in {
        f.check for f in verify(['add auth-key="RealKey42"'], Config())}


def test_an_empty_snmp_community_is_not_a_surviving_community():
    assert verify(["/snmp community", 'add name="" addresses=128.66.16.0/24'],
                  Config()) == []
    assert verify(["config system snmp community", "    edit 1",
                   '        set name ""'], Config()) == []


# ---------------------------------------------------------------------------
# An SNMP community in a grammar that gives the line no keyword. RouterOS
# writes `name=public` and FortiOS `set name "public"`, and in both the SECTION
# is the only evidence the value is a community string -- so `credential-left`,
# which reads one line at a time, went silent on a kept one. `secrets = "keep"`
# is allowed; passing `--strict` over it is the fail-open this check prevents.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("lines", [
    ["config system snmp community", '    edit 1', '        set name "pubR0nly"'],
    ["/snmp community", "add addresses=128.66.16.0/24 name=pubR0nly"],
])
def test_a_kept_snmp_community_is_reported_in_either_grammar(lines):
    assert "credential-left" in {f.check for f in verify(lines, Config())}


@pytest.mark.parametrize("lines", [
    ["config system snmp community", '    edit 1', '        set name "<REMOVED>"'],
    ["config system snmp community", '    edit 1',
     '        set name "<SECRET-a1b2c3>"'],
    ["/snmp community", "add addresses=128.66.16.0/24 name=<REMOVED>"],
])
def test_a_handled_snmp_community_is_not_reported(lines):
    assert verify(lines, Config()) == []


@pytest.mark.parametrize("lines", [
    # the same `set name` one section over is a policy label, not a secret
    ["config firewall policy", "    edit 1", '        set name "transit out"'],
    # and the section has to be closed by its `end`, or every later `set name`
    # in the file would read as a community
    ["config system snmp community", "end", "config firewall policy",
     "    edit 1", '        set name "transit out"'],
    ["/snmp community", "/ip firewall filter", "add chain=input name=notacommunity"],
])
def test_a_name_outside_the_community_section_is_not_a_credential(lines):
    assert verify(lines, Config()) == []


def test_a_clean_fortios_backup_verifies_clean(fortinet):
    result = sanitise_text(fortinet, Config(), salt=SALT)
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


def test_keeping_a_fortios_secret_still_fails_the_safety_net(fortinet):
    """Setting `secrets = "keep"` is allowed. Passing `--strict` silently over
    it is not, and that is what these checks are for."""
    result = sanitise_text(fortinet, policy(secrets="keep"), salt=SALT)
    assert "credential-left" in {f.check for f in result.findings}


# ---------------------------------------------------------------------------
# The RouterOS provenance header. Every other check knows a shape or a keyword,
# and a header value has neither: a licence id is an opaque word. So a header
# key no rule knew about left the tool with NOTHING reported -- silence, which
# this project treats as worse than a miss. This check's evidence is structural
# instead: the value sits in a header, and no rule claimed it.
# ---------------------------------------------------------------------------

ROS_HEADER = ["# 2025-10-15 16:00:14 by RouterOS 7.16.2",
              "# software id = ABCD-EFGH",
              "# model = RB5009UG+S+"]


def test_an_unclaimed_header_value_is_reported_when_identity_acts():
    lines = ROS_HEADER + ["# unit id = HQ-4471"]
    assert "routeros-header-left" in {
        f.check for f in verify(lines, policy(identity="redact"))}


def test_a_header_key_a_rule_owns_is_never_reported():
    """Ownership is asked of the rule table, not of a list written out in the
    verifier, so a key that gains a rule leaves this check the same day."""
    checks = {f.check for f in verify(ROS_HEADER, policy(identity="redact"))}
    assert "routeros-header-left" not in checks


def test_a_kept_identity_header_is_not_a_miss():
    """The gate: with `identity` kept, an unclaimed header value is kept on
    purpose and the report says so elsewhere."""
    assert verify(ROS_HEADER + ["# unit id = HQ-4471"], Config()) == []


@pytest.mark.parametrize("line", [
    # a colon is not this shape: RANCID and JunOS both use one
    "# RANCID-CONTENT-TYPE: mikrotik",
    "## Last changed: 2026-08-19 09:22:11 AEST by opsadmin",
    # netredact's own marker has no separator at all
    "# netredact-sanitised 0.1.0 -- sanitised output, not a device "
    "configuration; re-run from the original",
    # a separator line
    "#",
])
def test_the_header_check_stays_off_other_comment_shapes(line):
    assert verify([line], policy(identity="redact")) == []


@pytest.mark.parametrize("value", ["<REMOVED>", "<LICID-a1b2c3>"])
def test_a_header_value_netredact_already_wrote_is_not_a_finding(value):
    """Otherwise the check would fail `--strict` on netredact's own output.

    The recognised set is derived from the marker and constant tables, so a new
    marker cannot fall out of step with the check that has to see past it.
    """
    assert verify([f"# unit id = {value}"], policy(identity="redact")) == []


# ---------------------------------------------------------------------------
# FortiOS credentials, and the blind spot the check had over them. `psksecret`
# and `ppk-secret` end in a word the keyword list already carried, but the
# check reads whole words -- so an IPsec pre-shared key and an SNMPv3 secret
# left the tool in the device's encrypted form with NO finding at all, and
# `--strict` exited 0 over them. A bare `set key` was the same case with a word
# too ordinary to name unqualified.
#
# The first half is asserted with `secrets = "keep"`, because that is the only
# way to ask the question the check exists for: if the rule that handles the
# line ever regresses, does the tool still speak?
# ---------------------------------------------------------------------------

FORTIOS_CREDENTIALS = [
    "    set psksecret ENC AK1PskEXAMPLEsEcReTkEyMaTeRiAl==",
    "    set ppk-secret ENC AK1PpkEXAMPLEsEcReT6gQ==",
    "    set auth-pwd ENC AK1SnmpAuthPassEXAMPLE0aQ==",
    "    set priv-pwd ENC AK1SnmpPrivPassEXAMPLE1bQ==",
    "    set passphrase ENC AK1WifiPassphraseEXAMPLE7hQ==",
    "    set api-key ENC AK1FgtApiKeyEXAMPLEz0982kQ==",
    '    set key "NtpSharedSecret123"',
    "    set secret ENC AK1RadiusSecretEXAMPLE4eQ==",
    "    set password ENC AK1BgpNeighborPassEXAMPLE8iQ==",
    "    set passwd ENC AK1LocalUserPassEXAMPLE2cQ==",
]


@pytest.mark.parametrize("line", FORTIOS_CREDENTIALS)
def test_a_kept_fortios_credential_is_never_silent(line):
    checks = {f.check for f in verify([line], policy(secrets="keep"))}
    assert "credential-left" in checks, f"silent: {line!r}"


@pytest.mark.parametrize("line", FORTIOS_CREDENTIALS)
def test_the_check_accepts_the_placeholder_the_rule_leaves(line):
    """The other half: the check must not report a line it just dealt with.

    `ENC` stands between the keyword and the placeholder, so it has to be a
    known encoding hint (``rules.ENC``) -- otherwise every FortiOS credential
    fails ``--strict`` after being correctly destroyed.
    """
    result = sanitise_text(line + "\n", Config(), salt=SALT)
    assert "<REMOVED>" in result.text
    assert result.findings == [], "\n".join(str(f) for f in result.findings)


@pytest.mark.parametrize("line", [
    "    set key-id 7",                     # a key id, not a key
    "    set type password",                # the kind of account, not one
    "    set security wpa2-only-personal",
])
def test_the_fortios_shape_does_not_report_a_knob(line):
    assert verify([line], Config()) == []
