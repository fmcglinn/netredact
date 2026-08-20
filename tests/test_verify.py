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
               "operational-name-left", "as-number-left", "location-left")

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
