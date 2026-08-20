"""The ``platform`` family: what the box is and what it runs.

Two things are being asserted here, and they pull against each other.

The rules have to *reach* the material -- an Arista ``! device:`` header, a
``boot system`` line, a bare ``version`` line, the ``Model:`` and ``Software
image version:`` lines people paste in front of a config -- across all three
vendors, because a model plus a release number is a CVE list.

And they have to stop there. ``platform``, ``model`` and ``chassis`` are all
ordinary configuration keywords: ``platform qos map-mode`` and Arista's
``service routing protocols model multi-agent`` are commands, not disclosures.
Requiring a ``:`` or ``=`` is what separates the two, and the second half of
this file is the guard on that.

Arista's ``! device:`` header is the case that shaped the rule table. It puts
a hostname, a model and a release on one line, introduced by nothing but their
position. A rule for the whole header would be one family and one action for
all three, which puts the model and the release beyond the reach of
``[overrides]``. So ``hardware-model`` and ``os-version`` each read the header
themselves, and the hostname is left to ``hostnames``.
"""

import re

import pytest

from netredact import Config, sanitise_text
from netredact.config import RULE_SECTIONS
from netredact.vendors import detect_vendor

from .conftest import SALT, policy, section

#: an Arista `show running-config` preamble, which is where the header comment,
#: the boot image and the vendor's own best evidence all live on one page
EOS_HEADER = (
    "! Command: show running-config\n"
    "! device: agg-sw-02 (DCS-7280SR-48C6-M, EOS-4.32.1F)\n"
    "!\n"
    "! boot system flash:/EOS64-4.32.1F.swi\n"
    "!\n"
    "switchname agg-sw-02\n"
)


def redacted(text: str) -> str:
    cfg = policy(platform="redact")
    cfg.collection.rancid_diagnostics = "keep"
    return sanitise_text(text, cfg, salt=SALT).text


# -- reaching the material ---------------------------------------------------

def test_the_arista_header_loses_its_model_and_version_but_keeps_its_shape():
    out = redacted(EOS_HEADER)
    assert "! device: agg-sw-02 (<REMOVED>, <REMOVED>)" in out
    assert "DCS-7280SR" not in out and "EOS-4.32.1F" not in out
    # the hostname is a different family and is untouched at this policy; the
    # `! device:` line is one of the places the collect pass learns it from
    assert "agg-sw-02" in out


def test_each_field_of_the_arista_header_belongs_to_its_own_rule():
    """The reason there is no `device-header` rule.

    One rule carries one family and one action, so a rule for the whole header
    would put the model and the release out of reach of `[overrides]`. Three
    values of three kinds on one line need the three owners they already have.
    """
    cfg = policy(platform="redact")
    cfg.collection.rancid_diagnostics = "keep"
    result = sanitise_text(EOS_HEADER, cfg, salt=SALT)
    assert result.counts["hardware-model"] == 1     # DCS-7280SR-48C6-M
    assert result.counts["os-version"] == 1         # EOS-4.32.1F
    assert "device-header" not in result.families


def test_one_rule_of_the_section_keeps_its_own_action():
    cfg = section("platform", "redact", os_version="keep")
    cfg.collection.rancid_diagnostics = "keep"
    out = sanitise_text(EOS_HEADER, cfg, salt=SALT).text
    assert "! device: agg-sw-02 (<REMOVED>, EOS-4.32.1F)" in out


def test_a_rule_has_exactly_one_home():
    """[overrides] is gone: the section is the only place a rule is set."""
    from netredact import ConfigError
    with pytest.raises(ConfigError, match=r"now \[platform\] os-version"):
        Config.from_dict({"overrides": {"os-version": "keep"}})


def test_the_three_families_on_the_header_line_move_independently():
    cfg = policy(hostnames="pseudo")
    cfg.platform.default = "hash"
    cfg.collection.rancid_diagnostics = "keep"
    out = sanitise_text(EOS_HEADER, cfg, salt=SALT).text
    line = next(v for v in out.splitlines() if v.startswith("! device:"))
    assert re.fullmatch(
        r"! device: device-[0-9a-f]+ \(<MODEL-[0-9a-f]+>, <VERSION-[0-9a-f]+>\)",
        line), line


def test_a_boot_image_goes_whether_or_not_it_is_commented_out():
    out = redacted("! boot system flash:/EOS64-4.32.1F.swi\n"
                   "boot system flash:c2900-universalk9-mz.SPA.155-3.M.bin\n")
    assert out == ("! boot system <REMOVED>\n"
                   "boot system <REMOVED>\n")


@pytest.mark.parametrize("line,kept", [
    ("version 15.7\n", "version <REMOVED>\n"),                    # IOS
    ("version 9.3(5) Bios:version 07.66\n", "version <REMOVED>\n"),  # NX-OS
    ("version 21.4R3-S4.9;\n", "version <REMOVED>;\n"),           # JunOS
    ("set version 23.4R2-S5.6\n", "set version <REMOVED>\n"),     # JunOS set
])
def test_a_bare_version_line_is_the_software_release(line, kept):
    """The JunOS `;` is structure, not value, so it stays outside the span."""
    assert redacted(line) == kept


@pytest.mark.parametrize("line", [
    "Model Number : WS-C3850-48P\n",
    "! Hardware: DCS-7280SR-48C6-M\n",
    "Chassis type: MX240\n",
    "PID: ISR4331/K9\n",
    "Software image version: 4.32.1F\n",
    'System image file is "flash:packages.conf"\n',
    "Junos: 20.4R3-S4.9\n",
])
def test_the_show_version_lines_people_paste_in_front_of_a_config(line):
    out = redacted(line)
    assert "<REMOVED>" in out
    assert line.split(":")[-1].strip() not in out


# -- and stopping there ------------------------------------------------------

@pytest.mark.parametrize("line", [
    # `platform`, `model` and `chassis` are ordinary keywords. None of these
    # carries the `:` or `=` the hardware-model rule insists on, and that is
    # the entire reason the rule can afford to know those words at all.
    "platform qos map-mode\n",
    "service routing protocols model multi-agent\n",
    "chassis {\n",
    " platform punt-keepalive disable-kernel-core\n",
    # `version` as an argument rather than as the whole line
    # a bare product name is only a version line when a colon says so
    "eos flag set\n",
    "ip ssh version 2\n",
    " standby 1 version 2\n",
    "snmp-server host 203.0.113.99 version 2c\n",
    " ntp server 10.20.30.1 version 4 prefer\n",
    # a boot marker is not a boot image
    "boot-start-marker\n",
])
def test_a_configuration_keyword_is_not_a_platform_disclosure(line):
    assert redacted(line) == line


def test_platform_is_kept_by_default_and_counted_as_kept():
    cfg = Config()
    cfg.collection.rancid_diagnostics = "keep"
    result = sanitise_text(EOS_HEADER, cfg, salt=SALT)
    assert "DCS-7280SR-48C6-M, EOS-4.32.1F" in result.text
    assert result.kept_counts["hardware-model"] == 1
    assert result.kept_counts["os-version"] == 1
    assert result.kept_counts["boot-image"] == 1
    assert not result.counts


def test_a_destroyed_platform_value_counts_as_a_redaction():
    cfg = policy(platform="redact")
    cfg.collection.rancid_diagnostics = "keep"
    result = sanitise_text(EOS_HEADER, cfg, salt=SALT)
    assert result.families["os-version"] == "platform"
    assert result.redactions == sum(result.counts.values())


def test_the_section_defaults_to_keep_and_names_every_platform_rule():
    """Adding a sixth platform rule must not silently escape the section."""
    cfg = Config()
    assert set(RULE_SECTIONS['platform'].RULES) == {"hardware-model", "os-version",
                                   "software-image", "boot-image"}
    assert all(cfg.platform.action(r) == "keep" for r in RULE_SECTIONS['platform'].RULES)


# -- vendor detection --------------------------------------------------------
# Detection reads the input, never the output, because `platform` exists to
# destroy the very markers it depends on. These assert both halves: that the
# markers are read from the input, and that enough independent evidence
# survives redaction for the answer not to depend on that ordering.

@pytest.mark.parametrize("text,vendor", [
    ("! boot system flash:/EOS64-4.32.1F.swi\n", "arista"),
    ("! Command: show running-config\n! device: sw01 (X, EOS-4.32.1F)\n", "arista"),
    ("Building configuration...\nCurrent configuration : 4523 bytes\n", "cisco"),
    ("version 9.3(5)\nfeature bgp\n", "cisco"),
    ("version 21.4R3-S4.9;\nsystem {\n", "juniper"),
])
def test_a_platform_line_names_the_vendor_on_its_own(text, vendor):
    assert detect_vendor(text) == vendor


def test_detection_survives_the_platform_family_destroying_its_evidence():
    """Was the risk in adding this family at all.

    Every decisive Arista marker -- the EOS release, the `.swi` image -- lives
    in exactly the material `platform = "redact"` removes. The header shape
    and the `! Command:` preamble are hints in their own right, so the answer
    does not depend on detection happening to run before the rewrite.
    """
    out = redacted(EOS_HEADER)
    assert "EOS" not in out and ".swi" not in out
    assert detect_vendor(out) == "arista"
    assert sanitise_text(EOS_HEADER, policy(platform="redact"),
                         salt=SALT).vendor == "arista"
