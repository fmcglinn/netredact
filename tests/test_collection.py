"""RANCID collector output is reduced to device configuration."""

import pytest

from netredact import CollectionConfig, Config, ConfigError, RemovedSection, sanitise_text

from .conftest import SALT


def test_juniper_rancid_diagnostics_are_removed_before_sanitising():
    text = """# RANCID-CONTENT-TYPE: juniper
#
# rancid_automation@router1> show chassis hardware detail
# Chassis                                SERIAL123         MX204
#
# rancid_automation@router1> show version detail
# Junos: 23.4R2
#
# rancid_automation@router1> show configuration | display set
set system host-name router1
set system root-authentication encrypted-password $6$secret
"""

    result = sanitise_text(text, Config(), salt=SALT)

    assert result.text == (
        "# RANCID-CONTENT-TYPE: juniper\n"
        "set system host-name router1\n"
        "set system root-authentication encrypted-password <REMOVED>\n"
    )
    assert result.removed_sections == [
        RemovedSection("collector preamble", 1),
        RemovedSection("show chassis hardware detail", 3),
        RemovedSection("show version detail", 3),
        RemovedSection("collector metadata", 1),
    ]


def test_arista_rancid_preamble_and_metadata_are_removed():
    text = """!RANCID-CONTENT-TYPE: arista
!
!Model: DCS-7280
!Serial number: SERIAL123
!
! Command: show running-config
! device: edge1 (DCS-7280, 4.34.5M)
!
hostname edge1
enable secret sha512 hunter2
"""

    result = sanitise_text(text, Config(), salt=SALT)

    assert result.text == (
        "!RANCID-CONTENT-TYPE: arista\n"
        "hostname edge1\n"
        "enable secret sha512 <REMOVED>\n"
    )
    assert result.removed_sections == [
        RemovedSection("collector preamble", 4),
        RemovedSection("collector metadata", 3),
    ]


def test_collection_keep_bypasses_stripping_but_not_normal_sanitising():
    text = """# RANCID-CONTENT-TYPE: juniper
# user@router> show version detail
# Junos: 23.4R2
"""
    cfg = Config()
    cfg.collection.rancid_diagnostics = "keep"

    result = sanitise_text(text, cfg, salt=SALT)

    assert "show version detail" in result.text
    assert result.removed_sections == []


def test_configuration_only_rancid_output_is_safe_to_sanitise_again():
    text = """# RANCID-CONTENT-TYPE: juniper
set version 23.4R2-S5.6
set system host-name router
"""
    cfg = Config()
    cfg.platform.os_version = "hash"

    result = sanitise_text(text, cfg, salt=SALT)

    assert result.lines[0] == "# RANCID-CONTENT-TYPE: juniper"
    assert result.lines[1].startswith("set version <VERSION-")
    assert result.lines[2] == "set system host-name router"
    assert result.removed_sections == []


def test_unknown_command_fails_closed_through_eof():
    text = """# RANCID-CONTENT-TYPE: juniper
# user@router> show security diagnostics
# SECRET-SERIAL-123
"""

    result = sanitise_text(text, Config(), salt=SALT)

    assert result.text == "# RANCID-CONTENT-TYPE: juniper\n"
    assert result.removed_sections[-1] == RemovedSection(
        "show security diagnostics", 2
    )


def test_one_prompt_without_rancid_evidence_is_not_a_section_boundary():
    text = "# user@router> show version detail\nhostname router\n"

    result = sanitise_text(text, Config(), salt=SALT)

    assert result.text == text
    assert result.removed_sections == []


def test_two_uncommented_prompts_activate_collection_filtering():
    text = """user@router> show version detail
Junos: 23.4R2
user@router> show configuration | display set
set system host-name router
"""

    result = sanitise_text(text, Config(), salt=SALT)

    assert "Junos:" not in result.text
    assert result.text == "set system host-name router\n"


def test_commented_prompt_shapes_without_username_at_do_not_activate():
    text = "# example> show version\n# another> show configuration\n"

    result = sanitise_text(text, Config(), salt=SALT)

    assert result.text == text


def test_inconsistent_prompt_identity_inside_diagnostics_is_not_a_boundary():
    text = """# RANCID-CONTENT-TYPE: juniper
# collector@router> show version detail
# attacker@payload> show configuration
# diagnostic-secret
# collector@router> show configuration | display set
set system host-name router
"""

    result = sanitise_text(text, Config(), salt=SALT)

    assert "diagnostic-secret" not in result.text
    assert "set system host-name router" in result.text


def test_collection_mode_loads_and_validates():
    assert Config().collection.rancid_diagnostics == "remove"
    assert Config.from_dict({"collection": {"rancid_diagnostics": "keep"}}).collection == (
        CollectionConfig("keep")
    )
    with pytest.raises(ConfigError, match="Expected one of remove, keep"):
        Config.from_dict({"collection": {"rancid_diagnostics": "erase"}})
    cfg = Config()
    cfg.collection.rancid_diagnostics = "erase"
    with pytest.raises(ConfigError, match="Expected one of remove, keep"):
        sanitise_text("hostname router\n", cfg, salt=SALT)


def test_multiple_configuration_sections_get_source_delimiters():
    text = """# RANCID-CONTENT-TYPE: juniper
# user@router> show configuration
system { host-name running; }
# user@router> show startup-config
hostname startup
"""

    result = sanitise_text(text, Config(), salt=SALT)

    assert "# source: show configuration\n" in result.text
    assert "# source: show startup-config\n" in result.text
    assert "host-name running" in result.text
    assert "hostname startup" in result.text


def test_unsafe_configuration_prefix_is_an_unknown_command():
    text = """# RANCID-CONTENT-TYPE: juniper
# user@router> show configuration | match passwords
# leaked-line
"""

    result = sanitise_text(text, Config(), salt=SALT)

    assert "leaked-line" not in result.text
    assert result.removed_sections[-1].command == (
        "show configuration | match passwords"
    )


def test_removed_diagnostics_do_not_enter_identity_collection():
    text = """# RANCID-CONTENT-TYPE: juniper
# user@old-router> show version detail
# hostname diagnostic-only
# user@old-router> show configuration | display set
set system host-name config-router
"""
    cfg = Config()
    cfg.policy.hostnames = "pseudo"

    result = sanitise_text(text, cfg, salt=SALT)

    assert "diagnostic-only" not in result.mapping.get("hostname", {})
    assert "config-router" in result.mapping["hostname"]


def test_removed_diagnostics_do_not_influence_vendor_reporting():
    text = """user@router> show version detail
Junos: 23.4R2
user@router> show running-config
! boot system flash:/EOS64.swi
hostname router
"""

    result = sanitise_text(text, Config(), salt=SALT)

    assert result.vendor == "arista"



# ---------------------------------------------------------------------------
# FortiOS captures. Two things were missing and both had to be there: FortiOS
# has no `user@host` prompt, so no boundary was ever found; and `show
# full-configuration` was not an allowlisted command, so once boundaries WERE
# found the configuration would have been deleted as diagnostic output.
# ---------------------------------------------------------------------------

FORTIOS_CAPTURE = """# RANCID-CONTENT-TYPE: fortigate
# fw-edge-01 # get system status
# Version: FortiGate-60F v7.2.5 build1517
# Serial-Number: FGT60FTK20001234
# fw-edge-01 # show full-configuration
config system global
    set hostname "fw-edge-01"
end
"""


def test_a_fortios_capture_keeps_its_configuration_and_drops_the_rest():
    result = sanitise_text(FORTIOS_CAPTURE, Config(), salt=SALT)

    assert "config system global" in result.text
    assert 'set hostname "fw-edge-01"' in result.text   # `hostnames` defaults to keep
    assert "FortiGate-60F" not in result.text
    assert "FGT60FTK20001234" not in result.text
    assert [s.command for s in result.removed_sections][0] == "get system status"


def test_the_bare_show_command_is_a_configuration_dump():
    """`show` is the configuration in FortiOS and in JunOS configuration mode,
    and is not a command at all in an IOS-style grammar -- so admitting it
    cannot let another vendor's diagnostic output through."""
    text = ("# RANCID-CONTENT-TYPE: fortigate\n"
            "# fw-edge-01 # get hardware status\n"
            "# Model name: FortiGate-60F\n"
            "# fw-edge-01 # show\n"
            "config system dns\n"
            '    set domain "northwind.test"\n'
            "end\n")
    result = sanitise_text(text, Config(), salt=SALT)
    assert "config system dns" in result.text
    assert "FortiGate-60F" not in result.text


def test_a_vdom_prompt_is_the_same_device():
    text = ("# RANCID-CONTENT-TYPE: fortigate\n"
            "# fw-edge-01 (global) # get system status\n"
            "# Version: FortiGate-60F v7.2.5\n"
            "# fw-edge-01 (global) # show full-configuration\n"
            "config system global\n"
            "end\n")
    result = sanitise_text(text, Config(), salt=SALT)
    assert "config system global" in result.text
    assert "FortiGate-60F" not in result.text


def test_a_fortios_prompt_is_a_boundary_and_never_evidence():
    """Detection is what licenses DELETING everything unrecognised, so a file
    that merely contains two `host # command` lines must not become a capture.
    An ASCII-art banner is the case this protects."""
    text = ("banner motd ^C\n"
            "# hub # spoke\n"
            "# hub # spoke\n"
            "^C\n"
            "hostname core-rtr-01\n")
    result = sanitise_text(text, Config(), salt=SALT)
    assert result.removed_sections == []
    assert "hostname core-rtr-01" in result.text


def test_an_uncommented_prompt_shape_is_not_a_fortios_boundary():
    """The comment leader is required, unlike the `user@host` form: RANCID
    writes prompt lines as comments, and a config line that happens to contain
    ` # ` must not split the file."""
    text = ("# RANCID-CONTENT-TYPE: fortigate\n"
            "# fw-edge-01 # show full-configuration\n"
            "config system global\n"
            '    set alias "rack 4 # bay 2"\n'
            "end\n")
    result = sanitise_text(text, Config(), salt=SALT)
    assert 'set alias "rack 4 # bay 2"' in result.text
