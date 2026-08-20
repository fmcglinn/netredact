import json
import stat
import tomllib

import pytest

from netredact.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main


def test_print_config_is_valid_toml_and_shows_the_defaults(capsys):
    assert main(["--print-config"]) == EXIT_OK
    parsed = tomllib.loads(capsys.readouterr().out)
    assert parsed["secrets"]["default"] == "redact"
    assert parsed["text"]["default"] == "keep"
    assert parsed["policy"]["hostnames"] == "keep"
    assert parsed["ipv4"]["default"] == "keep"
    assert parsed["ipv6"]["default"] == "keep"
    assert parsed["macs"] == {"oui": "keep", "nic": "keep", "pool": "00:00:5e"}
    assert parsed["collection"] == {"rancid_diagnostics": "remove"}
    assert parsed["ipv4"]["pool"] == ["198.18.0.0/15", "100.64.0.0/10"]
    assert "well_known_resolvers" in parsed["ipv4"]


def test_print_config_documents_the_actions(capsys):
    main(["--print-config"])
    out = capsys.readouterr().out
    for action in ("keep", "pseudo", "hash", "redact"):
        assert action in out
    assert "pseudo is not available for secrets" in out


def test_list_rules_has_a_family_column(capsys):
    assert main(["--list-rules"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "family" in out
    assert "enable-secret" in out and "secrets" in out
    assert "location" in out and "text" in out
    assert "serial-number" in out and "identity" in out
    assert "junos-community" in out and "[stanza: snmp]" in out
    assert "credential-left" in out
    assert out.count("\n") > 45


def test_version_prints_and_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "netredact" in capsys.readouterr().out


def test_no_files_is_a_usage_error(capsys):
    assert main([]) == EXIT_USAGE
    assert "no input files" in capsys.readouterr().err


def test_stdout_by_default(fixtures, capsys):
    assert main([str(fixtures / "cisco.cfg")]) == EXIT_OK
    out = capsys.readouterr().out
    assert "enable secret 5 <REMOVED>" in out


def test_writes_to_directory(fixtures, tmp_path, capsys):
    rc = main([str(fixtures / "cisco.cfg"), str(fixtures / "arista.cfg"),
               "-o", str(tmp_path)])
    assert rc == EXIT_OK
    written = sorted(p.name for p in tmp_path.iterdir())
    assert written == ["arista.cfg.sanitised", "cisco.cfg.sanitised"]


def test_out_must_be_a_directory_for_many_inputs(fixtures, tmp_path, capsys):
    rc = main([str(fixtures / "cisco.cfg"), str(fixtures / "arista.cfg"),
               "-o", str(tmp_path / "one.txt")])
    assert rc == EXIT_USAGE


def test_in_place(fixtures, tmp_path):
    target = tmp_path / "c.cfg"
    target.write_text((fixtures / "cisco.cfg").read_text())
    assert main([str(target), "--in-place"]) == EXIT_OK
    assert "<REMOVED>" in target.read_text()
    assert "PlainTextPass123" not in target.read_text()


def test_a_missing_input_file_is_a_usage_error(tmp_path, capsys):
    assert main([str(tmp_path / "nope.cfg")]) == EXIT_USAGE


def test_config_file_is_honoured(fixtures, tmp_path, capsys):
    cfg = tmp_path / "netredact.toml"
    cfg.write_text('[policy]\nhostnames = "pseudo"\n')
    assert main([str(fixtures / "cisco.cfg"), "-c", str(cfg)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "core-rtr-01" not in out
    assert "hostname device-" in out


def test_bad_config_is_a_usage_error(fixtures, tmp_path, capsys):
    cfg = tmp_path / "bad.toml"
    cfg.write_text('[secrets]\ndefault = "pseudo"\n')
    assert main([str(fixtures / "cisco.cfg"), "-c", str(cfg)]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "config error" in err
    assert "use hash for an opaque marker" in err


def test_an_old_style_config_gets_a_migration_message(fixtures, tmp_path, capsys):
    cfg = tmp_path / "old.toml"
    cfg.write_text("[scrub]\nipv4 = true\n")
    assert main([str(fixtures / "cisco.cfg"), "-c", str(cfg)]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "[scrub] was replaced by [policy]" in err
    assert "now [ipv4] default" in err


def test_salt_file_created_0600_and_reused(fixtures, tmp_path, capsys):
    cfg = tmp_path / "netredact.toml"
    salt = tmp_path / "salt"
    cfg.write_text(f'salt_file = "{salt}"\n[ipv4]\ndefault = "pseudo"\n')
    args = [str(fixtures / "cisco.cfg"), "-c", str(cfg)]
    assert main(args) == EXIT_OK
    first = capsys.readouterr().out
    assert salt.exists()
    assert stat.S_IMODE(salt.stat().st_mode) == 0o600
    assert main(args) == EXIT_OK
    assert capsys.readouterr().out == first          # reproducible


def test_salt_file_creation_is_announced_on_stderr(fixtures, tmp_path, capsys):
    cfg = tmp_path / "netredact.toml"
    salt = tmp_path / "sub" / "salt"
    cfg.write_text(f'salt_file = "{salt}"\n')
    assert main([str(fixtures / "cisco.cfg"), "-c", str(cfg)]) == EXIT_OK
    err = capsys.readouterr().err
    assert "created salt file" in err and "mode 600" in err
    assert "re-identification key" in err


def test_map_out_is_written_0600(fixtures, tmp_path, capsys):
    cfg = tmp_path / "netredact.toml"
    cfg.write_text('[policy]\nhostnames = "pseudo"\n[ipv4]\ndefault = "pseudo"\n')
    mapfile = tmp_path / "map.json"
    rc = main([str(fixtures / "cisco.cfg"), "-c", str(cfg),
               "--map-out", str(mapfile)])
    assert rc == EXIT_OK
    assert stat.S_IMODE(mapfile.stat().st_mode) == 0o600
    data = json.loads(mapfile.read_text())
    entry = next(iter(data.values()))
    assert "core-rtr-01" in entry["hostname"]


def test_strict_exits_nonzero_on_findings(tmp_path, capsys):
    leaky = tmp_path / "leaky.cfg"
    # a blob shape no rule knows about, so no policy claims to have handled it
    leaky.write_text("hostname x\nweird-vendor blob "
                     "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbg==\n")
    assert main([str(leaky), "--strict"]) == EXIT_FINDINGS
    assert main([str(leaky)]) == EXIT_OK


def test_verify_strict_in_the_config_has_the_same_effect(tmp_path):
    leaky = tmp_path / "leaky.cfg"
    leaky.write_text("hostname x\nweird-vendor blob "
                     "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbg==\n")
    cfg = tmp_path / "netredact.toml"
    cfg.write_text("[verify]\nstrict = true\n")
    assert main([str(leaky), "-c", str(cfg)]) == EXIT_FINDINGS


def test_a_clean_file_exits_zero_under_strict(fixtures):
    assert main([str(fixtures / "cisco.cfg"), "--strict"]) == EXIT_OK


# -- the report --------------------------------------------------------------

def test_report_names_the_policy_and_the_changes(fixtures, capsys):
    main([str(fixtures / "cisco.cfg"), "--report"])
    err = capsys.readouterr().err
    assert "(vendor: cisco)" in err
    assert "policy: secrets=redact, everything else kept" in err
    assert "changes:" in err
    assert "VERIFY: clean" in err
    assert "does not guarantee anonymisation" in err


def test_report_audits_removed_collection_sections_without_their_contents(
        tmp_path, capsys):
    src = tmp_path / "rancid.conf"
    src.write_text(
        "# RANCID-CONTENT-TYPE: juniper\n"
        "# user@router> show version detail\n"
        "# private-build-identifier\n"
        "# user@router> show configuration | display set\n"
        "set system host-name router\n"
    )

    assert main([str(src), "--report"]) == EXIT_OK
    out, err = capsys.readouterr()
    assert "show version detail" not in out
    assert "collection: removed 2 line(s) [show version detail]" in err
    assert "private-build-identifier" not in err
    assert "is this really a device configuration?" not in err


def test_the_report_does_not_enumerate_what_was_kept(fixtures, capsys):
    """The report states the policy; it does not list every kept value.

    ``Result.kept_counts`` still carries the detail for a caller that wants
    it -- see ``docs/library.md``.
    """
    main([str(fixtures / "cisco.cfg"), "--report"])
    err = capsys.readouterr().err
    assert "KEPT" not in err
    # descriptions, banners and certificates are all kept at this policy, so
    # nothing in the report should name them
    assert "descriptions" not in err
    assert "banners" not in err


def test_report_warns_about_a_pool_collision(tmp_path, capsys):
    src = tmp_path / "cgnat.cfg"
    src.write_text(" ip address 100.64.5.9 255.255.255.0\n")
    cfg = tmp_path / "netredact.toml"
    cfg.write_text('[ipv4]\nother_unicast = "pseudo"\n')
    main([str(src), "-c", str(cfg), "--report"])
    err = capsys.readouterr().err
    assert "WARNING" in err and "pseudonym pool" in err


def test_report_says_so_when_nothing_matched(tmp_path, capsys):
    src = tmp_path / "notaconfig.txt"
    src.write_text("the quick brown fox\n")
    main([str(src), "--report"])
    assert "changes: NONE" in capsys.readouterr().err


def test_report_lists_findings_and_truncates_a_long_run(tmp_path, capsys):
    src = tmp_path / "leaky.cfg"
    src.write_text("".join(f"enable secret 5 PlainText{i}\n" for i in range(8)))
    cfg = tmp_path / "netredact.toml"
    cfg.write_text('[secrets]\ndefault = "keep"\n')
    assert main([str(src), "-c", str(cfg), "--strict", "--report"]) == EXIT_FINDINGS
    err = capsys.readouterr().err
    assert "VERIFY: 8 line(s) a human should look at" in err
    assert "and 3 more [credential-left]" in err


def test_the_report_is_off_by_default(fixtures, capsys):
    """A run that succeeds says nothing: the output and the exit code are it."""
    assert main([str(fixtures / "cisco.cfg")]) == EXIT_OK
    assert capsys.readouterr().err == ""


def test_findings_reach_stderr_without_report(tmp_path, capsys):
    """An exit code must never arrive unexplained, --report or not."""
    src = tmp_path / "leaky.cfg"
    src.write_text("enable secret 5 PlainText\n")
    cfg = tmp_path / "netredact.toml"
    cfg.write_text('[secrets]\ndefault = "keep"\n')
    assert main([str(src), "-c", str(cfg), "--strict"]) == EXIT_FINDINGS
    out, err = capsys.readouterr()
    assert "VERIFY: 1 line(s) a human should look at" in err
    assert str(src) in err, "the failing file must be named"
    assert "policy:" not in err, "only the problems, not the whole report"
    assert "PlainText" in out, "stdout still carries the configuration"


def test_findings_reach_stderr_without_strict(tmp_path, capsys):
    """Findings are worth saying even when they are not worth failing over."""
    src = tmp_path / "leaky.cfg"
    src.write_text("enable secret 5 PlainText\n")
    cfg = tmp_path / "netredact.toml"
    cfg.write_text('[secrets]\ndefault = "keep"\n')
    assert main([str(src), "-c", str(cfg)]) == EXIT_OK
    assert "VERIFY: 1 line(s)" in capsys.readouterr().err


def test_a_pool_collision_is_reported_without_report(tmp_path, capsys):
    src = tmp_path / "cgnat.cfg"
    src.write_text(" ip address 100.64.5.9 255.255.255.0\n")
    cfg = tmp_path / "netredact.toml"
    cfg.write_text('[ipv4]\nother_unicast = "pseudo"\n')
    main([str(src), "-c", str(cfg)])
    err = capsys.readouterr().err
    assert "WARNING" in err and "pseudonym pool" in err


def test_a_clean_file_names_itself_nowhere(fixtures, capsys):
    """Silence means clean: a file with nothing to say does not even print its name."""
    assert main([str(fixtures / "cisco.cfg")]) == EXIT_OK
    assert capsys.readouterr().err == ""


def test_stdin(fixtures, monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO((fixtures / "cisco.cfg").read_text()))
    assert main(["-"]) == EXIT_OK
    assert "<REMOVED>" in capsys.readouterr().out
