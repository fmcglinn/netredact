import json
import os
import re
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


def test_many_inputs_make_out_a_directory_and_create_it(fixtures, tmp_path):
    """Two inputs cannot share one file, so `-o one.txt` is a directory name.

    Created rather than refused: with more than one file to write there is
    nothing for `-o` to mean except a directory, and a directory that is only
    named is made on the first write -- the same as the zone directories a
    mirrored tree needs underneath it.
    """
    dest = tmp_path / "one.txt"
    rc = main([str(fixtures / "cisco.cfg"), str(fixtures / "arista.cfg"),
               "-o", str(dest)])
    assert rc == EXIT_OK
    assert sorted(p.name for p in dest.iterdir()) == [
        "arista.cfg.sanitised", "cisco.cfg.sanitised"]


def test_out_may_not_be_an_existing_file_when_a_tree_is_written(
        fixtures, tmp_path, capsys):
    """The one thing a mirrored run still refuses, and before it writes."""
    dest = tmp_path / "taken.txt"
    dest.write_text("mine\n")
    rc = main([str(fixtures / "cisco.cfg"), str(fixtures / "arista.cfg"),
               "-o", str(dest)])
    assert rc == EXIT_USAGE
    assert "is a file" in capsys.readouterr().err
    assert dest.read_text() == "mine\n"


def test_replace_writes_over_the_input(fixtures, tmp_path):
    target = tmp_path / "c.cfg"
    target.write_text((fixtures / "cisco.cfg").read_text())
    assert main([str(target), "-r"]) == EXIT_OK
    assert "<REMOVED>" in target.read_text()
    assert "PlainTextPass123" not in target.read_text()


def test_report_has_an_upper_case_short_flag(fixtures, tmp_path, capsys):
    """-r replaces files now, so the report's short form is -R.

    The risk in that swap is not the missing report, it is the muscle memory:
    a hand that types -r expecting a report must not get a rewritten file
    *and* a report that makes it look like the old flag still works.
    """
    assert main([str(fixtures / "cisco.cfg"), "-R"]) == EXIT_OK
    assert "policy:" in capsys.readouterr().err

    target = tmp_path / "c.cfg"
    target.write_text((fixtures / "cisco.cfg").read_text())
    assert main([str(target), "-r"]) == EXIT_OK
    assert "policy:" not in capsys.readouterr().err, "-r is not the report flag"


def test_replace_and_out_together_are_a_usage_error(fixtures, tmp_path, capsys):
    """Two destinations for one file: say so rather than silently picking."""
    target = tmp_path / "c.cfg"
    target.write_text((fixtures / "cisco.cfg").read_text())
    out = tmp_path / "clean"
    out.mkdir()
    assert main([str(target), "-r", "-o", str(out)]) == EXIT_USAGE
    assert "use one" in capsys.readouterr().err
    assert "PlainTextPass123" in target.read_text(), "the input was not touched"


# -- directory arguments -----------------------------------------------------

def tree(root, files: dict[str, str]):
    """Write ``{"a/b.cfg": text}`` under ``root`` and return it."""
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def test_a_directory_is_walked_recursively_and_replaced(fixtures, tmp_path):
    cisco = (fixtures / "cisco.cfg").read_text()
    root = tree(tmp_path / "backups", {
        "top.cfg": cisco,
        "zone_a/one.cfg": cisco,
        "zone_b/nested/two.cfg": cisco,
    })

    assert main([str(root), "-r"]) == EXIT_OK
    for name in ("top.cfg", "zone_a/one.cfg", "zone_b/nested/two.cfg"):
        text = (root / name).read_text()
        assert "<REMOVED>" in text, name
        assert "PlainTextPass123" not in text, name


def test_the_walk_skips_dot_files_and_says_so(fixtures, tmp_path, capsys):
    cisco = (fixtures / "cisco.cfg").read_text()
    root = tree(tmp_path / "backups", {"one.cfg": cisco, ".DS_Store": "junk"})
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("[core]\n")

    assert main([str(root), "-r"]) == EXIT_OK
    err = capsys.readouterr().err
    assert "skipped 1 file(s)" in err, "a dot-dir is pruned, not counted per file"
    assert ".DS_Store" in err
    assert (root / ".DS_Store").read_text() == "junk"
    assert (root / ".git" / "config").read_text() == "[core]\n"


def test_the_walk_never_rewrites_a_binary(fixtures, tmp_path, capsys):
    """errors="replace" would turn a binary into mojibake -- in place.

    The NUL is deliberately past the first 4 KB: an archive or a firmware
    image can open with kilobytes of plausible text, so a check that reads
    only the head of the file rewrites exactly the files it was meant to save.
    """
    root = tree(tmp_path / "backups", {"one.cfg": (fixtures / "cisco.cfg").read_text()})
    payload = b"! looks like a configuration for a while\n" * 200 + b"\x00binary\x00"
    assert payload.index(b"\x00") > 4096
    blob = root / "image.bin"
    blob.write_bytes(payload)

    assert main([str(root), "-r"]) == EXIT_OK
    assert blob.read_bytes() == payload
    assert "skipped 1 file(s)" in capsys.readouterr().err


def test_a_named_file_is_never_filtered_by_the_walks_rules(fixtures, tmp_path):
    """You typed it, so it is attempted: only the walk gets to be choosy."""
    target = tmp_path / ".hidden.cfg"
    target.write_text((fixtures / "cisco.cfg").read_text())
    assert main([str(target), "-r"]) == EXIT_OK
    assert "<REMOVED>" in target.read_text()


def test_a_directory_written_to_an_out_dir_mirrors_the_tree(fixtures, tmp_path):
    """Flattening would land two zones' same-named file on each other."""
    cisco = (fixtures / "cisco.cfg").read_text()
    root = tree(tmp_path / "backups",
                {"zone_a/router.cfg": cisco, "zone_b/router.cfg": cisco})
    out = tmp_path / "clean"
    out.mkdir()

    assert main([str(root), "-o", str(out)]) == EXIT_OK
    written = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())
    assert written == ["zone_a/router.cfg.sanitised", "zone_b/router.cfg.sanitised"]


def test_overlapping_directories_are_a_usage_error_not_an_overwrite(
        fixtures, tmp_path, capsys):
    cisco = (fixtures / "cisco.cfg").read_text()
    left = tree(tmp_path / "left", {"router.cfg": cisco})
    right = tree(tmp_path / "right", {"router.cfg": cisco})
    out = tmp_path / "clean"
    out.mkdir()

    assert main([str(left), str(right), "-o", str(out)]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "same file" in err
    assert list(out.iterdir()) == []


def test_a_directory_without_a_destination_is_a_usage_error(
        fixtures, tmp_path, capsys):
    """101 configs concatenated onto stdout is never what was meant."""
    root = tree(tmp_path / "backups",
                {"one.cfg": (fixtures / "cisco.cfg").read_text()})
    assert main([str(root)]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "is a directory" in err
    assert "-r" in err and "-o" in err
    assert "PlainTextPass123" in (root / "one.cfg").read_text()


def test_an_empty_directory_is_a_usage_error(tmp_path, capsys):
    root = tmp_path / "empty"
    root.mkdir()
    assert main([str(root), "-r"]) == EXIT_USAGE
    assert "no files found" in capsys.readouterr().err


def test_a_directory_argument_makes_out_a_directory_and_creates_it(
        fixtures, tmp_path):
    """Even when the walk finds one file, a directory is answered with a tree.

    So `-o one.txt` here names a directory, and it is created rather than
    refused. Deciding this on the number of files found would make it depend
    on the contents of the directory: the same command that wrote a regular
    file called `one.txt` today would mirror a tree tomorrow, once a second
    config landed in it.
    """
    root = tree(tmp_path / "backups",
                {"only.cfg": (fixtures / "cisco.cfg").read_text()})
    dest = tmp_path / "one.txt"

    assert main([str(root), "-o", str(dest)]) == EXIT_OK
    assert "<REMOVED>" in (dest / "only.cfg.sanitised").read_text()


def test_a_created_out_directory_mirrors_the_zones_under_it(
        fixtures, tmp_path):
    """One walk builds `-o` and everything the tree needs inside it."""
    cisco = (fixtures / "cisco.cfg").read_text()
    root = tree(tmp_path / "backups",
                {"nsw/rtr1.cfg": cisco, "vic/rtr1.cfg": cisco})
    dest = tmp_path / "deep" / "clean"

    assert main([str(root), "-o", str(dest)]) == EXIT_OK
    assert (dest / "nsw" / "rtr1.cfg.sanitised").exists()
    assert (dest / "vic" / "rtr1.cfg.sanitised").exists()


def test_nothing_is_created_when_the_run_is_refused_before_it_writes(
        fixtures, tmp_path, capsys):
    """A named-but-absent `-o` is built by the first write, and only then."""
    root = tree(tmp_path / "backups",
                {"nsw/rtr1.cfg": CISCO_LINES, "vic/rtr1.cfg": CISCO_LINES})
    dest = tmp_path / "clean"

    assert main([str(root), "-o", str(dest), "--suffix",
                 "/../escaped.cfg"]) == EXIT_USAGE
    assert not dest.exists()


def test_a_named_file_may_still_name_an_out_file(fixtures, tmp_path):
    """The rule is about directory arguments; naming one file is unaffected."""
    dest = tmp_path / "one.txt"
    assert main([str(fixtures / "cisco.cfg"), "-o", str(dest)]) == EXIT_OK
    assert "<REMOVED>" in dest.read_text()


def test_one_run_over_a_tree_shares_its_pseudonyms(tmp_path):
    """A whole tree in one invocation is one salt, so a host maps the same way.

    The two files differ in everything but the host name. Comparing two copies
    of the same file would hold under any salt scheme at all, including a
    fresh salt per file, which is the thing this is here to rule out: the
    pseudonym itself has to be the same token in both.
    """
    cfg = tmp_path / "netredact.toml"
    cfg.write_text('[policy]\nhostnames = "pseudo"\n')
    root = tree(tmp_path / "backups", {
        "a/one.cfg": "hostname core-rtr-01\n"
                     "enable secret 5 PlainTextPass123\n",
        "b/two.cfg": "hostname core-rtr-01\n"
                     "interface GigabitEthernet0/1\n"
                     " ip address 10.1.1.1 255.255.255.0\n",
    })

    assert main([str(root), "-c", str(cfg), "-r"]) == EXIT_OK
    one = (root / "a" / "one.cfg").read_text()
    two = (root / "b" / "two.cfg").read_text()
    assert "core-rtr-01" not in one and "core-rtr-01" not in two
    assert one != two, "two different configs, so this is not a copy-vs-copy test"

    pseudonyms = {text: re.search(r"^hostname (\S+)$", text, re.M).group(1)
                  for text in (one, two)}
    assert pseudonyms[one].startswith("device-")
    assert pseudonyms[one] == pseudonyms[two]


# -- the provenance marker and the second run --------------------------------

def test_the_output_says_netredact_wrote_it(fixtures, capsys):
    assert main([str(fixtures / "cisco.cfg")]) == EXIT_OK
    first = capsys.readouterr().out.splitlines()[0]
    assert first.startswith("! netredact-sanitised")
    assert "re-run from the original" in first


def test_the_marker_is_a_comment_in_the_files_own_grammar(fixtures, capsys):
    assert main([str(fixtures / "juniper.cfg")]) == EXIT_OK
    assert capsys.readouterr().out.splitlines()[0].startswith("# netredact-sanitised")


def test_a_second_run_is_refused_and_changes_nothing(fixtures, tmp_path, capsys):
    """The whole point of the marker: a re-run is refusable evidence."""
    target = tmp_path / "c.cfg"
    target.write_text((fixtures / "cisco.cfg").read_text())
    assert main([str(target), "-r"]) == EXIT_OK
    once = target.read_text()

    assert main([str(target), "-r"]) == EXIT_USAGE
    assert target.read_text() == once, "the file was not touched a second time"
    err = capsys.readouterr().err
    assert "already sanitised by netredact" in err
    assert "--force" in err


def test_force_allows_a_second_run_and_does_not_stack_markers(
        fixtures, tmp_path, capsys):
    target = tmp_path / "c.cfg"
    target.write_text((fixtures / "cisco.cfg").read_text())
    assert main([str(target), "-r"]) == EXIT_OK
    assert main([str(target), "-r", "--force"]) == EXIT_OK
    assert target.read_text().count("netredact-sanitised") == 1


def test_a_marked_file_in_a_tree_is_refused_and_the_rest_still_run(
        fixtures, tmp_path, capsys):
    cisco = (fixtures / "cisco.cfg").read_text()
    root = tree(tmp_path / "backups", {"clean.cfg": cisco, "done.cfg": cisco})
    assert main([str(root / "done.cfg"), "-r"]) == EXIT_OK
    done = (root / "done.cfg").read_text()

    assert main([str(root), "-r"]) == EXIT_USAGE, "one refusal fails the run"
    assert (root / "done.cfg").read_text() == done
    assert "netredact-sanitised" in (root / "clean.cfg").read_text()
    assert "already sanitised" in capsys.readouterr().err


def test_the_marker_can_be_switched_off_and_then_nothing_guards_a_re_run(
        fixtures, tmp_path, capsys):
    """Documented consequence: no marker, no evidence to refuse on."""
    cfg = tmp_path / "netredact.toml"
    cfg.write_text("marker = false\n")
    target = tmp_path / "c.cfg"
    target.write_text((fixtures / "cisco.cfg").read_text())

    assert main([str(target), "-c", str(cfg), "-r"]) == EXIT_OK
    assert "netredact-sanitised" not in target.read_text()
    assert main([str(target), "-c", str(cfg), "-r"]) == EXIT_OK


def test_reported_line_numbers_count_the_marker(tmp_path, capsys):
    """A line number a reader cannot trust is worse than none."""
    src = tmp_path / "leaky.cfg"
    src.write_text("hostname r1\nenable secret 5 PlainText\n")
    cfg = tmp_path / "netredact.toml"
    cfg.write_text('[secrets]\ndefault = "keep"\n')

    assert main([str(src), "-c", str(cfg)]) == EXIT_OK
    out, err = capsys.readouterr()
    # the secret is on line 2 of the body, line 3 of the file that was written
    assert out.splitlines()[2].strip().startswith("enable secret")
    assert "L3 [" in err


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


# -- what netredact refuses to touch -----------------------------------------
# Every test in this section is about destruction rather than output quality:
# each one describes a file that an earlier netredact would have rewritten,
# and under -r a rewritten file is the only copy there was.

CISCO_LINES = "hostname core-rtr-01\nenable secret 5 PlainTextPass123\n"


def test_the_walk_never_writes_through_a_symlink(fixtures, tmp_path, capsys):
    """A link is a path out of the tree, and -r would follow it."""
    outside = tmp_path / "outside.cfg"
    outside.write_text(CISCO_LINES)
    root = tree(tmp_path / "backups", {"one.cfg": CISCO_LINES})
    (root / "link.cfg").symlink_to(outside)

    assert main([str(root), "-r"]) == EXIT_OK
    assert outside.read_text() == CISCO_LINES, "a file outside the tree was written"
    assert "<REMOVED>" in (root / "one.cfg").read_text()
    err = capsys.readouterr().err
    assert "symlink" in err
    from netredact.cli import _walk
    assert "Symlinks are not followed" not in _walk.__doc__, \
        "the docstring must not read as a general guarantee"


def test_a_symlinked_directory_is_skipped_and_counted(tmp_path, capsys):
    """The other half of the same link: os.walk does not descend, we say so."""
    outside = tree(tmp_path / "elsewhere", {"secret.cfg": CISCO_LINES})
    root = tree(tmp_path / "backups", {"one.cfg": CISCO_LINES})
    (root / "zone_b").symlink_to(outside, target_is_directory=True)

    assert main([str(root), "-r"]) == EXIT_OK
    assert (outside / "secret.cfg").read_text() == CISCO_LINES
    assert "1 symlink" in capsys.readouterr().err


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root can read a mode-000 file")
def test_an_unreadable_file_is_an_error_not_a_clean_run(tmp_path, capsys):
    """"Not a configuration" about a file we could not open hides a leak.

    The old answer was to call it binary, which skipped it, printed a
    reassuring message and exited 0 -- with every secret in it untouched and
    nobody told.
    """
    root = tree(tmp_path / "backups", {"one.cfg": CISCO_LINES,
                                       "locked.cfg": CISCO_LINES})
    locked = root / "locked.cfg"
    locked.chmod(0o000)
    try:
        assert main([str(root), "-r"]) == EXIT_USAGE
        err = capsys.readouterr().err
        assert "locked.cfg" in err
        assert "denied" in err.lower() or "Errno 13" in err
    finally:
        locked.chmod(0o600)


def test_the_walk_never_rewrites_a_pem_key(tmp_path, capsys):
    """A key is text, so no NUL test can catch it -- and pem-key eats it."""
    key = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
           "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz\n"
           "-----END OPENSSH PRIVATE KEY-----\n")
    root = tree(tmp_path / "backups", {"one.cfg": CISCO_LINES, "id_rsa": key})

    assert main([str(root), "-r"]) == EXIT_OK
    assert (root / "id_rsa").read_text() == key
    err = capsys.readouterr().err
    assert "1 PEM file" in err
    assert "id_rsa" in err


def test_the_skip_message_counts_each_verdict_separately(tmp_path, capsys):
    """One sentence cannot say "not a configuration" about all of these."""
    root = tree(tmp_path / "backups", {
        "one.cfg": CISCO_LINES,
        ".DS_Store": "junk",
        "id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n",
    })
    (root / "blob.bin").write_bytes(b"\x00\x01\x02")

    assert main([str(root), "-r"]) == EXIT_OK
    err = capsys.readouterr().err
    assert "skipped 3 file(s)" in err
    for verdict in ("1 binary", "1 PEM file", "1 dot-file"):
        assert verdict in err
    assert "is not a configuration" not in err, "three verdicts, not one claim"


def test_a_named_binary_is_refused_and_not_destroyed(tmp_path, capsys):
    """`netredact backups/* -r` reaches us as typed names: a JPEG among them."""
    blob = tmp_path / "photo.jpg"
    payload = b"\xff\xd8\xff\xe0\x00\x10JFIF" + bytes(range(64))
    blob.write_bytes(payload)

    assert main([str(blob), "-r"]) == EXIT_USAGE
    assert blob.read_bytes() == payload
    err = capsys.readouterr().err
    assert "photo.jpg" in err
    assert "--force" in err, "a refusal has to say how to override it"


def test_a_named_pem_key_is_refused_and_not_destroyed(tmp_path, capsys):
    key = ("-----BEGIN RSA PRIVATE KEY-----\n"
           "MIIEowIBAAKCAQEAprivatekeymaterialAAAABBBBCCCCDDDDEEEEFFFF0123456789\n"
           "-----END RSA PRIVATE KEY-----\n")
    target = tmp_path / "id_rsa"
    target.write_text(key)

    assert main([str(target), "-r"]) == EXIT_USAGE
    assert target.read_text() == key
    err = capsys.readouterr().err
    assert "PEM" in err and "--force" in err


def test_force_processes_an_input_that_would_be_refused(tmp_path, capsys):
    """--force now means "I meant this file", not only "re-run a marked one"."""
    blob = tmp_path / "photo.jpg"
    blob.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF" + bytes(range(64)))

    assert main([str(blob), "-r", "--force"]) == EXIT_OK
    assert b"netredact-sanitised" in blob.read_bytes()


def test_a_refused_name_does_not_stop_the_files_that_are_safe(
        fixtures, tmp_path, capsys):
    """One refusal fails the run; it does not cancel the other inputs."""
    good = tmp_path / "good.cfg"
    good.write_text(CISCO_LINES)
    blob = tmp_path / "photo.jpg"
    blob.write_bytes(b"\x00\x01\x02\x03")

    assert main([str(good), str(blob), "-r"]) == EXIT_USAGE
    assert "<REMOVED>" in good.read_text()
    assert blob.read_bytes() == b"\x00\x01\x02\x03"


def test_crlf_line_endings_survive_a_replace(tmp_path):
    """Dropping every CR is an edit nobody asked for, in the only copy."""
    target = tmp_path / "windows.cfg"
    target.write_bytes(b"hostname core-rtr-01\r\nenable secret 5 PlainTextPass123\r\n")

    assert main([str(target), "-r"]) == EXIT_OK
    raw = target.read_bytes()
    assert b"<REMOVED>" in raw
    assert raw.count(b"\r\n") == raw.count(b"\n"), "an LF was left bare"
    assert raw.count(b"\r\n") >= 3, "marker line included"


def test_lf_line_endings_are_not_turned_into_crlf(tmp_path):
    target = tmp_path / "unix.cfg"
    target.write_bytes(b"hostname core-rtr-01\nenable secret 5 PlainTextPass123\n")
    assert main([str(target), "-r"]) == EXIT_OK
    assert b"\r" not in target.read_bytes()


def test_a_file_that_is_not_utf8_is_refused_rather_than_mangled(tmp_path, capsys):
    """errors="replace" writes U+FFFD over bytes we were not asked to touch."""
    target = tmp_path / "latin1.cfg"
    payload = b"hostname caf\xe9-rtr\nenable secret 5 PlainTextPass123\n"
    target.write_bytes(payload)

    assert main([str(target), "-r"]) == EXIT_USAGE
    assert target.read_bytes() == payload
    err = capsys.readouterr().err
    assert "UTF-8" in err and "--force" in err


def test_force_accepts_the_replacement_character(tmp_path, capsys):
    target = tmp_path / "latin1.cfg"
    target.write_bytes(b"hostname caf\xe9-rtr\nenable secret 5 PlainTextPass123\n")
    assert main([str(target), "-r", "--force"]) == EXIT_OK
    assert "�" in target.read_text(encoding="utf-8")


def test_a_suffix_cannot_carry_a_path_separator(tmp_path, capsys):
    """A suffix names the file; it does not get to say where the file goes."""
    root = tree(tmp_path / "backups", {"one.cfg": CISCO_LINES})
    out = tmp_path / "clean"
    out.mkdir()

    assert main([str(root), "-o", str(out), "--suffix",
                 "/../../escaped.cfg"]) == EXIT_USAGE
    assert "--suffix" in capsys.readouterr().err
    assert list(out.iterdir()) == []
    assert not (tmp_path.parent / "escaped.cfg").exists()
    assert not (tmp_path / "escaped.cfg").exists()


def test_a_named_out_path_does_not_invent_its_parent_directories(
        fixtures, tmp_path, capsys):
    """`-o deep/ly/nested/out.txt` with a typo in it is a mistake, not a tree.

    Reported rather than raised: a traceback would break the promise that an
    exit code never arrives unexplained.
    """
    dest = tmp_path / "deep" / "ly" / "nested" / "out.txt"
    assert main([str(fixtures / "cisco.cfg"), "-o", str(dest)]) == EXIT_USAGE
    assert not (tmp_path / "deep").exists()
    assert "No such file or directory" in capsys.readouterr().err


def test_a_named_pem_file_is_honoured_when_the_original_survives(
        tmp_path, capsys):
    """Refusal is about destruction, not about the file's shape.

    A file that opens with a PEM header may be a key, or a config fragment
    somebody pasted a certificate into -- netredact cannot tell. Where the
    write cannot destroy the original, the name the caller typed wins.
    """
    src = tmp_path / "pasted.cfg"
    src.write_text("-----BEGIN CERTIFICATE-----\nQUJDREVGRw==\n"
                   "-----END CERTIFICATE-----\n")
    out = tmp_path / "clean.txt"

    assert main([str(src), "-o", str(out)]) == EXIT_OK
    assert out.exists()
    assert "--force" not in capsys.readouterr().err


def test_a_failed_write_leaves_no_temporary_behind(fixtures, tmp_path, capsys):
    """A run that could not finish must not litter the tree it walked."""
    dest = tmp_path / "nope" / "out.txt"
    assert main([str(fixtures / "cisco.cfg"), "-o", str(dest)]) == EXIT_USAGE
    assert list(tmp_path.iterdir()) == []


def test_one_unwritable_file_does_not_abandon_the_rest_of_the_tree(
        fixtures, tmp_path, capsys):
    """Half a tree replaced, with no statement of which half, is the worst end."""
    root = tree(tmp_path / "backups", {
        "a_first.cfg": CISCO_LINES,
        "b_locked.cfg": CISCO_LINES,
        "c_last.cfg": CISCO_LINES,
    })
    if os.geteuid() == 0:
        pytest.skip("root ignores the permissions this test depends on")
    (root / "b_locked.cfg").chmod(0o444)
    locked_dir = root
    locked_dir.chmod(0o555)          # no new temp file may be created here
    try:
        rc = main([str(root), "-r"])
    finally:
        locked_dir.chmod(0o755)
        (root / "b_locked.cfg").chmod(0o644)

    assert rc == EXIT_USAGE
    err = capsys.readouterr().err
    # every file was attempted: the loop did not stop at the first failure
    assert err.count("netredact: [Errno") == 3, err
    assert not any(p.name.endswith(".netredact-tmp") for p in root.rglob("*"))


def test_a_mirrored_tree_still_creates_its_zone_directories(tmp_path):
    """The one case where creating directories is the point."""
    root = tree(tmp_path / "backups", {"zone_a/nested/router.cfg": CISCO_LINES})
    out = tmp_path / "clean"
    out.mkdir()
    assert main([str(root), "-o", str(out)]) == EXIT_OK
    assert (out / "zone_a" / "nested" / "router.cfg.sanitised").exists()


def test_two_named_files_sharing_a_base_name_collide(fixtures, tmp_path, capsys):
    """Not only overlapping trees: two typed names collide the same way."""
    from netredact.cli import _collisions
    assert "Only possible" not in _collisions.__doc__, \
        "the docstring claimed this could not happen"

    left = tree(tmp_path / "zone_a", {"router.cfg": CISCO_LINES})
    right = tree(tmp_path / "zone_b", {"router.cfg": CISCO_LINES})
    out = tmp_path / "clean"
    out.mkdir()

    assert main([str(left / "router.cfg"), str(right / "router.cfg"),
                 "-o", str(out)]) == EXIT_USAGE
    assert "same file" in capsys.readouterr().err
    assert list(out.iterdir()) == []


def test_a_trailing_separator_on_out_names_a_directory(fixtures, tmp_path):
    """`-o clean3/` said directory, so a regular file called clean3 is wrong.

    Said of one named file, where `-o` would otherwise be a file name: the
    separator is the whole of the evidence that a directory was meant.
    """
    dest = str(tmp_path / "clean3") + os.sep

    assert main([str(fixtures / "cisco.cfg"), "-o", dest]) == EXIT_OK
    assert (tmp_path / "clean3").is_dir()
    assert (tmp_path / "clean3" / "cisco.cfg.sanitised").exists()


def test_an_existing_out_directory_may_still_be_written_with_a_separator(
        tmp_path):
    """The separator is only wrong when the directory is not there."""
    root = tree(tmp_path / "backups", {"one.cfg": CISCO_LINES})
    out = tmp_path / "clean"
    out.mkdir()
    assert main([str(root), "-o", str(out) + os.sep]) == EXIT_OK
    assert (out / "one.cfg.sanitised").exists()


def test_an_unknown_flag_exits_usage_not_findings(capsys):
    """2 means "verification found something", so argparse may not spend it."""
    with pytest.raises(SystemExit) as exc:
        main(["--no-such-flag"])
    assert exc.value.code == EXIT_USAGE
    assert "no-such-flag" in capsys.readouterr().err


def test_help_still_exits_zero(capsys):
    """Asking for help is not a usage error."""
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == EXIT_OK
    assert "--force" in capsys.readouterr().out
