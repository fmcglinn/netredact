"""Command line interface.

Deliberately small: everything tunable lives in the configuration file, so
this handles files, destinations and reporting only.

``--report`` is written for the moment before you paste a config into a
ticket, so it says three things: the effective policy, what was changed, and
what netredact never looks at. It is off by default -- the common case is a
pipeline that wants the output and the exit code and nothing else.

Problems are not part of that bargain. Pool collisions and verification
findings always go to stderr, so a silent run means a clean run and an exit
code never arrives unexplained. Every diagnostic this module writes goes to
stderr; stdout carries sanitised configuration and nothing else. Nothing
outside this module prints -- the library returns findings on the ``Result``
and leaves reporting to the caller.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets as _secrets
import sys
import textwrap
from pathlib import Path

from . import __version__
from .config import DEFAULT_CONFIG_NAMES, Config, ConfigError
from .rules import RuleCatalogue
from .sanitise import Result, sanitise_text
from .verify import check_names

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_FINDINGS = 2

#: what to call a count key in the report. Rules not listed keep their rule
#: name, which is what you would put in its family's section.
LABELS = {
    "ipv4": "ipv4 addresses",
    "ipv6": "ipv6 addresses",
    "macs": "MAC addresses",
    "hostnames": "hostnames",
    "domains": "domain names",
    "usernames": "usernames",
    "emails": "e-mail addresses",
    "description": "descriptions",
    "interface-description": "interface descriptions",
    "vlan-name": "VLAN names",
    "acl-remark": "ACL remarks",
    "login-message": "login messages",
    "banner": "banners",
    "location": "locations",
    "contact": "contacts",
    "junos-location-body": "location details",
    "serial-number": "serial numbers",
    "license-udi": "license UDIs",
    "snmp-engineid": "SNMP engine IDs",
    "ssh-public-key": "SSH public keys",
    "hardware-model": "hardware models",
    "os-version": "software versions",
    "software-image": "software images",
    "boot-image": "boot images",
    "certificate-block": "certificates",
    "pem-cert": "PEM certificates",
    "key-string-block": "key-string blocks",
    "pem-key": "PEM private keys",
}

def label_for(key: str, family: str) -> str:
    """What to print for a count key.

    A whole family gets its plural English name; a named rule keeps its rule
    name unless a friendlier plural is worth having, because the rule name is
    what you would write in its family's section.
    """
    return LABELS.get(key, key if key != family else family)


def _grouped(counts, families: dict[str, str]) -> dict[str, list[str]]:
    """family -> its count keys, most-hit first."""
    out: dict[str, list[str]] = {}
    for key in sorted(counts, key=lambda k: (-counts[k], k)):
        out.setdefault(families.get(key, "secrets"), []).append(key)
    return out


def _joined(keys: list[str], family: str, width: int = 56) -> str:
    """Count keys as one comma-separated list, truncated with an ellipsis."""
    shown: list[str] = []
    used = 0
    for key in keys:
        name = label_for(key, family)
        if shown and used + len(name) + 2 > width:
            return ", ".join(shown) + " ..."
        shown.append(name)
        used += len(name) + 2
    return ", ".join(shown)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="netredact",
        description="Strip secrets and identifying data from Cisco, Arista and "
                    "Juniper configurations.",
        epilog="Configuration selects a part of the config and gives it an "
               "action: keep, pseudo, hash or redact. By default secrets are "
               "redacted and everything else is kept. Settings live in "
               f"{DEFAULT_CONFIG_NAMES[0]} -- run --print-config to get "
               "started.")
    ap.add_argument("files", nargs="*", help="config files, or - for stdin")
    ap.add_argument("-o", "--out", metavar="PATH",
                    help="output file, or a directory when several inputs are given")
    ap.add_argument("-c", "--config", metavar="PATH",
                    help="configuration file (default: search "
                         f"{', '.join(DEFAULT_CONFIG_NAMES)}, then "
                         "~/.config/netredact/config.toml)")
    ap.add_argument("--in-place", action="store_true", help="overwrite the inputs")
    ap.add_argument("--suffix", default=".sanitised",
                    help="suffix used when writing into an -o directory "
                         "(default: %(default)s)")
    ap.add_argument("--map-out", metavar="PATH",
                    help="write the pseudonym mapping as JSON. This file "
                         "de-anonymises the output -- never ship it alongside")
    ap.add_argument("--strict", action="store_true",
                    help=f"exit {EXIT_FINDINGS} if the verification pass finds "
                         "anything (overrides verify.strict)")
    ap.add_argument("--report", "-r", action="store_true",
                    help="print the per-file report (policy, changes and the "
                         "verification result) to stderr")
    ap.add_argument("--print-config", action="store_true",
                    help="write a fully commented default config to stdout and exit")
    ap.add_argument("--list-rules", action="store_true",
                    help="list every rule with its family, and every "
                         "verification check, then exit")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    return ap


def load_salt(cfg: Config) -> bytes:
    path = cfg.salt_path()
    if path is None:
        return _secrets.token_bytes(32)
    if path.exists():
        return path.read_bytes().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    salt = _secrets.token_hex(32).encode()
    path.write_bytes(salt)
    path.chmod(0o600)
    print(f"created salt file {path} (mode 600) -- it is a re-identification "
          f"key, keep it private", file=sys.stderr)
    return salt


def _problems(w, result: Result) -> bool:
    """Pool collisions and verification findings. True if anything was written.

    Factored out because these lines are the one part of the report a human
    has to see whether or not they asked for a report.
    """
    wrote = False
    if result.collisions:
        wrote = True
        sample = ", ".join(sorted(result.collisions)[:4])
        w(f"  WARNING: {len(result.collisions)} real address(es) were kept that fall\n"
          f"        inside a pseudonym pool ({sample}...). In the output they cannot\n"
          f"        be told apart from generated ones. Change [ipv4] pool /\n"
          f"        [ipv6] pool, or act on the class so that space moves too.\n")

    if result.findings:
        wrote = True
        w(f"  VERIFY: {len(result.findings)} line(s) a human should look at\n")
        seen: dict[str, int] = {}
        for f in result.findings:
            seen[f.check] = seen.get(f.check, 0) + 1
            if seen[f.check] <= 5:
                w(f"    {str(f)[:118]}\n")
        for name, n in seen.items():
            if n > 5:
                w(f"    ... and {n - 5} more [{name}]\n")
    return wrote


def problems(stream, label: str, result: Result) -> None:
    """What ``report`` says that a human must see even without ``--report``.

    Silence means a clean run, so a file with nothing to say prints nothing at
    all -- including its own name.
    """
    if not (result.collisions or result.findings):
        return
    stream.write(f"\n=== {label} ===\n")
    _problems(stream.write, result)


def report(stream, label: str, result: Result, cfg: Config) -> None:
    w = stream.write
    w(f"\n=== {label}  (vendor: {result.vendor}) ===\n")
    for line in textwrap.wrap(f"policy: {result.policy_summary}", width=76,
                              initial_indent="  ", subsequent_indent="          ",
                              break_long_words=False, break_on_hyphens=False):
        w(line + "\n")

    for section in result.removed_sections:
        w(f"  collection: removed {section.lines} line(s) "
          f"[{section.command}]\n")

    if result.counts:
        w("  changes:\n")
        groups = _grouped(result.counts, result.families)
        for family, keys in sorted(
                groups.items(), key=lambda kv: -sum(result.counts[k] for k in kv[1])):
            total = sum(result.counts[k] for k in keys)
            w(f"    {total:6d}  {_joined(keys, family)}\n")
    elif result.removed_sections:
        w("  changes: no value substitutions after collection preprocessing\n")
    else:
        w("  changes: NONE -- is this really a device configuration?\n")

    _problems(w, result)
    if not result.findings and cfg.verify.enabled:
        w("  VERIFY: clean (policy applied, no credential-shaped material left)\n")
    # VLAN names used to head this list. They have a section now -- [vlans] --
    # so they are no longer out of reach, only kept by default like everything
    # else the policy line already accounts for.
    w("  NOTE: interface numbering and unsupported vendor grammar are never scrubbed.\n"
      "  WARNING: netredact reduces exposure; it does not guarantee anonymisation.\n"
      "        Network configurations may retain identifying or confidential\n"
      "        material in unsupported syntax or relationships. Review every\n"
      "        output; you decide whether it is safe and lawful to share.\n")


def _destination(args, label: str, path: str) -> str | None:
    """Where a given input should be written. None means stdout."""
    if args.in_place and path != "-":
        return path
    if args.out and os.path.isdir(args.out):
        return os.path.join(args.out, os.path.basename(label) + args.suffix)
    if args.out:
        return args.out
    return None


def list_rules() -> None:
    """Every rule with its family, then every verification check."""
    print('rules (set one by name in its family\'s section, e.g. '
          '[text] location = "hash"):')
    print(f"  {'rule':24} {'section':12} {'dialect':9} where it applies")
    for info in RuleCatalogue.builtins().inventory():
        extra = (f"[stanza: {info.required_scope}]"
                 if info.required_scope else "")
        for out in info.excluded_scopes:
            extra += f"[outside: {out}]"
        print(f"  {info.name:24} {info.family:12} "
              f"{(info.vendor or ''):9} {extra}".rstrip())
    print("\nA rule's action comes from one place: the section named above,"
          "\nwhich either names the rule or falls back to that section's"
          "\n`default`. The family also decides how the replacement renders.")
    print("\n`dialect` is a label, not a filter: every rule is applied to every"
          "\nfile. A rule is held to one vendor's grammar by its pattern and by"
          "\nthe block it has to be inside -- evidence in the file -- and never"
          "\nby what the vendor detector guessed the file was.")
    print("\nverification checks (disable by name in verify.disable):")
    for name in check_names():
        print(f"  {name}")


def main(argv=None) -> int:
    """Entry point. Wraps :func:`run` so a closed pipe is not a crash.

    ``netredact config | head`` closes stdout while we are still writing it.
    That is the reader saying "enough", not a failure, so it exits cleanly --
    but stdout has to be pointed at the null device first, or the interpreter
    tries to flush the dead pipe on the way out and prints its own traceback
    from a place we can no longer catch.
    """
    try:
        rc = run(argv)
        sys.stdout.flush()
        return rc
    except BrokenPipeError:
        _mute_stdout()
        return EXIT_OK


def _mute_stdout() -> None:
    """Point stdout at the null device so the shutdown flush cannot fail.

    The descriptor is asked for first and closed afterwards: opening it inside
    the ``dup2`` call would leak it whenever ``fileno`` is the thing that
    raises, which is every in-process caller whose stdout is not a real file.
    """
    try:
        fd = sys.stdout.fileno()
    except (OSError, ValueError):        # stdout may not be a real fd
        return
    null = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(null, fd)
    except OSError:
        pass
    finally:
        os.close(null)


def run(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        list_rules()
        return EXIT_OK

    if args.print_config:
        sys.stdout.write(Config().to_toml())
        return EXIT_OK

    try:
        cfg = Config.load(args.config) if args.config else Config.load()
    except ConfigError as exc:
        print(f"netredact: config error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not args.files:
        build_parser().print_usage(sys.stderr)
        print("netredact: no input files given", file=sys.stderr)
        return EXIT_USAGE
    if len(args.files) > 1 and args.out and not os.path.isdir(args.out):
        print("netredact: -o must be an existing directory when several files "
              "are given", file=sys.stderr)
        return EXIT_USAGE

    strict = args.strict or cfg.verify.strict
    try:
        salt = load_salt(cfg)
    except OSError as exc:
        print(f"netredact: cannot use salt file: {exc}", file=sys.stderr)
        return EXIT_USAGE

    rc = EXIT_OK
    mappings: dict[str, dict] = {}

    for path in args.files:
        if path == "-":
            text, label = sys.stdin.read(), "<stdin>"
        else:
            try:
                text = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                print(f"netredact: {exc}", file=sys.stderr)
                rc = EXIT_USAGE
                continue
            label = path

        try:
            result = sanitise_text(text, cfg, salt=salt)
        except (ValueError, ConfigError) as exc:
            print(f"netredact: {label}: {exc}", file=sys.stderr)
            return EXIT_USAGE

        dest = _destination(args, label, path)
        if dest is None:
            sys.stdout.write(result.text)
            shown = "<stdout>"
        else:
            Path(dest).write_text(result.text, encoding="utf-8")
            shown = dest

        if args.report:
            report(sys.stderr, f"{label} -> {shown}", result, cfg)
        else:
            problems(sys.stderr, f"{label} -> {shown}", result)
        if result.findings and strict:
            rc = EXIT_FINDINGS
        mappings[label] = result.mapping

    if args.map_out:
        p = Path(args.map_out)
        p.write_text(json.dumps(mappings, indent=2, sort_keys=True, default=list),
                     encoding="utf-8")
        p.chmod(0o600)
        print(f"wrote the re-identification map to {p} (mode 600) -- this file "
              f"undoes the pseudonymising, keep it out of any share",
              file=sys.stderr)
    return rc
