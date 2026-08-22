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

A directory argument is walked, because a backup tree is how configurations
usually arrive. The walk is deliberately more cautious than an argument you
typed: see :func:`expand`.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets as _secrets
import sys
import textwrap
from dataclasses import dataclass, replace
from pathlib import Path
from typing import NoReturn

from . import __version__, provenance
from .config import DEFAULT_CONFIG_NAMES, Config, ConfigError
from .rules import RuleCatalogue
from .sanitise import Result, sanitise_text
from .verify import check_names

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_FINDINGS = 2

#: path separators this platform accepts, for the two places that have to read
#: a path as a shape rather than open it: whether ``-o`` names a directory, and
#: whether ``--suffix`` is trying to move a file instead of rename it.
_SEPARATORS = tuple(s for s in (os.sep, os.altsep) if s)

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


class _Parser(argparse.ArgumentParser):
    """argparse, except that a usage error exits ``EXIT_USAGE``.

    argparse exits 2 of its own accord, and this program has already spent 2
    on "verification found something". A pipeline that stops the release on 2
    would read a mistyped flag as a leak report, and -- worse in the other
    direction -- a pipeline that treats 1 as a mistake and 2 as findings would
    act on a run that never happened. ``--help`` and ``--version`` are not
    errors and still exit 0.
    """

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    ap = _Parser(
        prog="netredact",
        description="Strip secrets and identifying data from Cisco, Arista, "
                    "Juniper and Fortinet configurations.",
        epilog="Configuration selects a part of the config and gives it an "
               "action: keep, pseudo, hash or redact. By default secrets are "
               "redacted and everything else is kept. Settings live in "
               f"{DEFAULT_CONFIG_NAMES[0]} -- run --print-config to get "
               "started.")
    ap.add_argument("files", nargs="*",
                    help="config files or directories to walk, or - for stdin")
    ap.add_argument("-o", "--out", metavar="PATH",
                    help="output file, or a directory -- created if missing "
                         "-- when an input is a directory or several inputs "
                         "are given")
    ap.add_argument("-c", "--config", metavar="PATH",
                    help="configuration file (default: search "
                         f"{', '.join(DEFAULT_CONFIG_NAMES)}, then "
                         "~/.config/netredact/config.toml)")
    ap.add_argument("-r", "--replace", action="store_true",
                    help="replace the inputs, i.e. write each file back over "
                         "itself")
    ap.add_argument("--force", action="store_true",
                    help="process an input netredact would otherwise refuse: "
                         "one it has already marked (a second pass re-maps "
                         "pseudonyms), a named binary or PEM file, or one that "
                         "is not valid UTF-8. Every refusal is protecting the "
                         "file, and with -r the original is already gone")
    ap.add_argument("--suffix", default=".sanitised",
                    help="suffix used when writing into an -o directory "
                         "(default: %(default)s)")
    ap.add_argument("--map-out", metavar="PATH",
                    help="write the pseudonym mapping as JSON. This file "
                         "de-anonymises the output -- never ship it alongside")
    ap.add_argument("--strict", action="store_true",
                    help=f"exit {EXIT_FINDINGS} if the verification pass finds "
                         "anything (overrides verify.strict)")
    ap.add_argument("-R", "--report", action="store_true",
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


def _problems(w, result: Result, offset: int = 0) -> bool:
    """Pool collisions and verification findings. True if anything was written.

    Factored out because these lines are the one part of the report a human
    has to see whether or not they asked for a report.

    ``offset`` shifts the printed line numbers. Verification runs on the
    sanitised body; the file that gets written has the provenance marker on
    top of it, and a line number a reader cannot trust is worse than none.
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
                shown = replace(f, line=f.line + offset) if offset else f
                w(f"    {str(shown)[:118]}\n")
        for name, n in seen.items():
            if n > 5:
                w(f"    ... and {n - 5} more [{name}]\n")
    return wrote


def problems(stream, label: str, result: Result, offset: int = 0) -> None:
    """What ``report`` says that a human must see even without ``--report``.

    Silence means a clean run, so a file with nothing to say prints nothing at
    all -- including its own name.
    """
    if not (result.collisions or result.findings):
        return
    stream.write(f"\n=== {label} ===\n")
    _problems(stream.write, result, offset)


def report(stream, label: str, result: Result, cfg: Config,
           offset: int = 0) -> None:
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

    _problems(w, result, offset)
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


@dataclass(frozen=True)
class Source:
    """One input file: where to read it, and what to call it downstream.

    ``relative`` is the name the file keeps when it is written into an ``-o``
    directory. For a file you named it is the base name, as it always was; for
    a file found by walking a directory it is the path relative to that
    directory, so a tree is mirrored rather than flattened into one heap where
    two zones' ``router1.cfg`` would land on top of each other.
    """

    path: str                              # "-" for stdin
    relative: str

    @property
    def label(self) -> str:
        """What the report and the diagnostics call this input."""
        return "<stdin>" if self.path == "-" else self.path


#: what to say about a named input netredact refuses to sanitise unasked. Both
#: verdicts are about destruction rather than taste: the file would be read as
#: text and written back as text, and under ``-r`` there is no second copy.
REFUSALS = {
    "binary": "contains a NUL byte, so it is not a configuration -- writing it "
              "back as text would corrupt it, and with -r the original is gone. "
              "Pass --force if you meant this file",
    "PEM file": "starts with -----BEGIN, so it is a PEM key or certificate -- "
                "the pem-key rule replaces exactly that body, and no key comes "
                "back from that. Pass --force if you meant this file",
}


def _is_probably_binary(path: Path) -> bool:
    """True if the file contains a NUL byte anywhere in it.

    The whole file is read rather than a window of it: an archive or a
    firmware image can open with kilobytes of plausible text and carry its
    binary payload further in, and a check that stops early rewrites exactly
    those files. Configurations are small, so reading all of one costs nothing
    worth having.

    An unreadable file is not called binary. Reporting "not a configuration"
    about a file that could not be opened would hide a permission problem
    behind a reassuring message and exit 0 with the secrets still in place;
    leaving it in the source list means the read is attempted and the real
    OSError is what gets reported.
    """
    try:
        with path.open("rb") as fh:
            while chunk := fh.read(65536):
                if b"\0" in chunk:
                    return True
    except OSError:
        return False
    return False


def _is_pem(path: Path) -> bool:
    """True if the first line with anything on it opens a PEM block.

    A private key sitting in a backup tree is text, so no NUL test will ever
    catch it -- and the ``pem-key`` rule is built to replace the body of
    exactly this shape, over the top of an ``id_rsa`` that has no other copy.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    for line in head.splitlines():
        if line.strip():
            return line.startswith(b"-----BEGIN")
    return False


def _refusal(path: Path) -> str | None:
    """Which :data:`REFUSALS` verdict this file falls under, or None.

    One place decides "netredact would destroy this rather than sanitise it",
    so the walk and a name on the command line cannot drift into disagreeing
    about the same file.
    """
    if _is_probably_binary(path):
        return "binary"
    if _is_pem(path):
        return "PEM file"
    return None


@dataclass(frozen=True)
class Skip:
    """One input that was not sanitised, and the verdict that decided it.

    The reason travels with the path instead of being turned into a message
    where the decision was made, because the verdicts are not
    interchangeable: "binary" and "PEM file" say the file would have been
    destroyed, "symlink" says the write would have landed outside the tree,
    "dot-file" says nobody meant it. A reader told only that something was
    skipped cannot tell which of those happened.
    """

    path: str
    reason: str


def _by_reason(skipped: list[Skip]) -> str:
    """Counts per verdict, then a few of the paths behind them.

    One line per skipped file would bury the run in a hundred lines about a
    ``.git`` directory; one line that counts them but names none leaves nobody
    able to check the verdict. The counts say how much was left out and the
    examples say what kind of thing it was.
    """
    counts: dict[str, int] = {}
    for skip in skipped:
        counts[skip.reason] = counts.get(skip.reason, 0) + 1
    tally = ", ".join(f"{n} {reason}" for reason, n in
                     sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
    shown = ", ".join(skip.path for skip in skipped[:3])
    return (f"{tally}\n        ({shown}"
            f"{', ...' if len(skipped) > 3 else ''})")


def _verdict(path: Path, name: str) -> str | None:
    """Why the walk will not open this file, or None to sanitise it."""
    if name.startswith("."):
        return "dot-file"
    # Asked before ``is_file``, which resolves the link and would answer for
    # the target rather than for the thing found in the tree.
    if path.is_symlink():
        return "symlink"
    if not path.is_file():
        return "not a regular file"
    return _refusal(path)


def _walk(root: Path) -> tuple[list[Source], list[Skip]]:
    """Every file under ``root``, depth-first and sorted, and what was skipped.

    A directory argument is an instruction to find the configurations, so the
    walk skips what plainly is not one: dot-prefixed names (``.git``,
    ``.DS_Store``), symlinks, anything that is not a regular file, binaries
    and PEM blocks. Extensions are deliberately not filtered -- a RANCID
    repository names its files after the devices, with no extension at all.

    A symlink is skipped whichever kind it is, and neither half of that is
    ``os.walk``'s doing. A directory link is not descended into, so a link
    back up the tree cannot loop.

    A file link is not sanitised either, for two reasons that outlived the
    first one. Writes go through :func:`os.replace` now, so ``--replace`` no
    longer writes *through* a link into a file outside the tree -- it replaces
    the link itself with a regular file, which quietly destroys the structure
    somebody built the tree with. And a link pointing back inside the tree
    would be sanitised twice in one run, once under each name, which for
    ``pseudo`` is not idempotent: the second pass re-maps the first pass's
    substitutes.
    """
    found: list[Source] = []
    skipped: list[Skip] = []
    for dirpath, dirnames, filenames in os.walk(root):
        keep: list[str] = []
        for name in sorted(dirnames):
            if name.startswith("."):
                continue                   # pruned whole, not counted per file
            path = Path(dirpath) / name
            if path.is_symlink():
                skipped.append(Skip(str(path), "symlink"))
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            path = Path(dirpath) / name
            reason = _verdict(path, name)
            if reason:
                skipped.append(Skip(str(path), reason))
                continue
            found.append(Source(str(path), str(path.relative_to(root))))
    return found, skipped


def expand(paths: list[str], *,
           refuse_named: bool = False) -> tuple[list[Source], list[Skip], list[Skip]]:
    """Command-line arguments to the list of files to sanitise.

    A directory is walked; anything else is taken exactly as given, including
    a path that does not exist. That asymmetry is the point: an argument you
    typed is always attempted, and a failure to read it is reported against
    the name you used. Only the walk gets to decide that a text file is not
    worth opening, because only the walk chose it.

    A named file can still be one netredact would wreck rather than sanitise,
    and with ``refuse_named`` those go in the third list instead of being
    attempted. ``netredact backups/* -r`` arrives here as a list of typed
    names, because the shell expanded the glob before netredact could see it
    and nothing here can tell the two apart; without this a JPEG in that
    directory is silently destroyed. A refusal is not a skip: the caller named
    the file and is owed an error about it.

    ``refuse_named`` is set only when the run would write over its input,
    because that is the whole of the harm. Overriding a name costs something:
    a file that opens with a PEM header may be a key, or it may be a config
    fragment somebody pasted a certificate into, and netredact cannot tell --
    so where the original survives the write, the name is honoured and the
    caller gets what they asked for. A walked tree is different and refuses
    both regardless: the walk chose the file, so nothing was asked for.
    """
    sources: list[Source] = []
    skipped: list[Skip] = []
    refused: list[Skip] = []
    for path in paths:
        if path != "-" and os.path.isdir(path):
            found, ignored = _walk(Path(path))
            sources += found
            skipped += ignored
            continue
        reason = (_refusal(Path(path))
                  if refuse_named and path != "-" else None)
        if reason:
            refused.append(Skip(path, reason))
        else:
            sources.append(Source(path, os.path.basename(path)))
    return sources, skipped, refused


def _mirroring(args) -> bool:
    """Whether ``-o`` names a directory to mirror the inputs into.

    Four things say it does, and every one of them is visible before a file is
    read: the directory is already there, an input is a directory, more than
    one input was named, or the path ends in a separator. In each case ``-o``
    cannot be a file name -- a tree does not fit in one file -- so a path that
    is not there yet is a directory to create rather than a mistake to report.

    The evidence is read off the command line and never off the walk. Counting
    the files the walk happened to find would make the answer depend on the
    contents of the directory: ``-o clean`` against a tree of one config would
    write a regular file called ``clean`` today and mirror a tree tomorrow,
    once a second config landed in it.

    One named file with one ``-o`` path is the only ambiguous case, and there
    ``-o`` stays a file name: nothing is invented to satisfy a typo.
    """
    if not args.out:
        return False
    return (os.path.isdir(args.out)
            or args.out.endswith(_SEPARATORS)
            or len(args.files) > 1
            or any(p != "-" and os.path.isdir(p) for p in args.files))


def _destination(args, src: Source, *, mirror: bool) -> str | None:
    """Where a given input should be written. None means stdout."""
    if args.replace and src.path != "-":
        return src.path
    if mirror:
        return os.path.join(args.out, src.relative + args.suffix)
    if args.out:
        return args.out
    return None


def _mirrored(args, src: Source, *, mirror: bool) -> bool:
    """Whether this input's destination is a path built inside an ``-o`` dir.

    The distinction the write needs: only in this case may missing parent
    directories be created. A file found by walking carries the zone
    directories it was found in, and mirroring the tree means building them
    under ``-o`` -- including ``-o`` itself, which is why a named-but-absent
    output directory costs no `mkdir` of its own here. A single ``-o`` path is
    a name, and a name with a typo in it is a mistake to report rather than a
    directory tree to invent.
    """
    if args.replace and src.path != "-":
        return False
    return mirror


def _write(dest: Path, payload: str, *, mirrored: bool) -> None:
    """Write one output file, all of it or none of it.

    Through a temporary file in the same directory and then :func:`os.replace`,
    which is atomic on every platform netredact runs on. A plain write
    truncates first, so an interruption -- a full disk, a signal -- leaves a
    half-written file where, under ``--replace``, that file was the only copy
    of the configuration. The temporary is removed if anything fails, so a
    failed run does not litter the tree it was walking.

    Parent directories are created only for a mirrored tree, where making them
    is what mirroring means. A typo in a single ``-o`` path is not an
    instruction to build a directory chain.
    """
    if mirrored:
        dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".netredact-tmp")
    try:
        tmp.write_bytes(payload.encode("utf-8"))
        os.replace(tmp, dest)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def _collisions(args, sources: list[Source], *, mirror: bool) -> list[str]:
    """Destinations that two inputs would both write to.

    Several directory arguments mirrored into one ``-o`` directory whose trees
    overlap is the case that motivated the check, but two files named on the
    command line collide the same way as soon as they share a base name:
    ``zone_a/router.cfg`` and ``zone_b/router.cfg`` both become
    ``router.cfg.sanitised``, and until this check existed the second one
    silently overwrote the first. Worth a usage error rather than a silent
    overwrite: the file that loses is gone.
    """
    seen: dict[str, str] = {}
    clashes: list[str] = []
    for src in sources:
        dest = _destination(args, src, mirror=mirror)
        if dest is None or args.replace:
            continue
        if dest in seen and seen[dest] != src.path:
            clashes.append(f"{seen[dest]} and {src.path} -> {dest}")
        seen[dest] = src.path
    return clashes


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

    # A directory has to say where its files go. Without a destination every
    # config in the tree would be concatenated onto stdout, which is never
    # what anyone meant by naming the directory.
    dirs = [p for p in args.files if p != "-" and os.path.isdir(p)]
    if dirs and not (args.replace or args.out):
        print(f"netredact: {dirs[0]} is a directory -- add -r to replace the "
              "files in place, or -o DIR to write the sanitised tree "
              "elsewhere", file=sys.stderr)
        return EXIT_USAGE
    if args.replace and args.out:
        print("netredact: -r and -o both name a destination -- use one",
              file=sys.stderr)
        return EXIT_USAGE
    # The suffix names the file; it does not get to say where the file goes.
    # `--suffix /../../escaped.cfg` is concatenated onto the destination path
    # and the write then creates whatever parents that resolves to, which puts
    # output anywhere on the filesystem and on top of whatever is there.
    if any(s in args.suffix for s in _SEPARATORS):
        print(f"netredact: --suffix {args.suffix!r} contains a path separator "
              "-- the suffix renames the file inside the -o directory, it "
              "cannot move it elsewhere", file=sys.stderr)
        return EXIT_USAGE

    # Only a run that overwrites its input can destroy one, so that is the
    # only run that overrules a name the caller typed.
    sources, skipped, refused = expand(
        args.files, refuse_named=args.replace and not args.force)
    if skipped:
        print(f"netredact: skipped {len(skipped)} file(s) while walking: "
              f"{_by_reason(skipped)}", file=sys.stderr)
    for skip in refused:
        print(f"netredact: {skip.path}: {REFUSALS[skip.reason]}",
              file=sys.stderr)
    if not sources:
        # A refusal has already said, by name, why there is nothing to do.
        if not refused:
            print(f"netredact: no files found in {', '.join(args.files)}",
                  file=sys.stderr)
        return EXIT_USAGE
    # A directory argument is answered with a tree, and a tree cannot be
    # written into a single file, so `-o` there can only be a directory: it is
    # created on the first write, the same way and at the same moment as the
    # zone directories underneath it. What counts as naming a directory is
    # decided from the command line alone -- see _mirroring.
    mirror = _mirroring(args)
    # Only an existing regular file can still refuse the run, and it has to be
    # said here: found at write time it would be one message per file, after
    # the first of them had already been sanitised for nothing.
    if mirror and os.path.exists(args.out) and not os.path.isdir(args.out):
        print(f"netredact: -o {args.out} is a file, and this run writes a "
              "tree -- name a directory, or drop the extra inputs to write "
              "one file", file=sys.stderr)
        return EXIT_USAGE
    clashes = _collisions(args, sources, mirror=mirror)
    if clashes:
        print("netredact: two inputs would be written to the same file:\n  "
              + "\n  ".join(clashes[:5]), file=sys.stderr)
        return EXIT_USAGE

    strict = args.strict or cfg.verify.strict
    try:
        salt = load_salt(cfg)
    except OSError as exc:
        print(f"netredact: cannot use salt file: {exc}", file=sys.stderr)
        return EXIT_USAGE

    # A refused input has already been reported by name. The run still covers
    # the inputs that are safe to touch, and still fails at the end, so the
    # exit code says something was left undone -- the same bargain as an
    # already-marked file found in a tree.
    rc = EXIT_USAGE if refused else EXIT_OK
    mappings: dict[str, dict] = {}

    for src in sources:
        label = src.label
        crlf = False
        if src.path == "-":
            text = sys.stdin.read()
        else:
            try:
                raw = Path(src.path).read_bytes()
            except OSError as exc:
                print(f"netredact: {exc}", file=sys.stderr)
                rc = EXIT_USAGE
                continue
            # Decoded here rather than by read_text so the file can be written
            # back the way it arrived. errors="replace" turns an undecodable
            # byte into U+FFFD and universal newlines drop every CR: both are
            # edits to material netredact was never asked to touch, made
            # without saying so, and under -r they land in the only copy.
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                if not args.force:
                    print(f"netredact: {label}: not valid UTF-8 ({exc.reason} "
                          f"at byte {exc.start}) -- sanitising it would replace "
                          "every byte that cannot be decoded. Convert the file, "
                          "or pass --force to accept that", file=sys.stderr)
                    rc = EXIT_USAGE
                    continue
                text = raw.decode("utf-8", errors="replace")
            # The rules and the verifier work a line at a time, so CRLF input
            # is normalised for them and the endings are put back on the way
            # out; what is remembered here is only whether to put them back.
            crlf = b"\r\n" in raw
            if crlf:
                text = text.replace("\r\n", "\n")

        # Refuse netredact's own output. Checked before sanitising rather
        # than after, so a tree of already-clean files costs one scan each and
        # nothing is written on the way to finding out.
        if provenance.is_marked(text) and not args.force:
            print(f"netredact: {label}: already sanitised by netredact -- a "
                  "second pass would re-map pseudonyms and cannot be undone. "
                  "Sanitise the original, or pass --force", file=sys.stderr)
            rc = EXIT_USAGE
            continue

        try:
            result = sanitise_text(text, cfg, salt=salt)
        except (ValueError, ConfigError) as exc:
            print(f"netredact: {label}: {exc}", file=sys.stderr)
            return EXIT_USAGE

        # The marker goes on here rather than inside sanitise_text: it is a
        # property of the file being handed over, and the transformation
        # promises not to change the line count.
        text_out = (provenance.apply_text(result.text, result.vendor, __version__)
                    if cfg.marker else result.text)
        offset = 1 if text_out != result.text else 0

        # The endings the file arrived with go back on. A CRLF configuration
        # handed back LF-only has been rewritten in a way nobody asked for,
        # and the bytes are written as bytes so no layer underneath gets a
        # second opinion about newlines.
        payload = text_out.replace("\n", "\r\n") if crlf else text_out

        dest = _destination(args, src, mirror=mirror)
        if dest is None:
            sys.stdout.write(payload)
            shown = "<stdout>"
        else:
            try:
                _write(Path(dest), payload,
                       mirrored=_mirrored(args, src, mirror=mirror))
            except OSError as exc:
                # One unwritable file must not end the run. A tree abandoned
                # part-way is the worst outcome available: some files replaced,
                # some not, and no statement of which -- and a traceback here
                # would break the promise that an exit code is always explained.
                print(f"netredact: {exc}", file=sys.stderr)
                rc = EXIT_USAGE
                continue
            shown = dest

        if args.report:
            report(sys.stderr, f"{label} -> {shown}", result, cfg, offset)
        else:
            problems(sys.stderr, f"{label} -> {shown}", result, offset)
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
