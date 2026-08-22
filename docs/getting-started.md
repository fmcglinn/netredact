# Getting started

## Install

```bash
pip install netredact
```

Python 3.11 or newer. No runtime dependencies — standard library only, which
also means it is safe to run on a jump host with no package access.

## First run

```bash
netredact running-config.txt
```

That prints the sanitised configuration to stdout and nothing else. Add
`--report` for a summary of what it did:

```bash
netredact running-config.txt --report > clean.txt   # report on your terminal
```

The report goes to stderr, so a redirect separates the two cleanly.

Other destinations:

```bash
netredact configs/*.txt -o clean/             # a directory, one file each
netredact config.txt -o clean.txt             # a single named file
netredact config.txt -r                       # replace the input
cat config.txt | netredact -                  # stdin
```

## Walking a directory

An argument may be a directory, which is how a backup tree usually arrives:

```bash
netredact backups/ -r                         # every config in the tree, replaced
netredact backups/ -o clean/                  # same tree under clean/
```

A directory has to say where its output goes. `netredact backups/` on its own
is a usage error rather than 101 configurations concatenated onto your
terminal:

```
netredact: backups/ is a directory -- add -r to replace the files in place,
or -o DIR to write the sanitised tree elsewhere
```

The walk is recursive, depth-first and sorted, so a run is reproducible. It is
also deliberately choosier than an argument you typed, because a tree contains
things that are not configurations:

- dot-prefixed names are skipped, and a dot-directory is pruned whole rather
  than descended into, so `.git/`, `.svn/` and `.DS_Store` are left alone;
- symlinks are skipped, both kinds. A directory link is never descended into,
  so a link back up the tree cannot send the walk round in circles; a file link
  is never sanitised, because its target is either another file in the tree —
  which would then be sanitised twice, and `pseudo` is not idempotent — or a
  file outside the tree you named;
- a file with a NUL byte **anywhere** in it is skipped as binary. The whole
  file is read rather than a window of it, because an archive or a firmware
  image can open with kilobytes of plausible text and carry its payload much
  further in. Sanitising one would rewrite it as text — and under `-r` that is
  not a bad output, it is a destroyed file;
- a file whose first non-blank line starts with `-----BEGIN` is skipped as a
  PEM key or certificate. A private key sitting in a backup tree is text, so no
  NUL test will ever reach it, and the `pem-key` rule replaces exactly that
  body — over the top of an `id_rsa` that has no other copy;
- anything that is not a regular file at all is skipped;
- extensions are **not** filtered. A RANCID repository names its files after
  the devices, with no extension at all.

What the walk left out is counted on stderr: the verdicts with a count each,
then a few of the paths behind them, so you can check the decision without
being buried in one line per file.

```
netredact: skipped 6 file(s) while walking: 2 PEM file, 2 symlink, 1 binary, 1 dot-file
        (backups/linkdir, backups/.DS_Store, backups/link.cfg, ...)
```

That count is not an inventory of the tree, and cannot be: a dot-directory is
pruned as a unit, so the hundreds of files inside `.git/` are never opened,
never counted and never named. What the count covers is every decision the walk
made file by file.

Under `-o`, the tree is mirrored rather than flattened — `backups/nsw/rtr1.cfg`
becomes `clean/nsw/rtr1.cfg.sanitised` — so two zones' identically named files
cannot land on top of each other. Missing zone directories are created under
`-o`, since that is what mirroring means, and so is `-o` itself when it is not
there yet: a directory argument is answered with a tree, however few files the
walk finds in it, and a tree does not fit in one file, so `-o` there can only be
a directory. The same goes for any run with more than one file to write, and for
`-o clean/` — the trailing separator is a statement that the destination is a
directory, even where one named file would otherwise make `-o` a file name.

What decides this is the command line, never the walk. Deciding it on the number
of files found would make it depend on the contents of the directory — the
command that wrote a file called `clean` today would mirror a tree into it
tomorrow, once a second config landed. One named file with one `-o` path is the
only case where `-o` is a file name, and there nothing is invented: `-o
deep/ly/nested/out.txt` with a typo in it is reported, not built. A run that
does write a tree is refused, before it writes anything, if `-o` is there
already as a regular file. And if two directory arguments would collide on one
destination, that is a usage error too, not a silent overwrite.

One invocation is one salt, so pseudonyms are consistent across the whole tree:
`core-rtr-01` becomes the same `device-…` in every file. Splitting the tree
over several runs re-rolls it, unless you set `salt_file` (see the
[configuration reference](configuration.md)).

The tree's **file and directory names are never touched** — only contents. A
path like `backups/zone_NSW/backup_device_10.1.2.3.txt` still carries the zone
and the management address after a clean `-r` run.

`-r` overwrites the input, so the original is gone. netredact marks what it
writes and refuses to sanitise a marked file twice — see
[running it twice](#running-it-twice) — but on a tree you cannot re-fetch from
the devices, prefer `-o DIR`.

## When netredact refuses a file

A file you name on the command line is treated differently from one the walk
found, because you named it. A dot-file, a symlink or an extensionless file
passed as an argument is simply processed: only the walk gets to decide that a
file it chose is not worth opening.

The exception is destruction. Under `-r` a named binary or PEM file is refused,
because that is the one case where rewriting it as text leaves nothing to go
back to:

```
netredact: img.bin: contains a NUL byte, so it is not a configuration -- writing
it back as text would corrupt it, and with -r the original is gone. Pass --force
if you meant this file
```

With `-o` or stdout the harm does not exist — the original is still on disk —
so the name you typed wins and the file is processed. That asymmetry is what
separates naming a directory from globbing it: `netredact backups/* -r` arrives
as a list of typed names, because the shell expanded the glob before netredact
could see it and nothing downstream can tell the two apart. So the glob gets
the binary and PEM refusals and none of the walk's other caution — a symlink in
the expansion is written like any other name. Name the directory and you get
the whole walk.

Input must be valid UTF-8. Otherwise netredact says so, that file is skipped
and the run exits `1`:

```
netredact: latin1.cfg: not valid UTF-8 (invalid continuation byte at byte 10) --
sanitising it would replace every byte that cannot be decoded. Convert the file,
or pass --force to accept that
```

Decoding it anyway turns each undecodable byte into U+FFFD, and under `-r` that
lands in your only copy — an edit to material netredact was never asked to
touch, made without saying so. Convert the file, or pass `--force` to accept
the substitution.

`--force` is the single override for all of this: it means *process an input
netredact would otherwise refuse* — a file it has already marked (see
[running it twice](#running-it-twice)), a named binary or PEM file under `-r`,
or input that is not valid UTF-8. Every one of those refusals is protecting the
file, so reach for `--force` when you know which one you are overruling.

Line endings survive: a configuration that arrives with CRLF is written back
with CRLF. The rules and the verifier work a line at a time, so the endings are
normalised for them and put back on the way out.

Two things that are **not** skips, because treating them as skips would hide
them behind a clean exit code:

- an input netredact cannot read is an error carrying the real reason, and the
  run exits `1`. Calling it "not a configuration" would report success on a
  file whose secrets are still in place;

  ```
  netredact: [Errno 13] Permission denied: 'secret.cfg'
  ```

- an output netredact cannot write is reported the same way, and the rest of
  the run still happens. A tree abandoned half-way is the worst outcome
  available — some files replaced, some not, and no statement of which — so the
  failure is named, the exit code is `1`, and every other file is processed.

Each file is written through a temporary in the same directory and then moved
into place, so a full disk or a signal cannot leave a half-written
configuration where, under `-r`, that file was the only copy. Nothing is left
behind either way: a `.netredact-tmp` never survives a failure.

## Reading the report

`--report` is off by default: a *clean* run says nothing, so netredact drops
into a pipeline without polluting it. Turn it on whenever a human is looking.

Problems are not part of that bargain. Verification findings and pool-collision
warnings always go to stderr, `--report` or not, so an exit code never arrives
unexplained. Silence means clean.

This is the whole report for one of the test fixtures, at stock defaults:

```
=== running-config.txt -> <stdout>  (vendor: cisco) ===
  policy: secrets=redact, everything else kept
  changes:
        19  username-secret, enable-secret, encoded-key ...
  VERIFY: clean (policy applied, no credential-shaped material left)
  NOTE: interface numbering and unsupported vendor grammar are never scrubbed.
  WARNING: netredact reduces exposure; it does not guarantee anonymisation.
        Network configurations may retain identifying or confidential
        material in unsupported syntax or relationships. Review every
        output; you decide whether it is safe and lawful to share.
```

Three things to read:

- **policy** — your configuration in one line. If this does not say what you
  meant, nothing below it matters. At defaults it ends `everything else kept`,
  which is the whole caveat: only credentials were acted on, and every address,
  hostname, username and customer description is still in the output.
- **changes** — what was substituted, by rule or family name.  If it says
  `NONE`, the file probably is not a device configuration.
- **VERIFY** — the output pass. `clean` means nothing *known* was left behind.
  See [verification](verification.md) for what that does and does not promise.

The report does not enumerate what was *kept*. If you want that breakdown —
counts per rule and family, to work down as a file needs to travel further from
the business — `Result.kept_counts` carries it; see [library](library.md).

A count is per *value*, not per line: a certificate block or a multi-line
banner is one value however many lines it spans.

## Choosing how much to strip

Start from the destination, not from the options. Copy the closest
[example](examples/) and adjust.

| Where is it going | Profile | Reasoning |
|---|---|---|
| A colleague, your own ticket system | [`01-secrets-only`](examples/01-secrets-only.toml) | Credentials gone, everything else readable and diffable against the device. |
| Vendor TAC, under support contract | [`02-vendor-support`](examples/02-vendor-support.toml) | They need real addressing, descriptions and the serial number. Credentials, the banner and personal contact details go. |
| Contractor, consultant, auditor | [`03-external-review`](examples/03-external-review.toml) | Design stays legible; nothing ties the file to you or your subscribers. |
| A hosted language model | [`04-llm-analysis`](examples/04-llm-analysis.toml) | Addresses pseudonymised rather than destroyed, so subnet and ACL logic still holds. |
| Mailing list, forum, blog, slide | [`05-public-publication`](examples/05-public-publication.toml) | Indexed and unrecallable. Free text and device identity destroyed outright. |

Then:

```bash
netredact --print-config > netredact.toml     # or copy an example
netredact running-config.txt                  # picks it up automatically
netredact running-config.txt -c docs/examples/03-external-review.toml --report
```

The same fixture under `03-external-review` — same file, different policy:

```
  policy: secrets=redact, text=hash, locations=hash, identity=hash,
          platform=keep (per rule), interfaces=hash, vlans=pseudo,
          circuits=pseudo, domains=pseudo, usernames=pseudo, emails=hash,
          ipv4=keep (per class), ipv6=keep (per class), macs=keep/pseudo,
          everything else kept
  changes:
        19  username-secret, enable-secret, encoded-key ...
         5  ipv4 addresses
         5  usernames
         3  ACL remarks, banners, contacts
         2  interface descriptions
         2  ipv6 addresses
         1  certificates
         1  domain names
         1  locations
         1  MAC addresses
  VERIFY: clean (policy applied, no credential-shaped material left)
```

Eight addresses are still untouched — the ones that profile left at `keep`:
five in documentation space, two public resolvers and one RFC1918 address. The
hostname is deliberate too — site and role naming is how the design reads.

## Turning one rule off

When a built-in rule is wrong for your environment, do not fight it — give it
the `keep` action by name, in its own family's section:

```toml
[text]
default  = "hash"
[locations]
location = "keep"        # this fleet's location lines hold a rack label
```

`netredact --list-rules` prints every rule name next to the section it belongs
to. A kept rule still matches — it is counted in `Result.kept_counts` — it
simply is not substituted.

## Fleet-consistent output

Set `salt_file` and the same real value maps to the same substitute in every run
and every file. `128.66.16.20` becomes the same fake address on all forty
devices, so the topology still makes sense across a bundle.

```toml
salt_file = "~/.config/netredact/salt"
```

The file is created `0600` on first use.

> **The salt file is a re-identification key.** So is anything written by
> `--map-out`. Keep both out of whatever you are sharing. Without the salt,
> substitutes are fresh every run and nobody can correlate two bundles; with it,
> anyone holding the file can undo the mapping.

## Running it twice

Every file netredact writes carries one comment line at the top naming the
tool — `!` in IOS-style grammar, `#` in JunOS:

```
! netredact-sanitised 0.1.0 -- sanitised output, not a device configuration; re-run from the original
```

That line is there so the second run can be **refused**:

```
netredact: clean.txt: already sanitised by netredact -- a second pass would
re-map pseudonyms and cannot be undone. Sanitise the original, or pass --force
```

Exit `1`, and nothing is written. It matters because a second pass is not a
no-op. Sanitising sanitised output *is* a no-op for `hash` and `redact`:
netredact recognises its own markers and constants and leaves them alone.

It is **not** a no-op for `pseudo` on addresses and MACs. Those substitutes are
deliberately indistinguishable from real values — including to netredact — so a
second pass re-maps them. The reason is `100.64.0.0/10`: it is in the default
IPv4 pool and real ISPs use it, so treating every pool address as "already done"
would leave real CGNAT addresses in the output. Run once, from the original.

With `-r` there is no original — which is exactly why the marker exists. If you
mean it, `--force` sanitises a marked file anyway, and it is
[the one override](#when-netredact-refuses-a-file) for every refusal netredact
makes; the marker is not stacked, and the second mapping is not recoverable.
`marker = false` switches the line off and takes the guard with it.

Line numbers in the report count the marker, so `L3` is line 3 of the file that
was written.

## Failing a pipeline on suspicious output

```bash
netredact config.txt --strict -o clean.txt || echo "needs a human"
```

Exit codes: `0` clean, `1` a usage or configuration error, or a file that was
refused or could not be read or written, `2` the verification pass found
something (with `--strict`, or `verify.strict = true`). A mistyped flag exits
`1` like any other usage error, so a pipeline that stops the release on `2`
cannot read it as a leak report.

The findings themselves are printed either way, so you do not need `--report`
to see what failed — only to see what the policy was.

Note that `--strict` fails on **credential-shaped material**, not on a policy
choice. A config where you deliberately kept a password still fails, which is
intended. Nothing about `--strict` tells you whether your `keep` decisions are
acceptable — only you can decide that.

## Before you send anything

Read the output. netredact is rule-based: it knows the patterns it has been
taught, and the verification pass is a net, not a proof. In particular check the
names it never touches — ACLs, route-maps, VRFs — which on a real
service-provider config often carry customer names. VLAN names, interface
descriptions and circuit names carry them too, and those it *can* reach:
`[vlans]`, `[interfaces]` and `[circuits]`, all `keep` until you ask.
