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
netredact config.txt --in-place               # overwrite
cat config.txt | netredact -                  # stdin
```

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
  NOTE: never scrubbed -- ACL / route-map / prefix-list / policy names,
        AS numbers, VRF names and interface numbering.
        Read the output before sending it anywhere.
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
  policy: secrets=redact, text=hash, identity=hash, platform=keep (per
          rule), interfaces=hash, vlans=pseudo, circuits=pseudo,
          domains=pseudo, usernames=pseudo, emails=hash, ipv4=keep (per
          class), ipv6=keep (per class), macs=keep/pseudo, everything else
          kept
  changes:
        19  username-secret, enable-secret, encoded-key ...
         5  ipv4 addresses
         5  usernames
         4  ACL remarks, banners, contacts, locations
         2  interface descriptions
         2  ipv6 addresses
         1  certificates
         1  domain names
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

Sanitising sanitised output is a no-op for `hash` and `redact`: netredact
recognises its own markers and constants and leaves them alone.

It is **not** a no-op for `pseudo` on addresses and MACs. Those substitutes are
deliberately indistinguishable from real values — including to netredact — so a
second pass re-maps them. The reason is `100.64.0.0/10`: it is in the default
IPv4 pool and real ISPs use it, so treating every pool address as "already done"
would leave real CGNAT addresses in the output. Run once, from the original.

## Failing a pipeline on suspicious output

```bash
netredact config.txt --strict -o clean.txt || echo "needs a human"
```

Exit codes: `0` clean, `1` usage or configuration error, `2` the verification
pass found something (with `--strict`, or `verify.strict = true`).

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
