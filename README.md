# netredact

Strip secrets and identifying data out of Cisco IOS/IOS-XE/NX-OS, Arista EOS,
Juniper JunOS, MikroTik RouterOS and Fortinet FortiOS configurations, so you
can hand one to a vendor, a contractor, a forum or a language model.

Python 3.11+, standard library only, no runtime dependencies.

```bash
pip install netredact

netredact running-config.txt                 # -> stdout
netredact configs/*.txt -o clean/
netredact backups/ -r                        # walk a tree, replace in place
cat config | netredact -
netredact running-config.txt --report        # + a summary on stderr
```

Clean runs are silent. Verification findings and warnings always go to stderr;
stdout carries the sanitised configuration and nothing else.

## Documentation

Full docs live in [`docs/`](https://github.com/fmcglinn/netredact/tree/main/docs/):

- [Getting started](https://github.com/fmcglinn/netredact/blob/main/docs/getting-started.md) — install, first run, reading the report
- [Configuration reference](https://github.com/fmcglinn/netredact/blob/main/docs/configuration.md) — every section and key
- [Example configurations](https://github.com/fmcglinn/netredact/tree/main/docs/examples/) — six profiles, from secrets-only to public publication
- [Address classes](https://github.com/fmcglinn/netredact/blob/main/docs/address-classes.md) — the IPv4 / IPv6 taxonomy
- [Rule reference](https://github.com/fmcglinn/netredact/blob/main/docs/rules.md) — every rule and every verification check
- [Verification](https://github.com/fmcglinn/netredact/blob/main/docs/verification.md) — what the output pass catches, and what it cannot
- [Library use](https://github.com/fmcglinn/netredact/blob/main/docs/library.md) — the module API
- [The actions model](https://github.com/fmcglinn/netredact/blob/main/docs/design/actions-model.md) — why the configuration looks like this

## Selector, then action

Configuration names a **part of the config** and gives it an **action**. There
are four, and they differ in how much structure survives:

| Action | Equality relation | Output |
|---|---|---|
| `keep` | — | untouched |
| `pseudo` | **preserved** | a type-valid substitute; the config still loads |
| `hash` | **preserved** | an opaque `<DESC-f11e24>` marker; announces the sanitising |
| `redact` | **destroyed** | a family-appropriate constant; not even "these two were equal" survives |

Every substitute is an HMAC under a salt, never a random value, which is what
makes `pseudo` and `hash` consistent across files and across a fleet.

`pseudo` and `hash` both preserve equality, which is often the whole point:
seeing that fourteen ports share one description, or that forty devices share
one TACACS key, without learning what either says. `redact` destroys that
relation — and on a customer-facing network, the relation can itself be the
leak.

**One combination is illegal: `pseudo` on `secrets`.** A loadable
`enable secret secret-f11e24` looks harmless, but the value is an HMAC of the
real credential. Use `hash` for an audit-visible marker, or `redact`.

## What acts by default

Only `secrets`, and it redacts. Everything else is kept until you ask for it:

```toml
[secrets]
default = "redact"    # passwords, keys, community strings, hashes (no pseudo)

[text]
default = "keep"      # descriptions, remarks, banners, login messages, contact

[locations]
default = "keep"      # SNMP and structured JunOS physical locations

[identity]
default = "keep"      # serials, UDIs, engine IDs, certificates, SSH public keys

[platform]
default = "keep"      # hardware model, software release, boot image

[policy]
hostnames = "keep"    # device names, from the collect pass
domains   = "keep"    # domain names and search lists
usernames = "keep"    # local users, AAA users, JunOS login names
emails    = "keep"    # e-mail addresses, wherever they appear
```

(`--print-config` writes those four sections out in full, one key per rule.)
It is a narrow promise,
deliberately: default output still contains every address, hostname and customer
description, so it was never publishable anyway. `--report` opens with the
effective policy, so what is *not* being acted on is stated up front:

```
$ netredact running-config.txt --report > clean.txt
=== running-config.txt -> clean.txt  (vendor: cisco) ===
  policy: secrets=redact, everything else kept
  changes:
        19  username-secret, enable-secret, encoded-key ...
  VERIFY: clean (policy applied, no credential-shaped material left)
```

## Configuration

Everything tunable lives in a TOML file rather than in flags. Get a fully
commented starting point, every key at its default:

```bash
netredact --print-config > netredact.toml
```

It is discovered from, in order: `--config PATH`, `./netredact.toml`,
`./.netredact.toml`, `~/.config/netredact/config.toml`, then the built-in
defaults. Only the keys you set are overridden.

The sections are the selectors:

| Section | Selects |
|---|---|
| `[secrets]` / `[text]` / `[locations]` / `[identity]` / `[platform]` / `[interfaces]` / `[vlans]` / `[circuits]` | one action per named rule, plus a `default` for the family — between them, every rule |
| `[operational-names]` | independent actions for ACL/firewall filters, route maps, prefix lists, policy statements, VRFs, peer groups, MPLS label-switched paths and JunOS configuration groups |
| `[as-numbers]` | one consistent action for explicit AS-valued commands and AS-path prepends |
| `[policy]` | the four families with no rules: `hostnames`, `domains`, `usernames`, `emails` |
| `[ipv4]` / `[ipv6]` | one action per address class, plus `default`, `pool`, `well_known_resolvers`, `keep_networks` |
| `[macs]` | `oui` and `nic` independently, plus the `pool` prefix that `redact` writes |
| `[[custom]]` | rules of your own |
| `[collection]` | removal of non-configuration RANCID command output |
| `[verify]` | the pass that re-scans the output |

**Every rule has exactly one home.** A family whose members are named rules is
a section, and inside it each rule is a key alongside a `default` for the
family. There is no flat `[overrides]` table: a rule is set where it lives, and
`--print-config` prints every rule key at its default rather than three
commented examples.

```toml
[identity]
default       = "hash"       # serials, certs, keys -> markers
serial-number = "keep"       # except this one: TAC asks for it first
```

The four families with no rules at all — the names the collect pass learns —
stay one key each in `[policy]`.

RANCID captures are preprocessed before those selectors run. By default,
non-configuration command sections, collector prompts, and device metadata are
physically removed; only explicitly recognized configuration commands survive:

```toml
[collection]
rancid_diagnostics = "remove"  # default; use "keep" for an untouched wrapper
```

Detection requires a RANCID header, a recognized command header, or repeated
collector prompts. Unknown commands fail closed. Reports name removed commands
and line counts without echoing their contents.

Here is a **hardened profile** — not the default, and not what `--print-config`
prints:

```toml
salt_file = "~/.config/netredact/salt"

[secrets]
default = "redact"

[text]
default = "hash"             # <DESC-a1b2c3>: tells ports apart, not who they are

[identity]
default       = "hash"
serial-number = "keep"       # the support desk asks for it first

[platform]
default    = "keep"          # a reviewer needs the model
os-version = "redact"        # the release names your CVEs

[policy]
hostnames = "keep"           # site/role naming is how the design reads
domains   = "pseudo"
usernames = "pseudo"

[ipv4]
default       = "keep"       # 10.x tells an outsider nothing
cgnat         = "pseudo"     # subscriber-facing space
other_unicast = "pseudo"     # your allocated space -- WHOIS maps it to you
benchmark     = "pseudo"     # 198.18/15 is pool space; move any real use of it
# `pool` left at its default: capacity is a hard limit, one /24 of pool per
# distinct /24 in the file, and the default holds 16896.

[macs]
oui = "keep"                 # vendor prefix identifies hardware, not you
nic = "pseudo"

[verify]
strict = true                # exit 2 if anything is still suspicious
```

Six ready-made profiles are in [docs/examples/](https://github.com/fmcglinn/netredact/tree/main/docs/examples/).

### Addresses

Every address falls into exactly one class, checked most-specific first, so one
key governs it with no ambiguity. `default` covers the classes you do not name.

IPv4: `loopback`, `rfc1918`, `cgnat`, `link_local`, `multicast`,
`documentation`, `benchmark`, `reserved`, `well_known`, `other_unicast`.

IPv6: `unspecified`, `loopback`, `ula`, `link_local`, `multicast`,
`documentation`, `teredo`, `six_to_four`, `ipv4_mapped`, `well_known`,
`other_unicast`.

`pseudo` keeps the IPv4 host octet and prefix length — only the /24 moves — and
the IPv6 interface identifier. Full table with prefixes, RFCs and pool
collisions in **[docs/address-classes.md](https://github.com/fmcglinn/netredact/blob/main/docs/address-classes.md)**.

**Netmasks and wildcard masks are never touched**, whatever you set —
substituting `255.255.255.0` would break the config.

### Per-rule escape hatches

Every rule is a key in its family's section. `netredact --list-rules` prints
each name next to the section it belongs to, and a key in the wrong section is
rejected with the section it belongs to rather than silently ignored.

```toml
[text]
default = "hash"
banner  = "redact"

[locations]
default  = "hash"
location = "keep"            # this fleet's location is a safe rack label

[identity]
serial-number = "keep"       # TAC asks for it
```

`netredact --list-rules` prints every name with its family.

### Consistency across a fleet

Set `salt_file` and the same real value maps to the same substitute in every run
and every file — so `128.66.16.20` is the same fake address on all forty devices
and the topology still makes sense. The file is created `0600` if missing.

**The salt file is a re-identification key.** So is anything written by
`--map-out`. Keep both out of whatever you are sharing.

## Custom rules

For gear whose syntax netredact does not know:

```toml
[[custom]]
name    = "acme-shared-key"
pattern = '\s*acme\s+shared-key\s+'
family  = "secrets"       # decides both the action and the rendering
# stanza = "snmp"         # optional, restrict to a JunOS top-level stanza
```

There is no `mode` field: the shape of the pattern says where the value is.

- **No capture groups** — the pattern is a *prefix*, everything up to and
  including the keyword that introduces the value. netredact appends the value
  matcher itself, so quoting, JunOS `;` terminators and trailing
  `## SECRET-DATA` comments are handled for you.
- **With capture groups** — every group is a target and everything outside them
  is kept verbatim, so one rule can carry several values on one line. `%VAL%`
  expands to the value matcher as a capturing group.

`family` is what decides the action — via that family's section, or the rule's
own `action` key — and how the replacement is rendered.

See [docs/rules.md](https://github.com/fmcglinn/netredact/blob/main/docs/rules.md) for the full inventory and
[docs/configuration.md](https://github.com/fmcglinn/netredact/blob/main/docs/configuration.md#custom--rules-of-your-own) for the details.

## Verification

After transforming, netredact re-scans its own **output**. The credential
checks — crypt hashes, JunOS `$9$`, type-7, long hex/base64 runs, credential
keywords without a placeholder — are **unconditional**: they fire even when your
policy deliberately keeps a secret, which is why such a policy still fails
`--strict`. The rest (e-mail, addresses, SSH keys, certificates) run only when
the relevant family is not `keep`, because a value you chose to keep is not a
miss.

Verify therefore **cannot flag a policy choice**; the `policy:` line at the top
of `--report` is what states it. A clean report means "nothing known was left
behind", not "this file is safe to publish" — see
[docs/verification.md](https://github.com/fmcglinn/netredact/blob/main/docs/verification.md).

## Three behaviours worth knowing

**It refuses rather than damages.** `-r` leaves no original, so an input
netredact would rewrite instead of sanitise is refused by name and the run exits
`1`: a file it has already marked, a named binary or PEM key, input that is not
valid UTF-8. A walked directory is choosier still — dot-directories, symlinks,
binaries and PEM blocks are never opened. Writes go through a temporary and an
atomic rename, CRLF endings survive, and one file that cannot be read or written
is reported rather than abandoning the rest of the tree half-replaced. `--force`
is the single override —
[when netredact refuses a file](https://github.com/fmcglinn/netredact/blob/main/docs/getting-started.md#when-netredact-refuses-a-file).

**Blocks and banners count once.** A certificate block or a multi-line banner is
one value, however many lines it spans: one replacement, one entry in the
report.

**`hash` and `redact` are idempotent; `pseudo` on addresses is not.** Running
netredact over its own output changes nothing for markers and constants —
netredact recognises its own work. A pseudonymised address or MAC is
deliberately indistinguishable from a real one, including to netredact, so a
second pass re-maps it. That is not an oversight: the default IPv4 pool includes
`100.64.0.0/10`, and treating pool addresses as "already done" would leave real
CGNAT addresses untouched.

## Library use

```python
from netredact import Config, sanitise_text

cfg = Config.load()                    # or Config.load("netredact.toml")
result = sanitise_text(text, cfg)

result.text              # the sanitised configuration
result.vendor            # "cisco" | "arista" | "juniper" | "mikrotik" | "fortinet" | "unknown"
result.counts            # Counter of rule / family name -> values substituted
result.kept_counts       # Counter of what the policy deliberately left in place
result.policy_summary    # the one-line policy, as the report prints it
result.findings          # list[Finding] from the verification pass
result.mapping           # category -> {original: pseudonym}
```

Pass `salt=` for reproducible substitutes across calls. Full API in
[docs/library.md](https://github.com/fmcglinn/netredact/blob/main/docs/library.md).

## Limits and responsibility

Interface numbering, key-chain names, BGP communities and unsupported vendor
grammar are not transformed. Operational-name and AS-number controls are
opt-in and cover only the explicit grammar documented for them.

> **Warning:** netredact reduces exposure; it does not guarantee anonymisation.
> Configurations may retain identifying or confidential material in unsupported
> syntax or relationships between transformed values. Review every output. You
> are responsible for deciding whether it is safe and lawful to share.

VLAN names used to head that list. They have a section now — `[vlans]`, `keep`
by default — because on an access switch a VLAN name is frequently a service or
customer identifier, and nothing in the configuration could reach it:

```toml
[vlans]
default = "pseudo"           #  name CUST000000000123  ->  name vlname-f11e24
```

Interface descriptions have `[interfaces]` for the same reason: they are the one
piece of free text a TAC case cannot do without and a public post cannot
include, so they take an action of their own rather than sharing `[text]`'s.

Patch panel and pseudowire names have `[circuits]`, also `keep` by default. On a
provider edge these are order references with a customer in them, and unlike a
description they are cross-referenced — a `connector` line names a pseudowire
another section defines — so `pseudo` substitutes both mentions consistently and
the file still loads:

```toml
[circuits]
default = "pseudo"           #  patch acme_ORD000000111222  ->  patch circuit-f11e24
```

## Limitations

Rule-based, so it only knows the patterns it has been taught. Novel or
vendor-specific credential syntax will pass through — that is what the
verification pass and `[[custom]]` are for. Read the output before you send it
anywhere.

## Licence

MIT
