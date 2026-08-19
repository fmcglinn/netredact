# Configuration reference

Everything tunable lives in a TOML file rather than in command-line flags, so
that a decision about how much to strip is written down, reviewable, and
committed next to the rest of your tooling.

Get a fully commented starting point, with every key at its default:

```bash
netredact --print-config > netredact.toml
```

The same content is shipped as [`examples/annotated.toml`](examples/annotated.toml).

## The model in one paragraph

A section selects **a part of the config**; the value you give it is an
**action**. There are four, and only one combination is illegal.

| Action | Equality relation | Output |
|---|---|---|
| `keep` | — | untouched |
| `pseudo` | preserved | a type-valid substitute; the output still loads onto a device |
| `hash` | preserved | an opaque `<PREFIX-tag>` marker, e.g. `<DESC-f11e24>` |
| `redact` | destroyed | a family-appropriate constant; nothing survives, not even "these two were equal" |

`pseudo` is not available for `secrets`, because the substitute would be an
HMAC of the real credential and a lab config that reached production would
carry something computable:

```
netredact: config error: [policy] secrets: pseudo is not available for
secrets: use hash for an opaque marker, or redact
```

Why the model looks like this is in
[design/actions-model.md](design/actions-model.md).

## Discovery

The first file found wins:

1. `--config PATH` (or `Config.load(path)`)
2. `./netredact.toml`
3. `./.netredact.toml`
4. `$XDG_CONFIG_HOME/netredact/config.toml`, else `~/.config/netredact/config.toml`
5. the built-in defaults

Only the keys you set are overridden — a three-line file is perfectly valid and
everything else keeps its default. Unknown sections, unknown keys, unknown
actions and wrong types are rejected with a message naming the offender rather
than being silently ignored:

```
netredact: config error: [policy]: unknown key(s) ipv5. Expected: domains,
emails, hostnames, identity, secrets, text, usernames
netredact: config error: [ipv4] cgnat: unknown action 'scrub'. Expected one
of keep, pseudo, hash, redact
```

## Top level

| Key | Default | Meaning |
|---|---|---|
| `salt_file` | unset | File holding the HMAC salt, created `0600` if missing. Reuse it to keep substitutes consistent across runs and devices. **A re-identification key — protect it.** Unset means a fresh random salt each run. |
| `vendor` | `"auto"` | `auto`, `cisco`, `arista`, `juniper`. Only affects the report; every rule is applied to every file regardless. |

## `[policy]` — the seven families

These seven families are named by rules, not by a partition of a value space,
so they get one key each here plus per-rule exceptions in
[`[overrides]`](#overrides--per-rule-exceptions).

| Key | Default | Covers |
|---|---|---|
| `secrets` | `"redact"` | passwords, keys, community strings, password hashes — 32 rules |
| `text` | `"keep"` | descriptions, ACL remarks, banners, login messages, SNMP `location` and `contact` — 7 rules |
| `identity` | `"keep"` | serial numbers, license UDIs, SNMP engine IDs, certificates, SSH public keys — 6 rules |
| `hostnames` | `"keep"` | device names, learned by the collect pass and then substituted everywhere they appear |
| `domains` | `"keep"` | domain names and search lists |
| `usernames` | `"keep"` | local users, AAA users, JunOS login names |
| `emails` | `"keep"` | e-mail addresses, wherever they appear |

**Only `secrets` acts by default.** That is the whole default contract:
credentials are destroyed, nothing else is. Default output still contains every
address, hostname and customer description, which is why the report opens with
the effective policy rather than leaving you to guess.

**Learned names are matched as whole words, longest first.** `hostnames`,
`domains` and `usernames` are discovered by a first pass over the file and then
substituted wherever they appear, so the device's own name is caught in a
description or a peer group too, not just on the line that declared it. The
longest name wins, which is why `core-rtr-01.example.net` is replaced as one
FQDN rather than having its domain rewritten and the device name left standing.
Whole-word means `admin` never matches inside `network-admin`.

One exception: a **single-character** hostname or username is never
substituted. A two-character account like `lg` is, but rewriting every bare `s`
or `e` in a configuration would do more damage than a one-letter name is worth.

How each family renders:

| Family | `pseudo` | `hash` | `redact` |
|---|---|---|---|
| `secrets` | *illegal* | `<SECRET-4f2a1c>` | `<REMOVED>` |
| `text` | `desc-f11e24` | `<DESC-f11e24>` | `<DESCRIPTION-REMOVED>` (a banner gets `<REMOVED>`) |
| `identity` | `SN-f11e24`, `udi-…`, `eid-…`, `key-…`, `cert-…` | `<SERIAL-f11e24>`, `<UDI-…>`, `<EID-…>`, `<KEY-…>`, `<CERT-…>` | `<REMOVED>` |
| `hostnames` | `device-abc123` | `<HOST-abc123>` | `redacted` |
| `domains` | `d1a2b.example.com` | `<DOMAIN-abc123>` | `example.invalid` |
| `usernames` | `user-ab12` | `<USER-abc123>` | `user` |
| `emails` | `user-ab12@d1a2b.example.com` | `<EMAIL-abc123>` | `user@example.invalid` |

The rendering follows the family because it has to: `<REMOVED>` where an IP
address belongs stops the config parsing, so `redact` on an address writes an
RFC-reserved constant instead.

### `text`

On a service-provider config this is where the customer names live, so the
choice matters:

- `keep` — untouched. The report counts them so you know what you are shipping.
  Addresses and hostnames *inside* a kept description are still substituted if
  their own family acts.
- `pseudo` — `desc-f11e24`. Type-valid, so the config still loads.
- `hash` — `<DESC-f11e24>`. You can still tell two ports apart, and correlate
  the same port across files, without the text. Usually the right middle ground.
- `redact` — `<DESCRIPTION-REMOVED>`. Use this for anything public: even a
  stable token leaks how many distinct customers sit on a device.

Banners and login messages are in this family too. To act on just one of them,
name it in `[overrides]`: `banner = "redact"`.

### `identity`

Serial numbers, license UDIs, SNMP engine IDs, certificates and SSH public
keys. None of these is a credential, and all of them tie the file to a real
device. Under the old model they could not be kept by any configuration, which
was wrong: the serial number is the first thing a vendor's support desk asks
for. Now `identity = "hash"` with `[overrides] serial-number = "keep"` says
exactly that.

## `[ipv4]` and `[ipv6]` — per address class

Address classes **exhaustively partition** the address space, which is why they
get their own section: every address falls into exactly one class, checked
most-specific first.

```toml
[ipv4]
default       = "keep"       # the action for every class not named below
cgnat         = "pseudo"     # one class overrides `default`
other_unicast = "pseudo"
pool          = ["198.18.0.0/15"]
```

| Key | Default | Meaning |
|---|---|---|
| `default` | `"keep"` | The action for every class you do not name. |
| *class name* | inherit `default` | One action for that class. IPv4: `loopback`, `rfc1918`, `cgnat`, `link_local`, `multicast`, `documentation`, `benchmark`, `reserved`, `well_known`, `other_unicast`. IPv6: `unspecified`, `loopback`, `ula`, `link_local`, `multicast`, `documentation`, `teredo`, `six_to_four`, `ipv4_mapped`, `well_known`, `other_unicast`. |
| `pool` | v4 `["198.18.0.0/15", "100.64.0.0/10"]`, v6 `"2001:db8::/32"` | Where `pseudo` allocates from. v4 entries must be `/24` or shorter, the v6 pool `/64` or shorter. |
| `well_known_resolvers` | the public resolvers | The addresses that form the `well_known` **class**. The list and the class have different names on purpose — one is data, the other is taxonomy. |
| `keep_networks` | `[]` | Prefixes never to touch, whatever class they fall into. An escape hatch, e.g. to keep one management prefix readable. |

`pseudo` keeps the IPv4 host octet and prefix length — only the /24 moves — and
the IPv6 interface identifier, so same-subnet relationships and ACL logic
survive. `hash` writes `<IP-a1b2c3>` / `<IP6-a1b2c3>`; `redact` writes
`192.0.2.0` / `2001:db8::`.

Full table with prefixes and RFCs in [address classes](address-classes.md).

**Netmasks and wildcard masks are never touched**, whatever you set. They are
detected structurally, so `255.255.255.0` and `0.0.0.255` survive any policy.

### Pool size is a hard limit

One /24 of pool is consumed per **distinct source /24** in the file. A pool
entry holds `1 << (24 - prefixlen)` of them:

| Pool | Capacity |
|---|---|
| `198.18.0.0/15` | 512 /24s |
| `100.64.0.0/10` | 16384 /24s |
| the default, both together | 16896 /24s |

IPv6 is counted the same way in /64s — `1 << (64 - prefixlen)` — so the default
`/32` holds 4.3 billion and is never the constraint.

Exhausting the pool **fails the run** with
`RuntimeError: exhausted the v4net pseudonym space`, rather than reusing a
pseudonym and silently merging two subnets. A large service-provider
configuration can carry well over 512 distinct /24s, so a pool narrowed to a
single `/15` will not process one. Size the pool for the largest file you will
ever feed it.

If a pool overlaps address space your configuration actually uses, real and
generated addresses become indistinguishable — netredact detects this and warns;
see [pool collisions](address-classes.md#pool-collisions). Note that the two
concerns pull opposite ways, and that acting on the overlapping *class* settles
both: with `cgnat = "pseudo"` no real CGNAT address survives in the output, so
the whole of `100.64.0.0/10` is free to be pool.

## `[macs]` — two halves

A MAC partitions into a 24-bit vendor prefix and a 24-bit device half, so the
two take independent actions.

| Key | Default | Meaning |
|---|---|---|
| `oui` | `"keep"` | The vendor prefix. It identifies the hardware manufacturer, not you or a subscriber, and is often exactly what you are debugging. `redact` writes `pool`. |
| `nic` | `"keep"` | The device half. `pseudo` reseeds it; `redact` writes `00:00:00`. |
| `pool` | `"00:00:5e"` | The OUI that `redact` writes. IANA-reserved, so the result is unmistakably synthetic. |

The separator style (`aabb.ccdd.eeff` / `aa:bb:…` / `aa-bb-…`) is always
preserved.

`hash` replaces the **whole** address with one `<MAC-a1b2c3>` marker, so it is
only reachable by setting both halves to it:

```
netredact: config error: macs: hash applies to the whole address, set both
oui and nic to hash
```

## `[overrides]` — per-rule exceptions

The key is a rule name, the value an action. It takes precedence over
`[policy]`; the rule's family still decides how the replacement renders.

```toml
[overrides]
location      = "keep"       # this fleet's location lines hold a rack label
serial-number = "keep"       # TAC asks for it first
banner        = "redact"     # act on banners without acting on all of `text`
```

All 45 rule names are globally unique and none collides with an address class
name, so this table is flat: you can name a rule without knowing which family it
belongs to, which is exactly the state you are in when a false positive bites
you. `netredact --list-rules` prints every name with its family, and so does
the [rule reference](rules.md).

An unknown name is an error, not a silent no-op:

```
netredact: config error: [overrides]: unknown rule(s) nosuch. See netredact
--list-rules
```

Switching a rule off *is* an action: `[overrides] <rule> = "keep"`. The rule
still matches and is still counted, so the report can tell you what it left
behind.

## `[[custom]]` — rules of your own

For gear whose syntax netredact does not know.

```toml
[[custom]]
name    = "acme-shared-key"
pattern = '\s*acme\s+shared-key\s+'
family  = "secrets"          # default; decides the action and the rendering
# stanza = "snmp"            # optional, restrict to a JunOS top-level stanza
```

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique. Usable in `[overrides]` like any built-in. |
| `pattern` | yes | A regex. See below for what its shape means. |
| `family` | no, defaults to `"secrets"` | One of `secrets`, `text`, `identity`, `hostnames`, `domains`, `usernames`, `emails`, `ipv4`, `ipv6`, `macs`. |
| `stanza` | no | A JunOS top-level stanza the rule is restricted to, exactly like the built-in `junos-community`. |

Use **single-quoted** TOML strings so backslashes reach the regex engine intact.

### What the shape of the pattern means

There is no `mode` field. The pattern itself says where the value is:

- **No capture groups** — the pattern is a **prefix**: everything up to and
  including the keyword that introduces the value. netredact appends the value
  matcher itself, so you never handle quoting, JunOS `;` terminators or trailing
  `## SECRET-DATA` comments. A brace-only token is refused, so a pattern like
  this can never eat a `location {` stanza opener.
- **With capture groups** — every group is a target span, and everything outside
  the groups is kept verbatim. Use this when the value is not one token, or when
  one line carries several values.
- **`%VAL%`** expands to the value matcher *as a capturing group*, so a
  hand-written pattern can borrow the quoting and terminator handling and still
  declare its own targets.

```toml
[[custom]]
name    = "site-notes"
pattern = '^\s*site-notes\s+(.+)$'      # one group: the whole remainder
family  = "text"

[[custom]]
name    = "acme-vault-ref"
pattern = '^\s*vault-ref\s+%VAL%\s+for\s+%VAL%\s*$'   # two groups, two targets
family  = "secrets"
```

A bad regex is reported by name rather than swallowed. The old `mode` key is
rejected with a migration message.

[`06-custom-rules.toml`](examples/06-custom-rules.toml) is a worked example of
all of this.

## `[verify]` — the output pass

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Run the pass at all. |
| `strict` | `false` | Exit `2` if anything is found. `--strict` forces this on. |
| `disable` | `[]` | Check names to switch off. See [rules](rules.md#verification-checks). |
| `ignore_patterns` | `[]` | Extra regexes treated as expected rather than as findings — for token shapes of your own. |

Note that the credential checks are **unconditional**: a policy that keeps a
secret still fails `--strict`. See [verification](verification.md).

## Command-line flags

The CLI covers files and destinations only; behaviour lives in the config.

| Flag | Purpose |
|---|---|
| `-o, --out PATH` | Output file, or a directory when several inputs are given. |
| `-c, --config PATH` | Configuration file. |
| `--in-place` | Overwrite the inputs. |
| `--suffix SUFFIX` | Suffix when writing into an `-o` directory. Default `.sanitised`. |
| `--map-out PATH` | Write the mapping as JSON, `0600`. **De-anonymises the output — never ship it alongside.** |
| `--strict` | Exit `2` on findings, overriding `verify.strict`. |
| `-r, --report` | Print the per-file report to stderr. Off by default; findings and warnings print regardless. |
| `--print-config` | Write a fully commented default config to stdout. |
| `--list-rules` | List every rule with its family, and every verification check. |
| `--version` | Version. |

Exit codes: `0` clean, `1` usage or configuration error, `2` findings under
`--strict`.
