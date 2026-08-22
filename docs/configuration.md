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
netredact: config error: [secrets] default: pseudo is not available for
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
emails, hostnames, usernames
netredact: config error: [ipv4] cgnat: unknown action 'scrub'. Expected one
of keep, pseudo, hash, redact
```

## Top level

| Key | Default | Meaning |
|---|---|---|
| `salt_file` | unset | CLI-oriented file holding the HMAC salt, created `0600` by the CLI if missing. Reuse it to keep substitutes consistent across runs and devices. **A re-identification key — protect it.** Library callers pass `salt=` bytes to `sanitise_text`; the library never reads or writes this path. |
| `marker` | `true` | Write one comment line at the top of the output naming netredact and its version — `!` for IOS-style grammar, `#` for JunOS. It is the only thing in a sanitised file that says it is one, and so the only evidence a re-run can be refused on: turn it off and a second pass re-maps pseudonyms with nothing to warn you. CLI-oriented — `sanitise_text` never adds it, see [the library docs](library.md). |
| `vendor` | `"auto"` | `auto`, `arista`, `cisco`, `juniper` — the vendors the detector knows, and nothing else. Only affects the report; every rule is applied to every file regardless. |

## Every rule has exactly one home

There is no `[overrides]` table. A family whose members are **named rules**
gets a section, and inside it every rule is a key:

```toml
[identity]
default       = "hash"       # the action for every rule not named below
serial-number = "keep"       # TAC asks for it first
```

Eight families work this way — [`[secrets]`](#secrets), [`[text]`](#text),
[`[locations]`](#locations),
[`[identity]`](#identity), [`[platform]`](#platform),
[`[interfaces]`](#interfaces), [`[vlans]`](#vlans) and
[`[circuits]`](#circuits) — and between them they carry every rule; the [rule reference](rules.md) has the current count and the
split. The shape is the same as `[ipv4]` one section down: a `default` plus the
members it governs, so "all of this except that one" needs two lines rather
than a list of everything else.

The remaining four families have no rules at all, so they stay one key each
in `[policy]`.

## `[secrets]`

Passwords, keys, community strings and password hashes — 32 rules.
`default = "redact"`, and it is the only family that acts out of the box.

For configuration values, that is the whole default contract: credentials are
destroyed and everything else is kept. The separate `[collection]` preprocessing
step removes RANCID diagnostics by default. Output still contains every address, hostname and customer
description, which is why the report opens with the effective policy rather
than leaving you to guess.

`pseudo` is refused here, the one illegal cell in the model: a loadable
`enable secret secret-f11e24` looks harmless, but the value is an HMAC of the
real credential. Use `hash` for an audit-visible marker, or `redact`.

## `[text]`

Descriptions, ACL remarks, banners, login messages and `contact` — 5 rules.
On a service-provider config this is where the customer
names live, so the choice matters.

**An interface description is not in here.** It is the same selector split off
by the block it sits in, and it has [`[interfaces]`](#interfaces) to itself;
`[text] description` covers a description anywhere else — a VRF, a policy, a
peer group. The two partition the descriptions in a file, so exactly one of
them acts on any given line.

- `keep` — untouched. The report counts them so you know what you are shipping.
  Addresses and hostnames *inside* a kept description are still substituted if
  their own family acts.
- `pseudo` — `desc-f11e24`. Type-valid, so the config still loads.
- `hash` — `<DESC-f11e24>`. You can still tell two ports apart, and correlate
  the same port across files, without the text. Usually the right middle ground.
- `redact` — `<DESCRIPTION-REMOVED>`. Use this for anything public: even a
  stable token leaks how many distinct customers sit on a device.

## `[locations]`

Physical locations are independent of generic text. `location` covers SNMP
location values; `junos-location-body` covers structured JunOS building,
floor, rack, room, postal and street-address fields. Both default to `keep`.

```toml
[locations]
default             = "redact"
location            = "keep"
junos-location-body = "redact"
```

## `[operational-names]`

Typed operational identifiers default to `keep`. Options are
`acl-firewall-filter`, `route-map`, `prefix-list`, `policy-statement`, `vrf`,
`peer-group`, `label-switched-path` and `configuration-group`. Firewall-filter
and policy term names inherit their parent's action. `pseudo` preserves
supported declarations and references; `redact` may make output unloadable.

`label-switched-path` covers JunOS MPLS LSP names: the `label-switched-path`
and `static-label-switched-path` declarations, and the `lsp-next-hop`
references to them. The keyword carries the name in both the `set` and the
curly-brace syntax and at any depth, so an LSP declared inside a `groups`
stanza is treated the same as one under `protocols mpls`. Two names LSPs sit
next to are namespaces of their own and are deliberately out of scope: a
`primary` / `secondary` named path, and a `p2mp` tree.

`configuration-group` covers JunOS configuration groups: the `set groups NAME`
declaration, the names a `groups { ... }` block declares as its direct
children, and every `apply-groups` / `apply-groups-except` reference, bare or
in a bracketed list. The configuration nested *inside* a group is not a group
name and is acted on by whichever selector owns it, so a group is not a hiding
place and not a second set of rules. `groups` is selected as a statement, not
as a word: Cisco's `object-group` is untouched.

An operational name is treated as one whole value. Names very often encode
other identities -- `gncg-cor1_to_rcbc-agr1-1` carries two device names -- and
what separates them differs per network, so netredact does not take a name
apart. The consequence is worth stating plainly: while a type is `keep`,
anything embedded in its names stays, even where `[policy] hostnames` is
acting. Act on the type to remove the whole name.

## `[as-numbers]`

`default = "keep"` controls ASNs in explicit AS-valued commands and AS-path
prepends. `pseudo` maps one normalized ASN consistently, preserving dotted
notation, 16/32-bit width and public/private allocation class. Communities are
deliberately outside this option.

To act on banners without acting on the rest: `[text] banner = "redact"`.

## `[identity]`

Serial numbers, license UDIs, SNMP engine IDs, certificates and SSH public
keys — 6 rules. None of these is a credential, and all of them tie the file to
a real device. Under the old model they could not be kept by any configuration,
which was wrong: the serial number is the first thing a vendor's support desk
asks for. Now two lines say exactly that:

```toml
[identity]
default       = "hash"
serial-number = "keep"
```

## `[interfaces]`

What a port is called: the `description` on an interface, and only there. One
rule, `interface-description`.

```toml
[text]
default = "redact"           # every other description goes
[interfaces]
default = "keep"             # except the ones the topology is written in
```

It is a section of its own because it is the one piece of free text with two
incompatible audiences. A vendor support case is unreadable without the port
descriptions — they are how the path through the box is written down. A public
post is unpublishable with them, because they name the customer on each port.
Under one `text` action you had to choose for both, and the two lines above are
what that choice actually looks like.

It reaches an interface description in every dialect, because scope rather than
syntax is what picks it out:

| Where | Line |
|---|---|
| IOS / EOS / NX-OS | `interface Gi0/0` and the indented lines under it |
| JunOS braces | `interfaces { ge-0/0/5 { description "…"; } }` |
| JunOS `set` | `set interfaces xe-0/0/0 description "…"` |

`interface Vlan905` counts: an SVI is a port. Rendering follows `text` — a
description is a description, so `hash` writes `<DESC-f11e24>` and `redact`
writes `<DESCRIPTION-REMOVED>` here too.

## `[vlans]`

What a VLAN is called: the `name` under a `vlan <id>` block. One rule,
`vlan-name`.

```
vlan 905
 name CUST000000000123        ->  name vlname-f11e24
```

The one-line Catalyst form, `vlan 905 name CUST000000000123`, is the same rule.
`vlan 905` itself is structure and never moves — other lines refer to the id.

On a service-provider access switch a VLAN name is frequently a service or
customer identifier, and until this section existed no configuration could
reach it: the report had to list VLAN names among the things netredact never
touched. It no longer does.

**`pseudo` is usually the right action here**, not `hash`. The configuration
refers to a VLAN by name elsewhere, and `vlname-f11e24` is a valid name where
`<VLAN-f11e24>` is not — so the output still loads. The pseudo token is
deliberately not `vlan-…`: `VLAN-100` is a plausible real VLAN name, and
netredact would then read it as something it had already sanitised.

An `interface Vlan905` block is **not** in scope here. An SVI is a port, so its
description belongs to [`[interfaces]`](#interfaces), and only a `vlan <id>`
block defines a VLAN. A bare `name` line elsewhere — under a `route-map`, a
`class-map`, a `crypto` policy — is outside every VLAN block and is never
touched, which is what the scope buys.

## `[circuits]`

What a cross-connect or a pseudowire is called: Arista's `patch panel` names
and the pseudowires under `mpls ldp`. Two rules, `patch-name` and
`pseudowire-name`.

```
patch panel
   patch acme_ORD000000111222                       ->  patch circuit-f11e24
      connector 1 pseudowire ldp acme_…_1 alternate acme_…_2
      connector 2 interface Port-Channel1.100     ->  untouched: an interface
   !
mpls ldp
   pseudowires
      pseudowire acme_ORD000000111222_1             ->  pseudowire circuit-8c04a1
```

On a provider edge these names are order and customer references — the material
a ticket number is made of. `patch panel`, `pseudowires`, the connector numbers
and the interface a connector points at are all structure and never move.

**`pseudo` is the action to reach for here**, for the same reason as `[vlans]`
and one more besides. A `connector` line *references* a pseudowire that the
`mpls ldp` section *defines*, so the two mentions have to come out as the same
name or the file no longer loads. They do: the pseudonym is a function of the
value, and both rules render through one prefix. `redact` collapses every
circuit onto `<REMOVED>` and breaks that, which is fine for something published
and read but not for something reloaded.

`patch-name` and `pseudowire-name` are two rules and could be given two
actions — but the definition and the references of *one* pseudowire are two
branches of `pseudowire-name` alone, so those can never disagree.

### Why these are not gated to Arista

Only Arista writes this grammar, and `netredact --list-rules` labels both rules
`arista`. That label is documentation: **every rule is applied to every file**,
whatever vendor the report names.

What keeps `patch-name` off a JunOS config is that it has to be *inside* a
`patch panel` block, and JunOS opens none — evidence in the file rather than a
guess about the file. The distinction matters because vendor detection is a
whole-file heuristic reading exactly the material `[platform]` deletes, and it
answers `unknown` for the input this tool is handed most often: a pasted
fragment with no header on it. A rule that fired only when the detector agreed
would skip credential rules on a misread file silently, and `--strict` would
still exit 0.

## `[policy]` — the families with no rules

The collect pass reads these off the lines that declare them and then
substitutes them wherever they appear. There is no pattern table to name, so
there is nothing to set per rule.

| Key | Default | Covers |
|---|---|---|
| `hostnames` | `"keep"` | device names, learned by the collect pass and then substituted everywhere they appear |
| `domains` | `"keep"` | domain names and search lists |
| `usernames` | `"keep"` | local users, AAA users, JunOS login names |
| `emails` | `"keep"` | e-mail addresses, wherever they appear |

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

## How each family renders

| Family | `pseudo` | `hash` | `redact` |
|---|---|---|---|
| `secrets` | *illegal* | `<SECRET-4f2a1c>` | `<REMOVED>` |
| `text` | `desc-f11e24` | `<DESC-f11e24>` | `<DESCRIPTION-REMOVED>` (a banner gets `<REMOVED>`) |
| `interfaces` | `desc-f11e24` | `<DESC-f11e24>` | `<DESCRIPTION-REMOVED>` |
| `vlans` | `vlname-f11e24` | `<VLAN-f11e24>` | `<REMOVED>` |
| `circuits` | `circuit-f11e24` | `<CIRCUIT-f11e24>` | `<REMOVED>` |
| `identity` | `SN-f11e24`, `udi-…`, `eid-…`, `key-…`, `cert-…` | `<SERIAL-f11e24>`, `<UDI-…>`, `<EID-…>`, `<KEY-…>`, `<CERT-…>` | `<REMOVED>` |
| `platform` | `model-f11e24`, `ver-…`, `image-…` | `<MODEL-f11e24>`, `<VERSION-…>`, `<IMAGE-…>` | `<REMOVED>` |
| `hostnames` | `device-abc123` | `<HOST-abc123>` | `redacted` |
| `domains` | `d1a2b.example.com` | `<DOMAIN-abc123>` | `example.invalid` |
| `usernames` | `user-ab12` | `<USER-abc123>` | `user` |
| `emails` | `user-ab12@d1a2b.example.com` | `<EMAIL-abc123>` | `user@example.invalid` |

The rendering follows the family because it has to: `<REMOVED>` where an IP
address belongs stops the config parsing, so `redact` on an address writes an
RFC-reserved constant instead.

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

## `[platform]`

The hardware model, the software release and the boot image — what the box is
and what it runs. Four rules.

```toml
[platform]
default    = "keep"          # the model a reviewer needs
os-version = "redact"        # the release that names your CVEs
boot-image = "redact"        # and the image path
```

| Rule | Line |
|---|---|
| `hardware-model` | `Model Number : WS-C3850-48P`, `Hardware: …`, `Chassis type: …`, `PID: …` |
| `os-version` | a version declaration: IOS `version 15.7`, NX-OS `version 9.3(5)`, JunOS `version 21.4R3-S4.9;` or `set version 23.4R2-S5.6` |
| `software-image` | `Software image version: …`, `System image file is "…"`, `Junos: …` |
| `boot-image` | `boot system flash:/EOS64-4.32.1F.swi`, commented out or not |

This is neither a credential nor an instance identity: every device off the
same production line carries the same model and, on a well-run fleet, the same
release. What it discloses is the **attack surface** — a model plus a release
number is a CVE list, and a fleet-wide version is a fleet-wide one.

`default` is `keep` because the model is the first thing a support engineer
asks for, and because a reviewer, or a language model, cannot judge a
configuration without knowing which release it has to be valid on. Destroy it
for anything public; keep it for a TAC case.

### Arista's header

```
! device: agg-sw-02 (DCS-7280SR-48C6-M, EOS-4.32.1F)
```

Three values of three different kinds sit on one line, introduced by no keyword
at all — position is their only grammar. There is deliberately **no rule for
the header**. A rule carries one family and one action, so a header rule would
put the model and the release out of reach of both `[platform]` and
`[overrides]`. Instead `hardware-model` reads the model, `os-version` reads the
release, and the hostname is left to `hostnames`, which learns it from that
same line and substitutes it everywhere it appears. Each of the three keeps its
own action:

```toml
[policy]
hostnames = "pseudo"

[platform]
default = "hash"
```
```
! device: device-a1b2c3 (<MODEL-d4e5f6>, <VERSION-7890ab>)
```

### False positives, and the vendor detector

`hardware-model` insists on a `:` or `=` after the keyword. That separator is
the whole safety margin — `platform`, `model` and `chassis` are ordinary
configuration keywords, and `platform qos map-mode` and Arista's
`service routing protocols model multi-agent` must not be read as disclosures.

**The vendor detector reads the input, never the output**, for exactly this
reason: `[platform]` exists to remove the markers detection is best at
(`EOS-4.32.1F`, `.swi`, a JunOS release string). Detection also does not rest
on any single marker, so `--report` still names the vendor of a file whose
platform lines have been destroyed.

## Naming one rule

Every rule is a key in its family's section, in the rule's own spelling —
`netredact --list-rules` prints each name next to the section it belongs to,
and so does the [rule reference](rules.md).

```toml
[text]
default = "hash"
banner  = "redact"

[locations]
default  = "hash"
location = "keep"
```

A key in the wrong section is an error, not a silent no-op — and because the
rule is real, the message routes it rather than making you go and look:

```
netredact: config error: [text]: serial-number is a rule in [identity], not in
[text]: set it as [identity] serial-number
```

A key that names no rule at all is a typo, and then the section's own keys are
the useful answer:

```
netredact: config error: [text]: unknown key(s) serial-numbers. Expected:
acl-remark, banner, contact, default, description, login-message
```

Both mistakes in one section are reported together, one line each. A key that
names one of your own `[[custom]]` rules is routed too: a custom rule's action
is a key on its own `[[custom]]` entry, never a key in a family section.

Switching a rule off *is* an action: set it to `"keep"`. The rule still
matches and is still counted, so the report can tell you what it left behind.

### Why there is no flat `[overrides]` table

There used to be one, and the argument for it was that you could name a rule
without knowing its family — which is exactly the state you are in when a
false positive bites you. Two things beat it. A rule was then settable from
two places once `[platform]` existed, with a precedence to remember. And a
flat table is invisible: `--print-config` could only ever show a few commented
examples, so the granularity existed and nobody found it. Every rule key is now
printed at its default.

The cost is that a rule's family is part of the config surface. Moving a rule
between families becomes a breaking change to configs that name it — which is
arguably right, since the rendering changes with the family too.

## `[[custom]]` — rules of your own

For gear whose syntax netredact does not know.

```toml
[[custom]]
name    = "acme-shared-key"
pattern = '\s*acme\s+shared-key\s+'
family  = "secrets"          # default; decides the action and the rendering
# action = "hash"            # optional, this rule only
# stanza = "snmp"            # optional, restrict to a JunOS top-level stanza
```

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique across the rule table. |
| `pattern` | yes | A regex. See below for what its shape means. |
| `family` | no, defaults to `"secrets"` | One of `secrets`, `text`, `identity`, `platform`, `interfaces`, `vlans`, `circuits`, `hostnames`, `domains`, `usernames`, `emails`, `ipv4`, `ipv6`, `macs`. |
| `action` | no | This rule's own action, the way a named key gives one to a built-in rule. Without it the rule takes its family's action. |
| `stanza` | no | The block the rule is restricted to. A JunOS top-level stanza, exactly like the built-in `junos-community` — or `interfaces` / `vlans` / `patch-panel`, which match the IOS-style block of that name. See [scope](rules.md#scope-the-block-a-line-is-inside). |

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

## `[collection]` — collector wrappers

```toml
[collection]
rancid_diagnostics = "remove"  # "remove" (default) or "keep"
```

With `remove`, strong RANCID evidence—an explicit content-type header, a
recognized command header, or repeated collector prompts—activates a
fail-closed preprocessing pass. It physically deletes collector prompts,
device metadata, and every command section except an explicit allowlist of
configuration-producing commands such as `show configuration | display set`
and `show running-config`. Unknown commands are removed through the next
boundary or EOF, and arbitrary pipelines are not accepted.

The RANCID content-type header remains. If running and startup configurations
both occur, both bodies remain with source delimiters. Removal happens before
identity collection and verification, so deleted diagnostics cannot affect
pseudonym maps, counts, or findings. This is the intentional exception to the
usual line-count preservation guarantee. Use `keep` when diagnosing collector
output itself.

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

An argument may be a file, a directory or `-` for stdin. A directory is walked
recursively, depth-first and in sorted order, which is how backup trees
arrive; see [walking a directory](getting-started.md#walking-a-directory) for
what the walk leaves alone. A directory must say where its output goes —
`-r` or `-o DIR` — because a whole tree concatenated onto stdout is never what
naming the directory meant.

| Flag | Purpose |
|---|---|
| `-o, --out PATH` | Output file, or a directory — which it is, and is created as, whenever the input is a directory, the run has more than one file to write, or the path ends in a separator. A walked directory is mirrored inside it, zone directories and all, rather than flattened into one heap. Only an existing regular file refuses such a run, and it refuses before writing. One named file with one `-o` path still names a file: a typo in it is reported rather than built. |
| `-c, --config PATH` | Configuration file. |
| `-r, --replace` | Replace the inputs: write each file back over itself, in place of mirroring them elsewhere. Cannot be combined with `-o` — both name a destination. It is also the only mode that refuses a named binary or PEM file, because it is the only one where the original does not survive. |
| `--force` | Process an input netredact would otherwise refuse: one it has already marked, a named binary or PEM file under `-r`, or one that is not valid UTF-8. Without it each of those is refused with exit `1` and nothing is written for that file. See [when netredact refuses a file](getting-started.md#when-netredact-refuses-a-file). |
| `--suffix SUFFIX` | Suffix when writing into an `-o` directory. Default `.sanitised`. |
| `--map-out PATH` | Write the mapping as JSON, `0600`. **De-anonymises the output — never ship it alongside.** |
| `--strict` | Exit `2` on findings, overriding `verify.strict`. |
| `-R, --report` | Print the per-file report to stderr. Off by default; findings and warnings print regardless. |
| `--print-config` | Write a fully commented default config to stdout. |
| `--list-rules` | List every rule with its family, and every verification check. |
| `--version` | Version. |

Exit codes: `0` clean, `1` a usage or configuration error, or a file that was
refused or could not be read or written, `2` findings under `--strict`. A
mistyped flag exits `1` like any other usage error, so `2` only ever means the
verification pass.
