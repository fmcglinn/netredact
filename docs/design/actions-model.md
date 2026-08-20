# The actions model

Why netredact's configuration looks the way it does.

## The problem with sections that mean verbs

The first design had two sections. `[redact]` destroyed things; `[scrub]`
pseudonymised them. The action was encoded in the *section name*, and that one
choice caused every inconsistency the model had:

- **Free text was homeless.** An interface description sometimes wants
  destroying and sometimes wants pseudonymising, so it needed both sections.
  It ended up in `[redact]` with a three-value enum — `keep | hash | redact` —
  which meant `[redact]`, the "destruction" section, contained a
  pseudonymisation mode. `descriptions = "hash"` produced a stable salted
  token: the defining behaviour of `[scrub]`.
- **Some values were stranded.** SNMP `location` and `contact` are free text,
  not credentials, but they were implemented as keyword rules and so lived in
  the always-on secret table with no dial at all. At stock defaults the tool
  destroyed a street address while keeping `description Customer ACME
  service 12345` — it destroyed the less sensitive value and kept the more
  sensitive one, purely because of which table each pattern happened to
  land in.
- **Some values had no escape hatch.** `redact.disable` only accepted the 30
  keyword rule names, so serial numbers, license UDIs and certificates could
  not be kept by any configuration. Yet a serial number is the first thing a
  vendor's support desk asks for.
- **The shorthand did not compose.** `ipv4 = true` and `[scrub.ipv4]` cannot
  coexist — TOML rejects a key that is both a value and a table — so
  "pseudonymise every class except CGNAT" could only be written by spelling
  out all eleven classes.

## The model

Select a part of the config, choose an action. The action is a *value*, so
sections are free to organise by selector instead.

```toml
[secrets]
default = "redact"

[text]
default = "keep"

[policy]
hostnames = "keep"
```

## Four actions

The vocabulary is about **how much structure survives**:

| action | equality relation | output |
|---|---|---|
| `keep` | — | untouched |
| `pseudo` | preserved | type-valid substitute; the config still parses |
| `hash` | preserved | opaque marker; announces that sanitising happened |
| `redact` | destroyed | nothing survives, not even "these two were equal" |

`pseudo` and `hash` differ in a way that matters: `pseudo` keeps the output
loadable onto a device, `hash` makes the redaction visible to a reader. Both
preserve the equality relation, which is often the whole value of sanitised
output — being able to see that fourteen ports share one description, or that
forty devices share one TACACS key, without learning what either says.

`redact` destroys that relation. That is a real distinction and the reason
`redact` survives alongside `hash`: publishing `<DESC-f11e24>` tells the
reader which ports belong together, which for a customer-facing network may
itself be the leak.

Every derivation is an HMAC under the salt, never an RNG. There is no
`--map-in`, so cross-run and cross-device consistency depends entirely on
`salt_file`.

## Rendering follows the family

`redact` means one thing — destroy the equality relation — but it cannot
render the same way everywhere. `<REMOVED>` where an IP address belongs stops
the config parsing. So the *rendering* is a property of the family, not a
choice:

| family | `pseudo` | `hash` | `redact` |
|---|---|---|---|
| `secrets` | *illegal* | `<SECRET-4f2a1c>` | `<REMOVED>` |
| `text` | `desc-f11e24` | `<DESC-f11e24>` | `<DESCRIPTION-REMOVED>` |
| `interfaces` | `desc-f11e24` | `<DESC-f11e24>` | `<DESCRIPTION-REMOVED>` |
| `vlans` | `vlname-f11e24` | `<VLAN-f11e24>` | `<REMOVED>` |
| `identity` | `SN-f11e24` | `<SERIAL-f11e24>` | `<REMOVED>` |
| `platform` | `model-f11e24` | `<MODEL-f11e24>` | `<REMOVED>` |
| `hostnames` | `device-abc123` | `<HOST-abc123>` | `redacted` |
| `domains` | `d1a2b.example.com` | `<DOMAIN-abc123>` | `example.invalid` |
| `usernames` | `user-ab12` | `<USER-abc123>` | `user` |
| `emails` | `user-ab12@d1a2b.example.com` | `<EMAIL-abc123>` | `user@example.invalid` |
| `ipv4` | pool address | `<IP-a1b2c3>` | `192.0.2.0` |
| `ipv6` | pool address | `<IP6-a1b2c3>` | `2001:db8::` |
| `macs` | reseeded half | `<MAC-a1b2c3>` | `00:00:5e` / `00:00:00` |

The reserved constants are RFC-assigned where one exists: 5737 for IPv4, 3849
for IPv6, 2606 for domains, and the IANA `00:00:5e` prefix for MACs.

`interfaces` renders exactly as `text` does, deliberately: an interface
description *is* a description, and the marker's job is to say what was taken
out, not which section took it out. The two families are separable in the
configuration and identical in the output.

`vlans` does not, and the reason is worth stating: its `pseudo` token is
`vlname-…` rather than `vlan-…`. Every substitution here is idempotent —
netredact recognises its own output so a second pass is a no-op — and
`VLAN-100` is a name a real switch really has, which the tool would then read
as something it had already sanitised and leave standing. A marker prefix is
safe from that (`<VLAN-a1b2c3>` collides with nothing); a bare token is not.
The same reasoning already picked `ver-…` over `version-…` for `os-version`.

## One illegal cell

`pseudo` on `secrets`. A loadable `enable secret secret-f11e24` looks
harmless, but that value is `HMAC(salt, real_secret)` — if a config built for
a lab ever reaches production, the credential is computable by anyone who can
derive it. `hash` already provides what the lab case actually wanted: an
audit signal showing whether forty devices share one key or each has its own.

Everything else is legal. An earlier draft also rejected `hash` on addresses,
on the theory that `pseudo` dominates it. That was wrong: the default IPv4
pools include `100.64.0.0/10`, which real ISPs use, so a pseudo address can be
mistaken for a live one — which is exactly why the tool has pool-collision
detection. `<IP-a1b2c3>` is unambiguous where `100.64.5.9` is not.

## Families, and what gets its own section

A selector gets its own section when its members **exhaustively partition** a
value space: the ten IPv4 classes, the eleven IPv6 classes, the two halves of a
MAC. Those are taxonomy, they are mutually exclusive, and a `default` key
covers the rest of the partition.

A selector whose members are *named rules* gets a section too, on the same
shape: a `default`, plus one key per rule. Rules are not a partition — a line
can match several, and Arista's `! device:` header matches two `platform`
rules at once — but the ergonomics of a `default` are the same either way, and
without one "all of this except that one" means listing everything else.

### Why the flat `[overrides]` table went

There used to be one table holding every per-rule exception, flat, because
every rule name is globally unique and none collides with an address class
name. You could write `location = "keep"` without knowing which family
`location` belongs to, and not knowing is exactly the state you are in when a
false positive bites you. That was a real argument and it lost to two others.

**A rule had two homes.** Once `platform` had a section, `[platform]
os-version` and `[overrides] os-version` were both legal and one had to win.
One key, one place is worth more than the convenience of not knowing a family.

**A flat table is invisible.** `--print-config` prints every key at its
default, which is what makes the file a starting point rather than a puzzle.
It could never do that for `[overrides]` — only show three commented examples
— so the granularity existed and nobody found it. Every rule key is printed
now.

The cost is that a rule's family is part of the config surface: refiling a
rule between families breaks any config that names it, where before it broke
nothing. That is a genuine loss and it is priced in, on the grounds that
refiling also changes how the value renders (`<SECRET-…>` becomes `<DESC-…>`),
so a config that named the rule probably wanted to hear about it. The error
message routes: a rule named in the wrong section is rejected with the section
it belongs to, and `--list-rules` prints that section next to every name.

## Refilings

Four rules moved, because the old filing was an accident of implementation:

- `location`, `contact` → **text**. They are free text; they were only in the
  secret table because they were implemented as keyword rules.
- `snmp-engineid` → **identity**. An engine ID identifies a device. It assists
  offline attack on localised SNMPv3 keys, but it is not itself a credential.
- `ssh-public-key` → **identity**. A public key is not a secret.
- the model / release / boot-image rules → **platform**, not `identity`. They
  do identify something, but not a *device*: every box off the same production
  line carries them. What they disclose is an attack surface, which is why
  they are separable from a serial number that names one machine.
- `pem-block` **splits** into `pem-key` (secrets) and `pem-cert` (identity). A
  private key is a credential; a certificate is public data whose payload is
  identity — the CN is a hostname, the O is an organisation. Treating them
  identically meant a certificate could never be kept for a PKI support case.

## Scope, and splitting one selector into two families

Two families arrived later than the rest — `interfaces` and `vlans` — and they
are the first that are picked out by **where a line is** rather than by what is
on it.

`vlans` needs that. A VLAN name is a bare `name CUST000000000123` line, and the
identical line under a `route-map` is a route-map name that nothing may touch.
Only the enclosing block tells them apart, so the rule names the block it
requires and the sanitiser tracks two kinds of block — a JunOS brace stanza and
an IOS-style "column-zero header plus its indented lines" — under **one set of
names**. Using JunOS's own plural spellings (`interfaces`, `vlans`) is what
lets one rule cover `interface Gi0/0`, `interfaces { … }` and
`set interfaces …` without three patterns. It also generalises the
`[[custom]] stanza` key, which used to reach JunOS only.

`interfaces` is the more interesting case, because the *selector* was never in
doubt — an interface description was already matched by the `description` rule
in `text`. What was wrong was that one action had to serve two audiences:

- a vendor TAC case is unreadable without the port descriptions, because they
  are how the path through the box is written down;
- a public post is unpublishable *with* them, because they name the customer on
  each port.

Under a single `text` action you had to pick one, and the loser was whichever
mattered less that day. So the rule splits in two — one selector, one pattern,
partitioned by scope — and `[text] redact` with `[interfaces] keep` says the
thing that could not be said before. The two rules must partition rather than
overlap: they share a pattern, so if both could act on one line the second
would render the first's marker again, count it twice, and let `[text]`
override a `keep` that `[interfaces]` had asked for. `description` is therefore
scoped *out* of `interfaces` explicitly, in a table next to the rule.

The cost is the same one `[overrides]` paid: `[text] description = "hash"` no
longer reaches interface descriptions, so a config that relied on it changes
behaviour. That is priced in for the same reason — the family is part of the
config surface, and the split is exactly the distinction the config wanted to
draw.

## Defaults, and why the report carries the weight

Only `secrets` acts by default. Everything else is kept.

This makes the documented contract literally true — *secrets are destroyed,
everything else is opt-in* — and it costs today's destroy-by-default for
banners, serials, certificates and SNMP location. The justification is that
default output was never publishable anyway: it still contains every IP,
hostname, domain and customer description. The banner was not the weak link.

That trade only holds if the leak is never silent, and `verify` structurally
cannot help. Verify has two kinds of check: unconditional ones that ask *is
credential-shaped material present* (these fire even when a policy keeps a
secret, which is why `--strict` still fails — deliberate, and it must not
regress), and conditional ones that ask *was the scrub you requested applied*.
Neither can flag a policy choice. An unconditional text check would fail every
run at defaults; a conditional one never fires, because keeping is the policy.

So the report leads with an explicit policy line: at defaults it reads
`secrets=redact, everything else kept`, which states the caveat in the same
breath as the promise. The per-family breakdown of what was kept is available
programmatically as `Result.kept_counts` for anyone who wants to work down it,
but the report does not print it — at defaults that list is nearly the whole
config, and a wall of expected output is not a warning.

## Patterns

A rule's pattern used to be a *prefix*, with the value matcher appended
centrally so no rule had to spell out how to match a quoted string, a JunOS
`;` terminator or a trailing `## SECRET-DATA` comment. That rationale still
holds, so the prefix form is kept: a pattern with no capture groups is a
prefix.

A pattern *with* capture groups declares its own targets — every group is
acted on, everything outside them is preserved. That lifts the old engine's
one-value-per-line limit and lets a rule say what a key actually looks like
instead of relying on position. `%VAL%` is exposed so hand-written groups
still get quoting and terminators right.

This replaces the old `mode` field, which conflated three unrelated things:
which value matcher to append, a post-match filter that skipped JunOS keywords
and bare digits, and one hand-written token-walking code path for
`snmp-server host` lines. Only the last is genuinely code, and it stays as a
named handler.

## Bugs this design fixes

- `location` destroyed a JunOS `location {` stanza opener, leaving the config
  brace-unbalanced while the street address inside it survived.
- `aaa-server-key` matched `ntp server 10.0.0.1 key 5 prefer`, destroyed
  `prefer` and kept the key ID — config semantics lost, nothing protected.
- Serial numbers and certificates could not be kept by any configuration.
- `ipv4 = true` could not compose with per-class overrides.
