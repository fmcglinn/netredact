# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

### Changed

- **`[overrides]` is gone, and every rule now has exactly one home.** A family
  whose members are named rules is a section, and inside it each rule is a key
  alongside a `default` for the family. `[secrets]` (32 rules), `[text]` (7),
  `[identity]` (6) and `[platform]` (4) carry all 49 between them; the four
  families that have no rules — the names the collect pass learns — stay one
  key each in `[policy]`.

  ```toml
  [identity]
  default       = "hash"     # serials, certs, keys -> markers
  serial-number = "keep"     # except this one: TAC asks for it first
  ```

  The flat table went for two reasons. A rule became settable from two places
  the moment `[platform]` existed, with a precedence to remember. And a flat
  table is invisible: `--print-config` could only ever show a few commented
  examples of it, so the granularity existed and nobody found it — all 49 keys
  are printed at their defaults now. The cost, priced in deliberately, is that
  a rule's family is part of the config surface: refiling a rule between
  families breaks a config that names it, where before it broke nothing.

  Old configs are rejected with the move spelled out per key, not with a
  generic "unknown section":

  ```
  [overrides] is gone: a rule is set in the section for its own family ...
    overrides.serial-number: now [identity] serial-number
    overrides.banner: now [text] banner
  ```

  The section classes are **generated from the rule table**, so a rule added to
  a family gets a key, a line in `--print-config` and a cell in the option
  sweep with nothing to keep in step by hand.

- `[[custom]]` gained an optional **`action`** key, which is what `[overrides]`
  used to do for a custom rule. Without it the rule still takes its family's
  action.

- `netredact --list-rules` prints the **section** each rule belongs to, and a
  rule named in the wrong section is rejected with the right one. A real rule in
  the wrong place is a filing mistake rather than a typo, so the message routes
  it instead of reciting the section's keys:

  ```
  [text]: serial-number is a rule in [identity], not in [text]: set it as
  [identity] serial-number
  ```

  A key that names no rule at all still gets the section's own key list, both
  mistakes in one section are reported together, and a key naming one of your
  own `[[custom]]` rules is pointed at that rule's `action`. `--list-rules` also
  prints the block a rule is scoped to, and the block a rule is scoped *out* of.

- **`[text] description` no longer reaches interface descriptions.** They moved
  to `[interfaces]` (see below), so a config that set `[text]` expecting to act
  on port descriptions now needs to say so:

  ```toml
  [text]
  default = "hash"
  [interfaces]
  default = "hash"     # this line is the new part
  ```

  The two rules **partition** the descriptions in a file rather than
  overlapping: they share one pattern, so if both could act on a line the
  second would render the first's marker again, count it twice, and let
  `[text]` override a `keep` that `[interfaces]` asked for. Every shipped
  example profile was updated, and the change is priced in on the same grounds
  as the `[overrides]` removal: a rule's family is part of the config surface,
  and this split is exactly the distinction a config wanted to draw.

- **The report no longer claims VLAN names are never scrubbed**, because they
  are no longer out of reach. The `NOTE:` line lists ACL, route-map,
  prefix-list and policy names, AS numbers, VRF names and interface numbering —
  and `[vlans]` accounts for what left it.

- **The legal values of `vendor` are read off the vendor detector's own hint
  table**, rather than being written out a second time in `config.py` and a
  third time in the comment `--print-config` prints. A vendor netredact cannot
  detect is no longer a value you can set, and a vendor it can detect is always
  a value you can set. The list is now alphabetical wherever it is printed —
  `auto | arista | cisco | juniper`.

### Added

- **A `[vlans]` section, and the `vlan-name` rule.** The `name` under a
  `vlan <id>` block — and the one-line Catalyst `vlan <id> name <name>` form —
  is now something a configuration can reach. On a service-provider access
  switch a VLAN name is frequently a service or customer identifier, and until
  now nothing could touch it: the report had to list VLAN names among the things
  netredact never looks at, and that line is gone.

  ```toml
  [vlans]
  default = "pseudo"       #  name CUST000000000123  ->  name vlname-f11e24
  ```

  `pseudo` is the action to reach for. The configuration refers to a VLAN by
  name elsewhere, so a type-valid substitute keeps the output loadable where
  `<VLAN-f11e24>` would not. The pseudo token is `vlname-…` and deliberately not
  `vlan-…`: substitutions are idempotent, netredact recognises its own output,
  and `VLAN-100` is a name a real switch really has.

  **An SVI is not a VLAN definition.** `interface Vlan905` is an interface
  block, so its description belongs to `[interfaces]` below and this rule never
  looks at it. Only a `vlan <id>` block is in scope, which is also what keeps a
  bare `name` line under a `route-map` or a `class-map` untouched.

- **An `[interfaces]` section, and the `interface-description` rule.** The
  `description` on an interface is no longer part of `[text]`. It is the same
  selector, split off by the block it sits in, because it is the one piece of
  free text with two incompatible audiences: a vendor TAC case is unreadable
  without the port descriptions — they are how the path through the box is
  written down — and a public post is unpublishable with them.

  ```toml
  [text]
  default = "redact"       # every other description goes
  [interfaces]
  default = "keep"         # except the ones the topology is written in
  ```

  It reaches an interface description in every dialect, because scope rather
  than syntax picks it out: IOS / EOS / NX-OS `interface Gi0/0` blocks, JunOS
  `interfaces { … }` stanzas and `set interfaces … description …` lines alike.
  Rendering follows `text` — a description is a description — so `hash` still
  writes `<DESC-f11e24>` and `redact` still writes `<DESCRIPTION-REMOVED>`.

- **Scope: a rule can name the block it applies to, on any vendor.** Two kinds
  of block now answer that question under one set of names — a JunOS brace
  stanza, and an IOS-style header at column zero plus the indented lines under
  it (any other unindented line ends it, including the bare `!`). The names are
  JunOS's own, `interfaces` and `vlans`, which is what lets one rule cover three
  dialects instead of three patterns.

  This is what makes `vlan-name` possible at all: a bare `name` line is a VLAN
  name in one block and a route-map name in another, and only the enclosing
  block can tell them apart. It also generalises `[[custom]] stanza`, which
  reached JunOS only — `stanza = "interfaces"` now scopes a custom rule to an
  IOS interface block too.

- **A `[platform]` section**, and four rules to feed it: the hardware model,
  the software release and the boot image. `os-version` takes a line that is
  nothing but `version …`, across IOS `15.7`, NX-OS `9.3(5)` and JunOS
  `21.4R3-S4.9;`; `boot-image` takes `boot system …` whether or not it is
  commented out; `hardware-model` and `software-image` take the `Model:` /
  `PID:` / `Software image version:` / `System image file is …` lines people
  paste in front of a config.

  ```toml
  [platform]
  default    = "keep"      # the model a reviewer needs
  os-version = "redact"    # the release that names your CVEs
  boot-image = "redact"
  ```

  The keys are rule names, so they read the same in `[platform]` and in
  `--list-rules`.

  Arista's `! device: agg-sw-02 (DCS-7280SR-48C6-M, EOS-4.32.1F)` header gets
  **no rule of its own**. It carries three values of three kinds on one line,
  introduced by nothing but their position, and a rule carries one family and
  one action — so a header rule would put the model and the release out of
  reach of `[overrides]`. `hardware-model` and `os-version` each read the
  header themselves, and the hostname stays with `hostnames`.

  It is a family of its own rather than part of `identity` because it does not
  identify a *device*: every box off the same production line carries the same
  model, and a well-run fleet the same release. What it discloses is an attack
  surface — a model plus a release number is a CVE list. `keep` by default,
  since it is also the first thing a support desk asks for and the thing a
  reviewer or a language model needs in order to judge a config at all.

  `hardware-model` requires a `:` or `=` after the keyword. That separator is
  the whole safety margin: `platform qos map-mode` and Arista's
  `service routing protocols model multi-agent` are commands, not disclosures.

### Changed

- **Vendor detection no longer rests on a single marker per vendor.** The
  decisive Arista evidence — the `EOS-4.32.1F` release string, the `.swi` boot
  image — is exactly the material the new `platform` family destroys, so each
  vendor gained independent hints that survive it: the `! device:` header shape
  on its own, `! Command: show …`, `daemon TerminAttr` for Arista;
  `Building configuration` / `Current configuration :`, `! Last configuration
  change` and the NX-OS `9.3(5)` version shape for Cisco; the JunOS release
  string and `jinstall` / `junos-*` image names for Juniper. Detection reads
  the input and never the output, and now says so in the module.

## [0.1.0] - 2026-08-19

First release.

### Added

- **Redaction and pseudonymising of Cisco IOS/IOS-XE/NX-OS, Arista EOS and
  Juniper JunOS configurations** (both curly-brace and `set` formats), so a
  config can be handed to a vendor, a contractor, a forum or a language model.
  Python 3.11+, standard library only, no runtime dependencies.

- **The actions model.** Configuration selects a part of the config and chooses
  an action for it: `keep`, `pseudo` (a type-valid substitute, so the output
  still loads onto a device), `hash` (an opaque marker that announces the
  redaction), or `redact` (destroys the equality relation, so not even "these
  two values were the same" survives). Rendering follows the family — `redact`
  emits `<REMOVED>` for a secret but an RFC-reserved constant for an address,
  because `<REMOVED>` where an IP belongs stops the config parsing. Rationale
  in [docs/design/actions-model.md](docs/design/actions-model.md).

- **Ten families:** `secrets` (31 rules), `text` (6), `identity` (6),
  `hostnames`, `domains`, `usernames`, `emails`, `ipv4` (10 address classes),
  `ipv6` (11 classes) and `macs` (OUI and NIC halves, independently
  actionable). A family action is set in `[policy]`; a selector whose members
  exhaustively partition a value space gets its own section with a `default`
  key. All 43 rule names are globally unique, so `[overrides]` is flat — you
  can keep one rule by name without knowing its family.

- **Only `secrets` acts by default.** Secrets are destroyed; everything else is
  kept until you ask for it. `pseudo` is rejected on `secrets`, the single
  illegal combination: the substitute would be `HMAC(salt, real_secret)`, and a
  lab config that reached production would carry a computable credential.

- **43 redaction rules** across keyword patterns, inline blobs and multi-line
  blocks, covering enable and user credentials, AAA and shared keys, SNMP v1
  through v3, IKE and IPsec pre-shared keys, routing and redundancy protocol
  authentication, PPP, wireless, certificates, PEM blocks and SSH keys.

- **Custom rules** via `[[custom]]`. A pattern with capture groups declares its
  own targets — every group is acted on, everything outside them is preserved,
  so a rule can act on more than one value per line. A pattern without groups
  is treated as a prefix and the value matcher is appended centrally, so it
  never has to spell out how to match a quoted string, a JunOS `;` terminator
  or a trailing `## SECRET-DATA` comment. `%VAL%` exposes that matcher to
  hand-written groups. A custom rule joins a family and resolves its action
  through `[policy]` and `[overrides]` like any built-in.

- **Structure preservation.** Pseudonymous addresses keep the host octet,
  prefix length and same-subnet relationships; IPv6 keeps the interface
  identifier; MACs keep separator style and optionally the vendor prefix.
  Netmasks and wildcard masks are detected structurally and never touched.
  Address classes are mutually exclusive and checked most-specific first, so
  exactly one switch governs any given address.

- **Consistency across a fleet.** Every substitution is an HMAC under a salt,
  so the same real value maps to the same fake value in every run and every
  file. Set `salt_file` and forty devices stay mutually consistent; the file is
  created `0600` with a warning that it is a re-identification key.

- **Verification pass** over the output, with `--strict` for a non-zero exit.
  The credential-shaped checks are unconditional, so a policy that deliberately
  keeps a secret still fails verification.

- **Pool-collision detection** for configs that use CGNAT space, since the
  default IPv4 pools include `100.64.0.0/10` and a pseudonym there can be
  indistinguishable from a real subscriber address.

- **An opt-in report** (`-r` / `--report`, off by default so a pipeline gets
  the output and the exit code and nothing else). Verification findings and
  pool-collision warnings print to stderr regardless, so a clean run is silent
  and an exit code never arrives unexplained. The report leads with the
  effective policy — at defaults, `secrets=redact, everything else kept` — then what
  changed, the verification result, and what netredact never looks at. `verify`
  cannot flag a policy choice, so the policy line states it.
  `Result.kept_counts` carries the per-rule breakdown of what was left in place
  for callers that want it.

- **TOML configuration** with discovery (`--config`, `./netredact.toml`,
  `./.netredact.toml`, `$XDG_CONFIG_HOME/netredact/config.toml`, built-in
  defaults), per-key merging so a partial config overrides only what it names,
  validation that names the expected keys on a typo, and `--print-config`.

- **Six example profiles**, from secrets-only to public publication, plus a
  fully annotated reference config.

- **Library API:** `Config`, `sanitise_text`, `Result`. The library writes to
  no stream: problems come back on the `Result` or are raised, so reporting
  stays the CLI's job.
