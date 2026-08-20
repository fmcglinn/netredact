# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-08-20

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

- **Only `secrets` acts by default.** Secrets are destroyed; everything else is
  kept until you ask for it. `pseudo` is rejected on `secrets`, the single
  illegal combination: the substitute would be `HMAC(salt, real_secret)`, and a
  lab config that reached production would carry a computable credential.

- **Fourteen families, and 53 rules across them.** Seven families are made of
  named rules — `secrets` (32), `text` (7), `identity` (6), `platform` (4),
  `circuits` (2), `interfaces` (1) and `vlans` (1). Four are the names the
  collect pass learns rather than rules — `hostnames`, `domains`, `usernames`,
  `emails`. Three are value spaces with their own partition — `ipv4` (10
  address classes), `ipv6` (11 classes) and `macs` (OUI and NIC halves,
  independently actionable).

- **Every rule has exactly one home.** A family whose members are named rules
  is a section, and inside it each rule is a key alongside a `default` for the
  family:

  ```toml
  [identity]
  default       = "hash"     # serials, certs, keys -> markers
  serial-number = "keep"     # except this one: TAC asks for it first
  ```

  The section classes are **generated from the rule table**, so a rule added to
  a family gets a key, a line in `--print-config` and a cell in the option
  sweep with nothing to keep in step by hand. Every one of the 53 keys is
  printed at its default, so the granularity is discoverable rather than
  documented-only.

  A rule named in the wrong section is rejected with the right one, because a
  real rule in the wrong place is a filing mistake rather than a typo:

  ```
  [text]: serial-number is a rule in [identity], not in [text]: set it as
  [identity] serial-number
  ```

  A key that names no rule at all gets the section's own key list, both
  mistakes in one section are reported together, and a key naming one of your
  own `[[custom]]` rules is pointed at that rule's `action`.

- **53 redaction rules** across keyword patterns, inline blobs and multi-line
  blocks, covering enable and user credentials, AAA and shared keys, SNMP v1
  through v3, IKE and IPsec pre-shared keys, routing and redundancy protocol
  authentication, PPP, wireless, certificates, PEM blocks and SSH keys.

  The credential rules admit a **run** of encoding and algorithm hints between
  the keyword and the value, not just one, so a command that stacks two cannot
  shield the value behind them — Cisco's autonomous-AP
  `wpa-psk {ascii|hex} [0|7] <key>` is the plain case. Each repetition must end
  in whitespace, so the final token is never eaten: `password 0 12345678` still
  redacts `12345678`.

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

  Arista's `! device: agg-sw-02 (DCS-7280SR-48C6-M, EOS-4.32.1F)` header gets
  **no rule of its own**. It carries three values of three kinds on one line,
  introduced by nothing but their position, and a rule carries one family and
  one action — so a header rule would put the model and the release out of
  reach of the per-rule keys. `hardware-model` and `os-version` each read the
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

- **Scope: a rule can name the block it applies to, on any vendor.** Two kinds
  of block answer that question under one set of names — a JunOS brace stanza,
  and an IOS-style header at column zero plus the indented lines under it (any
  other unindented line ends it, including the bare `!`). The names are JunOS's
  own — `interfaces`, `vlans` and `patch-panel` — which is what lets one rule
  cover three dialects instead of three patterns. `patch-panel` is the first
  whose name is not JunOS's, because JunOS has no equivalent block to share it
  with.

  This is what makes `vlan-name` possible at all: a bare `name` line is a VLAN
  name in one block and a route-map name in another, and only the enclosing
  block can tell them apart. It also generalises `[[custom]] stanza`, which
  would otherwise reach JunOS only — `stanza = "interfaces"` scopes a custom
  rule to an IOS interface block too.

- **A `[vlans]` section, and the `vlan-name` rule.** The `name` under a
  `vlan <id>` block — and the one-line Catalyst `vlan <id> name <name>` form —
  is something a configuration can reach. On a service-provider access switch a
  VLAN name is frequently a service or customer identifier.

  ```toml
  [vlans]
  default = "pseudo"       #  name CUST000000000123  ->  name vlname-f11e24
  ```

  `pseudo` is the action to reach for. The configuration refers to a VLAN by
  name elsewhere, so a type-valid substitute keeps the output loadable where
  `<VLAN-f11e24>` would not. The pseudo token is `vlname-…` and deliberately
  not `vlan-…`: substitutions are idempotent, netredact recognises its own
  output, and `VLAN-100` is a name a real switch really has.

  **An SVI is not a VLAN definition.** `interface Vlan905` is an interface
  block, so its description belongs to `[interfaces]` and this rule never looks
  at it. Only a `vlan <id>` block is in scope, which is also what keeps a bare
  `name` line under a `route-map` or a `class-map` untouched.

- **An `[interfaces]` section, and the `interface-description` rule.** An
  interface description is the same selector as `[text] description`, split off
  by the block it sits in, because it is the one piece of free text with two
  incompatible audiences: a vendor TAC case is unreadable without the port
  descriptions — they are how the path through the box is written down — and a
  public post is unpublishable with them.

  ```toml
  [text]
  default = "redact"       # every other description goes
  [interfaces]
  default = "keep"         # except the ones the topology is written in
  ```

  The two rules **partition** the descriptions in a file rather than
  overlapping. They share one pattern, so if both could act on a line the
  second would render the first's marker again, count it twice, and let one
  override a `keep` the other asked for.

  It reaches an interface description in every dialect, because scope rather
  than syntax picks it out: IOS / EOS / NX-OS `interface Gi0/0` blocks, JunOS
  `interfaces { … }` stanzas and `set interfaces … description …` lines alike.
  Rendering follows `text` — a description is a description — so `hash` writes
  `<DESC-f11e24>` and `redact` writes `<DESCRIPTION-REMOVED>`.

- **A `[circuits]` section, with the `patch-name` and `pseudowire-name`
  rules.** Arista's `patch panel` names and the pseudowires under `mpls ldp`
  are something a configuration can reach. On a provider edge these are order
  references with a customer inside them — the material a ticket number is made
  of.

  ```toml
  [circuits]
  default = "pseudo"    #  patch acme_ORD000000111222  ->  patch circuit-f11e24
  ```

  `pseudo` is the action to reach for, for the reason `[vlans]` gives and one
  more besides: these names are **cross-referenced**. A `connector` line names a
  pseudowire that the `mpls ldp` section defines, so the two mentions have to
  come out as the same name or the file no longer loads. They do — the pseudonym
  is a function of the value, and both rules render through one prefix.

  ```
  patch panel
     patch circuit-aa62dc
        connector 1 pseudowire ldp circuit-e84f3c alternate circuit-fd5076
        connector 2 interface Port-Channel1.100      <- structure, untouched
  mpls ldp
     pseudowires
        pseudowire circuit-e84f3c                      <- the same name again
  ```

  The definition and the references of one pseudowire are two branches of
  `pseudowire-name` rather than two rules, deliberately: two rules could be
  given two actions and left pointing at nothing.

- **An advisory dialect label on every rule.** `netredact --list-rules` prints
  a `dialect` column and `docs/rules.md` carries the same label — `arista` on
  `patch-name`, `juniper` on `junos-type9`, seven rules labelled in all.
  `--list-rules` also prints the section a rule belongs to, the block it is
  scoped to, and the block it is scoped *out* of.

  **The label is documentation. Every rule is applied to every file**, and
  nothing netredact does depends on the vendor it reports. That is deliberate.
  What keeps `patch-name` off a JunOS config is that it has to be inside a
  `patch panel` block, and JunOS opens none — evidence in the file rather than
  a guess about the file. Vendor detection is a whole-file heuristic reading
  exactly the material `[platform]` deletes, and it answers `unknown` for the
  input this tool is handed most often: a pasted fragment with no header on it.
  A rule that fired only when the detector agreed would skip credential rules
  on a misread file silently, and `--strict` would still exit 0 — a fail-open
  path in a tool whose promise is fail-safe.

- **Vendor detection rests on several independent hints per vendor**, none of
  them the material the `platform` family destroys: the `! device:` header
  shape on its own, `! Command: show …` and `daemon TerminAttr` for Arista;
  `Building configuration` / `Current configuration :`, `! Last configuration
  change` and the NX-OS `9.3(5)` version shape for Cisco; the JunOS release
  string and `jinstall` / `junos-*` image names for Juniper. Detection reads
  the input and never the output. The legal values of `vendor` are the vendors
  the detector can actually detect, so a vendor netredact cannot detect is not
  a value you can set — `auto | arista | cisco | juniper`.

- **Custom rules** via `[[custom]]`. A pattern with capture groups declares its
  own targets — every group is acted on, everything outside them is preserved,
  so a rule can act on more than one value per line. A pattern without groups
  is treated as a prefix and the value matcher is appended centrally, so it
  never has to spell out how to match a quoted string, a JunOS `;` terminator
  or a trailing `## SECRET-DATA` comment. `%VAL%` exposes that matcher to
  hand-written groups. A custom rule joins a family and takes that family's
  action, or names its own with the optional `action` key.

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
  effective policy — at defaults, `secrets=redact, everything else kept` — then
  what changed, the verification result, and what netredact never looks at:
  ACL, route-map, prefix-list and policy names, AS numbers, VRF names and
  interface numbering. `verify` cannot flag a policy choice, so the policy line
  states it. `Result.kept_counts` carries the per-rule breakdown of what was
  left in place for callers that want it.

- **TOML configuration** with discovery (`--config`, `./netredact.toml`,
  `./.netredact.toml`, `$XDG_CONFIG_HOME/netredact/config.toml`, built-in
  defaults), per-key merging so a partial config overrides only what it names,
  validation that names the expected keys on a typo, and `--print-config`.

- **Six example profiles**, from secrets-only to public publication, plus a
  fully annotated reference config.

- **Library API:** `Config`, `sanitise_text`, `Result`. The library writes to
  no stream: problems come back on the `Result` or are raised, so reporting
  stays the CLI's job.
