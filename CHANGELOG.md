# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [0.1.0] - 2026-08-31

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

- **Fifteen families, and 73 rules across them.** Eight families are made of
  named rules — `secrets` (43), `identity` (9), `text` (8), `platform` (4),
  `interfaces` (4), `circuits` (2), `locations` (2) and `vlans` (1). Four are
  the names the collect pass learns rather than rules — `hostnames`,
  `domains`, `usernames`, `emails`. Three are value spaces with their own
  partition — `ipv4` (10 address classes), `ipv6` (11 classes) and `macs`
  (OUI and NIC halves, independently actionable).

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
  sweep with nothing to keep in step by hand. Every one of the 73 keys is
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

- **73 redaction rules** across keyword patterns, inline blobs and multi-line
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

- **An opt-in report** (`-R` / `--report`, off by default so a pipeline gets
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

- **Fortinet FortiOS / FortiGate support.** A FortiOS config states nothing
  twice: the grammar is `config <path>` … `end` with `edit <id>` … `next`
  inside it, and every value is a bare `set <attribute> <value>` whose meaning
  comes from the block above it rather than from the line. So the sanitiser
  tracks that block as a fourth kind of scope, sharing JunOS's names wherever
  the grammars share the block -- `config system interface` is scope
  `interfaces`, `config system snmp community` is scope `snmp` -- and one new
  rule, `fortios-secret`, covers every credential the platform has: `password`,
  `passwd`, `psksecret`, `ppk-secret`, `auth-pwd`, `priv-pwd`, `passphrase`,
  `api-key`, `secret` and `key`, with or without the `ENC` token FortiOS marks
  its encrypted values with. The keyword has to be the first token after `set`,
  which is what keeps the two ordinary words in that list off a JunOS `set`
  path where `bare-secret` and `quoted-key` own them. `fortios-snmp-community`
  selects a `set name` inside an SNMP community block and nowhere else -- a
  bare `set name` is everywhere in FortiOS, so the block is the whole of the
  evidence -- and `fortios-interface-alias` puts a port's `set alias` in the
  `interfaces` family beside its description. The `#config-version=` header is
  split across the families that own its parts, as Arista's `! device:` line
  already was: the model to `hardware-model`, the release, its build and the
  `#buildno=` / `#branch_pt=` lines to `os-version`, and the administrator in
  its `user=` field to `usernames`. `location`, `contact`, `description` and
  the hostname sources cover FortiOS's spellings of those fields
  (`set location`, `set contact-info`, `set comments`, `set hostname`), and the
  `set alias` in `config system global` is collected as a second name for the
  device itself -- so it and the hostname render as one pseudonym. An admin,
  API, local or SNMPv3 user's `edit "<name>"` is collected as a username, which
  is what makes one pseudonym reach both the account and the header that names
  it. Detection is reporting-only as ever, and its FortiOS hints are chosen to
  survive sanitising: the header it reads is exactly what `platform` deletes,
  so the `config` / `edit "` / `next` shapes carry the answer once it is gone.
  A bare `end` is deliberately not one of them -- an IOS running-config ends
  with one.

- FortiOS credentials are covered by the verification pass, which would
  otherwise have a silent blind spot over them: `psksecret` and `ppk-secret`
  end in a word `credential-left` knows, but the check reads whole words, so
  an IPsec pre-shared key, an SNMPv3 secret and an NTP `set key` could leave
  the tool in the device's encrypted form with **no finding at all** and
  `--strict` exiting 0. The keyword list carries the FortiOS spellings, and
  `key` / `secret` -- too
  ordinary to name unqualified -- are recognised in the `set <attribute>` shape
  that narrows them. `ENC` is one of the encoding hints the rules and the
  check share, so a FortiOS line whose credential netredact destroyed is not
  reported as a leak by the check that exists to catch them.

- A command-line argument may be a directory, walked recursively, so a backup
  tree can be sanitised in one run: `netredact backups/ -r`. The walk skips
  what plainly is not a configuration -- dot-files, dot-directories pruned
  whole rather than descended into, symlinks of either kind, anything with a NUL
  byte anywhere in it, and anything whose first non-blank line opens a PEM block
  -- because netredact would rewrite one of those as text rather than sanitise
  it, and under `-r` there is no second copy. It does not filter on extension,
  because a RANCID repository names its files after the devices. Each verdict is
  counted on stderr with a few of the paths behind it, so a run says how much it
  left out and what kind of thing it was. A file named on the command line is
  still attempted whatever it looks like, since naming it is the instruction;
  the exception is `-r`, where a named binary or PEM file is refused by name,
  because that is the only mode in which the original does not survive. Under
  `-o` the tree is mirrored rather than flattened, so two zones' identically
  named files cannot land on top of each other. `-o` is a directory whenever
  the command line says it can only be one -- an input is a directory, several
  inputs were named, or the path ends in a separator -- and it is created on the
  first write, along with the zone directories under it; only an existing regular
  file refuses such a run, and it refuses before anything is written. One named
  file with one `-o` path still names a file, so a typo in it is reported rather
  than built into a directory chain.
  Two inputs that would write to one destination are a usage error instead of a
  silent overwrite. A directory with no destination at all is a usage error
  too: a whole tree concatenated onto stdout is never what naming the directory
  meant. `-r` / `--replace` writes each file back over itself and cannot be
  combined with `-o`.

- A file comes back the way it arrived. Input is decoded as UTF-8, and a file
  that is not valid UTF-8 is refused rather than decoded lossily, because
  `errors="replace"` would put U+FFFD in the only copy under `-r`; `--force`
  accepts the substitution. CRLF endings are preserved: the rules and the
  verifier work a line at a time, so the endings are normalised for them and put
  back on the way out. Every output is written through a temporary in the same
  directory and then moved into place, which is atomic, so a full disk or a
  signal cannot leave a half-written configuration where that file was the only
  copy -- and no temporary survives a failure. A file that cannot be read or
  written is reported with the reason the operating system gave and the run
  exits 1, rather than being counted as a skipped non-configuration and reported
  as success with the secrets still in place. The rest of the run still happens,
  because a tree abandoned part-way -- some files replaced, some not, and no
  statement of which -- is the worst outcome available.

- Sanitised output says so. Every file the CLI writes carries one comment line
  at the top -- `! netredact-sanitised <version> ...`, or `#` in JunOS grammar --
  and netredact refuses to sanitise a file that already has one, because a
  second pass re-maps `pseudo` substitutes and with `-r` the original is
  already gone. `--force` overrides that refusal and every other one netredact
  makes -- a named binary or PEM file under `-r`, and input that is not valid
  UTF-8 -- so there is one flag to reach for and one thing it means: process an
  input netredact would otherwise refuse. `marker = false` switches the
  line off and takes the guard with it. The marker carries the tool and the
  version and nothing else: no timestamp, no counts, nothing that could hint
  at what was found. `sanitise_text` does not add it -- the transformation
  preserves line count, so writing the marker belongs to whoever writes the
  file (`netredact.provenance`), while `Result.already_sanitised` reports
  whether the input had one.

- MikroTik RouterOS `/export` configurations. RouterOS spells every argument as
  a `key=value` pair on an `add` / `set` command, so four new `secrets` rules
  match unanchored: `routeros-password` (`password=`, `passphrase=`, and the
  hyphenated `authentication-password=` / `encryption-password=`),
  `routeros-secret`, `routeros-pre-shared-key` (`pre-shared-key=`,
  `wpa-pre-shared-key=`, `wpa2-pre-shared-key=`) and `routeros-snmp-community`.
  The `=` is what keeps each of them off the space-form rule of the same name
  and that rule off them, so every value still has exactly one owner. A bare
  `name=` is deliberately NOT a secret outside `/snmp community`: everywhere
  else in an export it names an interface, a bridge or a firewall rule. All of
  these are *searched* rather than matched, because one command line can carry
  two pairs belonging to a single rule -- a wireless security profile routinely
  sets `wpa-pre-shared-key=` and `wpa2-pre-shared-key=` on one line, and a rule
  that fires once per line took the second and left the first passphrase
  standing next to a marker saying the line had been dealt with.

  WireGuard is covered by three of them: `routeros-private-key` takes the
  interface's own key, `routeros-pre-shared-key` admits RouterOS's second
  spelling of the same field -- `preshared-key=`, with no inner hyphen, beside
  the wireless `wpa2-pre-shared-key=` -- and `routeros-public-key` is
  `identity`, not `secrets`, because a public key is published on purpose. It
  still needs a rule: 44 characters of base64 is exactly what
  `long-base64-left` looks for, and the check cannot tell an authorised key
  from a leaked one, so a config that kept its peers failed `--strict` until a
  named `identity` rule claimed the span for the check to be blinded to.

  A qualified key name is still that key: RouterOS writes `ipsec-secret=`,
  `authentication-password=` and `wpa2-pre-shared-key=` and means the same field
  each time, so the credential rules admit any hyphenated prefix. `name=` and
  `comment=` deliberately do not, because there the guard is the point --
  `default-name=ether1` names a factory default, not something an operator
  chose. Getting that asymmetry wrong was silent in the worst direction: a bare
  `secret=` did not merely fail to help with `ipsec-secret=`, it refused it.

  `routeros-license-id` reads RouterOS's licence identifier under both names it
  goes by: the `/export` header writes `# software id = ` on some versions and
  platforms and `# system id = ` on others, and `/system license print` writes
  `system-id:`. One value, one meaning, one rule. The `:` or `=` is required,
  because `system-id` is IS-IS and FabricPath grammar too and neither carries a
  separator -- the same margin `hardware-model` keeps.

- A new conditional check, `routeros-header-left`, gated on `[identity]`
  acting. Every other check knows a shape or a keyword, and a value in a
  RouterOS `/export` provenance header has neither -- a licence id is an opaque
  word -- so a header key that no rule knew about left the tool with nothing
  reported at all. Silence is the one outcome this project treats as worse than
  a miss, so this check's evidence is structural instead: the value sits in a
  header comment, and no rule claimed it. Ownership is asked of the rule table
  rather than of a list of key names written out in the verifier, so a key that
  gains a rule leaves the check the same day, and values netredact itself wrote
  are recognised from the marker and constant tables.

  `comment=` is RouterOS's `description`, and it is split by scope in exactly
  the same way: `interface-comment` in `[interfaces]` inside a `/interface …`
  section, `comment` in `[text]` everywhere else, the two made disjoint so no
  comment is matched by both. The `/export` header is read by the rules that
  already own each kind of value -- `hardware-model` and `serial-number`
  admit a `#` comment leader alongside `!`, and `os-version` reads the release
  out of `by RouterOS 7.15.3` -- plus one new `identity` rule, `software-id`,
  because a licence id is tied to the one device and not to a production line.
  `location=` and `contact=` reach the rules of those names.

- A label `name=` is free text, and it is split into two rules by scope exactly
  as `description` is: `routeros-peer-name` in `[interfaces]` inside a RouterOS
  `/interface …` section, `routeros-object-name` in `[text]` everywhere else.
  On a provider config this is where a customer and an order reference live --
  `name="Cust: 4G - Quantum - BPI000000562604"` on a `/routing bgp connection`.

  Both are scoped to `object-labels`, which is the one scope named for a
  property rather than a block, and it earns that: it marks the sections whose
  `name=` nothing else refers to, currently `/interface wireguard peers` and
  `/routing bgp connection`. That distinction cannot be read off the line, the
  key or even the value -- only off the section -- and it is the difference
  between a rule that is safe and one that breaks the file. An interface, a
  bridge, a BGP template, an OSPF area or an address list is named so that
  another line can point at it (`interface=ether1-transit`,
  `area=backbone-v2`), so acting on such a declaration alone would break the
  configuration AND leak the value through every reference that kept it. The
  list is therefore the guard rather than a convenience, and the way to cover a
  referenced name is to carry its references in the same rule, as
  `pseudowire-name` does, not to add it here.

  A RouterOS section opens several scopes where its path nests, which is
  what lets a peer's `comment=` still be an interface comment while its `name=`
  is a rule of its own.

- `[operational-names] routing-filter-chain` acts on RouterOS routing-filter
  chain names: the `chain=` declaration under `/routing filter rule`, and the
  `input.filter=` / `output.filter-chain=` references on a `/routing bgp
  connection`, including RouterOS's abbreviated `.filter=` and `.filter-chain=`
  forms. On a service-provider router a chain name frequently carries the
  operator or the customer it describes.

  One type carries the declaration and every reference, which is the point: the
  tag is a function of the value, so a chain named in one section and used in
  another still name the same thing afterwards. Two types could be given two
  actions and the file would no longer load -- the argument `pseudowire-name`
  makes for being one rule.

  The declaration is scoped to `/routing filter rule` and nothing else, because
  `chain=` is firewall grammar too and `input`, `forward` and `srcnat` are
  RouterOS's own names: substituting one of those would break the file.
  `OperationalNames` tracks the RouterOS section itself, the way it already
  tracks JunOS brace depth, so a scoped declaration needs nothing from its
  caller. `input.allow-as=1` is a count and is left alone by this and by
  `[as-numbers]` alike.

- `[as-numbers]` reaches RouterOS's spellings. RouterOS writes an ASN as a
  `key=value` pair and RouterOS 7 abbreviates a nested property to a leading
  dot, so one `/routing bgp connection` line carries `as=65501` and `.as=65500`
  -- the latter being `remote.as=`. The existing patterns require whitespace
  after the keyword, so they reached none of them, not even the `remote-as=`
  RouterOS 6 wrote and whose keyword they already knew: an explicit
  `as-numbers` policy was silently doing nothing on a RouterOS file. The
  boundary in front of the bare two-letter `as` key is the safety margin, so a
  key that merely ends in those letters -- `alias=`, `class=`, `bias=` -- keeps
  its value.

  The verifier keeps no list of ASN grammars of its own: `as-number-left` asks
  `operational.asn_candidates`, i.e. the transformation itself. Two lists that
  drifted would go quiet about precisely what the rule failed to reach, which
  is the direction that matters.

- `routeros-auth-key` takes RouterOS's `auth-key=` and `authentication-key=`,
  e.g. on `/routing ospf interface-template`. It is spelled out rather than
  reached by a generic `key=`, which would also claim `public-key=` and put two
  rules with two families on one span; `auth=md5` and `auth-id=1` on the same
  line are a method and an index, and the `-key` is what tells them apart. An
  OSPF key is neither long enough nor hex enough for a shape check, so the
  keyword is in `credential-left` as well: without it a kept key would leave
  in silence.

- A third kind of block for the scope names the rules use: a RouterOS
  `/export` section, which a `/`-prefixed line opens and the next one ends.
  Where more than one dialect has the block the name stays JunOS's own, so one
  rule reaches all of them -- a `/interface ethernet` section is `interfaces`
  exactly as an `interface Gi0/0` block and an `interfaces { … }` stanza are.
  A section only RouterOS has keeps its own name: `snmp-community`,
  `system-identity`, `user`, `ppp-secret`. `/export terse` repeats the whole
  path on every command line and is scoped from the line itself, the way a
  JunOS `set` line is. Those own-name sections are what make a RouterOS
  `name=` decidable at all: it is the device's own name under `/system
  identity`, a login under `/user`, a subscriber's account under `/ppp secret`,
  a community string under `/snmp community`, and an object name everywhere
  else -- so the collect pass tracks the section too. None of this is a
  vendor gate: a file with no such section in it cannot reach the rules that
  need one.

- A wrap is undone with NOTHING in its place, not with a space. `/export` wraps
  at whatever column it runs out of room at, which is regularly in the middle of
  a token and even in the middle of a word inside a quoted string: a
  `/routing filter rule` carries `{set bgp-path-\` + `prepend 1; accept}` as one
  `bgp-path-prepend`, and `set bgp-large-communities orig\` + `in-inband-mgmt`
  as one `origin-inband-mgmt`. Joining those with a space would not merely
  reformat the file, it would corrupt it -- `bgp-path- prepend` is not a keyword
  and the list name becomes two words, so the output does not load. Where a
  separator is wanted the export has already written it before the backslash, so
  the line up to the backslash is kept verbatim, trailing space and all, and
  only the continuation's indent is dropped. A literal `\n` escape inside a rule
  string survives byte for byte.

- A wrapped RouterOS command is joined into one logical line before any rule
  runs, and written back out unwrapped. `/export` breaks a long command with a
  trailing `\` and continues it indented on the next line, and a rule sees one
  line at a time -- so a wrapped `wpa2-pre-shared-key="…` had the tail of its
  value carried past every rule that could recognise it: the value matcher
  could not close the quote, a marker landed on the opening fragment, and the
  rest of the passphrase left the tool with `--strict` reporting success. Only
  an `add` / `set` / `remove` at the start of a line is read this way, because a
  trailing backslash means nothing in IOS or JunOS but is perfectly ordinary in
  an ASCII-art banner. The line count of the output changes, as it already can
  where a block body or a banner collapses.

- `mikrotik` is a value `vendor` accepts and a value the detector answers,
  from `by RouterOS` and `# software id =` as decisive markers plus the section
  paths and `set [ find … ]`. Both decisive markers keep their keyword when the
  release and the id are removed, so detection still works on redacted output.
  The provenance marker comments with `#` on a RouterOS file, as it does on
  JunOS.

- `[operational-names] label-switched-path` acts on JunOS MPLS LSP names --
  the `label-switched-path` and `static-label-switched-path` declarations and
  the `lsp-next-hop` references to them -- in both the `set` and curly-brace
  syntaxes and at any depth, so an LSP declared inside a `groups` stanza is
  covered on the same terms as one under `protocols mpls`. Named paths and
  p2mp trees are separate namespaces and stay out of scope.

- `[operational-names] configuration-group` acts on JunOS configuration group
  names: the `set groups NAME` declaration, the names a `groups { ... }` block
  declares as its direct children, and every `apply-groups` /
  `apply-groups-except` reference, bare or in a bracketed list. Configuration
  nested inside a group is acted on by the selector that owns it, not treated
  as part of the name.

- Library callers can associate labels such as filenames with a sanitising run.
  `Result.label_replacements` exposes immutable, replacement-only metadata so
  callers can derive safe display tokens without retaining unmatched label
  fragments or re-identification data.

- RANCID collection preprocessing removes diagnostic command sections,
  collector prompts, and device metadata before normal sanitization. Unknown
  commands fail closed; `[collection] rancid_diagnostics = "keep"` restores
  the unstripped wrapper. Reports expose normalized command names and removed
  line counts without retaining diagnostic contents.

- `authentication password <secret>` is a credential wherever it sits on the
  line, not only where `password` opens it. `bare-password` is anchored, so it
  only ever saw the hierarchical form; JunOS subscriber management writes the
  same credential at the end of a long `set` path -- under `dhcp-local-server
  dual-stack-group <name> authentication` and under `interfaces <ifd>
  auto-configure stacked-vlan-ranges authentication` -- and those lines left the
  tool in cleartext with `--strict` exiting 0. The `authentication` qualifier is
  what keeps the unanchored form off the knobs: `no password`, `service
  password-encryption` and `aaa authentication password-prompt` are untouched.

- New `identity` rule `script-checksum` selects the digest a script file is
  pinned to: `set system scripts {commit,op,event} file <name> checksum sha-256
  <hex>`, the same tail under `event-options event-script file`, and the
  hierarchical spelling of both. It is not a credential, but a 64-character hex
  run trips `long-hex-left` and `long-base64-left`, which would fail `--strict`
  on configurations with no secret left in them. Filed under `identity` because
  a checksum ties the file to one exact script on one device: kept at defaults
  and not reported, and reachable by `[identity] script-checksum` when the
  policy wants it gone. It renders as `<CKSUM-…>` / `cksum-…`.

- `ssh-public-key` finds a key blob whose algorithm token is not glued to it.
  IOS renders an authorised key as `key-hash <alg> <fingerprint> <blob>`, where
  requiring the algorithm immediately before the blob would leave the key in
  place and let only `long-base64-left` speak -- a reported miss rather than a
  decision. A second branch recognises the blob by its own base64 type-string
  header, the signature `ssh-key-left` uses; both read it from one constant, so
  the rule and the check cannot disagree, and it covers
  `ecdsa-sha2-*` as well as `ssh-rsa` / `ssh-dss` / `ssh-ed25519`.

- FortiOS coverage is widened past the attribute list. `fortios-secret` names
  the credential keys FortiOS has always had, which is the right shape for
  those; two rules cover the ones it has not. `fortios-encrypted` reads the
  `ENC` marker alone, so a key no release has invented yet is still a
  credential the day it appears, and `fortios-credential-key` reads the
  qualified spelling without the marker -- `group-password`, `key-passphrase`,
  `password2` -- which is what a typed or templated configuration carries where
  a backup carries `ENC`. All three are disjoint by construction: two rules
  matching one span would splice twice and the second would hash the first's
  marker. The `\d*\s+` guard is what keeps the second off the knobs, because
  `set password-policy status enable` has a hyphen where `set password2
  <secret>` has a space. `fortios-object-name` takes a `set name` in a block
  whose names nothing references -- a firewall policy, addressed by its `edit
  <id>`.

- `FortiBlocks` does three things. A path may open SEVERAL scopes, because
  `config system interface` answers two questions at once -- what a `set
  description` in it is, and what its `edit` names. `config system snmp
  community` opens a `snmp-community` scope of its own, since `config system
  snmp sysinfo` is `snmp` too and a `set name` there is not a community string.
  And the header recogniser is permissive: it asks only what FortiOS itself
  asks, that the line begins with the word `config`. The two ways of being
  wrong are not symmetric -- a header that is missed unbalances the stack and
  can leave a secret in the file, while a line wrongly taken for a header
  over-applies a rule and cannot -- and a redaction tool takes the second.
  `config-register 0x2102` is not a section: a hyphen follows the word, not
  whitespace.

- `[operational-names] fortios-interface` acts on FortiOS interface names,
  carrying the `edit` declaration and every reference in ONE type -- `set
  interface`, `srcintf`, `dstintf`, `extintf`, `associated-interface`,
  `outgoing-interface`, `set member` inside the four interface-ish blocks, and
  `set device` under `config router static`. A list is a run of quoted names on
  one line and every entry moves. The tag is a function of the value, so the
  declaration and its references render alike and the file still loads.

  Names the platform owns stay: the factory ports, the pseudo-interfaces, and
  the `any` wildcard, which means *every* interface -- substituting it would
  change what a policy does. That is `_RESERVED_VRFS` reasoning, and it keeps
  true the report's promise that interface numbering is never scrubbed. This
  type defaults to `keep` and carries more risk than the others: coverage is a
  list of reference spellings rather than a closed grammar, and a spelling not
  on it leaves a reference naming an interface that no longer exists.

- A FortiOS RANCID capture is segmented and stripped. `show full-configuration`
  and the bare `show` join the allowlisted configuration commands, and FortiOS
  prompts -- `fw-edge-01 # show`, with the VDOM optionally in brackets -- are
  recognised, which `_PROMPT` never did because it requires a `user@host` that
  FortiOS does not write. They are boundaries only and never evidence for
  detection, and the comment leader is required: detection is what licenses
  deleting everything unrecognised, so a banner body containing `a # b` must not
  be able to turn a configuration into a capture.

- A kept SNMP community is reported in BOTH the grammars that give the line no
  keyword: RouterOS's `name=` under `/snmp community` and FortiOS's `set name`
  under `config system snmp community`. The block is the only evidence the
  value is a community string, so `credential-left` -- which reads one line at
  a time -- cannot see it on the line alone. `secrets = "keep"` is allowed; passing
  `--strict` over it is the fail-open these checks exist to prevent.

- `credential-left` ignores two shapes that carry no credential. A section path
  is all path -- a FortiOS `config` line, like the `/`-prefixed RouterOS path
  beside it -- so `config system replacemsg auth "auth-password-page"` and the
  `auth-cert-passwd-page` next to it are not read as surviving passwords; the
  lines UNDER the header are judged on their own. And an empty credential is
  nothing to report: RouterOS writes an unset key as `auth-key=""`, on a
  `/routing ospf interface-template` with no authentication on it, and `''` and
  the FortiOS `set <key> ENC ""` are the same case, as is an empty SNMP
  community in either grammar. This is the judgement `RANCID_SENTINEL` makes
  for `## SECRET-DATA`: evidence that the value is not there beats the keyword
  that introduces it. The empty value ends only its own match, so `auth-key=""
  password=hunter2` still fires on the second keyword -- which is what keeps
  the exemption from being a way to hide a real credential behind an empty one.
