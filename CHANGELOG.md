# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

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
