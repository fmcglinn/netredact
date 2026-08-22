# Library use

netredact is a normal importable package; the CLI is a thin wrapper over it.

```python
from netredact import Config, sanitise_text

cfg = Config.load()                       # searches the standard locations
result = sanitise_text(text, cfg)

print(result.text)
for finding in result.findings:
    print(finding)                        # L18 [type7-left] ...
```

## `Config`

```python
Config.load()                             # discover, or built-in defaults
Config.load("netredact.toml")             # explicit path
Config.load(path, search=False)           # no fallback search
Config.from_dict({"text": {"default": "hash"}})
Config()                                  # defaults, constructed directly
```

Build one in code without a file. Every section is a dataclass, and the value
you assign is an action string:

```python
from netredact import Config

cfg = Config()
cfg.text.default = "hash"                 # a whole family
cfg.policy.usernames = "pseudo"
cfg.ipv4.default = "keep"                 # every class not named
cfg.ipv4.other_unicast = "pseudo"         # one class
cfg.ipv4.pool = ["198.18.0.0/15"]
cfg.macs.nic = "pseudo"                   # the two halves are independent
cfg.identity.serial_number = "keep"       # one rule, by name
cfg.collection.rancid_diagnostics = "keep" # retain a RANCID wrapper
cfg.validate()                            # explicitly check after mutations
```

Construction validates initial values. Because section dataclasses remain
ordinary mutable objects, `sanitise_text` validates the complete `Config`
again before processing. Call `cfg.validate()` yourself when you want to check
a programmatically mutated configuration earlier. Every validation failure is
a `ConfigError`.

The actions and families are exported, so you can validate against them:

```python
from netredact import ACTIONS, ALLOWED, FAMILIES

ACTIONS            # ("keep", "pseudo", "hash", "redact")
FAMILIES           # ("secrets", "text", "identity", "platform", "interfaces",
                   #  "vlans", "circuits", "hostnames", "domains", "usernames",
                   #  "emails", "ipv4", "ipv6", "macs")
                   # the first seven have a section each, one key per rule
                   # (config.RULE_FAMILIES); only the next four are [policy]
                   # keys (config.POLICY_FAMILIES).
ALLOWED["secrets"] # ("keep", "hash", "redact") -- pseudo is illegal here
```

### Resolving an action

Three methods answer "what will happen to this?", which is also what the
sanitiser itself calls:

```python
cfg.action_for("emails")                  # a family -> "keep"
cfg.action_for_rule("description")        # the [text] key, else [text] default
cfg.ipv4.action("cgnat")                  # a class, with `default` applied
cfg.ipv4.any_active()                     # True if any class is not "keep"
cfg.platform.action("os-version")         # a rule, with `default` applied
cfg.family_of("serial-number")            # "identity"
```

### Errors

Invalid values raise `ConfigError` at construction, not at use, and the message
names the offender:

```python
>>> Config.from_dict({"secrets": {"default": "pseudo"}})
ConfigError: [secrets] default: pseudo is not available for secrets: use hash
for an opaque marker, or redact

>>> Config.from_dict({"identity": {"nosuch": "keep"}})
ConfigError: [identity]: unknown key(s) nosuch. Expected: certificate-block,
default, license-udi, pem-cert, serial-number, snmp-engineid, ssh-public-key

>>> Config.from_dict({"text": {"serial-number": "keep"}})
ConfigError: [text]: serial-number is a rule in [identity], not in [text]: set
it as [identity] serial-number

>>> Config.from_dict({"text": {"default": "shred"}})
ConfigError: [text] default: unknown action 'shred'. Expected one of keep,
pseudo, hash, redact

>>> Config.from_dict({"macs": {"oui": "hash", "nic": "pseudo"}})
ConfigError: macs: hash applies to the whole address, set both oui and nic
to hash
```

`cfg.to_toml()` renders the current configuration as a commented document —
this is what `--print-config` prints.

## `sanitise_text`

```python
sanitise_text(text: str, config: Config | None = None, *,
              salt: bytes | None = None,
              labels: Mapping[str, str] | None = None) -> Result
```

With no `salt`, a random one is generated and substitutes differ between calls.
Pass a stable salt for reproducible output:

```python
salt = Path("~/.config/netredact/salt").expanduser().read_bytes().strip()
for path in paths:
    result = sanitise_text(path.read_text(), cfg, salt=salt)
```

Passing the same salt across files is what makes a fleet pseudonymise
consistently. `Config.salt_file` is a CLI-oriented setting: `sanitise_text`
never reads, creates or writes that file. Library callers inject the bytes via
`salt=` explicitly.

Before normal collection and sanitization, detected RANCID input defaults to
removing non-configuration command sections. Set
`cfg.collection.rancid_diagnostics = "keep"` to bypass that preprocessing.

### Associated labels

Pass filenames, display names or other labels alongside their configuration:

```python
result = sanitise_text(
    text,
    cfg,
    salt=salt,
    labels={"filename": "EDGE-RTR-01_running.cfg"},
)
print(result.labels["filename"])
```

The mapping keys are caller-owned identifiers and stay unchanged. Its string
values use the exact same policy, salt, pseudonymiser and identities collected
from the configuration body. Matching is case-insensitive, longest-first and
aware of common filename separators, so an FQDN is handled before its domain
and a hostname next to `_` or `-` is still recognised. Recognisable IPv4,
IPv6 and MAC values are handled too.

Labels are associated metadata, not configuration input. They do not change
verification findings, counts, kept values, collisions or the re-identification
mapping. If sanitising any label fails, `sanitise_text` raises and no `Result`
containing the original labels is returned.

`result.label_replacements` is an immutable mapping from each supplied label
key to policy family to a tuple of rendered replacement values. It contains
only values actually substituted in that label: no originals and no values
whose action was `keep`. This lets a caller build a safe display token from a
known transformed hostname without retaining arbitrary unmatched filename
fragments.

## Nothing is printed

The library writes to no stream. Problems come back on the `Result` (`findings`,
`collisions`) or are raised — `ConfigError` for a bad configuration,
`PoolExhausted` for a pseudonym space too small for the input. Reporting is the
CLI's job, so `netredact` is safe to call from a web handler, a notebook or
another command-line tool without hijacking its output.

## Writing a file: the provenance marker

`sanitise_text` does **not** mark its output. The transformation preserves line
count, and a caller that hands `result.text` to a parser, a diff or a template
should get exactly the configuration and nothing else.

A marker is a property of the *artefact*, so the code that writes the file adds
it — which is what the CLI does, and what you should do if you are writing files
too. Without it, nothing in the file says where it came from and a second pass
cannot be refused:

```python
from netredact import Config, provenance, sanitise_text
import netredact

text = open("running-config.txt").read()
if provenance.is_marked(text):
    raise SystemExit("already sanitised -- work from the original")

result = sanitise_text(text, Config())
open("clean.txt", "w").write(
    provenance.apply_text(result.text, result.vendor, netredact.__version__))
```

`apply_text` is idempotent — a text that already carries a marker keeps exactly
one — and `sanitise_text` strips an incoming marker before the rules see it, so
its version number is never hashed and it is never counted as a change.
`Result.already_sanitised` reports what `is_marked` would have said about the
input.

### What the CLI does that `read_text` does not

`sanitise_text` takes and returns `str`, so everything about bytes on disk is
the caller's. The CLI does four things there that are worth copying if you are
writing over an input, because the shortcut in each case edits material nobody
asked netredact to touch:

- it decodes explicitly and treats a `UnicodeDecodeError` as a refusal.
  `read_text()` with `errors="replace"` turns an undecodable byte into U+FFFD
  in the file you are about to overwrite;
- it remembers whether the input used CRLF and puts the endings back, because
  universal-newline reading drops every CR;
- it encodes the payload itself and writes bytes, so no layer underneath gets a
  second opinion about newlines;
- it writes through a temporary in the same directory and then `os.replace`,
  which is atomic. A plain write truncates first, and an interruption then
  leaves a half-written file where that file was the only copy.

The CLI also refuses a file with a NUL byte anywhere in it or one whose first
non-blank line opens a PEM block — see
[when netredact refuses a file](getting-started.md#when-netredact-refuses-a-file).
Those verdicts are CLI policy, not library policy: `sanitise_text` sanitises
whatever text you hand it.

## `Result`

| Attribute | Type | Contents |
|---|---|---|
| `text` | `str` | The sanitised configuration. |
| `lines` | `list[str]` | Same, split. |
| `vendor` | `str` | `arista`, `cisco`, `juniper`, `mikrotik`, or `unknown`. |
| `already_sanitised` | `bool` | The input carried netredact's provenance marker, i.e. was itself output. The run still happened — you decide what that means — but any `pseudo` value in it has now been mapped twice. |
| `labels` | `dict[str, str]` | Sanitised associated filename/display-label values, keyed exactly as supplied. Empty when none were passed. |
| `label_replacements` | `Mapping[str, Mapping[str, tuple[str, ...]]]` | Immutable label key → family → rendered replacements. Contains no originals or kept values. |
| `counts` | `Counter` | Rule or family name → values substituted. A block or banner counts once, not once per line. |
| `kept_counts` | `Counter` | Rule or family name → occurrences deliberately left in place. The CLI report does not print this; see the recipe below. |
| `families` | `dict[str, str]` | Every key used in `counts` / `kept_counts` → its family, so you can group without re-deriving the rule table. |
| `policy_summary` | `str` | The policy in one line, e.g. `secrets=redact, everything else kept`. |
| `redactions` | `int` | How many values were destroyed: the rule-named families only (`config.RULE_FAMILIES`), since a substituted address or name still carries its equality relation. |
| `kept` | `dict[str, set[str]]` | Category → distinct values left in place, e.g. `{"ipv4.rfc1918": {"10.20.30.1"}}`. |
| `collisions` | `set[str]` | Real addresses kept that fall inside a pseudonym pool. |
| `findings` | `list[Finding]` | What the verification pass found. |
| `mapping` | `dict[str, dict[str, str]]` | Category → `{original: pseudonym}`. **The re-identification map.** |
| `removed_sections` | `list[RemovedSection]` | Collector audit entries with normalized `.command` and physically removed `.lines`; removed contents are never retained. |

`Finding` has `.line`, `.check` and `.text`, and a readable `str()`.

Descriptions are ordinary `text`-family rules, so they appear in `kept_counts`
under `description`, `acl-remark` and `login-message` like anything else.

## Recipes

**Refuse to write anything suspicious**

```python
result = sanitise_text(text, cfg, salt=salt)
if result.findings:
    raise SystemExit("\n".join(str(f) for f in result.findings))
out.write_text(result.text)
```

**Report what is still in the output**

The CLI report states the policy but does not enumerate what it kept. If you
want that breakdown — to work down as a file needs to travel further from the
business — build it yourself:

```python
for key, n in result.kept_counts.most_common():
    family = result.families[key]
    print(f"{n:5d}  {key:24} (family: {family})")
```

Remember that `findings` cannot tell you this. A kept family is a policy choice,
not a miss — see [verification](verification.md#what-it-cannot-do-judge-your-policy).

**Keep a re-identification map for your own use only**

```python
import json
Path("map.json").write_text(json.dumps(result.mapping, indent=2, default=list))
Path("map.json").chmod(0o600)
```

**Sanitise a whole directory consistently**

```python
from pathlib import Path
from netredact import Config, sanitise_text

cfg = Config.load()
salt = Path("fleet.salt").read_bytes()
for src in Path("configs").glob("*.cfg"):
    result = sanitise_text(src.read_text(), cfg, salt=salt)
    (Path("clean") / src.name).write_text(result.text)
    if result.findings:
        print(f"{src.name}: {len(result.findings)} finding(s)")
```

**Add a rule at runtime**

```python
from netredact import Config, CustomRule, sanitise_text

cfg = Config()
cfg.custom.append(CustomRule(name="acme-shared-key",
                             pattern=r"\s*acme\s+shared-key\s+",
                             family="secrets"))
result = sanitise_text(text, cfg, salt=salt)
```

A pattern with no capture groups is a prefix; one with groups declares its own
targets; `%VAL%` expands to the value matcher as a group. Same rules as
`[[custom]]` in the file — see
[configuration](configuration.md#what-the-shape-of-the-pattern-means).

## Lower-level pieces

Useful if you are building something more specialised.

```python
from netredact import (
    Sanitiser,           # the stateful transformer; one per file
    Pseudonymiser,       # HMAC-derived substitutes; renders every action
    verify,              # run the checks over any list of lines
    detect_vendor,
    RuleCatalogue,       # immutable rule inventory and traversal
    check_names,         # every verification check name
    classify_v4,         # address -> class name
    classify_v6,
    V4_CLASS_NAMES,
    V6_CLASS_NAMES,
    REMOVED,             # the "<REMOVED>" constant
)
```

```python
>>> classify_v4("100.64.5.9", frozenset())
'cgnat'
>>> catalogue = RuleCatalogue.builtins()
>>> next(info.family for info in catalogue.inventory()
...      if info.name == "serial-number")
'identity'
>>> len(catalogue.inventory())
45
```

`RuleCatalogue.inventory()` exposes immutable descriptive metadata. Compiled
patterns, scope state and the different execution forms stay behind the
catalogue interface. `catalogue.configured(cfg.custom)` returns a new catalogue
with custom rules merged in; it does not mutate the built-ins.

`Sanitiser` is two-pass and single-use — build one per file:

```python
san = Sanitiser(cfg, salt=salt)
san.collect(lines)          # learn this device's hostnames, domains, users
out = san.run(lines)        # transform
```

`Pseudonymiser.render(key, action, value)` is the single entry point for every
substitution, where `key` is a rule or family name. It is idempotent for `hash`
and `redact`; a pseudonymised address or MAC is not recognisable as netredact's
own output by design, so re-running over already-pseudonymised addresses re-maps
them.
