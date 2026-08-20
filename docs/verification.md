# Verification

After transforming, netredact re-scans **its own output** and reports anything
that still looks sensitive, with line numbers.

```
  VERIFY: 2 line(s) a human should look at
    L18 [type7-left] server-private 10.0.0.1 key 7 121A0C041104
    L42 [credential-left] weird-vendor auth-token AAAAB3NzaC1yc2EAAAA
```

## What it is for

netredact is rule-based. It knows the credential syntax it has been taught, and
a real config will eventually contain something it has not seen. The
verification pass is the backstop for exactly that case: it looks for the
*shape* of a secret rather than the keyword that introduces it, so it can catch
a leak that every rule missed.

It earns its keep. Both `type7-left` and `credential-left` above are real misses
found this way during development, not hypotheticals.

## What it cannot do: judge your policy

**Verify cannot flag a policy choice, and it is important to understand why.**

Suppose you leave `[text] default = "keep"`, which is the default, and the output
still contains `description Customer ACME - SVC-88412`. Is that a finding? An
unconditional text check would fire on that line for every config at stock
defaults, which is noise, not a warning. A conditional one would never fire,
because keeping is the policy. Neither shape of check can help: the material is
in the output *because you asked for it to be*.

So `--report` keeps the two questions apart:

- **`policy`** answers *what did I ask for?* — and by implication what was left
  behind, since a family that is not named as acting was kept. Whether the file
  is fit to send is a judgement about that line, not about `VERIFY`.
- **`VERIFY`** answers a narrower question: *is there credential-shaped material
  in the output?* — including material no rule recognised.

A clean `VERIFY` line therefore means "nothing known was left behind", not "this
file is safe to publish".

## The three kinds of check

The full table, with the gate on each check, is in the
[rule reference](rules.md#verification-checks).

### Unconditional — credential shapes

`crypt-hash-left`, `junos-type9-left`, `type7-left`, `long-hex-left`,
`long-base64-left`, `credential-left`, and `pem-left` for a private key or DH
parameter block.

These fire **regardless of policy**. If you set `[secrets] default = "keep"`, or
`[secrets] enable-secret = "keep"`, the output still fails `--strict`:

```
$ netredact config.txt --strict        # with [secrets] default = "keep"
  VERIFY: 19 line(s) a human should look at
    L9 [crypt-hash-left] enable secret 5 $1$mERr$M6KsMCsLPnvvKmnZkH3xF/
    L9 [credential-left] enable secret 5 $1$mERr$M6KsMCsLPnvvKmnZkH3xF/
    L10 [type7-left] enable password 7 070C285F4D06
    L10 [credential-left] enable password 7 070C285F4D06
    ...
$ echo $?
2
```

That is deliberate and must not regress. It is what makes the secrets-only
default defensible: whatever the configuration says, a file that still carries
a password is not quietly declared clean.

### Conditional — the material you may have chosen to keep

`email-left`, `ipv4-left`, `ipv6-left`, `ssh-key-left`, and the *certificate*
half of `pem-left`.

Each of these runs only when its relevant resolved action is not `keep` — e-mail
on `[policy] emails`, addresses per class in `[ipv4]` / `[ipv6]`, SSH keys on
`[identity] ssh-public-key`, and certificates on `[identity] pem-cert`. A rule
override activates its check even when the section's `default` remains `keep`.
Otherwise these checks would fire on every line of a config you deliberately
chose not to touch, and the report would be unreadable for exactly the users who
read it most carefully.

The address checks use the **same classification as the sanitiser**, so they
report genuine misses — an address whose class you act on that nevertheless
survived — rather than second-guessing with a different rule. Addresses already
inside a pseudonym pool, inside `keep_networks`, or equal to a redaction
constant are recognised as netredact's own output, not as input.

### Shape-only — blinded to what you kept on purpose

`ssh-key-left`, `pem-left`, `long-hex-left` and `long-base64-left` know a
*shape*, not a meaning. A 40-character base64 run is an authorised SSH key, a
certificate body, an asset tag or a leaked credential, and the regex cannot tell
which.

So when a rule in the `identity` or `text` family has the action `keep`, these
four are blinded to the spans that rule matches — including the body of a kept
certificate or key-string block. Otherwise a policy that did exactly what it was
told would fail `--strict`, and the `policy` line already says that material
was kept.

**A kept `secrets` rule never blinds anything.** That is the whole point of the
safety net, and it is the difference between "you kept a certificate" and "you
kept a password".

## Suppressed by default

Some things look like findings but are not, and are filtered before any check
runs: netredact's own placeholders and `<PREFIX-tag>` markers, `no password`,
`service password-encryption`, `key-chain`, `## SECRET-DATA`, the pseudonymous
e-mail form — and, importantly for any service-provider config, BGP communities
in all their forms (`set community`, `community X members`,
`community 64512:666`, `community-list`). Without that last group the report
would be unreadable: on one real provider config, 44 of 46 findings were BGP
communities.

## Tuning it

Switch off a check that does not suit your environment:

```toml
[verify]
disable = ["long-hex-left"]
```

Teach it that a token shape of your own is expected:

```toml
[verify]
ignore_patterns = ['\bACME-ASSET-[0-9A-F]{26}\b']
```

Prefer `ignore_patterns` to `disable`: it keeps the check working for everything
except the shape you named. An unknown name in `disable` is an error, not a
silent no-op.

If you find yourself ignoring a real credential shape, write a
[custom rule](configuration.md#custom--rules-of-your-own) to destroy it instead.

## In a pipeline

```bash
netredact config.txt --strict -o clean.txt || exit 1
```

Findings print to stderr whether or not you asked for `--report`, so a failing
exit code always comes with the lines that caused it.

`--strict` (or `verify.strict = true`) exits `2` when anything is found. Use it
in CI or in a wrapper script so an unrecognised credential syntax stops the job
rather than shipping quietly.

Remember what that gate does and does not cover: it is a credential gate, not a
privacy gate. A run can exit `0` with every customer name, address and hostname
still in the file, because that is what the policy asked for. If you want CI to
enforce more than "no credentials", enforce it by pinning the profile — commit
the `netredact.toml` you intend and pass it with `-c`.

## Reading a finding

Findings are advisory, and some need judgement:

- `credential-left` on a line ending in `<REMOVED>` — a false positive worth
  reporting as a bug; the check tolerates encoding hints between the keyword and
  the placeholder, but syntax varies.
- `long-hex-left` / `long-base64-left` — often a certificate serial, an engine ID
  or a hardware identifier. Check what it is; if it is a secret, add a custom
  rule; if it is yours and harmless, add an `ignore_patterns` entry.
- `ssh-key-left` / `pem-left` — if `identity` acts and one of these fires, a key
  or certificate got past the block handler. Worth reporting.
- `ipv4-left` / `ipv6-left` — a genuine gap: that class acts and the address
  still moved through untouched. Worth reporting.

## What it can never see

- A secret with no recognisable shape. A short plaintext password with no keyword
  near it is indistinguishable from a hostname.
- Anything in the categories that are
  [never touched](README.md#never-touched). An ACL named `ACME-CORP-IN` will
  never be reported. Nor will a VLAN name, a circuit name or an interface
  description that `[vlans]` / `[circuits]` / `[interfaces]` were told to keep
  -- a value the policy kept on purpose is not a miss.
- Meaning. `description Bob's Bakery` is a customer name to you and ordinary
  text to a regex.

Read the output before you send it anywhere.
