# netredact documentation

Strip secrets and identifying data out of Cisco IOS/IOS-XE/NX-OS, Arista EOS,
Juniper JunOS and Fortinet FortiOS configurations.

## Start here

- **[Getting started](getting-started.md)** — install, first run, and reading the
  report so you know what is still in the file.
- **[Configuration reference](configuration.md)** — every section and key, and
  how files are discovered.
- **[Example configurations](examples/)** — six profiles, from secrets-only to
  public publication.

## Reference

- **[Address classes](address-classes.md)** — the IPv4 and IPv6 taxonomy that
  `[ipv4]` and `[ipv6]` act on. *Generated from source.*
- **[Rule reference](rules.md)** — every rule with its family and the block it
  is scoped to, and every verification check. *Generated from source.*
- **[Verification](verification.md)** — what the output pass catches, what it
  structurally cannot, and how to read its findings.
- **[Library use](library.md)** — the module API.
- **[The actions model](design/actions-model.md)** — the reasoning behind the
  configuration model. Read this if you want to know *why*, not *how*.

## The one thing to understand first

Configuration selects **a part of the config** and gives it an **action**:

| Action | Equality relation | Output |
|---|---|---|
| `keep` | — | untouched |
| `pseudo` | preserved | a type-valid substitute; the output still loads onto a device |
| `hash` | preserved | an opaque marker such as `<DESC-f11e24>` |
| `redact` | destroyed | a family-appropriate constant; not even "these two were equal" survives |

Every substitute is an HMAC under a salt, never a random value, so `pseudo` and
`hash` are consistent within a file, across files and across a fleet.

`pseudo` and `hash` both preserve the equality relation, which is often the
whole value of sanitised output: you can see that fourteen ports share one
description, or that forty devices share one TACACS key, without learning what
either says. `redact` destroys that relation — and on a customer-facing network
the relation can itself be the leak, which is why both actions exist.

**One combination is illegal:** `pseudo` on `secrets`. The substitute would be
an HMAC of the real credential, so a lab config that reached production would
carry something computable. `hash` gives you the audit signal instead.

## What happens by default

Only the `secrets` family acts, and it redacts. Everything else — free text,
device identity, addresses, hostnames, domains, usernames, e-mail, MACs — is
kept until you ask for it.

That makes the default promise narrow and literally true: **credentials are
destroyed, nothing else is.** Default output still contains every address,
hostname and customer description, so it was never publishable anyway.

The trade only works if the policy is never a surprise, so `--report` opens
with it in one line — at defaults, `secrets=redact, everything else kept`. Read
it before you send anything.

## What remains outside the guarantee

Interface numbering, key-chain names, BGP communities and unsupported grammar
are not transformed. Operational names and ASNs are opt-in and limited to the
documented Cisco, Arista, JunOS and FortiOS forms.

**Warning:** netredact reduces exposure; it does not guarantee anonymisation.
Review every output and decide whether it is safe and lawful to share.
