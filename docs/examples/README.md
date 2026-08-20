# Example configurations

Five profiles, ordered by how far the output is travelling from the business,
plus one that demonstrates the escape hatches. Copy the closest one to
`netredact.toml` and adjust — they are starting points, not a menu of finished
answers.

Every profile is written in the same model: a section selects a part of the
config, and the value is an **action** — `keep`, `pseudo`, `hash` or `redact`.
The reasoning behind that model is in
[design/actions-model.md](../design/actions-model.md).

| File | Destination | `[secrets]` | `[text]` | `[interfaces]` | `[vlans]` | `[identity]` | `[platform]` | Names | Addresses | MACs |
|---|---|---|---|---|---|---|---|---|---|---|
| [`01-secrets-only.toml`](01-secrets-only.toml) | Inside the business | `redact` | `keep` | `keep` | `keep` | `keep` | `keep` | kept | kept | kept |
| [`02-vendor-support.toml`](02-vendor-support.toml) | Vendor TAC, under contract | `redact` | `keep`, banner + contact `redact` | `keep` | `pseudo` | `hash`, serial + UDI kept | `keep` | users `pseudo`, e-mail `hash` | kept | kept |
| [`03-external-review.toml`](03-external-review.toml) | Contractor, consultant, auditor | `redact` | `hash` | `hash` | `pseudo` | `hash` | `keep`, boot image `redact` | hostnames kept, rest `pseudo`/`hash` | public + CGNAT `pseudo` | NIC half `pseudo` |
| [`04-llm-analysis.toml`](04-llm-analysis.toml) | A hosted language model | `redact` | `hash` | `hash` | `pseudo` | `hash` | `keep` | all `pseudo` | all `pseudo` but protocol constants | NIC half `pseudo` |
| [`05-public-publication.toml`](05-public-publication.toml) | Forum, list, blog, slide | `redact` | `redact` | `redact` | `redact` | `redact` | `redact` | all `pseudo` | all `pseudo` but protocol constants | OUI `redact`, NIC `pseudo` |
| [`06-custom-rules.toml`](06-custom-rules.toml) | — (a demonstration) | `redact` | `hash` | `keep` | `keep` | `keep` | `keep` | kept | kept | kept |

Run `netredact -c <profile> config.txt --report` and read the `policy:` line:
it is that profile in one sentence. Anything it does not name as acting was
kept.

## Why the choices differ

The interesting decisions are not "how much can I remove" but which trade-offs a
given destination justifies.

**Secrets-only spells out the defaults.** An empty file behaves identically.
It is written out because the honest description of the default is narrow —
credentials are destroyed, *nothing else is* — and that is much easier to
believe when you can see the `keep`s written down.

**Vendor TAC keeps the serial number.** A support engineer cannot open a case
without it, and under the old two-section model no configuration could express
"destroy identity but keep the serial" at all. Now `identity = "hash"` acts on
certificates, SSH keys and the engine ID, and `serial-number = "keep"` in the
same section names the one exception. Addressing and descriptions stay too: nobody
diagnoses a routing problem against substituted addresses, and the relationship
is already contractual. What does go is the credential set, the personal
contact line and the banner.

**External review keeps RFC1918 and hostnames.** `10.20.30.1` tells an outsider
nothing about who you are — it only shows internal topology, which is the thing
you are paying them to look at. Site and role naming is the same argument. What
moves is the space that WHOIS maps back to you (`other_unicast`) and the space
your subscribers sit in (`cgnat`). Free text becomes `<DESC-a1b2c3>`: two ports
are still distinguishable, and the same port still correlates across files,
without the text.

**Port descriptions and VLAN names move separately from other free text.**
`[interfaces]` and `[vlans]` are the two places a customer name reaches
material the config depends on, and each has an audience the other does not.
TAC needs the port descriptions and has no use for the VLAN names, so 02 keeps
one and pseudonymises the other. A reviewer needs both to be *distinguishable*
rather than readable, so 03 hashes the descriptions and pseudonymises the names.
A public post needs neither, so 05 destroys both. VLAN names are `pseudo` and
not `hash` wherever the file still has to load: the configuration refers to a
VLAN by name elsewhere, and `<VLAN-a1b2c3>` is not a name a switch will accept.

**LLM analysis pseudonymises rather than destroys.** `pseudo` preserves the
equality relation *and* keeps the output type-valid, so subnet relationships,
link adjacencies and ACL logic all still hold and the model can reason about
them. Protocol constants — loopback, multicast, benchmark, reserved, the public
resolvers — stay put, because moving them costs readability for no privacy gain.

**Only public publication destroys the platform.** Model and release are
`keep` in four of the five profiles, and the reasons are not the same reason:
TAC cannot match a bug to your box without them, a reviewer cannot tell whether
a stanza is even valid on that release, and a language model asked to rewrite a
config will answer in the wrong syntax without them. What they do disclose is
an attack surface — a model plus a release number is a CVE list — which is a
fair trade under a support contract and a poor one on a public forum. If the
release is the point of the post, put that one rule back with
`os-version = "keep"` in the same `[platform]` section and say so.

**Public publication destroys free text and identity rather than hashing them.**
A stable `<DESC-a1b2c3>` still says which ports belong to the same customer and
how many customers there are; on a customer-facing network the equality relation
*is* the leak. Addresses and names stay pseudonymous, because an example nobody
can follow is not worth publishing. This profile also discards the MAC OUI,
which every other profile keeps.

**Custom rules is a demonstration, not a destination.** It shows the three
escape hatches: `[[custom]]` for a pattern netredact has never seen,
a named key in a family section for a built-in rule that is wrong for your
fleet, and
`[verify] ignore_patterns` for a token shape of your own that is not a finding.

## A note on the pool

Every profile that pseudonymises addresses leaves `pool` at its default,
`["198.18.0.0/15", "100.64.0.0/10"]`. That is deliberate, and it is worth
knowing why, because an earlier draft of these profiles narrowed it to the
`/15` alone and **crashed on a real 6687-line service-provider config**.

Pool capacity is a hard limit: one /24 of pool per distinct source /24, and a
`/15` is only 512 of them. The real file needed 668, so the run died with
`exhausted the v4net pseudonym space`. A profile that cannot process real input
is worse than one that warns about collisions.

The narrowing was trying to avoid a genuine problem — `100.64.0.0/10` is CGNAT
space that a real ISP uses, and pseudonyms minted there can be mistaken for live
addresses. But the profiles resolve that a better way: they give `cgnat` (and
`benchmark`, which is the other half of the default pool) an action instead of
keeping it. Once no real address in pool space survives into the output, there
is nothing left to confuse, and the full 16896 /24s are available.

`240.0.0.0/4` was considered as an unroutable alternative — it is enormous and
will never be allocated — and rejected: many devices refuse to configure class E
addresses at all, which would break the one thing `pseudo` promises, that the
output still loads.

See [pool collisions](../address-classes.md#pool-collisions) and
[pool capacity](../configuration.md#pool-size-is-a-hard-limit).

## `annotated.toml`

[`annotated.toml`](annotated.toml) is every key at its default value with
comments — the same content as `netredact --print-config`. It is generated from
the source by `tools/gen_docs.py`, so it always matches the code. Do not edit it
by hand.

## Validating a profile

Every example here is exercised by the test suite against every fixture, so they
are known to load and to verify clean. To check one against your own config:

```bash
netredact running-config.txt -c docs/examples/03-external-review.toml \
    --strict --report
```

Then read the `policy:` line. Anything it does not name as acting is still in
the output exactly as it was; `Result.kept_counts` has the per-rule breakdown if
you want it enumerated (see [library](../library.md)).
