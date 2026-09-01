# Language support

[Documentation map](../README.md) · [Working notes](README.md)

- **Status:** promoted — normative behavior now lives in
  [Specification 0002](../specs/0002_python_support.md) (Python) and
  [Specification 0003](../specs/0003_typescript_support.md) (TypeScript)
- **Created:** 2026-08-31
- **Last updated:** 2026-09-01
- **Purpose:** Clarify how Proofbound applies beyond Rust, what a Python repository can use today, and what “works on any codebase” should honestly mean.

## Summary

A normal Python or TypeScript repository can use Proofbound today. The assurance
graph, claims, assumptions, source closures, status derivation, receipts,
releases, and independent verifier are language-neutral. Specifications 0002
and 0003 define the ready-made ecosystem routes; this note retains the product
rationale and is no longer the normative support inventory.

Proofbound is not yet turnkey for literally every language and toolchain. Some
of its deepest evidence producers—Kani bounded checking and Charon/Aeneas source
refinement—remain Rust-specific. Supporting a new ecosystem means adding a
typed, fail-closed adapter and its wire contract; it must not mean accepting an
arbitrary command that reports success.

The correct product claim is therefore:

> Proofbound's assurance model is language-neutral. Its current adapters offer
> ready-made paths for Rust, Python, TypeScript, and Lean, while additional
> ecosystems need typed adapters that preserve the same trust guarantees.

## The architecture is more portable than the examples suggest

Proofbound has two distinct layers:

1. The **assurance layer** models claims, evidence, assumptions, source and
   artifact identity, trust profiles, semantic closure, status, and portable
   receipts. None of these concepts requires the subject repository to be
   written in Rust.
2. The **evidence-production layer** executes a particular testing, checking,
   translation, or proof tool and converts its result into typed evidence. This
   layer is necessarily ecosystem-specific.

The Rust-heavy examples reflect where the deepest adapters currently exist,
not a Rust constraint in the assurance model. A team consuming an installed
Proofbound binary does not need to make its application a Rust project.

## What works for Python today

| Capability | Python support | What it establishes |
|---|---|---|
| Claims, assumptions, exclusions, and open obligations | Available | The assurance contract and its known uncertainty |
| Exact source closures and change impact | Available | Which reviewed bytes and dependencies a claim relies on |
| pytest example and seeded Hypothesis routes | Available | That the exact registered test inventory executed successfully under the registered seed |
| mypy static checking | Available | That the registered analyzer reported no diagnostics for its byte-pinned configuration and targets |
| Sealed pytest mutation replay | Available | That one exact witness detects a registered full-file mutant in an independent shadow |
| Reproducible wheels and sdists | Available | That two independent builds match the registered distribution bytes; wheels also match their `RECORD` inventory |
| Reproducible Python generators | Available | That a fresh generated candidate exactly matches committed outputs |
| Independent Python checkers | Available | A strict canonical result with an exact inventory, rather than exit status alone |
| Canonical artifact checking | Available | Evidence about exact registered artifact bytes and format rules |
| Trusted transcription | Available | A connected source-to-transcription-to-source round trip with explicit TCB roles |
| Portable release receipts | Available | A release result that the standalone verifier can recheck without trusting the producer |
| Kani bounded model checking | Rust-specific | Not currently a Python route |
| Charon/Aeneas source refinement | Rust-specific | Not currently a Python route |
| Native Python formal refinement or proof linkage | Not yet available | Requires a new sound integration rather than a status-label shortcut |

The Python adapter does more than run `pytest` and trust its exit code. It
discovers and binds an exact nonempty test inventory, runs registered nodes
individually, and requires an exact passing summary. Missing, extra, duplicate,
or substituted nodes fail closed.

Generator verification also avoids trusting a pre-existing output tree. It
creates a fresh candidate, runs the registered generator there, and compares
the resulting path-to-byte inventory with the committed outputs. Independent
checkers use a strict result schema instead of being permitted to manufacture
assurance from a zero exit status.

## A realistic Python adoption flow

For a repository with `pyproject.toml` and at least one uniquely selectable
pytest test:

1. Run `proofbound init` to discover the Python test surface and create an
   initial claim and evidence unit.
2. Rewrite the generated claim in the language the team is actually willing to
   defend—for example, “an unauthenticated request cannot reach this operation.”
3. Register the assumptions and exclusions on which that claim depends, such as
   an identity provider supplying authentic subject identifiers.
4. Run a fresh check and inspect the claim's formal, linkage, and assumption
   facets.
5. Use the assumptions and gap views to distinguish evidence-backed uncertainty
   from work that is merely unexamined.
6. Produce a release receipt and verify it independently.

An ordinary pytest-backed claim should derive a status such as `TESTED`, not
`PROVED`. Proofbound's value is partly that it preserves this distinction and
states what remains model-only, assumed, or out of scope.

## Why this matters for notification fatigue

Most engineering tools emit findings in the vocabulary of the tool: a failed
test, a lint warning, a scanner alert, a coverage reduction, or an expired SLA.
They rarely explain which product claim has weakened, which assumption is now
unsupported, or whether the finding can affect a shipping artifact. The result
is a queue of alerts whose urgency engineers must reconstruct by hand. Over
time, even correct notifications become background noise.

Proofbound should not become another notification source. Its role is to
compile heterogeneous evidence into a claim-oriented account of uncertainty:

- which claims are affected;
- which exact source or artifact changed;
- whether evidence disappeared, weakened, or merely became stale;
- which assumptions remain load-bearing;
- what is explicitly outside the registered scope; and
- whether the change can alter a release's independently verified status.

This applies just as naturally to Python as to Rust. A failed Python test does
not need to become a generic red badge. It should weaken only the claims to
which that exact test is registered, expose the resulting gap, and leave
unrelated claims alone. Conversely, a green pytest run should not erase an open
identity-provider assumption or masquerade as formal proof.

The long-term product opportunity is not “support every scanner.” It is to give
teams a common, evidence-backed language for deciding which signals matter.

## Current Python caveats

### Pytest plugins

Proofbound disables ambient pytest plugin autoload so that test discovery does
not silently depend on whatever happens to be installed in the invoking
environment. Projects that depend on automatically loaded plugins may need an
explicit, registered plugin configuration. Proofbound now records each
plugin's providing distribution, version, and origin bytes, while collection
failures and `doctor` identify missing registered modules.

### Property-based testing

A Hypothesis test can run through the registered pytest property-test route,
which binds and enforces an explicit seed. The evidence attests to the exact
pytest node and its observed run.
It does not independently model Hypothesis's generated search space, shrinking
behavior, or case count. A future record could expose richer stable metadata
without overstating generated cases as exhaustive proof.

### Python-native deep assurance

Mypy static checks and sealed pytest mutation replays now have first-class
routes. Pyright remains deliberately reserved because its stock JSON reports a
file count rather than authoritative file identities. Coverage systems,
symbolic execution, and Python-to-proof refinement remain unsupported. Such
integrations should be added only when Proofbound can define:

- an authoritative, nonempty inventory;
- exact tool and environment identity;
- a typed result that cannot be upgraded by an exit code or checker-authored
  Boolean;
- source and artifact bindings appropriate to the claim; and
- equivalent validation in the producer and independent verifier where the
  evidence is portable.

## What “any codebase” should mean

Language portability is better understood as a ladder than a Boolean feature:

1. **Assurance governance:** any repository can register claims, assumptions,
   exclusions, owners, source closures, and open obligations.
2. **Empirical evidence:** a repository can attach exact tests, generators,
   artifacts, and independent checkers through a supported typed adapter.
3. **Ecosystem-native evidence:** type checkers, model checkers, mutation tools,
   build systems, and package artifacts have dedicated trustworthy routes.
4. **Semantic linkage:** formal or refinement evidence is connected to the code
   and artifacts that ship rather than proving only a separate model.

Proofbound can credibly target level 1 for almost any conventional repository,
and reaches level 3 for its supported Python and TypeScript routes. Level 4
remains ecosystem- and semantics-specific. The product should show this
capability level honestly rather than presenting a single “supported” badge.

## Promoted reference demonstration

The pure-Python
[`demo/python-inventory-service`](../../demo/python-inventory-service/README.md)
now exercises the promoted design with no Rust application code. It contains:

- exact pytest examples;
- one seeded Hypothesis property test with explicit limits;
- one mypy static-check unit;
- one sealed pytest mutation replay;
- an explicit external-service or identity-provider assumption;
- an independent Python policy checker with a strict inventory;
- a wheel reproduced twice and checked against its `RECORD` inventory; and
- a portable release receipt verified by the standalone verifier.

This demonstrates the language-neutral product and makes the
notification-fatigue thesis tangible: the final output is not a pile of test
and scanner alerts, but a bounded account of which
claims are supported, which assumptions remain, and why each remaining gap
matters.

## Promotion outcome

The product claims are woven into the product vision, and normative Python and
TypeScript behavior lives in Specifications 0002 and 0003. Future work should
focus on formal linkage only where there is a defensible mapping between
ecosystem semantics, a model, and the shipping artifact.
