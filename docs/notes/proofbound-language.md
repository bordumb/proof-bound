# Proofbound language

[Documentation map](../README.md) · [Working notes](README.md)

- **Status:** exploring
- **Created:** 2026-09-01
- **Last updated:** 2026-09-01
- **Purpose:** Explore a native high-assurance programming language that shares Proofbound's semantic kernel, while using Proofbound's existing-language assurance system as the practical adoption bridge.

## Summary

Proofbound may have two complementary long-term forms:

1. **Proofbound assurance** applies a common assurance model to existing
   Python, TypeScript, Rust, Lean, and other repositories through strict typed
   evidence producers.
2. **The Proofbound language** makes specifications, proofs, effects,
   assumptions, uncertainty, hermetic builds, and release evidence native to
   programs written from scratch.

The first is the adoption bridge for the software that already exists. The
second is a possible greenfield destination in which assurance does not have to
be reconstructed after development from unrelated test runners, analyzers,
build systems, proof tools, and CI logs. Both should compile into one small,
versioned assurance intermediate representation and remain checkable by one
independent semantic kernel.

This is not a proposal to stop supporting existing languages or immediately
begin implementing a general-purpose language. The current framework is useful
in its own right and is also the empirical research program from which the
native language's semantics should be learned.

## Why consider a native language?

Proofbound's Python and TypeScript work exposed a recurring integration cost.
Each ecosystem represents similar concepts differently:

- pytest and Vitest discover and name tests differently;
- Hypothesis and fast-check expose different property-test controls;
- mypy and `tsc` report analyzed surfaces differently;
- wheels, sdists, and npm tarballs have different archive rules;
- every tool has its own version, output, environment, and completeness
  semantics.

Strict adapters are necessary for existing projects, but an unbounded set of
tool-specific meanings would turn Proofbound into a fragile “tower of Babel.”
A native language could instead start with one meaning for:

- executable code and specifications;
- examples, sampled properties, bounded checks, and universal proofs;
- authority and side effects;
- assumptions and excluded conditions;
- source and artifact identity;
- dependency and build closure;
- uncertainty and invalidation; and
- release policy.

That would not eliminate the external world, but it could eliminate much of the
accidental diversity inside a program's assurance boundary.

## One semantic kernel, two adoption surfaces

The project should avoid building two unrelated products. Existing-language
Proofbound and a native Proofbound language should share the same semantic
centre:

```text
Existing repositories                      Native Proofbound programs
Python · TypeScript · Rust · Verus          code · specs · proofs · effects
          │                                             │
          │ strict typed adapters                       │ native compiler
          └──────────────────┬──────────────────────────┘
                             ▼
                 Canonical Assurance IR
                 claims · subjects · assumptions
                 observations · artifacts · bindings
                 uncertainty · derivations · policy
                             │
                             ▼
              Small independent verification kernel
                             │
                             ▼
                 graph · receipt · release verdict
```

The invariant is more important than the surface syntax:

> There may be many evidence producers, but only a small, carefully versioned
> set of evidence meanings.

Existing adapters compile native tool observations into that meaning. A native
language constructs the same meaning directly, with fewer translation
boundaries and stronger static guarantees.

## What kind of language?

“Proofbound language” could initially mean a declarative assurance DSL and
eventually include executable application code. Those stages should not be
conflated.

### Stage A: assurance DSL

The first language would replace scattered manifests with typed modules for
claims, assumptions, evidence, uncertainty, and policy. Application code would
remain in existing languages.

```proofbound
module inventory.assurance

subject Reservations =
  python.module("inventory_service.reservations")
  closed_over "src/inventory_service/**/*.py"

claim CapacityIsNeverExceeded {
  subject = Reservations
  public = "Accepted reservations never exceed available capacity."

  assumes CPythonSemantics
  excludes ConcurrentDatabaseWriters

  supported_by {
    ReservationExamples
    CapacityProperty
    AcceptOverCapacityMutation
    ReservationTypes
  }

  publish_at most Tested
}
```

This is already more than typed configuration if the compiler can derive
invalidation, constrain status, and prevent evidence-family substitution.

### Stage B: native high-assurance language

A later language could combine executable code, mathematical specifications,
proofs, effects, and assurance declarations:

```proofbound
module inventory.reservations

resource Inventory {
  capacity: Nat
  reserved: Nat
}

invariant WithinCapacity(state: Inventory) =
  state.reserved <= state.capacity

exec fn reserve(state: Inventory, quantity: PositiveNat)
  -> Result<Inventory, InsufficientCapacity>
requires
  WithinCapacity(state)
ensures result:
  match result {
    Ok(next) =>
      WithinCapacity(next)
      and next.reserved == state.reserved + quantity,
    Err(_) => next_state == old(state),
  }
{
  if state.reserved + quantity > state.capacity {
    return Err(InsufficientCapacity)
  }

  Ok(state with reserved += quantity)
}

proof fn reserve_preserves_capacity(state, quantity)
  ensures reserve(state, quantity).is_ok implies
    WithinCapacity(reserve(state, quantity).value)
{
  // proof body or obligations discharged by checked automation
}
```

The goal is not novel syntax. It is to make important assurance distinctions
part of the type system.

## Type evidence by what it establishes

The language should not represent all successful tools as a Boolean check. It
should make evidence strength explicit:

```text
Evidence<Example<Subject>>
Evidence<SampledProperty<Subject, Seed, Cases>>
Evidence<Exhaustive<Subject, FiniteDomain>>
Evidence<BoundedModelCheck<Subject, Bounds>>
Evidence<UniversalSourceProof<Subject, Proposition>>
Evidence<ArtifactCorrespondence<Source, Artifact>>
Evidence<Reproducible<Artifact>>
```

A sampled property must not satisfy a requirement for a universal proof. A
source theorem must not satisfy a requirement about shipping bytes without an
artifact correspondence. Evidence values should be non-forgeable: only
kernel-recognized constructors backed by validated observations may create
them.

This would turn current runtime validation errors into compile-time guidance:

```text
expected: Evidence<UniversalSourceProof<Reservations, CapacityInvariant>>
found:    Evidence<SampledProperty<Reservations, 1729, 10000>>

10,000 generated cases do not establish a universal proposition.
Lower the policy ceiling to Tested or provide a registered proof.
```

## Make effects and authority visible

Assurance depends not only on returned values but also on what code was allowed
to observe or change. The native language should track effects and capabilities
such as:

```text
Pure
Clock
Randomness
Network[service]
SecretRead[name]
Read[closure]
Write[ephemeral]
Write[reviewed]
Execute[tool]
HumanJudgment
```

For example:

```proofbound
exec fn charge(request: Charge) -> Receipt
effects {
  Network[PaymentProvider]
  SecretRead[PaymentCredential]
  Clock
}
```

Build and evidence protocols could constrain effects statically:

```proofbound
artifact InventoryWheel = reproducible_build {
  source = InventoryPackage
  builds = 2
  allow { Read[SourceClosure], Write[Ephemeral] }
  deny { Network, Write[Reviewed] }
}
```

The compiler should reject a supposedly hermetic build that imports a
network-capable dependency or requests unregistered ambient authority.

## Treat assumptions and uncertainty as values

No programming language can prove that its formal model perfectly captures
customer intent, hardware, operators, external services, or physical reality.
A native Proofbound language should therefore expose assumptions rather than
marketing them away:

```proofbound
assumption DatabaseTransactionModel {
  statement =
    "Database.transaction provides serializable atomic execution."
  owner = Platform.Database
  expires = 2027-01-01

  supported_by {
    vendor_contract "postgresql-18-serializable"
    integration_test SerializableReservationTest
  }
}

uncertainty ExternalWriterRace {
  affects CapacityIsNeverExceeded
  reason = "A legacy writer bypasses the registered transaction boundary."
  consequence = High
  owner = Team.Inventory
}
```

Compilation should produce a claim-oriented explanation instead of a volume of
tool-oriented notifications:

```text
CapacityIsNeverExceeded
  status: PROVED in the registered source model
  artifact binding: reproducible, compiler-assumption-bound
  remaining uncertainty: ExternalWriterRace
  publication: blocked by ProductionPolicy
```

This is the connection to notification fatigue: notify when justified
confidence changes, identify the affected claim and assumption, and leave
unrelated claims alone.

## The bridge for existing software

The native language cannot require organizations to rewrite their systems
before receiving value. Existing-language Proofbound should support gradual
migration by representing foreign components honestly:

```proofbound
foreign python InventoryClient {
  source = python.module("inventory_service.client")

  contract fn reserve(Request) -> Response

  correspondence assumed_by PythonImplementationConforms

  supported_by {
    pytest InventoryExamples
    hypothesis InventoryProperty
    mypy InventoryTypes
  }
}
```

The graph would show that the interface contract is evidence-backed but not
universally proved. A component could later be replaced with native code:

```text
Foreign Python component
  TESTED · assumption-bound correspondence
            │
            │ gradual replacement
            ▼
Native Proofbound component
  source-proved · typed effects · reproducible artifact
```

Mixed systems should remain a permanent supported state, not merely a temporary
migration concession. Real systems will continue to depend on operating
systems, databases, cloud APIs, device firmware, and libraries written in other
languages.

## Formal backends still have a role

A native language does not require inventing every prover and solver again.
Verus, Lean, SMT solvers, model checkers, and validated code generators may
remain proof-producing backends. The important boundary is that they emit
proof objects or typed observations whose assumptions and inventories the
Proofbound kernel can validate.

The division should be:

```text
Backend: search for a proof or produce an observation
Kernel:  check the proof or observation and assign its meaning
Policy:  decide whether the resulting assurance permits publication
```

Backends must not manufacture `PROVED` or `ADMITTED` results themselves.

## Keep the trusted kernel small

A full compiler may be large, ergonomic, optimizing, and capable of invoking
automation. It should not be the final authority. It should emit a smaller
canonical representation and, where relevant, proof objects:

```text
Rich compiler and proof automation
              │
              ▼
Canonical Assurance IR + proof objects
              │
              ▼
Small independent checker
```

The checker should not need Python, Node, Cargo, pytest, Verus, Lean, or the
native Proofbound compiler installed to verify a portable release. If it must
recreate the whole frontend ecosystem, the design has failed.

## What the language cannot guarantee by itself

Even a verified native program ultimately depends on correspondences outside
the language:

- the public claim matches stakeholder intent;
- hardware implements the assumed execution model;
- external services honour their registered contracts;
- operators deploy the checked artifact with the checked configuration;
- secrets and credentials are managed as assumed;
- physical and organizational exclusions remain valid.

The language can make these boundaries explicit, attach evidence, track
owners, and block publication when they become stale. It cannot abolish them.

## Risks

### Rebuilding the world

A new language begins without mature libraries, package ecosystems, editors,
debuggers, cloud SDKs, database clients, operating experience, or a developer
community. Reimplementing these may create more risk than the language removes.

### An oversized trusted compiler

Combining type checking, proof search, code generation, dependency resolution,
build isolation, and assurance derivation could create a trusted computing base
too large to audit. A small independent kernel is a hard requirement.

### False unification

Examples, randomized properties, bounded exploration, theorem proofs, artifact
reproduction, and human review are not interchangeable. A pleasant syntax must
not flatten their epistemic differences.

### Assurance ceremony

If ordinary code requires excessive proof scaffolding before it can run, teams
will bypass the language or encode meaningless specifications. The design must
support progressive assurance while keeping confidence ceilings honest.

### Premature syntax design

An attractive parser is not the difficult part. Designing syntax before the
semantic IR, evidence algebra, effect model, and trust boundary stabilize would
lock accidental implementation details into the language.

## Proposed research sequence

1. **Extract the assurance algebra.** Identify the smallest stable set of
   subjects, evidence families, assumptions, bindings, uncertainty, effects,
   and derivation rules already demonstrated across Rust, Python, TypeScript,
   Lean, and external repositories.
2. **Specify a canonical Assurance IR.** Make current manifests and adapters
   compile into it without changing their meaning.
3. **Build a typed assurance DSL.** Replace repeated TOML authoring with modules,
   reusable patterns, useful diagnostics, formatting, and editor support.
4. **Prove frontend equivalence.** Demonstrate that representative TOML and DSL
   projects produce identical canonical IR and receipts.
5. **Prototype effects and capabilities.** Start with build and evidence
   execution, where ambient authority is already a concrete source of risk.
6. **Prototype a small native executable core.** Choose a bounded domain such
   as a parser, state machine, policy engine, or security-critical library—not
   a general web framework.
7. **Connect proof-producing backends.** Require independently checked proof
   objects or typed observations rather than backend-authored status labels.
8. **Run a mixed-language migration.** Replace one foreign component while the
   surrounding system remains in an existing ecosystem; measure whether the
   graph communicates the changing boundary honestly.
9. **Decide whether to expand.** Promote the design only if the native route
   materially improves assurance, usability, and notification quality without
   making the trusted kernel or developer burden unmanageable.

## Promotion criteria

This note should become an ADR and one or more dedicated specifications only
after the project can demonstrate:

- a canonical Assurance IR shared by at least three existing-language routes;
- a small, independently implemented checker for that IR;
- compile-time rejection of at least one real evidence-strength substitution;
- an effect rule that prevents a demonstrated ambient-authority defect;
- mixed native/foreign components in one graph;
- source-to-artifact correspondence for a native component;
- explicit residual assumptions and uncertainty in its release verdict; and
- a measured reduction in duplicated adapter semantics rather than merely a
  second syntax for the same manifests.

## Current position

The existing Proofbound system should continue to be developed as a useful
language-agnostic assurance product. It is simultaneously the bridge for
adoption and the evidence base for deciding whether a native language should
exist.

The long-term thesis is:

> **Proofbound assures software written anywhere. The Proofbound language is
> the optional native route for software whose assurance is designed in from
> the first line. Both produce the same independently verifiable account of
> claims, evidence, assumptions, uncertainty, and released artifacts.**
