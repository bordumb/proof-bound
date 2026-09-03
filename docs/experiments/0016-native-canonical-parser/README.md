# Experiment 0016: Native canonical parser

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Programme ID:** EXP-LANG-007
- **Status:** Rust producer implemented; independent execution pending
- **Registered:** 2026-09-03
- **Started / concluded:** — / —
- **Subject:** Proofbound `d809a9968f2e00805d4a82e5c01b02b9e5b16bf7`
- **Operator:** Codex (GPT-5)

## Why this experiment

Proofbound now has a bounded, backend-neutral semantic target and a finite
adequacy-tested parser specification. It still has no native source programme,
compiler, executable artifact, or independently checkable functional
certificate. Without those, the language proposal could remain an assurance
manifest system with aspirational syntax.

This experiment implements one deliberately small native programme: a
canonical length-prefixed parser and serializer over a four-value type. The
compiler emits deterministic research bytecode, verification conditions for
Z3, and a finite universal certificate. An independently written Python
checker reparses the source, recompiles the artifact, executes the bytecode,
and validates the certificate without rerunning Z3.

## Questions (pre-registered)

1. **Q1 — Native source closure.** Can a small typed syntax express the frozen
   value type, result type, total encoder/decoder, pattern matching, five
   specifications, effects, and resource bound without backend callbacks?
   **Pass:** the canonical source parses and type-checks in both implementations
   and all registered syntax, duplicate, partiality, type, effect, and bound
   attacks reject exactly. **Falsifier:** a required property lives only in
   compiler code or either parser accepts ambiguous source.
2. **Q2 — Independently checkable functional assurance.** Can proof search and
   proof checking be separated? **Pass:** Z3 reports `unsat` for every negated
   verification condition; the emitted certificate covers every value and
   bounded input; the Python checker independently recomputes every trace and
   obligation without invoking Z3; all certificate attacks reject exactly.
   **Falsifier:** the checker trusts a reported theorem/status, requires proof
   search, or misses a registered semantic mutant.
3. **Q3 — Honest source-to-artifact binding.** Can the artifact be reproduced
   and checked without calling the Rust compiler? **Pass:** Rust and Python
   compilers emit byte-identical bytecode in ten repetitions, both execute the
   same cases, source/artifact/certificate/tool identities are bound, and all
   artifact substitution/truncation/trailing/opcode attacks reject. **Falsifier:**
   artifact meaning depends on ambient compiler state or a same-size mutation
   retains the binding.
4. **Q4 — Assurance distinctions.** Does the result state exactly what is
   universal, bounded, tested, and assumed? **Pass:** round trip is universal
   over the declared four-value type; malformed rejection, canonicality,
   consumption, and termination are exhaustive only over the frozen bounded
   byte carrier; examples remain tests; the compiler/runtime correspondence is
   an explicit assumption; no decision calls the artifact proved. **Falsifier:**
   a finite result is reported unbounded or source proof becomes artifact proof.
5. **Q5 — Native feasibility.** Is the prototype stronger and still small
   enough to justify mixed-language research? **Pass:** source is at most 4 KiB,
   bytecode 128 bytes, certificate 128 KiB, SMT input 16 KiB, Rust native module
   1,800 nonblank non-comment lines, Python checker 1,500 lines, verification
   completes in 30 seconds, and every one of six semantic mutants is rejected.
   **Falsifier:** the candidate exceeds a ceiling, needs an unrestricted effect,
   or supplies no assurance beyond the existing finite table.

The universal claim is over the complete declared finite `U2` type, not over
arbitrary integers or future type extensions. The bounded byte-input claims do
not become universal merely because their carrier is exhaustive.

## Candidate architecture

```text
canonical .pb source
       │
       ├── Rust parser/type checker ── deterministic bytecode
       │               │
       │               ├── SMT-LIB VCs ── Z3 proof search
       │               └── finite certificate + execution traces
       │
       └── Python parser/type checker ── same bytecode
                               │
                               └── independent certificate/VM checker
```

The bytecode is a tiny versioned parser VM artifact, not native machine code.
This avoids pretending that an unverified optimizing compiler preserves the
source proof. The Rust compiler remains an untrusted producer because the
Python checker independently derives and checks its output. The VM checker and
artifact format remain trusted research code subject to the frozen mutation
corpus.

## Registered measurements

- `M-NP-001`: exact source attack rejections / registered source attacks;
- `M-NP-002`: Z3-unsat verification conditions / five;
- `M-NP-003`: independently checked certificate obligations / total;
- `M-NP-004`: six registered semantic mutants rejected / six;
- `M-NP-005`: Rust/Python artifact and report disagreements;
- `M-NP-006`: stable artifact, SMT, certificate, and report identities / ten;
- `M-NP-007`: exact artifact/certificate attack rejections / registered;
- `M-NP-008`: source, artifact, certificate, SMT, and report bytes; and
- `M-NP-009`: compiler/checker lines and elapsed time.

## Scope

- **In:** one canonical two-byte format; a four-value algebraic type; explicit
  `Result`; total pattern match; pure encode/decode functions; five typed
  specifications; bounded cost; deterministic bytecode; Z3 VC search; finite
  certificate; independent parser/compiler/VM/checker; six semantic mutants.
- **Out:** general-purpose language syntax; recursion; heap allocation;
  concurrency; I/O; operating-system sandboxing; native machine code; verified
  compiler; arbitrary byte-string theorem; production Proofbound integration;
  performance comparison with mature languages.

## Procedure

1. Commit this preregistration before native syntax, bytecode, VCs,
   certificates, attacks, expected values, or implementation.
2. Freeze source grammar, canonical programme, bytecode semantics, finite
   carriers, six mutants, attacks, tool invocation, and complexity ceilings.
3. Implement the Rust parser, type checker, compiler, VM, VC producer, Z3
   runner, and certificate producer.
4. Implement the Python parser, compiler, VM, and certificate checker
   independently. It may inspect Z3 provenance but may not invoke the solver.
5. Execute all valid and adversarial cases ten times before opening expected
   values; retain source, artifact, SMT, certificate, and result identities.
6. Decide Q1--Q5 separately. Do not call bounded input checks universal or the
   bytecode artifact formally proved.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0016-F001 | Reserved for execution. | — | pending |

## Outcome

Q1--Q5 remain unanswered until the independently implemented checker and
retained execution are complete. The frozen corpus and Rust producer now
exist; neither implementation result is treated as experimental evidence yet.
