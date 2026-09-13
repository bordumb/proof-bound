# Experiment 0016: Native canonical parser

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Programme ID:** EXP-LANG-007
- **Status:** concluded; Q1--Q5 passed over the frozen finite native subset
- **Registered:** 2026-09-03
- **Started / concluded:** 2026-09-03 / 2026-09-03
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
| EXP-0016-F001 | Independent parsers, compilers, VMs, and certificate checkers reconstruct one complete native result. | Canonical model report `sha256:b9f706c9dfd7a9116a7e57b7bccfd2d5882f7618e064acc2016e0b70814be262`; ten stable repetitions | retain the source, bytecode, and certificate shapes as bounded inputs to EXP-LANG-008 |
| EXP-0016-F002 | Proof search can be separated from checking for the frozen programme. | five Z3 `unsat` results; Python checker invokes no solver and independently reconstructs four universal value rows plus 156 bounded input rows | retain solver provenance as evidence, never as a substitute for the certificate |
| EXP-0016-F003 | Independent dual compilation makes every byte of the research artifact reviewable and substitution-sensitive. | exact 22-byte artifact; seven artifact attacks reject; artifact and semantic identities agree | retain source proof and artifact correspondence as distinct facets |
| EXP-0016-F004 | The native result preserves assurance scope rather than collapsing finite exhaustiveness into proof. | universal round trip over four declared values; bounded input properties over alphabet `0..4`, length `0..3`; examples remain tests; `artifact_proved=false` | carry these distinctions across the mixed-language boundary |
| EXP-0016-F005 | A useful native semantic slice fits within the frozen complexity budget, but it is a research VM rather than native machine code. | 856-byte source; 1,276 Rust lines; 874 Python lines; 25,973-byte report; 811 ms; six of six mutants killed | bounded support for H7; machine-code, release, and mature-language comparisons remain open |

## Outcome

All five questions pass over the frozen finite native subset:

- **Q1 passed:** both parsers accepted the exact canonical source and rejected
  all ten source attacks with their registered codes.
- **Q2 passed:** Z3 returned five `unsat` results, while the independent checker
  reconstructed every value and bounded-input obligation without proof search.
- **Q3 passed:** both compilers emitted the same 22 bytes in ten complete
  repetitions, and every artifact mutation rejected.
- **Q4 passed:** the report kept finite-type universality, bounded input
  exhaustiveness, examples, and compiler correspondence distinct.
- **Q5 passed:** all six semantic mutants were killed and every source,
  artifact, certificate, SMT, implementation, report, and elapsed-time ceiling
  held.

This supports a small native assurance semantics and independently checkable
research bytecode as the subject for EXP-LANG-008. It does not prove either
implementation, verify a machine-code compiler, establish arbitrary-byte
properties, integrate a release pipeline, or show that a new language is more
cost-effective than a Verus, Lean, or Dafny component.
