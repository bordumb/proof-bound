# Experiment 0015: Assurance IR differential kernel

[Research programme](../../research/proofbound-language/README.md) ·
[Machine preregistration](preregistration.json) · [Journal](JOURNAL.md) ·
[Artifacts](ARTIFACTS.md)

- **Programme ID:** EXP-LANG-010
- **Status:** concluded; Q1--Q5 passed over the frozen finite corpus
- **Registered:** 2026-09-03
- **Started / concluded:** 2026-09-03 / 2026-09-03
- **Subject:** Proofbound `3a94ed968ada9a4a73542aa4366dc97ed2d3bb75`
- **Operator:** Codex (GPT-5)

## Why this experiment

The first Assurance IR candidate retained most portable evidence meaning but
failed to retain the complete typed dependency projection needed to justify
cache reuse. Later experiments independently established narrower pieces that
a successor must join: closed derivation rules, precise invalidation under a
declared model, enforceable effect boundaries for mediated work, typed
uncertainty and claim consequences, specification-adequacy evidence, and exact
artifact roles.

Those positive results do not prove that the pieces compose. A larger record
could still admit semantic aliases, permit a strong decision to omit one of
its premises, make invalidation disagree with derivation, or grow into a union
of backend-specific schemas. This experiment therefore tests a research-only
Assurance IR `/2` candidate with independently implemented Rust and Python
kernels before any production schema or native language depends on it.

## Questions (pre-registered)

1. **Q1 — Closed canonical meaning.** Can the candidate decode, validate, and
   re-encode representative programmes without backend-specific common
   variants? **Pass:** all six frozen templates and 500 deterministically
   generated valid programmes are accepted by both kernels with byte-identical
   reports; every constructor is exercised. **Falsifier:** either kernel needs
   a tool-named common branch, accepts unknown meaning, or disagrees.
2. **Q2 — Cross-component joins.** Are evidence, dependencies, effects,
   specifications, artifact roles, uncertainty, derivation, invalidation, and
   admission bound rather than merely colocated? **Pass:** all registered
   omitted, substituted, aliased, reordered, and forged joins reject with the
   exact frozen code in both kernels. **Falsifier:** a self-consistently
   rehashed stronger decision survives after any load-bearing join changes.
3. **Q3 — No assurance strengthening.** Does the kernel preserve the
   distinctions among sampled, bounded, formal, transcription, correspondence,
   and artifact evidence? **Pass:** every registered family coercion and
   decision upgrade rejects, while each valid family reaches only its frozen
   maximum formal/linkage facets. **Falsifier:** tested becomes proved, bounded
   becomes universal, transcription becomes refinement, or a theorem becomes
   artifact-bound without correspondence.
4. **Q4 — Differential and mutation adequacy.** Do independent kernels agree
   beyond hand-authored examples? **Pass:** a frozen generator produces 500
   valid and 500 single-mutation adversarial programmes spanning every rule;
   Rust and Python agree on acceptance, complete report bytes, or exact error
   code in ten repetitions. **Falsifier:** any unexplained disagreement,
   surviving mutation, unstable identity, or unexercised rule remains.
5. **Q5 — Small-kernel feasibility.** Is the common checker materially smaller
   than the backend union and within the registered complexity budget?
   **Pass:** the candidate uses no adapter dependency or backend name, stays
   within 1,800 nonblank non-comment Rust lines, 1,800 equivalent Python lines,
   24 top-level/variant constructors, 32 validation codes, 16 KiB per canonical
   report, and 64 MiB peak corpus bytes. **Falsifier:** a representative route
   requires opaque callback execution, schema-specific delegation, or exceeds
   a frozen ceiling.

The generated domain is finite. Passing would support this candidate as an
input to the native-parser experiment, not prove the kernel correct for every
future programme.

## Candidate under test

```text
AssuranceProgramV2 {
  claim,
  specification,
  dependencies,
  effects,
  artifacts,
  evidence,
  uncertainties,
  derivation,
  expected_decision
}

KernelReport {
  semantic_identity,
  dependency_identity,
  invalidation_identity,
  derivation_identity,
  decision,
  consumed_uncertainties,
  cache_eligibility
}
```

The common model may name evidence families and assurance concepts, but it may
not name pytest, Vitest, Kani, Lean, Verus, Aeneas, npm, Cargo, or another
producer. Backend identity is data attached to a typed tool dependency.

Dependencies distinguish semantic source, execution input, tool, environment,
absence, and external-contract roles. Effects distinguish statically denied,
mediated, externally enforced, and opaque execution. Uncertainty distinguishes
assumptions, exclusions, open obligations, stale evidence, conflicting
evidence, and unavailable telemetry. Specifications carry an exact suite and
adequacy identity. Artifacts carry source, generated, bound, sealed, and
reproduced roles. Decisions must be derived from these components through a
closed rule table; no input supplies a reported status as authority.

## Registered measurements

- `M-IR2-001`: accepted valid programmes / 500;
- `M-IR2-002`: exact adversarial rejections / 500;
- `M-IR2-003`: exact registered template attacks / attack count;
- `M-IR2-004`: Rust/Python canonical report disagreements;
- `M-IR2-005`: exercised constructors / registered constructors;
- `M-IR2-006`: exercised validation codes / registered validation codes;
- `M-IR2-007`: stable model identities / ten repetitions;
- `M-IR2-008`: maximum report and corpus bytes; and
- `M-IR2-009`: nonblank non-comment kernel lines and direct dependencies.

## Registered attack classes

The machine preregistration freezes 28 exact attacks covering schema and
canonicality, duplicate and aliased identities, missing and substituted
dependencies, hidden or weakened effects, forged external enforcement,
specification omission and inadequacy, artifact-role substitution, uncertainty
omission and coercion, derivation/root substitution, invalidation skew, cache
eligibility forgery, family coercions, and reported-decision upgrades.

## Scope

- **In:** six representative assurance programmes; backend-neutral family
  semantics; complete typed dependency/effect joins; specification adequacy;
  artifact roles; six uncertainty states; closed derivation and admission;
  deterministic generation; independent Rust/Python checking.
- **Out:** production wire migration; actual sandbox enforcement; backend
  execution; arbitrary policies; theorem proving; native parser code; source
  syntax; human usability; a proof of either checker.

## Procedure

1. Commit this preregistration before the `/2` model, templates, attacks,
   generator configuration, expected values, or implementation.
2. Freeze the complete corpus and its complexity ceilings in a separate
   commit, without opening implementation-derived outputs.
3. Implement the Rust kernel and generator from the frozen corpus.
4. Implement the Python kernel independently, without generated bindings or
   shared validation code.
5. Add a post-implementation evaluator that runs both kernels before reading
   expected values; execute ten repetitions and retain the result.
6. Decide Q1--Q5 separately. Preserve failures and revise rather than silently
   changing `/2` under the same name.

## Findings

| ID | Observation | Evidence | Disposition |
|---|---|---|---|
| EXP-0015-F001 | Independent kernels produce the same complete semantic report across hand-authored and generated programmes. | Model report `sha256:b9219f06063b61c73094d2d8ed6b608f5dbbef9d98947fe27427c53c0f9fe8ef`; 500 valid programmes; ten repetitions | retain `/2` as the bounded semantic target for EXP-LANG-007 |
| EXP-0015-F002 | Colocating records is insufficient; exact joins make same-count substitutions and omitted premises observable. | 28/28 named attacks and 500/500 generated mutations rejected exactly | retain typed references and independently recomputed identities at every boundary |
| EXP-0015-F003 | One backend-neutral family table preserves all registered assurance ceilings. | sampled/bounded/mutation remain tested; theorem remains model-only; transcription remains transcribed; artifact binding alone reaches artifact-bound | prohibit backend-named common rules and reported statuses |
| EXP-0015-F004 | Dependency, effect, invalidation, and cache semantics can share one deterministic projection for the bounded profiles. | hidden/omitted dependencies, opaque reuse, forged enforcement, and invalidation skew all reject | carry the joined projection into native and migration experiments; do not infer real sandbox enforcement |
| EXP-0015-F005 | The joined candidate remains small enough for independent reimplementation, but the experiment is not production parity. | Rust 1,576 lines; Python 855; 16 constructors; 10,241-byte report; no forbidden dependency or backend name | preserve the candidate as research `/2`; require wider route coverage before production adoption |

## Outcome

All five questions pass over the frozen finite corpus:

- **Q1 passed:** six templates and all 500 generated valid programmes produced
  byte-identical complete Rust and Python reports with all 16 constructors.
- **Q2 passed:** every named join/integrity attack and all 500 generated
  single-mutation cases rejected with the exact frozen code.
- **Q3 passed:** all family ceilings were preserved and the four explicit
  assurance-strengthening attacks rejected.
- **Q4 passed:** valid and adversarial corpus identities and complete model
  reports were stable and identical across ten repetitions.
- **Q5 passed:** both kernels, the 4,701,210-byte generated corpus, and the
  10,241-byte report remained inside every frozen complexity ceiling without a
  backend name or forbidden direct dependency.

This supports the [Assurance IR `/2` research candidate](../../research/proofbound-language/assurance-ir-v2.md)
as the semantic target for EXP-LANG-007. It does not freeze a production wire,
prove either checker, validate an operating-system sandbox, or establish
complete parity with every current Proofbound route.
