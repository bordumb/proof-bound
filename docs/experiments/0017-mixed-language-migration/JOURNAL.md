# Experiment 0017 journal

[Experiment registration](README.md)

Append-only execution notes begin after the preregistration commit.

## 2026-09-03 — Preregistered

Registered the mixed-language migration study after EXP-LANG-007 concluded and
before defining its ABI, call corpus, foreign callers, mixed graphs, attacks,
expected values, or implementations. The study makes its critical ceiling
explicit: a proved native component may strengthen a dependency fact, but it
must not turn a Python or TypeScript application claim into a proof.

## 2026-09-03 — Migration corpus frozen

Committed a backend-neutral ABI, exact EXP-LANG-007 artifact binding, two
runtime registrations, twelve encode/decode cases, baseline and migrated claim
graphs, explicit affected/unaffected sets, 30 attacks, and complexity ceilings.
The baseline carries a legacy-parser assumption. The migrated graph introduces
one finite native source claim, strengthens only the two packet callers'
artifact linkage, retains their tested formal ceiling, and records runtime,
bridge, and compiler-correspondence assumptions. Neither caller or graph kernel
existed when the corpus was frozen.

## 2026-09-03 — Foreign callers implemented

Implemented independent Python and TypeScript callers after the ABI and cases
were frozen. Each validates its runtime and the complete contract, executes all
twelve cases through both a direct legacy implementation and the exact native
artifact path, represents boundary failures as tagged data, forbids callbacks,
and emits domain-separated call and observation identities. All 48 calls
matched the frozen outcomes, and their semantic projections agreed across
language and phase. The callers measure 162 and 154 lines, below the registered
300-line ceiling. No common graph kernel existed when this entry was added.
