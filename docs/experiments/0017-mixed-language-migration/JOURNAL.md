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

## 2026-09-03 — Rust graph kernel implemented

Implemented the first common graph kernel after freezing the corpus and
observing agreement between the foreign callers. The Rust kernel accepts only
canonical observation envelopes, independently rechecks the ABI and every
call identity, derives the baseline and migrated claim graphs, emits the exact
migration explanation, and applies all 30 registered attacks. Focused tests
rejected every attack with its registered code. The kernel measures 1,395
nonblank non-comment lines, within the frozen 1,400-line ceiling, and its
source contains none of the forbidden backend names. The independent Python
kernel and retained execution did not exist when this entry was added.

## 2026-09-03 — Independent graph kernel implemented

Implemented a separately authored Python graph kernel after the Rust kernel.
It parses the frozen controls without generated bindings, validates canonical
observation envelopes and all contract, graph, evidence-family, assumption,
and migration joins, reconstructs both phase reports, and independently
executes all 30 attacks. Focused parity tests used one canonical four-set
observation envelope: the kernels emitted byte-identical reports and exact
attack codes. The independent kernel measures 877 nonblank non-comment lines,
within the 1,400-line ceiling, and contains none of the forbidden backend
names. The actual registered callers and retained evaluator result did not
exist when this entry was added.

## 2026-09-03 — Evaluator implemented

Implemented the evaluator only after both common kernels agreed. It launches
both registered callers in both phases, constructs their canonical envelope,
runs both kernels for ten repetitions, compares the complete report bytes,
and only then opens the frozen expectations to decide Q1--Q5. It also measures
all registered line, report-size, elapsed-time, migration-set, explanation,
and forbidden-name ceilings. A development execution passed, but no result was
retained and no question was concluded when this entry was added.

## 2026-09-03 — Preregistered execution retained

Ran the exact registered Python 3.12.11 and Node 22.22.2 callers through the
legacy and native-backed phases. All 48 calls collapsed to the same twelve
semantic projections. The independent kernels emitted the same canonical
8,477-byte report with raw identity `sha256:a34b6298…07e2` across ten
repetitions, and all 30 attacks rejected with their exact registered codes.
The run completed in 3,387 ms. Callers measured 162 and 154 lines; kernels
measured 1,395 and 877 lines. No forbidden common backend name occurred. The
raw retained result is `sha256:e4bf92b8…0f2c`. Interpretive conclusions were
deliberately deferred to the next commit.

## 2026-09-03 — Concluded with bounded support

Accepted Q1--Q5 within the frozen scope. The decisive result is not that a
native proof transfers to either application; it is that the graph refuses
that transfer while still recording a useful artifact-bound strengthening.
The foreign applications remain tested, the native property remains universal
only over the declared four-value type, and compiler correspondence, bridge,
and runtime assumptions remain visible. The two independent common kernels do
not require backend-named rules for this contract. The result supports a
bridge-first language path, not general FFI safety, verified machine code, a
production language, or a final language-versus-framework decision.
