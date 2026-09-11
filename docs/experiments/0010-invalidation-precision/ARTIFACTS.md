# Experiment 0010 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0010-R001 | `README.md` | preregistered in `26f460f`; subsequently concluded without changing the registered criteria | Human questions, model, corpus, measures, stop rules, findings, and decisions |
| EXP-0010-R002 | `preregistration.json` | preregistration revision 1, `sha256:df6c3aa3ba48f20f673a93f8ae89100cb761bb90bcfac6a1e5f017b4730683da` | Machine-readable subjects, routes, change classes, attacks, and decisions |
| EXP-0010-C001 | `corpus/cases.json` | frozen corpus revision 1, `sha256:72fcbb055e00830ec9d2377df3d554d4f8c76661c8b469be7fb8ad9fa63b73ee` | Fifteen controlled unit manifests, two external semantic closures, and the auxiliary mode fixture |
| EXP-0010-C002 | `corpus/scenarios.json` | frozen scenario revision 1, `sha256:562e1db45e9a021fba982f4e4e188e8278f7f6a07e608b842af4fb25d4d9b7b1` | Twenty-five change scenarios with exact evaluation scopes and affected-unit sets |
| EXP-0010-C003 | `corpus/fixtures/mode-project/` | frozen executable-mode fixture; exact files and executable mode are bound by the corpus commit | A Cargo build whose same-byte helper permission is load-bearing |
| EXP-0010-C004 | `corpus/extension-r2.json` | frozen corpus extension revision 2, `sha256:361697ae72217abdc6242655e3c421da0c8ced65a363d3b11841f74b1960a323` | Corrects the transitive-source interpretation with a selected package consuming a repository-owned source outside its package root |
| EXP-0010-C005 | `corpus/scenario-bindings-r3.json` | frozen scenario binding revision 3, `sha256:b25d65993c24b335f6c344be39f9b254d4f5489a927a3d7761cdfd63b8f01e99` | Separates typed changed-node selectors from the independently registered expected affected sets |
| EXP-0010-E001 | `results/execution.json` | model execution, `sha256:9d3f3dd4091aac0ccb00beb9e6e98a37d675731ea1e4eb1eab65395e38eaa141` | Nineteen source-derived projections and independently checked traces for all twenty-six registered scenarios; this is not forced-fresh route evidence |
| EXP-0010-E002 | `results/forced-fresh-smoke.json` | retained fresh execution, `sha256:374c781e11bd1398e1c7184a6d1360688995c98eca476e21a29e0934a8dd6fcf` | Controlled and holdout baseline outcomes plus load-bearing auxiliary mutations; records the incomplete change matrix and unanswered Lean route |
| EXP-0010-E003 | `results/revision-falsifier.json` | retained executable falsifier, `sha256:57a6ea5bef0a98088cc2083f3efde8dd65540bbcfafcafb966ce87ed4b55d95e` | Demonstrates stale reuse under declared-only dependencies and over-invalidation under a global revision identity |

The registration rows receive their historical commit and digest in the first
result closeout rather than changing the registered question text. Executed
artifacts are immutable and receive new rows rather than overwriting registered
inputs.
