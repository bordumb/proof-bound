# Experiment 0011 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0011-R001 | `README.md` | preregistered in `025aec9`, registration bytes `sha256:d44d91abe5c37c9af7dcb1eb659ccea4e990d6e45bbd90f21b92bdea76af8046` | Human questions, candidate boundary, metrics, attacks, and stop rules |
| EXP-0011-R002 | `preregistration.json` | preregistration revision 1, `sha256:63c9398d5597770b9cdcfe5c5c7338dc7801978ee749e54d8d22a4da3bf45458` | Machine-readable subjects, frontend/tool policy, questions, and exact attack codes |
| EXP-0011-C001 | `corpus/GRAMMAR.md` | frozen grammar revision 1, `sha256:b6578d38f1d8e7bffa77b485d5d01e61019d8765d9ed90f81fc518e0c03c8369` | Canonical model, custom grammar, Pkl authority, source-map, and metric rules |
| EXP-0011-C002 | `corpus/subjects.json` | frozen subject revision 1, `sha256:32dd9af0e19dc4bd4de5c94b0f1d5f0ca2dd3110136a3852dcc47d5b7c374bfd` | Source identities and expected canonical programme identities for all three projects |
| EXP-0011-C003 | `corpus/metrics.json` | frozen metric revision 1, `sha256:73cdf22d6bb4b9b3cf8a150c292c1c84ca0960bc90975e4d1de3397f7efb10cc` | Pre-implementation assignment counts and 25% threshold |
| EXP-0011-C004 | `corpus/attacks.json` | frozen attack revision 1, `sha256:c057c1b020a8b076358d85c24d08f9aa54619741c75d196b783124e3b66b78fd` | Twenty-two source, authority, canonicalization, and source-map attacks with exact codes |
| EXP-0011-C005 | `corpus/Schema.pkl` and project `.pkl`/`.pb` sources | frozen source identities in `subjects.json`; Pkl schema `sha256:01ddaf13508aac29b30ec0b5895e0436fb97a54e930c8b01ec56adcd43c689bc` | Equivalent typed frontend sources, validated with the pinned Pkl evaluator before compiler work |
| EXP-0011-E001 | `results/execution.json` | executed, `sha256:926d897ac28f790dd0de30c88d068720ffe42b2cea7bb8d9fbe324cb0d9bef25` | Ten repetitions of all nine compiler pairs, restricted Pkl observations, independent agreement, frozen controls, metrics, and 22 attacks |
| EXP-0011-E002 | `crates/proofbound-ir-prototype/src/frontend.rs` | implemented in `1bd21b6`, executable commands in `4d383d5` and `9fa8415` | Typed Rust compiler, formatter, validator, source-map/receipt derivation, and experiment boundary |
| EXP-0011-E003 | `python/proofbound/frontend_research.py` | implemented in `ca1b2df` | Independently written Python compiler, normalizer, source-map/receipt validator, and effective-programme checker |
| EXP-0011-E004 | `python/proofbound/frontend_experiment.py` | implemented in `9fa8415` | Repeated differential executor and adversarial harness |
