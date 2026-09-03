# Experiment 0015 artifact ledger

[Experiment registration](README.md) · [Journal](JOURNAL.md)

| ID | Path | Status | Meaning |
|---|---|---|---|
| EXP-0015-R001 | `README.md` | preregistered | Human questions, candidate, measurements, attacks, scope, and procedure |
| EXP-0015-R002 | `preregistration.json` | preregistered | Machine-readable subject, questions, attacks, generation, and complexity ceilings |
| EXP-0015-C001 | `corpus/model.json` | frozen, `sha256:2832f7d3f94c9c79a7bef266b69a724cb04cde8ac6ea2d68c616066f144aded4` | Closed families, roles, effects, uncertainty, rules, constructors, and validation codes |
| EXP-0015-C002 | `corpus/templates.json` | frozen, `sha256:b7cd310d4ff7e3c60fc825b36c3048274a3e70bc805823444a628e266fcac651` | Six backend-neutral expansion profiles |
| EXP-0015-C003 | `corpus/attacks.json` | frozen, `sha256:dc33edbadf387677cf72354054ed17ac5041ce69a3790b8f8d9f13ec599c065a` | Twenty-eight exact typed and integrity mutations |
| EXP-0015-C004 | `corpus/generation.json` | frozen, `sha256:e4dae6c1e1408907253b855b0d73fa639653ff3a7f77adee38bd51ae0cd5f3b0` | Deterministic 500/500 selection and suffix algorithm |
| EXP-0015-C005 | `corpus/expected.json` | frozen, `sha256:f7ab4465b505fd61d51c870d4893d8edff1b4addbf4a0452c9e613fe854467f3b` | Counts and complexity ceilings without implementation outputs |
| EXP-0015-C006 | `corpus/CONTRACT.md` | frozen, `sha256:5420e9051d45f42e92ee4eaefc97fc0acffc8d9bf9cee38a8ef4dd280d8f02f1` | Independent profile expansion, validation precedence, derivation, and generation contract |
| EXP-0015-I001 | `crates/proofbound-ir-prototype/src/assurance_v2.rs` | implemented; 1,576 nonblank non-comment lines | Rust typed differential kernel, profile expansion, deterministic generator, and exact attack executor |
| EXP-0015-I003 | `crates/proofbound-ir-prototype/src/main.rs` | implemented | Research-only `execute-assurance-v2` command |
| EXP-0015-I002 | `python/proofbound/assurance_v2_research.py` | implemented independently; 855 nonblank non-comment lines | Python closed-record kernel, profile expansion, deterministic generator, and exact attack executor |
| EXP-0015-I004 | `python/tests/test_assurance_v2_research.py` | passing | Full frozen corpus, self-consistent decision upgrade, and dependency-identity regressions |
| EXP-0015-E001 | `results/execution.json` | absent | Retained comparison and Q1--Q5 decisions |
