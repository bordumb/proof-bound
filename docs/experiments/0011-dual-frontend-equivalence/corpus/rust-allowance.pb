programme "rust-allowance" ecosystem "rust"

defaults "cargo-common"
tier = 0
assumptions = []
outputs = []
environment_allowlist = ["CARGO_HOME","PATH","RUSTUP_HOME"]
resource_budget = {"time_seconds":120,"disk_bytes":1073741824,"memory_bytes":2147483648}
end

claim "DEMO-TRANSFER-003"
title = "Accepted transfers respect the configured cap"
statement = "For every accepted request, the requested amount is less than or equal to its configured cap."
public_language = "Given the explicit identity-provider assumption, every accepted transfer respects its configured per-transfer cap; Kani additionally checks the registered finite 2^34 request domain."
subject = "rust:allowance-kernel::decide_transfer"
formal_declaration = "ProofboundDemo.Claims.Transfer.accept_respects_cap"
statement_encoding = "lean-expr-cbor/1"
statement_sha256 = "sha256:8e10c3a3ef53e898dd400d8348ac0a70cb485c9012aaade92f7ba49ef94324be"
foundational_axioms = ["Quot.sound","propext"]
profile = "kernel-with-assumptions"
tier = 2
primary_linkage = "model-only"
evidence = ["theorem:accept-respects-cap","bounded-check:transfer-bounds","example-test:rust-kernel-tests","mutation-witness:remove-cap-guard"]
assumptions = ["DEMO-IDENTITY-AX-001"]
premises = ["DEMO-U64-REP-001"]
open_obligations = ["Produce a deterministic Charon/Aeneas receipt for the registered shipping symbol."]
out_of_scope = ["Whether the configured cap reflects an appropriate business policy."]
source_roots = ["demo/allowance/rust/kernel/src/decision.rs","demo/allowance/rust/kernel/src/lib.rs","demo/allowance/lean/ProofboundDemo/Claims/Transfer.lean","demo/allowance/lean/ProofboundDemo/Transfer.lean","demo/allowance/lean/ProofboundDemo/TransferRefinement.lean"]
bounded_domain = {"id":"allowance-u8-seeds-with-overflow-lane","description":"All four u8 numeric seeds, both authorization values, and both low/high destination lanes; 2^34 finite requests, including destination-overflow cases.","cardinality":17179869184,"ordering_key":[0,1,2,3,4,5]}
end

evidence lean-theorem "accept-respects-cap"
claims = ["DEMO-TRANSFER-003"]
tier = 2
assumptions = []
expected_inventory = ["ProofboundDemo.Claims.Transfer.accept_conserves","ProofboundDemo.Claims.Transfer.accept_never_overdraws","ProofboundDemo.Claims.Transfer.accept_respects_cap","ProofboundDemo.Claims.Transfer.denial_unchanged"]
inputs = ["demo/allowance/lean/ProofboundDemo/Claims/Transfer.lean","demo/allowance/lean/ProofboundDemo/Transfer.lean"]
outputs = []
environment_allowlist = ["LEAN_PATH","PATH"]
evaluation_mode = "kernel"
theorem = "ProofboundDemo.Claims.Transfer.accept_respects_cap"
operation = {"type":"lean-audit","targets":["ProofboundDemo.Claims.Transfer.accept_respects_cap"],"paths":["demo/allowance/lean/ProofboundDemo/Claims/Transfer.lean"]}
resource_budget = {"time_seconds":60,"disk_bytes":268435456,"memory_bytes":1073741824}
end

evidence rust-mutation "remove-cap-guard" using "cargo-common"
claims = ["DEMO-TRANSFER-003","DEMO-TRANSFER-005"]
expected_inventory = ["remove-cap-guard"]
inputs = ["demo/allowance/proofbound/mutations/mutants/remove-cap-guard/decision.rs","demo/allowance/proofbound/mutations/remove-cap-guard.toml","demo/allowance/rust/kernel/src/decision.rs","demo/allowance/rust/kernel/tests/mutation_witnesses.rs"]
mutation = {"schema":"proofbound-mutation-replay/1","registry":"demo/allowance/proofbound/mutations/remove-cap-guard.toml"}
operation = {"type":"cargo-test","package":"allowance-kernel","manifest":"Cargo.toml","targets":[]}
end

evidence rust-example "rust-kernel-tests" using "cargo-common"
claims = ["DEMO-TRANSFER-001","DEMO-TRANSFER-002","DEMO-TRANSFER-003","DEMO-TRANSFER-004","DEMO-TRANSFER-005","DEMO-TRANSFER-006"]
expected_inventory = ["allowance_kernel::tests::accepted_transfer_uses_checked_arithmetic","allowance_kernel::tests::canonical_encoding_round_trips","canonical_fixtures::accepted_fixture_decodes_and_evaluates","canonical_fixtures::decoder_rejects_noncanonical_and_trailing_inputs","canonical_fixtures::denied_fixtures_have_stable_codes_and_unchanged_state"]
inputs = ["demo/allowance/rust/kernel/src/lib.rs","demo/allowance/rust/kernel/tests/canonical_fixtures.rs","demo/allowance/fixtures/v1/manifest.json"]
operation = {"type":"cargo-test","package":"allowance-kernel","manifest":"Cargo.toml","targets":["--lib","--test=canonical_fixtures"]}
end

evidence kani-bounded "transfer-bounds"
claims = ["DEMO-TRANSFER-001","DEMO-TRANSFER-002","DEMO-TRANSFER-003","DEMO-TRANSFER-004"]
tier = 1
assumptions = []
expected_inventory = ["kani_harnesses::accepted_conserves_value","kani_harnesses::accepted_never_overdraws","kani_harnesses::accepted_respects_cap","kani_harnesses::denial_returns_unchanged_state"]
inputs = ["demo/allowance/rust/kernel/src/lib.rs","demo/allowance/proofbound/model-checks/transfer-bounds.toml"]
outputs = []
environment_allowlist = ["CARGO_HOME","RUSTUP_HOME","PATH"]
operation = {"type":"kani","package":"allowance-kernel","manifest":"demo/allowance/proofbound/model-checks/transfer-bounds.toml","targets":["kani_harnesses::accepted_conserves_value","kani_harnesses::accepted_never_overdraws","kani_harnesses::accepted_respects_cap","kani_harnesses::denial_returns_unchanged_state"]}
bounded_domain = {"id":"allowance-u8-seeds-with-overflow-lane","description":"All four u8 numeric seeds, both authorization values, and both low/high destination lanes; 2^34 finite requests, including destination-overflow cases.","cardinality":17179869184,"ordering_key":[0,1,2,3,4,5]}
resource_budget = {"time_seconds":600,"disk_bytes":2147483648,"memory_bytes":4294967296}
end

end
