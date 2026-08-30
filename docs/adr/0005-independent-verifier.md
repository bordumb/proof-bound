# ADR 0005: Independently implement receipt verification

Status: accepted

The orchestration CLI executes tools and compiles statuses, so its own defect
could overstate a claim. `proofbound-verify` is therefore a separate crate and
binary with no dependency on any `proofbound-*` workspace crate. It parses
release records, validates their identities, reconstructs evidence closure, and
reimplements Specification 0001 §6.3.

The implementations share only immutable JSON conformance cases. CI requires
exact facet and assumption-set equality for every case. The verifier's success
language is “receipt-consistent”; it does not claim that an external tool ran
honestly.

