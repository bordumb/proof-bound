# ADR 0024: Unit-run diagnostics in status reports

- **Status:** Proposed
- **Date:** 2026-09-11
- **Decision owners:** Proofbound maintainers
- **Origin:** Proofbound Runtime PBF-0003

## Context

`proofbound check` already retains one `UnitRun` for each selected evidence
unit, including adapter diagnostics. The status renderer omitted those records.
A missing adapter, protocol mismatch, or adapter-reported failure therefore
appeared only as downstream missing evidence, obscuring the actual cause.

## Proposed decision

The machine-readable check/status projection advances to
`proofbound-report/2` and requires the complete ordered `unit_runs` array.
Every entry carries the unit, expected adapter, cache identity, closed outcome,
optional evidence identity, inventory, and structured diagnostics. Human status
output renders the same outcome, diagnostic code, message, optional path, and
remediation.

The orchestrator distinguishes these outcomes:

- `verified-now`;
- `verified-from-cache`;
- `failed` for an adapter that ran and rejected its unit;
- `unavailable` when the registered executable could not start; and
- `protocol-failed` for malformed or identity-mismatched adapter responses.

Invocation failures preserve their stable `PB-ADAPTER-*` cause instead of
collapsing to a generic wrapper. Adapter-reported failures preserve the
adapter's own structured diagnostics even though they produce no evidence.
Downstream missing-citation errors remain present and fail closed.

## Compatibility

This is a versioned status-report change, not a reinterpretation of report
version 1. Evidence receipts, policy derivation, exit codes, assumptions,
bounds, linkage, and trusted-computing-base roles are unchanged.

## Required falsifiers

- absent executable reports `PB-ADAPTER-0003`, its expected executable, and an
  installation remediation;
- wrong response identity reports `PB-ADAPTER-0007` as `protocol-failed`;
- adapter-returned failure diagnostics survive unchanged; and
- the JSON and human projections classify the same unit outcome.

## Review gate

The implementation is present on the PBF-0003 claim-wave branch. This ADR
remains proposed until a reviewer other than the change author approves the
report schema and failure-classification tests.
