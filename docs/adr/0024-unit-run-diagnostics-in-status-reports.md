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
- `protocol-failed` for malformed or identity-mismatched adapter responses;
  and
- `timeout` when the adapter reports `PB-ADAPTER-0010`.

Invocation failures preserve their stable `PB-ADAPTER-*` cause instead of
collapsing to a generic wrapper. The invocation boundary returns a typed error;
the report path does not recover a code by scanning display text. Every run
uses the registered adapter executable name as its adapter identity, whether
the result came from cache, a successful response, an adapter-reported
failure, or an invocation failure. Adapter-reported failures preserve the
adapter's own structured diagnostics even though they produce no evidence.
Downstream missing-citation errors remain present and fail closed.

## Compatibility

This is a versioned status-report and adapter-protocol change, not a
reinterpretation. The report advances to `proofbound-report/2`. The subprocess
protocol advances to `proofbound-adapter-protocol/2` because failed responses
must carry at least one structured diagnostic. Protocol version 1 is rejected
instead of receiving the stronger meaning. Evidence receipts, policy
derivation, exit codes, assumptions, bounds, linkage, and trusted-computing-
base roles are unchanged.

## Required falsifiers

- an actual absent registered executable reaches a retained unit run with
  `PB-ADAPTER-0003`, its expected executable, and an installation remediation;
- wrong response identity reports `PB-ADAPTER-0007` as `protocol-failed`;
- a nested diagnostic-like token in an untyped error cannot replace the
  generic orchestrator failure code;
- cache, success, adapter failure, and invocation failure use the same
  executable identity;
- protocol version 1 and a version-2 failed response without diagnostics are
  rejected;
- adapter-returned failure diagnostics survive unchanged; and
- the JSON and human projections classify the same unit outcome.

## Review gate

The implementation is present on the PBF-0003 claim-wave branch. This ADR
remains proposed until a reviewer other than the change author approves the
report schema and failure-classification tests.
