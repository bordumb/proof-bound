# Proofbound language research metrics

[Programme dashboard](README.md)

Metric IDs are stable. Experiments may add context but must not silently change
these definitions.

| ID | Metric | Definition | Target |
|---|---|---|---|
| M-SOUND-001 | False evidence acceptance | Registered adversarial cases accepted as valid evidence | Zero |
| M-SOUND-002 | Stale retention | Load-bearing changes after which cached evidence is accepted | Zero |
| M-SOUND-003 | Producer/checker disagreement | Cases for which independent implementations disagree on validation, derivation, or publication | Zero |
| M-SOUND-004 | Forbidden coercion | Cases where one evidence family is accepted as a stronger family | Zero |
| M-IR-001 | Backend-name branches | Concrete tool/language-name conditionals in generic IR validation or status derivation | Zero for selected routes |
| M-IR-002 | Unclassified consumed fields | Assurance-relevant source fields without exactly one primary classification | Zero at EXP-0005 close |
| M-IR-003 | Canonical disagreement | Positive cases whose canonical bytes differ between independent implementations | Zero |
| M-INV-001 | Invalidation precision | Truly affected evidence divided by all invalidated evidence | Report by change class; improve over full rerun |
| M-INV-002 | Re-execution reduction | Work avoided relative to a complete fresh run | Report without compromising M-SOUND-002 |
| M-UX-001 | Impact-assessment time | Time to identify affected claims and required action | Lower than tool-oriented baseline |
| M-UX-002 | Missed critical consequence | Scenarios where a participant misses a real publication-impacting change | No increase over baseline |
| M-UX-003 | False escalation | Unaffected scenarios escalated for investigation | Lower than tool-oriented baseline |
| M-OPS-001 | Independent verification time | Wall time for the standalone checker over a pinned release | Record per corpus and environment |
| M-OPS-002 | Portable receipt size | Canonical release bytes required for independent verification | Record per evidence family and claim |

Finite corpus targets are not universal soundness claims. Every result must name
the corpus version and environment under which it was observed.
