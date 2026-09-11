# Experiment 0027 journal

[Experiment registration](README.md) · [Artifact ledger](ARTIFACTS.md)

This journal distinguishes diagnostic implementation runs from the retained
confirmation. Failed and partial runs produced no reusable assurance evidence.

## 2026-09-04 — Preregistered

Registered a successor to EXP-0026 before implementing the observer, executor,
validators, or results. The registration retained all 51 workloads and the
entire Windows boundary, introduced four typed network outcomes, required
read-only WFP collection, retained all 38 attacks, and added ten attribution
attacks. Only an exact synchronous denial or fully bound capability-drop event
could satisfy the network-denial question.

## 2026-09-04 — Candidate implemented

Implemented a native Rust WFP observer, a Python executor, and independent
Python and Rust validators. The observer links directly to `Fwpuclnt`, queries
collection, subscribes before workload execution, and retains capability drop
and allow events. Static closure validation rejects policy-changing WFP and
firewall APIs. Local replay of the prior capture with synthetic event records
confirmed byte-identical reports and all 48 exact attack classifications.

## 2026-09-04 — Diagnostic corrections

[Run 33843851413](https://github.com/bordumb/proof-bound/actions/runs/33843851413)
proved that collection and subscription were available, then failed because
the application ID was queried after AppContainer profile teardown. The lookup
was moved into the already suspended child boundary, after token verification
and before resume; this changed no workload or authority.

[Run 33844067259](https://github.com/bordumb/proof-bound/actions/runs/33844067259)
completed native execution and produced byte-identical semantic reports. It
then exposed a diagnostic-corpus defect: zero live WFP events left event-field
mutations with no source record. The attack generator was made self-contained
by first adding a valid synthetic, identity-bound event and then applying each
registered corruption. Synthetic events exercise rejection only and never
enter the positive report.

## 2026-09-04 — Retained native confirmation

[GitHub run 33844439146](https://github.com/bordumb/proof-bound/actions/runs/33844439146)
completed every registered stage. All 30 permitted workloads and all 18 non-
network authority denials remained exact. Three controls connected; zero
sandbox connections were accepted. WFP collection stayed enabled and the
observer changed no policy, but it retained zero capability events. All three
network outcomes were therefore `bounded-non-delivery`.

Python and Rust emitted identical 6,306-byte semantic reports and identical
5,158-byte attack reports. All 48 attacks rejected exactly. The 457,009-byte
capture completed in 54,015 ms with no tree change or reusable denied result.

## 2026-09-04 — Concluded with revision required

Q1, Q3, Q4, and Q5 pass. Q2 fails because zero of three network attempts has a
registered synchronous denial or fully bound WFP capability-drop event. The
immutable decision is `revise`; non-delivery remains explicit and non-reusable.
