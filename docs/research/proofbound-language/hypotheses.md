# Proofbound language hypotheses

[Programme dashboard](README.md)

Hypothesis IDs are stable. A material revision retires an ID and introduces a
new one; it does not rewrite the original claim after results are known.

| ID | Status | Hypothesis | Primary falsifier | Tested by |
|---|---|---|---|---|
| H1 | falsified for draft `/1`; revision pending | Existing evidence routes can compile into a small canonical Assurance IR without losing assurance-relevant detail. | The IR requires proliferating tool-named core variants or cannot reproduce current semantic projections. | EXP-0005 |
| H2 | testing | Evidence strength can be represented as a closed algebra with statically constrained composition. | Common routes require ad hoc status rules outside the algebra or flatten unlike evidence. | EXP-0005, EXP-0008, EXP-0009 |
| H3 | testing | Exact semantic dependencies can invalidate evidence soundly and more narrowly than repository-wide reruns. | A load-bearing change retains evidence or routine unrelated changes invalidate most of the graph. | EXP-LANG-003 / Experiment 0010 |
| H4 | planned | A typed assurance DSL can reduce authoring errors and duplication while compiling identically to existing manifests. | Equivalent frontends diverge or the effective programme is harder to review. | planned EXP-LANG-004 |
| H5 | planned | An effect and capability model can prevent demonstrated ambient-authority defects before evidence execution. | Known defects pass static checks or useful operations require effectively unrestricted authority. | planned EXP-LANG-005 |
| H6 | planned | First-class uncertainty yields more actionable, lower-volume signals than tool-oriented alerts. | Users miss more critical consequences or gain no measurable reduction in irrelevant escalation. | planned EXP-LANG-006 |
| H7 | planned | A small native executable subset can bind code, specification, proof, build, and release more strongly than existing-language adapters. | Trusted complexity exceeds the gain or an existing verified language provides the same outcome more simply. | planned EXP-LANG-007 |
| H8 | planned | Native and foreign components can share one graph without presenting empirical correspondence as formal proof. | Foreign boundaries become untyped escape hatches or obscure claim meaning. | planned EXP-LANG-008 |

## Current interpretation

H1's draft `/1` form is falsified by EXP-0005: portable cache evidence lacks
the complete dependency projection required by its registered losslessness
criterion. This does not reject the existence of every possible Assurance IR;
it requires a revised candidate grounded in EXP-LANG-003 rather than a silent
patch to `/1`. EXP-0008 and EXP-0009 support bounded slices of H2, but do not
establish the complete production algebra. H2 remains under test.
