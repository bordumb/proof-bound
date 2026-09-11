# Research programmes

[Documentation map](../README.md)

This directory coordinates sustained research that spans several experiments.
It is non-normative: research models do not define shipping behavior until an
accepted decision is recorded in `docs/adr/` and the corresponding obligations
are incorporated into `docs/specs/`.

## Organization

Research is **topic-first**. Each programme owns a stable directory containing
its hypotheses, roadmap, corpus, metrics, open questions, and workstreams.
Chronological observations remain in numbered experiment folders under
`docs/experiments/`; dates appear only in append-only journals and immutable run
results.

```text
research/<programme>/         questions, dependencies, gates, and synthesis
experiments/<number>-<name>/  preregistration, execution, results, and findings
adr/                          accepted architectural decisions
specs/                        normative obligations
```

Programme documents summarize experiment evidence by link. They must not copy
raw results or silently reinterpret a registered question.

## Programmes

| Programme | Status | Current gate | Active experiment | Purpose |
|---|---|---|---|---|
| [Proofbound language](proofbound-language/README.md) | active | Gate 1 — shared semantics | [Experiment 0005](../experiments/0005-assurance-ir-extraction/README.md) | Determine whether one assurance kernel can support existing-language projects, a typed assurance DSL, and eventually native executable programs. |

## Required programme files

Every active programme should maintain:

- `README.md` — compact dashboard and current synthesis;
- `hypotheses.md` — stable hypothesis IDs and falsifiers;
- `roadmap.md` — dependency-ordered gates and decision rules;
- `corpus.md` — controlled and external research subjects;
- `metrics.md` — shared measurement definitions;
- `open-questions.md` — unresolved questions that are not yet decisions; and
- `workstreams/` — bounded research areas linked to experiments.

## Lifecycle

```text
note → research programme → preregistered experiment → finding/divergence
     → ADR → specification → guide or independently checkable audit
```

Null results and stop decisions are valid research outcomes. A programme is
archived rather than deleted when its central hypotheses fail.
