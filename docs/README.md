# Documentation

This is the entry point for Proofbound's design, product, evidence, and working
documents. Different directories carry different authority; a working note is
not a specification, and an experiment record is not an accepted design
decision.

## Product direction

- [Product vision](product-vision.md) describes the durable product thesis and
  intended user outcomes.
- [Product analysis](product-analysis.md) evaluates the present implementation
  and adoption surface.
- [Working notes](notes/README.md) preserve topic-led ideas that have not yet
  graduated into a normative or user-facing document.
- [Research programmes](research/README.md) coordinate related hypotheses,
  workstreams, corpora, metrics, and preregistered experiments without making
  their provisional models normative.

## Normative design and decisions

- [Specification 0001](specs/0001_initial_spec.md) is the normative design.
- [Specification 0002](specs/0002_python_support.md) defines Python
  ecosystem support.
- [Specification 0003](specs/0003_typescript_support.md) defines TypeScript
  ecosystem support.
- [Architecture decision records](adr/) explain accepted decisions and their
  consequences.

## Papers

- [Proofbound paper](papers/README.md) — the academic systems paper
  (`papers/proofbound.md`, built to PDF with Pandoc/XeLaTeX).

## Using Proofbound

- [Adoption guide](guides/adoption.md)
- [Manifest guide](guides/manifests.md)
- [TypeScript adoption guide](guides/typescript.md)
- [Release verification guide](guides/release-verification.md)

## Evidence and investigations

- [Experiments](experiments/README.md) contain pre-registered questions,
  journals, measured results, and divergence dispositions.
- [Audits](audits/README.md) contain polished assurance assessments promoted
  from completed investigations.
- [Assurance records](assurance/README.md) contain machine-oriented reference
  audit material.

## Where new material belongs

| Material | Location |
|---|---|
| Unsettled product or engineering idea | [Working notes](notes/README.md) |
| Multi-experiment research programme | [Research programmes](research/README.md) |
| Accepted architecture or trust-boundary decision | `adr/` |
| Normative behavior or wire contract | `specs/` |
| User procedure | `guides/` |
| Pre-registered investigation and raw results | `experiments/` |
| Polished, independently checkable assessment | `audits/` |

The [working-notes conventions](notes/README.md) explain naming, dating,
indexing, and promotion in more detail.
