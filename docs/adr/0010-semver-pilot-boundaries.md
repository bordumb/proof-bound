# ADR 0010: Treat foreign-code entry costs as evidence, not exceptions

Status: accepted

## Context

Experiment 0003 applied Proofbound to the crates.io `semver` 1.0.28 package.
The pilot exposed four distinct boundaries. First, the Rust closure discovery
code emitted `/**` for the common case where a Cargo package is the project
root. Second, a Charon command can exit successfully while selecting no
declarations, so process success alone is not translation evidence. Third, the
shipping prerelease comparator's generic string/iterator implementation is
outside the tested Aeneas subset and needs a substantial pure byte-kernel
extraction. Fourth, the phrase “build metadata ignored, total order” conflates
a total preorder on concrete versions with a total order on their precedence
projection.

The mutation exercise also distinguishes a registered witness from automatic
mutant replay. Proofbound's current mutation registry binds IDs, witness test
nodes, and declared input bytes, but does not itself apply the path named by a
`mutant` field. That limitation must remain visible when interpreting the
evidence.

## Decision

- Normalize a project-root Rust package to the relative recursive glob `**`,
  never the absolute-looking `/**`. Retain the same helper for nested packages
  and test both cases.
- Treat a translation as absent unless the adapter observes the exact required
  symbols and a nonempty local inventory. A zero exit status with an empty
  report is not evidence.
- Record the measured +180/−4 pure-kernel refactor as Pattern-B entry cost. Do
  not copy the temporary extraction into Proofbound and do not weaken the
  generic framework around the subject's compact unsafe string representation.
- State build-insensitive precedence as a total preorder on concrete
  `Version` values, or as a total order on a projection/quotient modulo build
  metadata. A future theorem must choose one explicitly.
- Interpret current mutation-witness evidence as execution of exact registered
  witness nodes over byte-bound inputs. Seeded source mutations must still be
  applied in isolated snapshots and shown to flip the applicable claim; do not
  imply that v0.5 automatically replays an arbitrary patch named in the
  registry.
- Treat one mutation-witness unit as one evidence fate. If per-mutation claim
  attribution is required, register one mutation and witness per evidence unit;
  a shared unit is deliberately conservative and fails all attached claims
  when any witness fails.

## Consequences

Tier 0 remains achievable without formal tooling. Q2 can pass honestly with a
large measured refactor outcome, while Q3 remains unanswered until a real
termination-and-refinement proof exists. The root-package fix is reusable
Proofbound code; all semver extraction and mutation work stays in isolated
experiment branches and is not upstreamed.
