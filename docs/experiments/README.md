# Experiments

Structured records of Proofbound pilots and use-case tests. Each experiment
answers pre-registered questions about the framework against a real subject —
a reference repository, an external crate, or Proofbound itself.

## Index

| # | Experiment | Subject | Tests | Status |
|---|---|---|---|---|
| [0001](0001-matrix-math-release-verification/README.md) | Matrix Math release verification | `matrix-math-publish` (GitHub) | Pattern A at scale; independent release verification; producer-absent boundary | planned |
| [0002](0002-auths-proof-algebra-kernel/README.md) | Auths Proof algebra kernel | `auths-proof` repo | §11.3 manifest inversion; per-harness Kani inventory | planned |
| [0003](0003-semver-precedence/README.md) | semver precedence | `semver` crate (crates.io) | Tier 0 brownfield UX; Pattern B on foreign code | planned |
| [0004](0004-base64-canonical-bytes/README.md) | base64 canonical bytes | `base64` crate (crates.io) | Tier 0→1 ladder; Pattern A on foreign bytes | planned |

Statuses: `planned` (pre-registered, not started) · `running` · `concluded` ·
`abandoned` (a status, not a deletion — the journal stays).

## Rules

1. **Pre-registration is a commit.** An experiment's Questions section lands
   in git before its first journal entry. That commit is the ordering
   evidence — the lesson of ADR 0001, applied forward.
2. **Every divergence gets a disposition.** Each finding is dispatched to
   `spec-change`, `adr`, `case-record`, `bug (fixed)`, or
   `accepted-limitation`, and indexed in [DIVERGENCES.md](DIVERGENCES.md).
   This is the Specification 0001 M5 acceptance evidence, in one file.
3. **Cite digests, not vibes.** Subjects are pinned by full commit or crate
   version; artifacts by content address. Large artifacts go to the CAS;
   the experiment folder holds pointers.
4. **Journals are append-only.** Corrections are new entries, never edits.
5. **Cross-repo pilots keep their record here.** Work happens in the subject
   repository; the learning belongs to proof-bound.

New experiments copy [TEMPLATE.md](TEMPLATE.md). Public-facing audit reports
graduate to [docs/audits/](../audits/README.md); the raw experiment record
stays here.
