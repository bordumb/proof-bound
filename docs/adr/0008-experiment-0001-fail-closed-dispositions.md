# ADR 0008: Keep Experiment 0001 failures fail-closed

Status: accepted

## Context

Experiment 0001 applied Proofbound v0.5 to the pinned
`matrix-math-publish` snapshot. It exposed five divergences: a subject-native
substring release reader, incompatible empty-collection wire shapes between
Proofbound's release producer and verifier, no executable trusted-transcription
adapter/TCB path, omitted subject test fixtures, and contradictory literal
wording in the pre-registered producer-absence criterion.

The specification already requires structured parsing, canonical receipts,
explicit trust boundaries, and honest not-proved sections. Relaxing those
requirements would hide the findings. Editing the pre-registered questions
after START would also destroy the experiment's ordering evidence.

## Decision

- Do not use the subject's substring-based release verifier as evidence for
  Q1. Use Proofbound's independent verifier as the veto, and record Q1 as
  failed when that verifier rejects the emitted release.
- Do not fork `proofbound-core`, fabricate the absent rank artifact, or map a
  generic test observation to trusted-transcription. Record Q3 as failed and
  preserve the missing adapter/TCB representation as product work.
- Do not fetch the missing Mathlib toolchain during the unattended pilot.
  Record the formal omega question as unanswered.
- Switch the Tier-0 demonstration only after recording the omitted fixture;
  bind the replacement to a self-contained existing exact-byte test.
- Apply Q4 literally and record failure. Future experiments may state the
  operational boundary as “no private producer artifact, code, identity,
  command, or evidence dependency enters closures or the TCB; the mandatory
  exclusion statement may name the excluded producer.” This clarification
  does not retroactively change Experiment 0001's frozen question.

## Consequences

Experiment 0001 has no stretched pass and no aggregate score. The v0.5
specification remains normative and unchanged. The product and subject defects
remain visible as numbered findings, while later fixes can cite this ADR and
the original failing evidence instead of rewriting the pilot record.
