# ADR 0019: Bind assurance approvals to a reviewed subject commit

## Context

Proofbound requires assurance regressions to be approved against exact Git
revisions. The first pull request to exercise that gate exposed a circular
protocol: a committed review manifest named the digest of the exact head
commit, but adding the review manifest necessarily created a different head
commit. No committed pull request could satisfy the rule.

Dropping exact revision binding would make approvals reusable after unrelated
changes. Computing an identity that excludes review files would avoid the
cycle, but it would introduce a second tree-identity scheme and an exclusion
boundary whose mistakes could hide reviewed bytes.

## Decision

An assurance approval uses two phases:

1. A **subject commit** contains the complete code, manifests, generated
   artifacts, documentation, and the registered review-manifest pattern.
2. A later **approval envelope** adds the review manifest or manifests. Each
   review binds the domain-separated identities of the merge base and subject
   commit and enumerates every approved regression exactly.

When CI is asked to compare the base with the approval-envelope head,
Proofbound resolves the review's subject identity to an ancestor, requires the
subject-to-envelope tree delta to consist exclusively of newly added,
registered review manifests, computes regressions over base-to-subject, and
loads approvals from the envelope.

The comparison base is stable across CI event types. Pull-request checks use
the event's base revision. A push to any non-default ref, including a tag,
recomputes the merge base between that head and the fetched default branch; it
does not use the previous feature-branch tip. A default-branch push uses the
event's `before` revision. Scheduled and release checks compare their snapshot
from the fetched default-branch merge base; when the snapshot is the current
default tip, that transition diff is empty while the fresh verification stages
still run. Missing event revisions or a missing default-branch ref fail closed.
This prevents the same approval envelope from being interpreted against a
different base merely because it was delivered by a different event.

Review records are immutable in an envelope. Modifying, deleting, or renaming
a review, adding any non-review byte after the subject, naming a non-ancestor,
or mismatching any regression field invalidates the approval. A review glob may
match no files before approval; zero matched reviews grant zero approvals and
therefore remain fail closed.

The subject commit must remain in ancestry. A merge that preserves the subject
and its tree may retain the approval. Squashing or rebasing changes the subject
identity and requires a new approval.

## Consequences

- A pull request can carry an exact, attributable approval without a
  self-referential commit hash.
- The approval commit is intentionally content-restricted and easy to inspect.
- Any post-review change, including documentation, requires regeneration and
  renewed approval.
- Repositories using squash-only integration must either change that policy or
  regenerate approvals for the resulting subject revision.
- Review manifests remain historical graph evidence; they are not a blanket
  exception or a suppression rule.
