# Manifest guide

The root `proofbound.toml` selects an adoption tier and file patterns for
claims, assumptions, evidence units, translations, model checks, policies, and
reviews. All formats are versioned and reject unknown fields.

Paths are repository-relative. Proofbound rejects absolute paths, `..`,
ambiguous matches, and symlinks at sealed boundaries. Collection and byte
limits apply before parsing. Translation packages, symbols, destinations,
bridges, warnings, and resource budgets belong in manifests; adapters contain
no project-specific lists.

Formal claim identity is a triple: fully qualified declaration,
`lean-expr-cbor/1`, and the domain-separated SHA-256 of its canonical CBOR.
Pretty-printed theorem text is diagnostic only.

See `schemas/` for the public contracts and either demo for complete consumers.

## Assurance-regression reviews

Register a repository-relative review pattern in `proofbound.toml`, for
example:

```toml
review_manifests = ["proofbound/reviews/*.toml"]
```

It is valid for this pattern to match no files before a review is needed. An
empty review collection grants no approvals.

Approvals use two commits. First commit the complete proposed change as the
**subject commit**. Run `proofbound diff BASE..SUBJECT --json` and review every
reported regression. Then add one or more `proofbound-review/1` manifests in a
separate **approval-envelope commit**. Each manifest binds
`proofbound-revision/1` identities for `BASE` and `SUBJECT` and copies every
approved regression's ID, claim, kind, and detail exactly.

The envelope may add only registered review manifests. A modified, deleted, or
renamed review, a non-review change, an unlisted regression, a stale extra
approval, or a subject that is no longer in the checked head's ancestry fails
closed. Squashing or rebasing the subject invalidates its approval.

For feature branches, both pull-request and push CI compare from the
default-branch merge base. Tag pushes use that merge base too, even when a tag
has the same short name as the default branch. The previous feature-branch tip
is deliberately not used: it is a transport cursor, not the base identity
reviewed by the approval.
Pushes to the default branch continue to use the event's `before` revision.
Scheduled runs and releases compare the checked snapshot from the fetched
default-branch merge base; they still execute all fresh gates even when that
snapshot transition is empty.

See [ADR 0019](../adr/0019-bind-approvals-to-a-reviewed-parent.md) for the
reason this is a two-phase protocol.
