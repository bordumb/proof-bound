# Q1 finalization capture revision 1

[Finalization preregistration](../../q1-finalization-preregistration.json) ·
[Capture index](index.json)

This immutable research capture carries the Python and TypeScript semantic
artifacts forward byte-for-byte from `q1-completion-r1` and replaces only the
Rust vertical. The Rust replacement was produced from a detached clean
worktree at `4bdbb3f68f37e7346843bd4f5f4aadfc6cc4d3b7`, after the preregistered
correction changed `unit:rust-kernel-tests` from `property-test` to
`example-test`.

The full fresh project check admitted all nineteen claims. A portable release
was then independently checked by `proofbound-verify` with verdict
`receipt-consistent`, `publication_blocked=false`, and payload identity
`sha256:5ae497838b5abd06aa686446bf3312bf73839ae812642268ff86cdeca243d92e`.
The retained Rust receipt contains 32 evidence records; the corrected unit is
an example with the same five exact deterministic test targets and contains no
sampling detail.

The TypeScript receipt remains frozen under its original wire meaning. Any
layered sampling meaning is supplied by a separately versioned research
extension that must bind the exact receipt record and independently validated
case. It is not inserted into or inferred from these historical bytes.

As in revision 1, the retained files are semantic research artifacts, not a
redistributed complete release. Native binaries, copied public schemas, and
private execution state are deliberately excluded.
