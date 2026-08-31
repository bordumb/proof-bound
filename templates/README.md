# Proofbound templates

These are copy-and-edit starting points for four recurring assurance
boundaries. They are deliberately outside the root project manifest: a
template describes intended evidence, but it does not become evidence until a
consumer registers it, replaces every `EXAMPLE-*` identity and `path/to/*`
location, and reproduces the corresponding units.

- [`artifact-checker/`](artifact-checker/) starts a strict canonical binary
  checker and keeps theorem evidence distinct from exact-byte binding.
- [`rust-aeneas-refinement/`](rust-aeneas-refinement/) starts a pure Rust
  kernel, a manifest-driven two-run Charon/Aeneas translation, and a
  handwritten refinement boundary outside the generated tree.
- [`explicit-assumption/`](explicit-assumption/) shows a Tier-0 claim whose
  real-world meaning depends on a visible external-provider assumption.
- [`trusted-transcription/`](trusted-transcription/) runs an exact external
  round trip through typed values while retaining separate transcriber and
  re-encoder trust roles.

The TOML examples conform to their declared public schema versions without
invented statement, artifact, or bridge digests. A missing digest remains an
open obligation until the responsible tool computes it.
