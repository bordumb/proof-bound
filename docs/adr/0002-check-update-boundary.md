# ADR 0002: Separate verification from regeneration

Status: accepted

`proofbound check` may write only beneath `.proofbound/`, which is ignored and
treated as an evidence cache. It never changes manifests, fixtures, translated
Lean, closures committed for review, or other source artifacts.

`proofbound update UNIT` is the only regeneration path. It first requires a
clean worktree, reproduces into bounded temporary directories, validates file
count/size/path/symlink constraints, and then replaces only the unit's declared
outputs. CI invokes verify-only commands on every event; update workflows emit
a reviewable diff and never accept it automatically.

