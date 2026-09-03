# Experiment 0010 corpus

The bounded corpus will contain source-retained dependency projections,
before/after change scenarios, and explicit ground-truth invalidation sets for
the fifteen controlled units and two external holdouts registered in
[`preregistration.json`](../preregistration.json).

No fixture exists at preregistration time. Corpus revision 1 must be generated
only after the registration commit and must bind every source path to exact
bytes, size, permission model, and role. Dependency directories, build output,
private caches, and executable binaries remain outside Git; their bounded
identities and relevant metadata are retained instead.
