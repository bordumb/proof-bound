# Experiment 0013 corpus

[`CONTRACT.md`](CONTRACT.md) freezes the closed data model, baseline,
claim-oriented grouping algorithm, oracle measurements, and human-evidence
boundary. `scenarios.json` contains six scenarios, 20 raw findings, and all six
uncertainty states. `oracle.json` independently names six publication-critical
actions. `attacks.json` fixes the 20 preregistered mutations. `expected.json`
freezes counts and thresholds; `instrument.json` freezes a study shape but
contains no participant responses.

The engines must not read `oracle.json` or `expected.json` while constructing
notifications. Those files are inputs only to the post-execution evaluator.
