# Experiment 0011 corpus

The corpus is frozen after preregistration and before compiler implementation.
It contains:

- `GRAMMAR.md`, the closed normalization, DSL grammar, Pkl authority policy,
  source-map contract, and metric algorithm;
- `subjects.json`, exact source and expected canonical programme identities;
- three `.pb` custom-DSL sources;
- `Schema.pkl` and three typed Pkl programme sources;
- `metrics.json`, expected assignment counts fixed before measurement; and
- `attacks.json`, one exact mutation and rejection code for every registered
  attack.

The current TOML files remain source subjects at the exact identities in the
preregistration. Generated dependency directories and the Pkl executable stay
outside Git; their exact release identity is registered separately.
