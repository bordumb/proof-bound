# Experiment 0014 frozen corpus

- `universe.json` is the external finite carrier, variable, role, and mutant
  registration.
- `contracts.json` is the candidate typed specification suite.
- `execution-tables.json` records the correct relation and all six mutants
  explicitly.
- `attacks.json` contains the 20 preregistered mutations.
- `expected.json` contains withheld counts and complexity ceilings.
- `CONTRACT.md` freezes normalization, evaluation, adequacy, and identity rules.

The corpus commit precedes both checker implementations. Changing any file
requires a new experiment revision rather than rewriting the retained result.
