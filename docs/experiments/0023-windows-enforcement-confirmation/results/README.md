# EXP-0023 results

These are the canonical artifacts retained from
[GitHub Actions run 33814855635](https://github.com/bordumb/proof-bound/actions/runs/33814855635):

- `host-probe.json` qualifies the exact native host and required API surface;
- `process-smoke.json` records the actual suspended child token, job ordering,
  AppContainer profile, private desktop, staged executable, and exit status;
- `execution.json` derives the preregistered `revise` decision.

The workflow also retained `process-smoke-exit.txt` as control-flow evidence.
It contains `1`; it is omitted here because the typed process receipt preserves
the underlying `0xc0000142` child status and the derived execution binds that
receipt by identity.
