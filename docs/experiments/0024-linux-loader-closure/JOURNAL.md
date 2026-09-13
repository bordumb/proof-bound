# EXP-0024 journal

## 2026-09-03 — registered

Preregistered the exact ELF-interpreter role after EXP-0022 denied every
dynamically linked runtime before workload entry.

## 2026-09-03 — first candidate execution

GitHub Actions run 33810683583 showed the policy itself worked: 30 permitted
runs completed and 21 attacks were denied. Independent validation exposed an
older evaluator vocabulary defect because native Python, Node, and Rust report
environment and access denials as `KeyError`, `EACCES`, `EPERM`, and
`NotPresent` as well as textual permission errors. The raw observations were
not changed; both validators were amended to recognize those exact native
denial forms.

## 2026-09-03 — confirmatory execution

Run 33811874795 repeated the full corpus, produced byte-identical independent
reports, rejected 20 registered attacks in each validator, and derived `pass`
for Q1–Q5. The upload action was also advanced to its Node-24-compatible major
version; the earlier Node message was a deprecation warning, not an enforcement
failure.
