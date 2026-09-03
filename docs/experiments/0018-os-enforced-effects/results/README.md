# Experiment 0018 retained results

`capture.json` is the canonical raw capture from the first complete registered
execution on the macOS arm64 host. It retains 30 positive executions, 21
authority-denial probes, exact process streams, policy bytes, runtime and
enforcer identities, project preimages, and the measured 93,574 ms wall time.

`rust-report.json` and `python-report.json` are independently derived from that
capture. Byte equality is a registered result; the duplicate files are kept so
each implementation's output remains independently inspectable. These reports
describe enforcement and invalidation semantics. The final question decisions,
including the failed 60,000 ms performance subcriterion, belong in
`execution.json`. The registered decision is `revise`: Q1--Q4 pass, while Q5
fails because 93,574 ms exceeds the frozen 60,000 ms ceiling.
