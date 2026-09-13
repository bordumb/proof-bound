# Experiment 0019 conclusion

Experiment 0019 concludes **pass**. Concurrent scheduling repaired the only
failed criterion from Experiment 0018 without sharing a sandbox, runtime,
ephemeral root, output, plan, or receipt between logical executions.

## Result

The retained capture completed 30 positive executions and 21 live authority
probes in 6,048 ms. Experiment 0018 took 93,574 ms over the same subject and
operation counts. The 87,526 ms reduction is an observed scheduling result on
one host; it is not a general throughput estimate.

All 51 processes remained independently enforced. Each slot names one plan,
one Seatbelt policy, one fresh ephemeral root, one raw child outcome, and one
receipt. Every denial remained non-reusable. The reviewed corpus was identical
before and after execution.

The scheduler validator projected a canonical EXP-0018 view and reran its
entire 30-attack semantic suite. It then rejected ten batch-specific attacks:
missing, duplicated, reordered, and swapped slots; shared roots and outputs;
partial completion; policy weakening; reusable denial; and report forgery.
Rust and independently implemented Python validation produced byte-identical
reports.

## Interpretation

The failed latency criterion did not require a shared long-lived sandbox.
Parallelizing independently enforced processes and avoiding redundant
preflight work was enough on the registered machine. That is the safer
production candidate because a stalled or compromised language runtime cannot
carry state or authority into another logical run.

This result supports retaining the enforced-effect type and the original
60-second ceiling. It does not authorize production cache reuse: macOS
Seatbelt is an unsupported API, reads outside the home boundary remain broad,
and equivalent Linux and Windows enforcement has not yet been demonstrated.

## Handoff

Experiment 0020 must determine whether the same effect meaning can be compiled
and enforced with Linux Landlock, `no_new_privs`, and seccomp. Experiment 0021
must perform the analogous Windows test. Neither study may treat policy
compilation, a container, or execution on this macOS host as live enforcement
evidence.
