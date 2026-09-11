# Experiment 0018 conclusion

[Registration](README.md) · [Machine result](results/execution.json) ·
[Journal](JOURNAL.md) · [Artifacts](ARTIFACTS.md)

- **Decision:** revise
- **Executed / concluded:** 2026-09-03 / 2026-09-03
- **Scope:** one macOS arm64 host using the identified
  `/usr/bin/sandbox-exec` artifact

## Result

The central assurance result is positive and the overall registered decision
is **revise**, not pass. One backend-neutral effect plan and receipt model ran
ordinary Python, Node, and Rust subjects. All 30 positive repetitions
completed with a stable receipt identity per subject. All 21 live authority
probes were denied: undeclared sibling and nested reads, undeclared environment
access, unregistered process execution, local network contact, reviewed-file
writes, and writes outside the ephemeral boundary. No denied receipt was
reusable, and the reviewed corpus remained byte-identical.

Independent Rust and Python validators emitted the same 11,762 canonical
bytes and report identity. They rejected all 30 preregistered receipt, policy,
ordering, identity, alias, authority, invalidation, downgrade, and report
attacks with their exact codes. Registered input changes invalidate each
subject; the unrelated control does not. These results pass Q1--Q4 within the
frozen platform and corpus.

Q5 failed because the complete run took 93,574 ms against the frozen 60,000 ms
ceiling. Parallelizing independent subjects did not bring the measurement
below the limit on this host. We retain that result rather than raising the
ceiling after observation. The implementation, subject, policy, and report
size criteria passed, all repetition identities were stable, and reviewed
source did not change; only the wall-time subcriterion failed.

## What changed in the model

The experiment confirmed EXP-LANG-003's missing premise for the tested project
authority: an identified OS boundary can make a registered project-input set
enforceable rather than merely declarative. It also sharpened what “exact” can
honestly mean. Node must inspect metadata on ancestor directories to resolve a
registered entrypoint. The final policy therefore permits exact ancestor
metadata while denying undeclared file contents. Python and Node also require
their identified runtime roots below home. Reads outside home remain a named
`default-allow-outside-home` system boundary; the result does not pretend to
observe or enumerate them.

This suggests a useful language split:

1. the assurance language declares typed project preimages, absences,
   environment identities, executable identities, and output authority;
2. a platform compiler lowers that meaning into an identified enforcement
   policy;
3. the runner retains raw process results and postconditions; and
4. independent kernels validate the typed plan, exact policy bytes, receipt,
   invalidation, and status consequences without trusting a child-authored
   `sandboxed` flag.

## Boundaries and non-claims

- Seatbelt is a platform-bounded research mechanism, not a portable or
  verified sandbox API.
- The policy denies undeclared project and home authority but allows system
  reads outside home. It is not syscall-complete hermeticity.
- The Rust source is compiled before the measured sandboxed executions. The
  compiler and produced executable are byte-identified, but this experiment
  does not establish verified source-to-binary correspondence.
- The corpus contains standalone programmes, not package managers, build
  backends, native extensions, subprocess trees, secrets, clocks, randomness,
  distributed workers, or interactive tools.
- Stable denial classes are derived from typed modes, raw exits, bounded
  streams, listener postconditions, and filesystem snapshots. English OS error
  text is supporting evidence, not the assurance claim.
- The 93,574 ms result is one-host evidence. It does not establish why Seatbelt
  startup was slow or predict production overhead.

## Next research

Keep the enforced effect type in the Assurance IR candidate, but do not yet use
this prototype as production cache authority. The next experiment should test
a long-lived or batched enforcement worker with separately retained per-run
receipts, while preserving the exact denial matrix and the original 60-second
result. A subsequent portability study should preregister semantically
equivalent Linux and Windows policies and explicitly compare their unavoidable
system-read and metadata boundaries. Production adoption requires zero stale
reuse, independent policy compilation checks, acceptable latency, and a
supported enforcement mechanism on every admitted platform.
