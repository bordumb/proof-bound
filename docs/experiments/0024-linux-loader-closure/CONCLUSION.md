# EXP-0024 conclusion

EXP-0024 passes all five preregistered questions on GitHub's native Ubuntu
24.04 ARM64 runner. The host exposed Landlock ABI 7, `no_new_privs`, and the
registered seccomp filter. Adding exact read-and-execute authority for the ELF
interpreter repaired the EXP-0022 failure without adding execute authority to
the broad system-read roots.

- all 30 permitted Python, Node, and Rust executions completed;
- all 21 frozen authority probes were denied and none was reusable;
- the reviewed tree was unchanged;
- the run completed in 3,101 ms, below the 60-second ceiling;
- Rust and Python emitted byte-identical reports; and
- each validator rejected all 20 registered attacks with its exact code.

All three registered runtimes resolved the requested
`/lib/ld-linux-aarch64.so.1` interpreter to
`/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1`. The capture binds its
SHA-256, size, and executable mode. `/usr/bin/true` remained unapproved and was
denied, demonstrating that the repair is an artifact role rather than a broad
system-directory execution grant.

This is bounded evidence for the registered Ubuntu ARM64 runtime closure. It
does not establish an architecture-independent loader resolver, static ELF
execution, arbitrary shared-library discovery, or Windows equivalence.

The exact successful run is
[GitHub Actions run 33811874795](https://github.com/bordumb/proof-bound/actions/runs/33811874795).
Artifact hashes and the canonical decision digest are retained in
[ARTIFACTS.md](ARTIFACTS.md).
