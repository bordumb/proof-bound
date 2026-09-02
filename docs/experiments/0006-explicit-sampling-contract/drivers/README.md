# EXP-0006 observer prototypes

These files are research-only adapter-owned instrumentation. They are not a
Proofbound plugin ABI and are not imported by production code.

`vitest-observer.config.mjs` loads `fast-check-observer.mjs` before an unchanged
Vitest property. The observer uses fast-check's public global reporter and
writes one exclusive-create JSON record containing the effective seed, run
count, skips, shrinks, framework version, and selected effective parameters.
The experiment separately binds the test target and generator/source closure;
the observer is not allowed to author either identity or an assurance status.

The report path and subject project root are explicit environment inputs. A
missing path, pre-existing report, second property report, or failed property
causes the run to fail closed.

Vitest module isolation may prevent the setup module from observing the
application's fast-check instance. The registered global teardown therefore
requires and strictly decodes the report after execution. A passed test with
no observer record is a failed experiment run, never successful evidence.
