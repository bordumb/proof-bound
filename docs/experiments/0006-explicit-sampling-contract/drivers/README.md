# EXP-0006 driver prototypes

These files are research-only adapter-owned instrumentation and property
drivers. They are not a Proofbound plugin ABI and are not imported by
production code.

`hypothesis-driver.py` and `fast-check-driver.ts` implement the candidate
driver ABI. Application modules export only a generator and predicate. The
driver owns the seed, successful-case budget, persistence policy, shrink
policy, framework invocation, counters, and exclusive-create report. Passing
and counterexample outcomes share `proofbound-sampling-observation/1`; a
counterexample report is written before the process exits unsuccessfully.

The drivers bind a lexically sorted exact generator closure and emit a
domain-separated generator identity plus the complete registered contract.
The backend-neutral Rust and Python validators compare that observation with
a separate registration and the live closure bytes. Execution commands and
driver bytes still belong in outer adapter provenance; the nested report does
not claim to replace process provenance.

## Failed setup instrumentation

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
