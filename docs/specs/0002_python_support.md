# Specification 0002: Python Ecosystem Support

**Status:** Draft for review

**Version:** 0.2.0

**Date:** 2026-09-01

**Project:** Proofbound

**Process:** Proof-Driven Development (PDD)

**Depends on:** Specification 0001, version 0.11.0 or later

### Revision history

- **0.2.0** — analyzer governance: closed admission criteria for new
  `static-check` analyzer operations and the reserved operation
  spellings `ty`, `pyrefly`, and `ruff` (§7.4); offline pyright
  provisioning with a networkless doctor probe (§7.3, §11.1).
- **0.1.0** — initial draft, promoted from the working note
  `docs/notes/language-support.md`: normative Python baseline inventory
  (§4); typed pytest plugin registration (§5.2); Hypothesis observation
  route (§6); the `static-check` evidence kind and the mypy/pyright routes
  (§7); pytest mutation-witness operation for sealed singleton mutation
  replay (§8); the reserved `proofbound-evidence-unit/4` distribution
  reproduction route for wheels and sdists (§9); Python subject-identity
  limits (§10); doctor and init behavior (§11); milestones (§13).

## 1. Executive summary

Specification 0001 defines a language-neutral assurance layer and a
Rust-first evidence layer. This specification makes Python a first-class
evidence ecosystem without weakening any trust boundary.

Python support today already includes exact pytest evidence, reproducible
generators, independent checkers, canonical artifacts, and trusted
transcription. This specification does three things:

1. **Restates the existing Python baseline normatively** (§4), so the
   supported surface is a contract rather than an example.
2. **Closes the known gaps in that baseline**: pytest plugin registration
   (§5.2) and Hypothesis observation (§6).
3. **Adds four new typed routes**: static type-checking evidence via mypy
   or pyright (§7), pytest mutation witnesses (§8), reproducible
   distribution artifacts (§9), and the doctor/init behavior that makes
   them discoverable (§11).

The governing rule is inherited unchanged from Specification 0001 §10.2 and
§17: every route is a typed, fail-closed adapter operation with an
authoritative inventory. A zero exit status is never evidence. An arbitrary
registered command is never an adapter.

The correct product claim after this specification is implemented:

> A Python repository reaches Tier 0 and Tier 1 with ready-made routes:
> exact tests, property tests, static checks, mutation witnesses,
> generators, independent checkers, canonical artifacts, reproducible
> distributions, and trusted transcription. Formal linkage for Python
> remains out of scope and is reported as such.

## 2. Amendments to Specification 0001

This specification amends Specification 0001 as follows. Adopting it
requires a Specification 0001 revision entry; until then this document is a
proposal and none of its wire versions may ship.

1. **§5 evidence taxonomy** gains one kind, `static-check` (§7.1 below).
2. **§9.1 `ledger`** admits `static-check` as empirical evidence.
3. **§11.2.2 sealed singleton mutation replay** gains the `pytest`
   operation type (§8 below).
4. **§11.2** gains §11.2.3, the `proofbound-evidence-unit/4` distribution
   reproduction route (§9 below).
5. **§12.2 `doctor`** gains the Python capability probes of §11.1.
6. `schemas/evidence-unit.schema.json`, `schemas/evidence.schema.json`,
   `schemas/adapter-observation.schema.json`, and
   `schemas/receipt.schema.json` change exactly as required by §§6–9 and
   MUST remain field-for-field consistent with this document.

No other section of Specification 0001 changes meaning. In particular the
aggregate-score ban (0001 §3.2), the closed adapter protocol (0001 §10.2),
and the check/update contract (0001 §12.2) apply to every route below.

## 3. Goals and non-goals

### 3.1 Goals

This specification MUST:

1. Give an ordinary `pyproject.toml` + pytest repository a complete Tier 0
   path using only documented, typed routes.
2. Make every Python evidence route derive its inventory from tool
   metadata, never from source-text scanning.
3. Bind the exact Python interpreter, frozen dependency set, and every
   registered plugin or analyzer into evidence provenance.
4. Classify static type-checking honestly: empirical-class evidence,
   capped at `TESTED`, never a linkage or proof.
5. Bind the bytes users install (wheel, sdist) to claims through
   deterministic reproduction, not through trust in a build log.

### 3.2 Non-goals

This specification MUST NOT:

- add a generic "run this command" adapter or operation;
- admit coverage percentages, mutation scores, or any other scalar as
  status-bearing evidence (0001 §3.2 applies; such numbers MAY appear only
  inside diagnostics);
- claim formal linkage (`REFINED`, `ARTIFACT_BOUND`) for any Python
  subject — no defensible Python refinement route exists, and no
  status-label shortcut is acceptable;
- reinterpret Hypothesis or any property-test framework's run as
  exhaustive coverage of its search space;
- treat a type checker's silence as a semantic property of the program
  beyond "the registered analyzer reported zero violations under the
  registered configuration".

## 4. Normative Python baseline

The following routes exist at Specification 0001 version 0.11.0 and are
hereby part of the supported Python contract. Implementations MUST NOT
regress them.

| Route | Unit schema | Operation | Evidence kind |
|---|---|---|---|
| Exact pytest nodes | `proofbound-evidence-unit/1` | `pytest` | `example-test`, `property-test` |
| Reproducible generators | `/1` | `generator` | `example-test` (verify-only; 0001 §11.2) |
| Independent checkers | `/1` | `independent-check` | `independent-check` (strict `schemas/checker-result.schema.json` ABI) |
| Canonical artifacts | `/1` | `artifact-check` | `artifact-soundness` inputs (0001 §7.1) |
| Trusted transcription | `/2` | `transcription` | `trusted-transcription` (0001 §11.2.1; the driver ABI is `python3`-based) |

Baseline invariants restated as requirements:

- The pytest route discovers nodes with
  `python3 -m pytest --collect-only -q`, runs each registered node
  individually, and requires that exactly one test ran and passed per
  node. Missing, extra, duplicate, or substituted nodes fail closed.
- Ambient pytest plugin autoload is disabled for every pytest execution
  (`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` in the child environment). §5.2
  defines the only way a plugin enters a run.
- All Python subprocesses execute inside the sealed shadow of 0001 §11.2
  with a cleared environment and the unit's explicit
  `environment_allowlist`.
- The resolved `python3` executable identity is recorded in provenance.

## 5. Python environment identity

### 5.1 Frozen environment

A Python evidence unit's tool identity is the pair (interpreter,
dependency closure):

- The adapter resolves `python3` through the allowlisted `PATH`, records
  the resolved path's SHA-256 and reported `python3 --version` output in
  the observation, and MUST fail when resolution is ambiguous through a
  symlinked directory (0001 §17 symlink rules apply).
- When the project registers a Python toolchain descriptor
  (`[toolchains].python`, 0001 §11.1) and/or a lock file (`uv.lock`,
  `requirements.txt` pinned by the project's runner closure), those bytes
  are automatic cache inputs. The adapter does not install packages;
  environment preparation is the operator's step, and `doctor` reports
  mismatches (§11.1).

### 5.2 Typed pytest plugin registration

The `pytest` operation gains one optional field:

```toml
[operation]
type = "pytest"
plugins = ["hypothesis"]
```

- `plugins` is a strict sorted set of at most 32 module names matching
  `^[a-z_][a-z0-9_]*(\.[a-z0-9_]+)*$`. Each entry is passed to pytest as a
  separate typed argument pair `-p NAME`. The manifest cannot supply any
  other pytest argument.
- Autoload remains disabled. A plugin not named in `plugins` MUST NOT be
  loaded; a named plugin that fails to import fails the unit closed with a
  stable `PB-ADAPTER-…` diagnostic naming the module.
- For each registered plugin the adapter records, in the observation's
  nested `python_plugins` array (new in `proofbound-adapter-observation/2`),
  the module name, the providing distribution name and version as reported
  by `importlib.metadata`, and the SHA-256 of the module's resolved origin
  file. The array is in strict module-name order and is empty when
  `plugins` is absent.
- The compiler preserves `python_plugins` in `proofbound-evidence/3`
  provenance. The independent verifier requires the array to be sorted,
  duplicate-free, and consistent with the registered `plugins` list when
  both sides are present in the portable receipt.

## 6. Hypothesis observation route

A `property-test` pytest unit MAY register a property table:

```toml
schema = "proofbound-evidence-unit/1"
id = "transfer-properties"
adapter = "python-test"
kind = "property-test"
claims = ["EXAMPLE-TRANSFER-001"]
tier = 0
expected_inventory = ["tests/test_transfer.py::test_conserves"]
inputs = ["python/transfer.py", "tests/test_transfer.py"]
outputs = []
environment_allowlist = ["PATH"]

[operation]
type = "pytest"
plugins = ["hypothesis"]

[property]
schema = "proofbound-python-property/1"
framework = "hypothesis"
seed = 4025493768
```

Rules:

- `[property]` is admissible only when `kind = "property-test"`,
  `operation.type = "pytest"`, and `plugins` contains the framework's
  plugin module. A `[property]` table anywhere else is invalid.
- `framework` is the closed vocabulary `hypothesis`. `seed` is a required
  integer in `[0, 2^64)`. The adapter appends the typed argument
  `--hypothesis-seed=SEED`; the manifest cannot add arguments.
- The observation and canonical evidence carry a nested
  `proofbound-python-property/1` record: `{framework, seed}` plus the
  resolved framework distribution version. Both status engines require
  the record's seed to equal the registered seed.
- **Evidentiary limit (normative reader text).** The evidence attests that
  the exact registered node passed under the registered seed. It does not
  model the generated search space, shrinking behavior, or case count, and
  MUST NOT be rendered as exhaustive. The claim's status derivation is
  unchanged: `property-test` remains empirical evidence (0001 §6.3.2).
- Richer statistics (observed case counts) are reserved for a future
  `/2` property record; parsing Hypothesis's human-readable statistics
  output is prohibited (0001 §17: inventories from tool metadata only).

## 7. Static type-check route

### 7.1 The `static-check` evidence kind

Specification 0001 §5 gains:

| Evidence kind | Meaning |
|---|---|
| `static-check` | A registered static analyzer completed over an exact registered target inventory with zero violations under a byte-pinned configuration. Empirical-class evidence about the analyzed source, not a semantic proof. |

Closed rules:

- Minimum tier: 0. `static-check` is empirical for status derivation: it
  can contribute at most `TESTED` to the formal facet and never
  contributes linkage. The `ledger` profile admits it.
- The kind ripples exactly here: the core and verifier evidence-kind
  enums, `schemas/evidence-unit.schema.json`,
  `schemas/evidence.schema.json`, `schemas/receipt.schema.json`, and the
  status-conformance corpus. The corpus MUST gain at least two cases: a
  claim whose only evidence is a passing `static-check` derives
  `TESTED · MODEL_ONLY`, and an attack case asserting `PROVED` from
  `static-check` evidence is rejected by both engines.
- A failing, drifted, or unregistered static-check record follows the
  ordinary `INVALID` rules of 0001 §6.3.2.

### 7.2 The mypy operation

```toml
schema = "proofbound-evidence-unit/1"
id = "kernel-types"
adapter = "python-test"
kind = "static-check"
claims = ["EXAMPLE-TRANSFER-001"]
tier = 0
expected_inventory = ["python/transfer.py"]
inputs = ["mypy.ini", "python/transfer.py"]
outputs = []
environment_allowlist = ["PATH"]

[operation]
type = "mypy"
configuration = "mypy.ini"
targets = ["python/transfer.py"]
```

- `configuration` is a repository-relative regular file, present in
  `inputs`, obeying the path rules of 0001 §11.3. `targets` is a strict
  sorted nonempty set of at most 4096 repository-relative `.py` files or
  package directories, each present in `inputs` or covered by the unit's
  semantic closure. `expected_inventory` equals `targets` exactly.
- The adapter runs exactly:

  ```text
  python3 -m mypy --version
  python3 -m mypy --config-file CONFIGURATION --output json \
      --no-incremental --no-error-summary TARGETS…
  ```

  The adapter owns every argument; the manifest and configuration file
  cannot add command-line arguments (configuration file *contents* are
  mypy's concern and are byte-pinned as inputs).
- Success requires exit status 0 **and** zero parsed JSON diagnostic
  lines on stdout. Any diagnostic line, any unparseable line, a nonzero
  exit, or truncated output is failure; the first diagnostic's file, line,
  and code are surfaced in the unit diagnostics. Exit 0 with nonempty
  diagnostics, or empty diagnostics with nonzero exit, are both failures:
  the two signals must agree.
- The observation carries a nested `proofbound-static-check/1` record:
  `{tool: "mypy", tool_version, configuration_sha256, targets,
  diagnostics: 0}`. The compiler and independent verifier both require
  `diagnostics == 0`, the configuration identity to match the sealed
  input bytes, and `targets` to equal the registered set.

### 7.3 The pyright operation

Identical shape with `type = "pyright"`, `configuration` naming the
project's pyright configuration file, and the exact commands:

```text
node_modules-free resolution is not used; pyright is resolved as an
executable named `pyright` through the allowlisted PATH.

pyright --version
pyright --outputjson --project CONFIGURATION
```

- Success requires exit status 0 and a parsed JSON summary with
  `errorCount == 0` and `warningCount == 0`, and `filesAnalyzed >= 1`.
  `generalDiagnostics` must be empty. Pyright analyzes the files selected
  by the registered configuration; the registered `targets` set MUST equal
  the repository-relative members of the reported analyzed files, compared
  bidirectionally — a missing or extra analyzed file fails closed.
- The nested record is `{tool: "pyright", tool_version,
  configuration_sha256, targets, diagnostics: 0}` with the same engine
  checks as §7.2.
- **Offline provisioning.** Common pyright distributions — notably the
  PyPI wrapper package — download a Node.js runtime on first
  invocation. Provisioning that runtime is the operator's
  environment-preparation step, exactly as dependency installation is
  (§5.1). Every adapter invocation of pyright MUST complete without
  network access: a pyright execution that attempts retrieval fails the
  unit closed, and the §11.1 doctor probe MUST succeed without network
  before any pyright unit is reported runnable.

One unit registers exactly one analyzer. A project MAY register separate
mypy and pyright units for the same claim; they remain distinct evidence
records.

### 7.4 Admission criteria and reserved analyzers

A new analyzer earns an operation type under the `static-check` kind
only when all of the following hold. The criteria are closed; execution
speed and popularity are not criteria.

1. an authoritative, nonempty analyzed inventory derivable from tool
   metadata, never from source-text scanning;
2. an exact tool and environment identity obtainable from a native
   identity command with exact observable matching;
3. machine-readable diagnostic output that is a stable, versioned
   contract — a typed result that cannot be upgraded by an exit code or
   an analyzer-authored Boolean;
4. source and configuration bindings appropriate to the claim, with the
   configuration byte-pinned as an input; and
5. validation implementable in the producer and, wherever the evidence
   is portable, independently in the verifier.

The operation spellings `ty`, `pyrefly`, and `ruff` are **reserved** and
MUST be rejected until a revision of this specification defines their
routes against these criteria — the Specification 0001 §11.3
`audited-rewrite` pattern. Rejection is by name, as an unsupported
capability with a stable code, never a silent fallback to another
analyzer. `ty` is the intended first addition once its diagnostic
output stabilizes as a versioned contract; its execution speed
materially improves the check-cycle cost that Specification 0001 §16.3
treats as a design constraint.

## 8. Pytest mutation witnesses

Specification 0001 §11.2.2 (`proofbound-evidence-unit/3`,
`proofbound-mutation-registry/2`) gains a second operation type. All
structural rules of §11.2.2 — singleton registry, identical unit/mutation
IDs, byte-pinned full-file mutant, exact sorted inputs, two independent
shadows, preimage/postimage verification, no outputs, `update`
unsupported — apply unchanged. Only the witness execution differs:

```toml
[operation]
type = "pytest"
```

- `adapter` is `python-test`. The registry `witness` is an exact pytest
  node ID (`path::name` grammar of the baseline route); `witness_path` is
  the node's file.
- Registry `subject` uses the Python subject grammar
  `^python:[a-z][a-z0-9-]*(::[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*)?$`
  (distribution name, optionally `::` dotted module-and-qualname path).
- Baseline shadow: the adapter collects and runs exactly the witness node
  and requires exit status 0 with exactly one passed test.
- Mutated shadow: after installing the registered mutant bytes and
  verifying the postimage, the adapter reruns exactly the witness node and
  requires **exit status 1** (pytest: tests were collected and ran, some
  failed) with exactly one failed test. Exit statuses 2, 3, 4, and 5
  (interrupted, internal error, usage error, no tests collected) are not
  witnesses. A collection error, a skipped or xfailed result, truncated
  output, or any extra changed path is not a witness.
- The evidence kind, `mutation-witness`, remains empirical (0001 §5).

## 9. Distribution reproduction route (`proofbound-evidence-unit/4`)

This route binds the bytes users install to the reviewed tree. It is a
new closed unit version; versions 1–3 are not reinterpreted, and `/4`
forbids every field of the transcription and mutation routes.

```toml
schema = "proofbound-evidence-unit/4"
id = "wheel-reproduction"
adapter = "python-test"
kind = "example-test"
claims = ["EXAMPLE-DIST-001"]
tier = 0
expected_inventory = ["dist/example_pkg-1.2.0-py3-none-any.whl"]
inputs = ["pyproject.toml", "python/transfer.py", "python/__init__.py"]
outputs = []
environment_allowlist = ["PATH"]

[operation]
type = "python-distribution"

[distribution]
schema = "proofbound-distribution-reproduction/1"
format = "wheel"
artifact_name = "example_pkg-1.2.0-py3-none-any.whl"
artifact_sha256 = "sha256:…"
source_date_epoch = 315532800
```

Rules:

- `format` is the closed vocabulary `wheel` or `sdist`. `artifact_name`
  is the exact expected file name (printable ASCII, at most 255 bytes, no
  path separators). `artifact_sha256` is the registered expected digest.
  `source_date_epoch` is a required nonnegative integer.
- `inputs` is the exact sorted set of source files the build may read; it
  MUST include the project's `pyproject.toml`. `outputs` is empty: the
  built artifact is never written to the reviewed tree; nothing in this
  route is committed. `expected_inventory` is exactly
  `["dist/" + artifact_name]`.
- The adapter creates **two independent sealed shadows** from the same
  reviewed source and in each runs exactly:

  ```text
  python3 -m build --FORMAT --no-isolation --outdir DIST_DIR
  ```

  where `--FORMAT` is `--wheel` or `--sdist`, `DIST_DIR` is
  adapter-owned, and the child environment contains
  `SOURCE_DATE_EPOCH=<source_date_epoch>` in addition to the allowlist.
  The build backend and its dependencies come from the frozen environment
  (`--no-isolation`); the adapter performs no network access.
- Each run MUST produce exactly one file in `DIST_DIR`, named exactly
  `artifact_name`. The adapter requires:
  1. run 1 bytes equal run 2 bytes (byte-for-byte determinism); and
  2. both equal the registered `artifact_sha256`.
- For `format = "wheel"` the adapter additionally unpacks the archive
  (rejecting absolute paths, `..`, symlinks, and members beyond the disk
  budget) and verifies every member against the wheel's `RECORD` hashes;
  a `RECORD` mismatch, an unlisted member, or a listed-but-absent member
  fails closed.
- The observation carries a nested
  `proofbound-distribution-reproduction/1` record with the format, both
  run digests, the registered digest, `source_date_epoch`, and the build
  backend distribution name and version read from `pyproject.toml`'s
  sealed bytes. Generated artifacts are exactly
  `distribution/<unit-id>/candidate-1` and
  `distribution/<unit-id>/candidate-2` in lexical order.
- A passing record is `example-test` evidence (the reproduction is
  empirical, exactly as generator verification is in 0001 §11.2) whose
  provenance carries the artifact identity, so claims about the artifact
  can cite it and canonical-artifact or independent-check units can bind
  the same registered bytes. It cannot yield `PROVED`, any linkage facet,
  or any statement about the artifact's behavior.
- Non-reproducible builds are unsupported, not accommodated: a backend
  that embeds timestamps despite `SOURCE_DATE_EPOCH` fails determinism
  and the route reports that failure; the adapter MUST NOT normalize
  archive contents to force agreement.

## 10. Subject identity limits

Python has no compiled subject artifact. This specification binds claims
to (a) the semantic source closure, (b) exact registered file inventories,
and (c) for §9, distribution bytes. Symbol-level subjects use the grammar
of §8 as identity strings only; Proofbound does not pretend to bind a
running interpreter's view of a symbol, and receipts MUST NOT suggest
otherwise. Monkeypatching, import-order effects, and dynamic dispatch are
out of scope of every route in this specification, and the mandatory
"not proved / out of scope" section of an affected claim SHOULD say so.

## 11. Doctor, init, and reporting

### 11.1 doctor

`proofbound doctor` MUST probe, with native identity commands and exact
observable matching (0001 §12.2, ADR 0018 pattern):

- `python3 --version` and the resolved interpreter identity;
- `python3 -m pytest --version`;
- `python3 -m mypy --version` when any `mypy` unit is registered;
- `pyright --version` when any `pyright` unit is registered — this
  probe MUST succeed without network access (§7.3), and a probe that
  attempts retrieval reports the unit not runnable;
- `python3 -m build --version` when any `/4` unit is registered;
- importability of every distinct registered plugin module.

Each probe reports available/unavailable and which registered units the
host can therefore run; an unavailable tool never weakens to a warning
when a registered unit requires it.

### 11.2 init

`proofbound init` on a Python repository (existing behavior, restated):
discovers a uniquely selectable pytest node in a sealed shadow and
scaffolds a Tier 0 ledger. Additionally, after this specification:

- when discovery observes that collection fails without a plugin that
  autoload would have provided, the failure diagnostic MUST name the
  module and the `plugins` field that registers it; and
- the scaffolded project MUST include `.proofbound/` in the repository's
  ignore rules or report, in the init output, that the operator must do
  so before `release` and `update` are reachable.

### 11.3 Reporting

Static-check and property records render beneath claim summaries with
their tool, version, configuration identity, and registered seed where
applicable. No Python route introduces a percentage, score, or grade
anywhere in human or JSON output.

## 12. Security and failure policy

All of Specification 0001 §17 applies. Python-specific additions:

- pytest plugin autoload stays disabled in every execution, including
  discovery, collection, witnesses, and builds that invoke pytest.
- All analyzer and build configuration files are byte-pinned inputs;
  drift invalidates cached evidence via the ordinary cache key.
- Archive extraction (§9) rejects absolute paths, `..` components,
  symlinks, hard links, and members exceeding the declared disk budget.
- Selector, node-ID, plugin, and target strings reject characters that
  could become command-line syntax, exactly as 0001 §11.3 selectors do.
- The adapter never installs packages, resolves indexes, or touches the
  network. Environment preparation failures surface through `doctor`.

## 13. Milestones

### M-PY1: plugin registration and Hypothesis observation

§5.2 and §6. Acceptance: a registered Hypothesis unit runs with autoload
disabled, the seed is enforced and receipted, an unregistered plugin
import fails closed, and the conformance suite covers the new nested
records.

### M-PY2: static-check kind and analyzer routes

§7. Acceptance: the taxonomy amendment lands in core, verifier, schemas,
and corpus (both new corpus cases pass in both engines); a mypy unit and a
pyright unit each produce `TESTED · MODEL_ONLY` for a demo claim; a
seeded type error flips the unit to failed and the claim to `INVALID`.

### M-PY3: pytest mutation witnesses

§8. Acceptance: a registered Python mutant is detected in the mutated
shadow by exactly the registered witness with exit status 1, and every
non-witness pytest exit status is rejected by a dedicated test.

### M-PY4: distribution reproduction

§9. Acceptance: a wheel builds twice byte-identically under
`SOURCE_DATE_EPOCH`, matches its registered digest, passes `RECORD`
verification, and a single-byte source change invalidates the cached
record; the independent verifier recomputes both digest comparisons from
the portable receipt.

### M-PY5: pure-Python reference vertical

The demonstration repository of `docs/notes/language-support.md`: a small
service with exact pytest examples, one Hypothesis property with its
stated limits, one static-check unit, one explicit external-provider
assumption, one distribution reproduction, an independent checker, and a
deliberately failing signal that weakens only its registered claim.
Acceptance: the full board renders from `init` through `release` with no
Rust application code, and the release verifies with the standalone
verifier.

## 14. Success criteria

1. A Python-only team reaches an honest Tier 0 board and a verified
   release receipt using only routes in this document.
2. Every Python evidence record names its exact tool identity, inventory,
   and configuration, and no route trusts an exit status alone.
3. Type-check evidence renders as `TESTED`-class support and is never
   conflated with proof; property evidence never claims its search space.
4. The bytes a user installs can be bound to a claim through registered,
   independently reverifiable reproduction.
5. The "not proved / out of scope" section of every Python claim states
   the dynamic-language limits of §10 where they apply.
