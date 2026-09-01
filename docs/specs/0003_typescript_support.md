# Specification 0003: TypeScript Ecosystem Support

**Status:** Initial implementation specification

**Version:** 0.2.0

**Date:** 2026-09-01

**Project:** Proofbound

**Process:** Proof-Driven Development (PDD)

**Depends on:** Specification 0001, version 0.12.0 or later;
Specification 0002 §7.1 (the `static-check` evidence kind) and §7.4
(analyzer admission criteria)

### Revision history

- **0.2.0** — tooling governance: vitest identity command and
  minimum-version floor (§6); the reserved `tsgo` operation spelling as
  the native-compiler succession path and admission of future analyzers
  by Specification 0002 §7.4 (§7); Bun and Deno runtimes recorded as
  deferred typed routes (§13).
- **0.1.0** — initial draft: the `proofbound-adapter-node` adapter and
  `node-test` adapter kind (§4); sealed dependency installation with
  lifecycle scripts disabled (§5); the exact vitest evidence route (§6);
  the `tsc` static-check route (§7); the npm package operation for the
  distribution reproduction route (§8); vitest mutation witnesses (§9);
  init and doctor behavior (§10); security policy (§12); milestones
  (§14).

## 1. Executive summary

TypeScript is where the largest volume of new — increasingly
machine-generated — application code is written, and npm is where the
industry's worst supply-chain failures live. Both facts argue for
Proofbound support; neither excuses weakening it.

TypeScript is also the weakest major ecosystem for deep evidence: it has
no bounded model checker, no source-refinement pipeline, and a build step
that means the code that ships (`dist/`, the packed tarball) is not the
code that was reviewed (`src/`). This specification therefore does two
deliberate things:

1. It targets the **honest capability level**: assurance governance and
   empirical evidence (levels 1–2 of the portability ladder in
   `docs/notes/language-support.md`), plus two level-3 routes — static
   type-checking and registered mutation witnesses — that have
   trustworthy tool metadata. The strongest status a TypeScript claim can
   derive under this specification is `TESTED · MODEL_ONLY`, and every
   report says so.
2. It makes the **package artifact the anchor identity**. Because the
   shipped bytes diverge from the reviewed source, binding the packed
   npm tarball to the reviewed tree through deterministic reproduction is
   worth more here than in any ecosystem Proofbound already supports.

What this specification refuses is the ecosystem's default: `npm test`
as evidence. Every route below derives its inventory from tool metadata,
disables lifecycle scripts, and fails closed on anything it cannot
inventory. A zero exit status is never evidence.

## 2. Adopted amendments to Specification 0001

Specification 0001 version 0.12.0 adopts this specification's typed
routes and wire contracts as follows.

1. **§10.2 adapter inventory** gains the `node-test` adapter, executable
   `proofbound-adapter-node` (§4).
2. **§11.2.2 sealed singleton mutation replay** gains the `vitest`
   operation type (§9).
3. **§11.2.3 distribution reproduction** (introduced by Specification
   0002 §9 as `proofbound-evidence-unit/4`) gains the `npm-package`
   operation and the `npm-package` distribution format (§8).
4. **§12.2 `doctor`** gains the Node capability probes of §10.1, and
   `init` gains the Node discovery path of §10.2.
5. `schemas/evidence-unit.schema.json`, `schemas/evidence.schema.json`,
   `schemas/adapter-observation.schema.json`, and
   `schemas/receipt.schema.json` change exactly as required by §§5–9 and
   MUST remain field-for-field consistent with this document.

This specification adds **no** evidence kind: it reuses `example-test`,
`property-test`, `mutation-witness`, and Specification 0002's
`static-check`. It adds no trust profile and no linkage facet.

## 3. Goals and non-goals

### 3.1 Goals

This specification MUST:

1. Give an ordinary `package.json` + vitest repository a complete Tier 0
   path using only documented, typed routes.
2. Execute all Node tooling from the repository's own pinned dependency
   closure — never from the network, never via `npx`.
3. Prevent dependency lifecycle scripts from executing during any
   Proofbound operation.
4. Bind Node interpreter, package-manager, lockfile, and per-tool
   identities into evidence provenance.
5. Bind the packed npm tarball to the reviewed tree through
   deterministic reproduction and an exact member inventory.

### 3.2 Non-goals

This specification MUST NOT:

- add a generic "npm script" or "package.json scripts" adapter — a named
  script is an arbitrary command with a friendlier spelling, and 0001
  §10.2/§17 already prohibit it;
- admit coverage percentages or mutation scores as status-bearing
  evidence; in particular a Stryker run and its score MAY exist in a
  project's own CI but are not Proofbound evidence — only the registered
  singleton mutation route of §9 produces `mutation-witness` records;
- claim any formal facet above `TESTED` or any linkage facet other than
  `MODEL_ONLY` for a TypeScript subject;
- support Jest, pnpm, yarn, bundler pipelines (webpack, esbuild, rollup
  configurations), or npm workspaces in this version — each is reserved
  vocabulary that fails closed as an unsupported capability until a
  typed route exists (the 0001 §11.3 `audited-rewrite` precedent);
- extend the trusted-transcription driver ABI to Node — the
  `proofbound-transcription-driver/1` ABI is `python3`-based by
  definition (0001 §11.2.1); a Node driver ABI would be a new versioned
  ABI and is out of scope here.

## 4. Adapter architecture

- New adapter kind `node-test`, executable **`proofbound-adapter-node`**,
  a Rust crate at `crates/proofbound-adapter-node` following the existing
  adapter layout: a stdin/stdout binary speaking
  `schemas/adapter-protocol.schema.json`, a cleared child environment
  with per-unit allowlists, bounded output drains, deadline enforcement,
  and observations in `proofbound-adapter-observation/2`.
- Error family: `PB-NODE-NNNN`, following the 0001 §12.3 contract.
- Operation vocabulary owned by this adapter (closed):
  `vitest` (§6), `tsc` (§7), `npm-package` (§8), and the `vitest`
  witness execution inside `/3` mutation units (§9).
- The adapter resolves **no** tool through `PATH` except `node` and
  `npm` themselves. Every other executable (vitest, tsc) is resolved as
  the exact repository file `node_modules/.bin/<tool>` inside the sealed
  shadow, after the installation step of §5. A missing, symlinked-out-
  of-tree, or non-regular binary fails closed.

## 5. Environment identity and sealed installation

### 5.1 Identity

Every Node evidence unit binds:

- the resolved `node` executable path identity and its exact
  `node --version` output;
- the resolved `npm` identity and `npm --version` output;
- the byte identity of `package.json` and `package-lock.json`, which are
  required inputs of every Node unit and automatic cache inputs.

`package-lock.json` MUST be present, parse as canonical JSON with
`lockfileVersion >= 3`, and carry an `integrity` value for every
depended-upon package entry. An `inBundle = true` child MAY omit its own
value only when a proper containing package entry carries the integrity
that binds the bundled bytes. A missing lockfile, an otherwise missing integrity
field, or a `file:`/`link:`/`git:` dependency is an unsupported
capability failure in this version.

### 5.2 Sealed installation

Node tooling requires an installed `node_modules` tree. Installation is a
distinct, explicitly recorded step — the only step in this specification
permitted network access — under 0001 §16.1's sealed
external-retrieval rule:

- In the sealed shadow the adapter runs exactly:

  ```text
  npm --version
  npm ci --ignore-scripts --no-audit --no-fund
  ```

  The adapter owns every argument. `--ignore-scripts` is
  non-negotiable: no dependency lifecycle script (`preinstall`,
  `install`, `postinstall`, `prepare`, or any other) executes during any
  Proofbound operation. A dependency that does not function without its
  install scripts (native addons, node-gyp builds) is an unsupported
  capability failure, reported as such — never worked around by
  enabling scripts.
- The installation command, its runs, and the lockfile identity enter
  provenance as ordinary observed processes. npm's own integrity
  enforcement against the lockfile's sha512 values is the retrieval
  check; a lockfile/registry mismatch is a hard failure.
- After installation the adapter verifies that the reviewed source
  portion of the shadow is unchanged (the 0001 §11.2.1
  `ensure_tree_unchanged` pattern, applied around the install with
  `node_modules` and npm's cache directory excluded as adapter-owned).
- All subsequent commands in the unit run with network access
  forbidden. Where the platform cannot enforce a network boundary, the
  adapter records that limit in the observation rather than claiming an
  enforcement it does not have; tools below are invoked with their
  offline/no-update flags where they exist.

## 6. Vitest evidence route

Exact-node test evidence, kinds `example-test` and `property-test`
(fast-check properties run as ordinary vitest nodes and follow
Specification 0002 §6's evidentiary-limit language, without the
Hypothesis-specific seed table).

```toml
schema = "proofbound-evidence-unit/1"
id = "decode-vectors"
adapter = "node-test"
kind = "example-test"
claims = ["EXAMPLE-DECODE-001"]
tier = 0
expected_inventory = ["src/decode.test.ts::rejects trailing bytes"]
inputs = ["package.json", "package-lock.json", "src/decode.test.ts", "src/decode.ts", "vitest.config.ts"]
outputs = []
environment_allowlist = ["PATH"]

[operation]
type = "vitest"
configuration = "vitest.config.ts"
```

Rules:

- A node ID is `FILE::NAME` where `FILE` is a repository-relative test
  file obeying the 0001 §11.3 path rules and `NAME` is the full test name
  (describe-block names joined to the test name by ` > ` exactly as
  vitest reports them), printable ASCII, at most 1024 bytes, with no
  character admissible as command-line syntax. `expected_inventory` is
  the strict sorted nonempty set of registered node IDs.
- `configuration` is an optional byte-pinned config file present in
  `inputs`; when absent, the adapter passes no config argument and
  vitest's zero-config resolution applies to the sealed shadow only.
- **Version floor.** Before discovery the adapter runs exactly
  `node_modules/.bin/vitest --version` and requires the reported
  version to be **2.1.0 or later** — the earliest line carrying
  `vitest list --json`. An older version is an unsupported capability
  failure with a stable `PB-NODE-` code naming vitest and the floor,
  never a generic subprocess error from a command the tool does not
  understand. The reported version enters the observation's tool
  identity.
- **Discovery.** The adapter then runs exactly:

  ```text
  node_modules/.bin/vitest list --json=LIST_FILE [--config CONFIGURATION]
  ```

  and parses `LIST_FILE` as the authoritative inventory of
  `(file, full name)` pairs. The registered inventory MUST match the
  discovered inventory of the registered files bidirectionally at node
  granularity: a registered node absent from discovery, a duplicate
  discovered name within a registered file, or an unparseable listing
  fails closed. Ungated discoveries in *unregistered* files are not this
  unit's failure; project-level bidirectional coverage is the claim
  inventory's concern (0001 §17), not the unit's.
- **Execution.** For each registered node, in inventory order, the
  adapter runs exactly:

  ```text
  node_modules/.bin/vitest run FILE --reporter=json \
      --testNamePattern PATTERN [--config CONFIGURATION]
  ```

  where `PATTERN` is the registered name with every regular-expression
  metacharacter escaped, anchored as `^NAME$`. Success requires exit
  status 0 and a parsed JSON report with `numTotalTests == 1`,
  `numPassedTests == 1`, and the reported file and full name equal to
  the registered node. Zero or multiple executed tests, a skipped or
  todo result, a truncated report, or a name mismatch fails closed —
  exactly one test ran, and it is the registered one.
- The observation's inventory is the exact registered node set; per-run
  records follow the ordinary 0001 §10.2 command/run alignment.

## 7. TypeScript static-check route

Uses Specification 0002 §7.1's `static-check` evidence kind unchanged.
Any future analyzer under this specification is admitted only against
the closed criteria of Specification 0002 §7.4.

```toml
[operation]
type = "tsc"
configuration = "tsconfig.json"
```

- `configuration` is a required repository-relative `tsconfig.json`,
  byte-pinned in `inputs`. In this version it MUST parse as plain
  canonical-JSON-compatible JSON (no comments, no trailing commas) so
  the adapter can validate it structurally; a JSONC configuration is an
  unsupported capability failure. The parsed configuration MUST set
  `compilerOptions.strict = true` and MUST NOT set `extends` (a
  configuration chain hides strictness; flatten it).
- The adapter runs exactly:

  ```text
  node_modules/.bin/tsc --version
  node_modules/.bin/tsc --project CONFIGURATION --listFilesOnly
  node_modules/.bin/tsc --project CONFIGURATION --noEmit --pretty false
  ```

- The repository-relative members of the `--listFilesOnly` output form
  the analyzed inventory. It MUST be nonempty and MUST equal the unit's
  registered `expected_inventory` bidirectionally; members under
  `node_modules/` are counted and recorded in the nested record but are
  not registered members.
- Success requires the `--noEmit` run to exit 0 with empty diagnostic
  output. Any emitted diagnostic line fails the unit and surfaces the
  first diagnostic's file and code. Exit and output must agree, as in
  Specification 0002 §7.2.
- The nested record is `proofbound-static-check/1` with
  `{tool: "tsc", tool_version, configuration_sha256, targets,
  diagnostics: 0}`; both status engines apply the Specification 0002
  §7 checks. The evidentiary meaning is exactly the kind's: zero
  violations under the registered configuration. Type soundness of
  TypeScript itself is not claimed, and gradual-typing escape hatches
  (`any`, assertions, `@ts-ignore`) are inside the analyzed source's
  semantics, not repaired by this route; a claim leaning on this
  evidence SHOULD name that limit in its out-of-scope list.
- The operation spelling `tsgo` is **reserved** for the native
  TypeScript compiler. When the `tsc` command shape is succeeded
  upstream, its route enters by a revision of this specification
  evaluated against Specification 0002 §7.4 — never by silently
  reinterpreting the `tsc` operation under a new binary. Until then
  `tsgo` is rejected by name as an unsupported capability.

## 8. npm package reproduction (`proofbound-evidence-unit/4`)

Extends Specification 0002 §9's distribution reproduction route with a
second ecosystem. All `/4` structural rules apply (two independent
shadows, no outputs, empty-tree ownership, registered digest, nested
record, `example-test` evidence, no linkage, no normalization to force
agreement). The npm operation differs as follows:

```toml
[operation]
type = "npm-package"

[distribution]
schema = "proofbound-distribution-reproduction/1"
format = "npm-package"
artifact_name = "example-pkg-1.2.0.tgz"
artifact_sha256 = "sha256:…"
source_date_epoch = 0
```

- Installation (§5.2) runs first in each shadow when the package has a
  build step; the package's own `prepack`/`prepare` scripts remain
  disabled (`--ignore-scripts`), so **the packed content must be
  producible without lifecycle scripts**. A package whose published
  content depends on a pack-time script is unsupported in this version;
  the typed build-unit route (a future revision mirroring the 0001
  §11.3 generated-tree model for compiler output) is the reserved path
  for it. `source_date_epoch` is present for schema uniformity and MUST
  be `0`: npm's packer stamps its own fixed timestamps.
- In each shadow the adapter runs exactly:

  ```text
  npm pack --json --pack-destination DIST_DIR
  ```

  and requires a parsed JSON report describing exactly one tarball named
  exactly `artifact_name`, with its `files` array, `integrity`, and
  `shasum` fields present.
- The adapter requires: run 1 tarball bytes equal run 2 bytes; both
  equal the registered `artifact_sha256`; and the two runs' reported
  `files` inventories are identical.
- The adapter unpacks the tarball (rejecting absolute paths, `..`,
  symlinks, hard links, members outside the `package/` prefix, and
  members beyond the disk budget) and requires the unpacked member set
  to equal the report's `files` inventory bidirectionally, and every
  member's bytes to equal the corresponding sealed source file where the
  member is a source passthrough. Members produced by a compilation step
  cannot be admitted in this version (no lifecycle scripts ran, so none
  should exist); an unpacked member with no sealed source origin fails
  closed.
- The nested record carries the format, both run digests, the registered
  digest, the npm-reported `integrity` value, and the member inventory.
  Generated artifacts are `distribution/<unit-id>/candidate-1` and
  `distribution/<unit-id>/candidate-2`.

The meaning, stated exactly: *the registered tarball is deterministically
reproducible from the reviewed tree with no script execution, and its
members are byte-identical to reviewed sources.* Nothing about the
package's behavior is claimed.

## 9. Vitest mutation witnesses

Specification 0001 §11.2.2 gains a third operation type,
`type = "vitest"`, `adapter = "node-test"`, under all structural rules
of that section (singleton byte-pinned full-file mutant, two independent
shadows, preimage/postimage verification, `update` unsupported):

- The registry `witness` is an exact vitest node ID in the §6 grammar;
  `witness_path` is the node's file. The registry `subject` uses the
  Node subject grammar
  `^npm:[a-z0-9][a-z0-9._-]*(::[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*)?$`
  (package name, optionally `::` export path).
- Installation (§5.2) runs once per shadow before discovery.
- Baseline shadow: the witness node is discovered and executed exactly
  as in §6 and must pass (`numTotalTests == 1`, `numPassedTests == 1`,
  exit 0).
- Mutated shadow: after the registered mutant bytes are installed and
  the postimage verified, the same node is rediscovered and executed and
  MUST fail with **exit status 1** and a parsed report showing
  `numTotalTests == 1`, `numFailedTests == 1`. Any other exit status, a
  collection error, a skipped result, truncated output, or an extra
  changed path is not a witness.
- The evidence kind, `mutation-witness`, remains empirical. A Stryker
  or other mutation-score run is not admissible through this route or
  any other (§3.2).

## 10. Doctor and init

### 10.1 doctor

`proofbound doctor` MUST probe with native identity commands and exact
observable matching: `node --version`, `npm --version`, and — inside the
project, without installation — the presence and file identity of
`node_modules/.bin/vitest` and `node_modules/.bin/tsc` for each
registered unit that needs them, reporting per-unit runnability. Doctor
never installs anything.

### 10.2 init

`proofbound init` gains a Node discovery path, attempted when
`package.json` and `package-lock.json` exist and the Rust and Python
paths do not apply:

- Discovery runs in the sealed shadow: §5.2 installation, then §6
  listing, requiring at least one uniquely selectable vitest node. If
  vitest is not a lockfile dependency, or no node is uniquely
  selectable, init fails closed with a diagnostic naming the missing
  capability (the 0001 §12.2 no-invented-claims rule applies; init
  never fabricates a runnable unit).
- The scaffold mirrors the Rust/Python scaffold: `proofbound.toml`
  (tier 0), one claim bound to the discovered node as `example-test`
  evidence via a `node-test`/`vitest` unit, one runtime assumption, and
  the ignore-rule guidance of Specification 0002 §11.2.

## 11. Tier and status ceiling

A TypeScript claim under this specification derives at most
`TESTED · MODEL_ONLY`, at Tier 0. No route here produces theorem,
bounded-check, refinement, transcription, or artifact-soundness
evidence. Canonical-artifact and independent-check evidence about
registered package bytes remain available through the existing
language-neutral checker routes (the checker itself follows 0001 §10.2's
ABI). Reports MUST NOT present the §8 reproduction as a behavioral
guarantee, and the capability ladder of `docs/notes/language-support.md`
SHOULD be the user-facing description of this ceiling.

## 12. Security and failure policy

All of Specification 0001 §17 applies. Node-specific additions, all
fail-closed:

- Lifecycle scripts never execute: every `npm` invocation carries
  `--ignore-scripts`, and no route invokes `npm run`, `npm exec`, or
  `npx` under any circumstance.
- Network access is confined to the §5.2 installation step and is
  integrity-bound by the lockfile; every other command runs offline.
- Tools execute only as exact regular files under the shadow's
  `node_modules/.bin`; `PATH` resolution is limited to `node` and `npm`.
- Registered names, patterns, and paths reject command-line syntax
  characters; `--testNamePattern` values are metacharacter-escaped and
  anchored by the adapter, never taken verbatim from the manifest.
- Tarball extraction rejects traversal, symlinks, hard links, prefix
  escapes, and budget overruns.
- `package.json` and `package-lock.json` are byte-pinned inputs of every
  Node unit; lockfile drift invalidates every cached Node record.
- An unsupported capability (Jest, pnpm, yarn, workspaces, JSONC
  tsconfig, script-dependent packages, native addons) is a typed,
  stable-coded failure naming the capability — never a silent skip and
  never a fallback to weaker checking.

## 13. Open questions deferred to future revisions

Recorded so their absence is a decision, not an oversight:

1. A typed **build unit** for compiler output (tsc/esbuild emit under
   the 0001 §11.3 generated-tree ownership model) — required before
   script-dependent or compiled packages can use §8.
2. Jest, pnpm, and yarn routes; npm workspaces.
3. A Node transcription driver ABI (`proofbound-transcription-driver/2`).
4. Richer fast-check observation (seed registration parallel to
   Specification 0002 §6).
5. Bun and Deno runtimes — each carries its own test runner, package
   resolution, and TypeScript execution model, so support means a typed
   runtime route with its own sealed-installation and identity rules,
   not a `node` alias. Until such a route exists, a Bun or Deno project
   is outside this specification.

## 14. Milestones

### M-TS1: adapter and vitest route

§§4–6. Acceptance: a demo repository's registered vitest nodes produce
`example-test` receipts; an unregistered discovered node in a registered
file, a renamed node, a multi-match pattern, and a lifecycle-script
dependency each fail closed with a stable `PB-NODE-` code; the sealed
install runs with `--ignore-scripts` and its provenance is receipted.

### M-TS2: tsc static-check

§7 (after Specification 0002 M-PY2 lands the kind). Acceptance: a strict
tsconfig unit derives `TESTED · MODEL_ONLY`; a seeded type error and a
`strict = false` configuration each fail closed; the listed-files
inventory match is bidirectional.

### M-TS3: package reproduction

§8. Acceptance: `npm pack` reproduces byte-identically across two
shadows and matches the registered digest; a tarball member without a
sealed source origin, a traversal member, and a digest mismatch each
fail closed; the independent verifier recomputes both digest
comparisons from the portable receipt.

### M-TS4: mutation witnesses and init

§§9–10. Acceptance: a registered mutant is caught by exactly the
registered witness in the mutated shadow; `proofbound init` scaffolds a
working Tier 0 ledger on a vitest repository in a sealed shadow.

### M-TS5: TypeScript reference vertical

A small published-shape package (for example, a canonical JSON or
base64url codec) with exact vitest nodes, one fast-check property with
stated limits, a strict tsc unit, a package reproduction unit, one
explicit assumption, and one seeded defect demonstrating fail-closed
behavior. Acceptance: `init` → `check` → `status` → `release` →
standalone verification, end to end, with no capability claim beyond
`TESTED · MODEL_ONLY`.

## 15. Success criteria

1. A TypeScript-only team reaches an honest Tier 0 board and a verified
   release receipt using only routes in this document, without any
   lifecycle script executing.
2. No Proofbound operation on a Node repository can be escalated through
   `package.json` scripts, install hooks, or test-name injection.
3. The packed artifact users install is bound to reviewed bytes by
   reproduction that a third party can recheck from the receipt alone.
4. Every unsupported ecosystem capability fails closed by name; nothing
   downgrades silently.
5. Status language never exceeds `TESTED · MODEL_ONLY`, and every
   report's "not proved / out of scope" section carries the TypeScript
   ceiling of §11.
