# TypeScript adoption

Proofbound supports TypeScript repositories through closed Node routes. It does
not run `npm test`, `npm run`, `npm exec`, or `npx`. A repository must use npm,
commit a lockfile with `lockfileVersion >= 3`, and pin Vitest or TypeScript in
that lockfile. Workspaces, pnpm, yarn, Jest, script-dependent builds, and native
addons are unsupported in this version.

Start in a repository that already has at least one passing Vitest node:

```sh
proofbound init
proofbound doctor
proofbound check --fresh
proofbound status
```

`init` discovers one exact node in an isolated copy after
`npm ci --ignore-scripts --no-audit --no-fund`. It creates a Tier 0 placeholder
claim and conservatively registers the repository's JavaScript and TypeScript
source files. Review and replace the placeholder language before publishing.
`doctor` never installs dependencies; it reports Node, npm, and each required
local `node_modules/.bin` tool by identity.

## Exact Vitest evidence

A Vitest inventory item is `FILE::NAME`, where `NAME` is the full name emitted
by `vitest list --json`:

```toml
schema = "proofbound-evidence-unit/1"
id = "reject-padding"
adapter = "node-test"
kind = "example-test"
claims = ["CODEC-001"]
tier = 0
expected_inventory = ["src/decode.test.ts::decoder > rejects padding"]
inputs = ["package-lock.json", "package.json", "src/decode.test.ts", "src/decode.ts"]
outputs = []
environment_allowlist = ["PATH"]

[operation]
type = "vitest"

[resource_budget]
time_seconds = 300
disk_bytes = 1073741824
memory_bytes = 2147483648
```

Proofbound inventories every node in each registered test file, compares that
inventory bidirectionally, escapes and anchors the selected full name, and
requires an exact one-test machine report. Fast-check properties use the same
route and remain bounded empirical evidence; record the seed and limits in the
test and claim language.

## Strict TypeScript analysis

The `tsc` route requires strict JSON configuration with `strict: true` and no
`extends`. It binds the configuration bytes, inventories repository files with
`--listFilesOnly`, and then requires a diagnostic-free `--noEmit` run:

```toml
[operation]
type = "tsc"
configuration = "tsconfig.json"
```

Register the exact repository file inventory in `expected_inventory` and pin
the configuration in `inputs`. This establishes zero diagnostics for the
registered tool and configuration; it does not establish TypeScript soundness
or remove escape hatches such as `any`, assertions, and `@ts-ignore`.

## npm package reproduction

The `proofbound-evidence-unit/4` `npm-package` route performs clean installs in
two independent shadows, packs each without lifecycle scripts, and requires
both tarballs to equal the registered SHA-256 digest. Every regular tar member
must match a reviewed source file byte-for-byte; generated build output is not
supported yet.

The resulting evidence says that one exact npm tarball is reproducible from the
reviewed source closure. It does not say the package behaves correctly. Under
Specification 0003 every TypeScript claim remains capped at
`TESTED · MODEL_ONLY`, with its assumptions and exclusions shown in status and
release reports.

See the complete runnable manifests in
[`demo/typescript-codec`](../../demo/typescript-codec/).
