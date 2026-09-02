import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import fastCheck from "fast-check";
import packageMetadata from "fast-check/package.json" with { type: "json" };

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function canonicalJson(value: Json): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function domainHash(domain: string, value: Json): string {
  const hash = createHash("sha256");
  hash.update(domain, "utf8");
  hash.update(Buffer.from([0]));
  hash.update(canonicalJson(value), "utf8");
  return `sha256:${hash.digest("hex")}`;
}

function argument(name: string): string {
  const index = process.argv.indexOf(name);
  if (index === -1 || index + 1 >= process.argv.length) {
    throw new Error(`missing ${name}`);
  }
  return process.argv[index + 1];
}

function repeatedArguments(name: string): string[] {
  return process.argv.flatMap((value, index) =>
    value === name && index + 1 < process.argv.length ? [process.argv[index + 1]] : [],
  );
}

const root = argument("--root");
const modulePath = argument("--module");
const target = argument("--target");
const seed = Number(argument("--seed"));
const cases = Number(argument("--cases"));
const outputPath = argument("--output");
if (!Number.isSafeInteger(seed) || seed < 0 || !Number.isSafeInteger(cases) || cases < 1) {
  throw new Error("seed and case budget are outside the registered domain");
}

function normalizedRelativePath(value: string): string {
  if (
    isAbsolute(value) ||
    value.includes("\\") ||
    value.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    throw new Error("closure path is not a normalized relative path");
  }
  return value;
}

normalizedRelativePath(modulePath);
const propertyModule = await import(pathToFileURL(resolve(root, modulePath)).href);
if (propertyModule.target !== target) {
  throw new Error("property target differs from registration");
}
const arbitrary = propertyModule.buildArbitrary(fastCheck);
const run = fastCheck.check(fastCheck.property(arbitrary, propertyModule.predicate), {
  numRuns: cases,
  seed,
});
if (run.interrupted && !run.failed) {
  throw new Error("registered fast-check property was interrupted without a counterexample");
}

const closure = repeatedArguments("--closure")
  .map((logicalName) => {
    normalizedRelativePath(logicalName);
    const bytes = readFileSync(resolve(root, logicalName));
    return {
      logical_name: logicalName,
      sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
      size_bytes: bytes.length,
    };
  })
  .sort((left, right) => left.logical_name.localeCompare(right.logical_name));
const generator: { [key: string]: Json } = {
  entrypoint: `${modulePath}::buildArbitrary+predicate`,
  closure,
};
generator.identity_sha256 = domainHash("proofbound-generator-closure/1", generator);
const contract: { [key: string]: Json } = {
  schema: "proofbound-sampling-contract/1",
  framework: { name: "fast-check", version: packageMetadata.version },
  seed: { encoding: "decimal-u64", value: seed },
  successful_cases: cases,
  generator,
  targets: [target],
  replay: "fresh-only",
  persistence: "disabled",
  shrinking: "enabled",
};
const result: Json = run.failed
  ? {
      status: "counterexample",
      counterexample: run.counterexample as Json,
      failure_kind: "property-false-or-threw",
    }
  : { status: "passed" };
const report: Json = {
  schema: "proofbound-sampling-observation/1",
  contract,
  contract_identity: domainHash("proofbound-sampling-contract/1", contract),
  actual_seed: { encoding: "decimal-u64", value: run.seed },
  completed_cases: run.numRuns,
  skipped_cases: run.numSkips,
  shrink_count: run.numShrinks,
  targets: [target],
  result,
};
writeFileSync(outputPath, canonicalJson(report), { flag: "wx", mode: 0o600 });
if (run.failed) {
  process.exitCode = 1;
}
