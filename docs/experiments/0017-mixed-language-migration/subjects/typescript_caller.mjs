#!/usr/bin/env node
"use strict";

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const CALL_SCHEMA = "proofbound-research-foreign-call/1";
const OBSERVATIONS_SCHEMA = "proofbound-research-foreign-observations/1";
const CONTRACT_SCHEMA = "proofbound-research-foreign-contract/1";

function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function domainHash(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain)
    .update(Buffer.from([0]))
    .update(canonicalJson(value))
    .digest("hex")}`;
}

function validateContract(contract) {
  const candidate = structuredClone(contract);
  const identity = candidate.identity;
  candidate.identity = "";
  if (identity !== domainHash(CONTRACT_SCHEMA, candidate)) {
    throw new Error("contract identity differs");
  }
  if (
    contract.schema !== CONTRACT_SCHEMA ||
    contract.abi_version !== 1 ||
    canonicalJson(contract.operations) !== canonicalJson(["decode", "encode"]) ||
    contract.request_encoding !== "canonical-lowercase-hex-or-u2" ||
    contract.response_encoding !== "canonical-json-tagged-result" ||
    contract.error_policy !== "error-as-data-no-host-exception" ||
    contract.callback_policy !== "forbidden"
  ) {
    throw new Error("unsupported foreign contract");
  }
}

function result(accepted, value, outputHex, error, consumed) {
  return { accepted, value, output_hex: outputHex, error, consumed };
}

function decode(value, prefix, length, maximum) {
  if (value.length !== length) {
    return result(false, null, null, "invalid-length", value.length);
  }
  if (value[0] !== prefix) {
    return result(false, null, null, "invalid-prefix", value.length);
  }
  if (value[1] > maximum) {
    return result(false, null, null, "invalid-payload", value.length);
  }
  return result(true, value[1], value.toString("hex"), null, value.length);
}

function executeLegacy(testCase) {
  if (testCase.operation === "encode") {
    const value = testCase.input_value;
    return result(true, value, Buffer.from([1, value]).toString("hex"), null, 0);
  }
  return decode(Buffer.from(testCase.input_hex, "hex"), 1, 2, 3);
}

function validateArtifact(contract, artifact) {
  const registered = contract.artifact;
  const opcodes = [7, 9, 10, 11, 13, 16, 19, 21].map((index) => artifact[index]);
  if (
    artifact.toString("hex") !== registered.hex ||
    artifact.length !== registered.size_bytes ||
    sha256Bytes(artifact) !== registered.sha256 ||
    artifact.subarray(0, 7).toString("hex") !== "5042564d01040b" ||
    canonicalJson(opcodes) !== canonicalJson([0x10, 0x11, 0xff, 0x20, 0x21, 0x22, 0x23, 0xfe])
  ) {
    throw new Error("native artifact differs");
  }
}

function executeArtifact(artifact, testCase) {
  if (testCase.operation === "encode") {
    const value = testCase.input_value;
    return result(true, value, Buffer.from([artifact[8], value]).toString("hex"), null, 0);
  }
  return decode(Buffer.from(testCase.input_hex, "hex"), artifact[15], artifact[12], artifact[18]);
}

function executeCase(contract, testCase, phase, artifact) {
  let actual;
  let artifactIdentity = null;
  if (phase === "migrated") {
    validateArtifact(contract, artifact);
    actual = executeArtifact(artifact, testCase);
    artifactIdentity = contract.artifact.identity;
  } else {
    actual = executeLegacy(testCase);
  }
  if (canonicalJson(actual) !== canonicalJson(testCase.expected)) {
    throw new Error(`case result differs: ${testCase.id}`);
  }
  const call = {
    schema: CALL_SCHEMA,
    case_id: testCase.id,
    phase,
    language: "typescript",
    contract_identity: contract.identity,
    artifact_identity: artifactIdentity,
    operation: testCase.operation,
    input_hex: testCase.input_hex,
    input_value: testCase.input_value,
    ...actual,
    identity: "",
  };
  call.identity = domainHash(CALL_SCHEMA, call);
  return call;
}

function main(arguments_) {
  if (arguments_.length !== 3 || !["baseline", "migrated"].includes(arguments_[2])) {
    throw new Error("usage: typescript_caller.mjs CONTRACT CASES baseline|migrated");
  }
  const contract = JSON.parse(readFileSync(arguments_[0]));
  const cases = JSON.parse(readFileSync(arguments_[1]));
  const phase = arguments_[2];
  validateContract(contract);
  const runtime = contract.runtimes.find((item) => item.language === "typescript");
  const actualRuntime = {
    language: "typescript",
    program: "node",
    version: process.version,
    executable_sha256: sha256Bytes(readFileSync(process.execPath)),
  };
  if (canonicalJson(actualRuntime) !== canonicalJson(runtime)) {
    throw new Error("registered TypeScript runtime differs");
  }
  const artifact = Buffer.from(contract.artifact.hex, "hex");
  const calls = cases.cases.map((testCase) =>
    executeCase(contract, testCase, phase, artifact),
  );
  const observation = {
    schema: OBSERVATIONS_SCHEMA,
    language: "typescript",
    phase,
    contract_identity: contract.identity,
    runtime,
    calls,
    identity: "",
  };
  observation.identity = domainHash(OBSERVATIONS_SCHEMA, observation);
  process.stdout.write(canonicalJson(observation));
}

main(process.argv.slice(2));
