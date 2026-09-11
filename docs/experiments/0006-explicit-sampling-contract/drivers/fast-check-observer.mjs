import { createRequire } from "node:module";
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { vi } from "vitest";

const projectRoot = process.env.PROOFBOUND_PROPERTY_PROJECT;
const outputPath = process.env.PROOFBOUND_SAMPLING_REPORT;
if (!projectRoot || !outputPath) {
  throw new Error("sampling observer requires project and report paths");
}

const requireFromProject = createRequire(
  pathToFileURL(`${projectRoot}/package.json`),
);
const packagePath = requireFromProject.resolve("fast-check/package.json");
const packageMetadata = requireFromProject(packagePath);

const observe = (details) => {
    const report = {
      schema: "proofbound-fast-check-observation/1",
      framework: "fast-check",
      framework_version: packageMetadata.version,
      seed: details.seed,
      completed_cases: details.numRuns,
      skipped_cases: details.numSkips,
      shrink_count: details.numShrinks,
      interrupted: details.interrupted,
      failed: details.failed,
      effective: {
        num_runs: details.runConfiguration.numRuns,
        random_type: details.runConfiguration.randomType,
        seed: details.runConfiguration.seed,
      },
    };
    writeFileSync(outputPath, `${JSON.stringify(report)}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    if (details.failed) {
      throw new Error("fast-check property failed; see the bound observation");
    }
};

vi.doMock("fast-check", async (importOriginal) => {
  const original = await importOriginal();
  const observedAssert = (property, parameters = {}) => {
    if (parameters.reporter || parameters.asyncReporter) {
      throw new Error("application property cannot replace the sampling observer");
    }
    return original.assert(property, { ...parameters, reporter: observe });
  };
  return {
    ...original,
    assert: observedAssert,
    default: { ...original.default, assert: observedAssert },
  };
});
