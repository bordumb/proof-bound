import { readFileSync } from "node:fs";

export default function registerSamplingReportVerification() {
  return verifySamplingReport;
}

function verifySamplingReport() {
  const outputPath = process.env.PROOFBOUND_SAMPLING_REPORT;
  if (!outputPath) {
    throw new Error("sampling observer report path is missing");
  }
  let report;
  try {
    report = JSON.parse(readFileSync(outputPath, "utf8"));
  } catch (error) {
    throw new Error("sampling observer did not emit strict JSON", {
      cause: error,
    });
  }
  const required = [
    "schema",
    "framework",
    "framework_version",
    "seed",
    "completed_cases",
    "skipped_cases",
    "shrink_count",
    "interrupted",
    "failed",
    "effective",
  ];
  if (
    Object.keys(report).sort().join("\0") !== required.sort().join("\0") ||
    report.schema !== "proofbound-fast-check-observation/1"
  ) {
    throw new Error("sampling observer report has the wrong closed shape");
  }
}
