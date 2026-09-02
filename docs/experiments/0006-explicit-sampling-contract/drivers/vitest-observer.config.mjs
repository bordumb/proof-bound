import { fileURLToPath } from "node:url";

const projectRoot = process.env.PROOFBOUND_PROPERTY_PROJECT;
if (!projectRoot) {
  throw new Error("sampling observer requires the project root");
}

export default {
  root: projectRoot,
  test: {
    globalSetup: [
      fileURLToPath(
        new URL("./fast-check-observer-teardown.mjs", import.meta.url),
      ),
    ],
    setupFiles: [
      fileURLToPath(new URL("./fast-check-observer.mjs", import.meta.url)),
    ],
  },
};
