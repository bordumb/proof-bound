import { describe, expect, test } from "vitest";
import fc from "fast-check";

import { decodeBase64Url, encodeBase64Url } from "./base64url.js";

describe("base64url codec", () => {
  test("round trips bounded byte arrays", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 256 }), (bytes) => {
        expect(Array.from(decodeBase64Url(encodeBase64Url(bytes)))).toEqual(
          Array.from(bytes),
        );
      }),
      { numRuns: 100, seed: 424242 },
    );
  });
});
