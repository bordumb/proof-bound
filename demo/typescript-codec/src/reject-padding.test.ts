import { describe, expect, test } from "vitest";

import { decodeBase64Url } from "./base64url.js";

describe("base64url codec", () => {
  test("rejects padding", () => {
    expect(() => decodeBase64Url("Zg==")).toThrow(TypeError);
  });
});
