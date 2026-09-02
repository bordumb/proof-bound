import type { Arbitrary } from "fast-check";

import { decodeBase64Url, encodeBase64Url } from "../../../../../demo/typescript-codec/src/base64url.js";

export const target =
  "roundtrip_property::base64url_codec_round_trips_bounded_byte_arrays";

export function buildArbitrary(fastCheck: {
  uint8Array(constraints: { maxLength: number }): Arbitrary<Uint8Array>;
}): Arbitrary<Uint8Array> {
  return fastCheck.uint8Array({ maxLength: 256 });
}

export function predicate(bytes: Uint8Array): boolean {
  const decoded = decodeBase64Url(encodeBase64Url(bytes));
  return (
    decoded.length === bytes.length &&
    decoded.every((value, index) => value === bytes[index])
  );
}
