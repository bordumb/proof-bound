import type { Arbitrary } from "fast-check";

export const target = "failing_property::nonnegative_integers_are_negative";

interface FastCheckSurface {
  integer(constraints: { min: number; max: number }): Arbitrary<number>;
}

export function buildArbitrary(fastCheck: FastCheckSurface): Arbitrary<number> {
  return fastCheck.integer({ min: 0, max: 10 });
}

export function predicate(value: number): boolean {
  return value < 0;
}
