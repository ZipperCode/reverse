/**
 * ArkType compatibility facade — `@reverse/reversetype/ark`.
 *
 * Lets code written against arktype keep its imports and names while running
 * on the reversetype lazy-JIT runtime: swap `from "arktype"` for
 * `from "@reverse/reversetype/ark"` and nothing else changes. New code should
 * import `@reverse/reversetype` directly.
 *
 * Compatibility affordance: `ArkError` / `ArkErrors` alias `ReverseError` /
 * `ReverseErrors`. All schema builders, including recursive `scope()`, are
 * re-exported unchanged.
 */
import { ReverseError, ReverseErrors } from "./errors";

export * from "./index";

export const ArkError = ReverseError;
export type ArkError = ReverseError;
export const ArkErrors = ReverseErrors;
export type ArkErrors = ReverseErrors;
