/**
 * Compatibility alias for `rva://` docs scope grammar, delegating to `reverse-scope`.
 */
import {
	reverseDocFilename,
	reverseDocRel,
	reverseDocsScopeEntries,
	type ReverseDocEntry,
} from "./reverse-scope";
import type { InternalUrl, ResolveContext } from "./types";

/** Host + path of an `rva://` URL, exactly as the handler reads it; `""` when the URL names the docs root. */
export const rvaDocFilename = reverseDocFilename;

/**
 * Canonical doc path relative to `docs/` for an `rva://` URL, or `""` for the
 * docs root (`rva://`, `rva:///`, `rva://docs`, `rva://docs/`).
 */
export const rvaDocRel = reverseDocRel;

/** One embedded doc of a `rva://` root scope. */
export type RvaDocEntry = ReverseDocEntry;

/**
 * Every embedded doc for a root scope, in docs-index (sorted) order. Empty
 * when no docs corpus is reachable.
 */
export async function rvaDocsScopeEntries(context?: ResolveContext): Promise<RvaDocEntry[]> {
	return reverseDocsScopeEntries(context, "rva");
}
