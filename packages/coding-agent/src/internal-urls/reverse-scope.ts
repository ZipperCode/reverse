/**
 * Grammar for `reverse://` docs scopes:
 * which doc a URL names, and the whole embedded corpus for the docs root.
 */
import * as path from "node:path";
import { getDocFilenames, getEmbeddedDoc } from "./docs-index";
import type { InternalUrl, ResolveContext } from "./types";

/** Host + path of an internal doc URL, exactly as the handler reads it; `""` when the URL names the docs root. */
export function reverseDocFilename(url: InternalUrl): string {
	const host = url.rawHost || url.hostname;
	const pathname = url.rawPathname ?? url.pathname;
	return host ? (pathname && pathname !== "/" ? host + pathname : host) : "";
}

/**
 * Canonical doc path relative to `docs/` for an internal doc URL, or `""` for the
 * docs root (`scheme://`, `scheme:///`, `scheme://docs`, `scheme://docs/`). Throws on
 * absolute paths and `..` traversal — the rejections the handler reports.
 */
export function reverseDocRel(url: InternalUrl): string {
	const filename = reverseDocFilename(url);
	if (filename.length === 0) return "";
	const scheme = url.protocol ? url.protocol.replace(/:$/, "") : "reverse";
	if (path.isAbsolute(filename)) throw new Error(`Absolute paths are not allowed in ${scheme}:// URLs`);
	const normalized = path.posix.normalize(filename.replaceAll("\\", "/"));
	if (normalized === ".." || normalized.startsWith("../") || normalized.includes("/../")) {
		throw new Error(`Path traversal (..) is not allowed in ${scheme}:// URLs`);
	}
	if (normalized === "." || normalized === "docs") return "";
	return normalized.startsWith("docs/") ? normalized.slice("docs/".length) : normalized;
}

/** One embedded doc of a doc root scope. */
export interface ReverseDocEntry {
	/** Canonical URL. */
	url: string;
	/** Doc text. */
	content: string;
}

/**
 * Every embedded doc for a root scope, in docs-index (sorted) order. Empty
 * when no docs corpus is reachable.
 */
export async function reverseDocsScopeEntries(
	context?: ResolveContext,
	scheme = "reverse",
): Promise<ReverseDocEntry[]> {
	const entries: ReverseDocEntry[] = [];
	for (const rel of getDocFilenames()) {
		context?.signal?.throwIfAborted();
		const content = await getEmbeddedDoc(rel);
		if (content === undefined) continue;
		entries.push({ url: `${scheme}://${rel}`, content });
	}
	return entries;
}
