/**
 * Protocol handler for reverse:// URLs.
 *
 * Serves statically embedded documentation files bundled at build time.
 *
 * URL forms:
 * - reverse:// - Lists all available documentation files
 * - reverse://<file>.md - Reads a specific documentation file
 */
import * as path from "node:path";
import { resolveContainedPath, resolveContainedPathSync } from "../discovery/contained-path";
import reverseDoc from "../prompts/internal-urls/reverse.md" with { type: "text" };
import { getDocFilenames, getDocsDiskRoot, getEmbeddedDoc } from "./docs-index";
import { reverseDocFilename, reverseDocRel, reverseDocsScopeEntries } from "./reverse-scope";
import type {
	InternalResource,
	InternalUrl,
	LocateOptions,
	ProtocolHandler,
	ResolveContext,
	SchemeSpec,
	UrlCompletion,
} from "./types";

/**
 * Repo `docs/` tree the embedded corpus is generated from. Only the
 * docs-index-owned root (getDocsDiskRoot) is ever probed.
 */
function docFileOnDisk(docPath: string): string | undefined {
	const root = getDocsDiskRoot();
	if (root === null || !getDocFilenames().includes(docPath)) return undefined;
	const resolution = resolveContainedPathSync(root, path.resolve(root, docPath));
	return resolution.status === "ok" ? resolution.realPath : undefined;
}

/** File a doc URL may link to, or `undefined` for the docs root and doc-less URLs. */
function docFileFor(url: InternalUrl): string | undefined {
	const docPath = reverseDocRel(url);
	return docPath.length > 0 ? docFileOnDisk(docPath) : undefined;
}

/**
 * Handler for reverse:// URLs.
 *
 * Resolves documentation file names to their content, or lists available docs.
 */
export class ReverseProtocolHandler implements ProtocolHandler {
	readonly scheme: string;
	readonly spec: SchemeSpec = { backing: "virtual", selectors: "lines", immutable: true, linkable: true };

	constructor(scheme = "reverse") {
		this.scheme = scheme;
	}

	promptDoc(): string {
		return reverseDoc.trim();
	}

	async resolve(url: InternalUrl): Promise<InternalResource> {
		const filename = reverseDocFilename(url);
		// The docs root (`scheme://`, `scheme://docs`) names no doc.
		const docPath = reverseDocRel(url);

		if (!filename || !docPath) {
			return this.listDocs(url);
		}

		return this.readDoc(docPath, filename, url);
	}

	/** The docs root expands to every embedded doc; a single-doc URL yields that doc (or throws when unknown). */
	async enumerate(url: InternalUrl, context?: ResolveContext): Promise<Array<{ url: string; content: string }>> {
		const docPath = reverseDocRel(url);
		if (!docPath) {
			const entries = await reverseDocsScopeEntries(context, this.scheme);
			if (entries.length === 0) {
				throw new Error("No documentation files found");
			}
			return entries;
		}
		const resource = await this.readDoc(docPath, reverseDocFilename(url), url);
		return [{ url: `${this.scheme}://${docPath}`, content: resource.content }];
	}

	async complete(): Promise<UrlCompletion[]> {
		return getDocFilenames().map(value => ({ value }));
	}

	locateSync(url: InternalUrl): string | undefined {
		try {
			return docFileFor(url);
		} catch {
			return undefined;
		}
	}

	async locate(url: InternalUrl, _context?: ResolveContext, _options?: LocateOptions): Promise<string | null> {
		const docPath = reverseDocRel(url);
		if (docPath.length === 0) return null;
		const root = getDocsDiskRoot();
		if (root === null || !getDocFilenames().includes(docPath)) return null;
		const resolution = await resolveContainedPath(root, path.resolve(root, docPath));
		return resolution.status === "ok" ? resolution.realPath : null;
	}

	protected async listDocs(url: InternalUrl): Promise<InternalResource> {
		const filenames = getDocFilenames();
		if (filenames.length === 0) {
			throw new Error("No documentation files found");
		}

		const listing = filenames.map(f => `- [${f}](${this.scheme}://${f})`).join("\n");
		const content = `# Documentation\n\n${filenames.length} files available:\n\n${listing}\n`;

		return {
			url: url.href,
			content,
			contentType: "text/markdown",
			size: Buffer.byteLength(content, "utf-8"),
		};
	}

	protected async readDoc(docPath: string, filename: string, url: InternalUrl): Promise<InternalResource> {
		const content = await getEmbeddedDoc(docPath);
		if (content === undefined) {
			const lookup = docPath.replace(/\.md$/, "");
			const suggestions = getDocFilenames()
				.filter(f => f.includes(lookup) || lookup.includes(f.replace(/\.md$/, "")))
				.slice(0, 5);
			const suffix =
				suggestions.length > 0
					? `\nDid you mean: ${suggestions.join(", ")}`
					: `\nUse ${this.scheme}:// to list available files.`;
			throw new Error(`Documentation file not found: ${filename}${suffix}`);
		}

		return {
			url: url.href,
			content,
			contentType: "text/markdown",
			size: Buffer.byteLength(content, "utf-8"),
		};
	}
}
