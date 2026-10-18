/**
 * Protocol handler for rva:// URLs.
 *
 * Serves statically embedded documentation files bundled at build time.
 *
 * URL forms:
 * - rva:// - Lists all available documentation files
 * - rva://<file>.md - Reads a specific documentation file
 */
import * as path from "node:path";
import { resolveContainedPath, resolveContainedPathSync } from "../discovery/contained-path";
import rvaDoc from "../prompts/internal-urls/rva.md" with { type: "text" };
import { getDocFilenames, getDocsDiskRoot, getEmbeddedDoc } from "./docs-index";
import { rvaDocFilename, rvaDocRel, rvaDocsScopeEntries } from "./rva-scope";
/**
 * Repo `docs/` tree the embedded corpus is generated from. Only the
 * docs-index-owned root ({@link getDocsDiskRoot}) is ever probed: resolving
 * `docs/` relative to this module would land in the consumer's own tree
 * (their project's `docs/`, `node_modules/docs`) on installs where the
 * corpus is embedded.
 */
function docFileOnDisk(docPath) {
    const root = getDocsDiskRoot();
    if (root === null || !getDocFilenames().includes(docPath))
        return undefined;
    const resolution = resolveContainedPathSync(root, path.resolve(root, docPath));
    return resolution.status === "ok" ? resolution.realPath : undefined;
}
/** File a doc URL may link to, or `undefined` for the docs root and doc-less URLs. */
function docFileFor(url) {
    const docPath = rvaDocRel(url);
    return docPath.length > 0 ? docFileOnDisk(docPath) : undefined;
}
/**
 * Handler for rva:// URLs.
 *
 * Resolves documentation file names to their content, or lists available docs.
 */
export class RvaProtocolHandler {
    scheme = "rva";
    spec = { backing: "virtual", selectors: "lines", immutable: true, linkable: true };
    /** Always advertised: harness docs are embedded in every build. */
    promptDoc() {
        return rvaDoc.trim();
    }
    async resolve(url) {
        const filename = rvaDocFilename(url);
        // The docs root (`rva://`, `rva://docs`) names no doc. The grammar also
        // rejects absolute paths and `..` traversal.
        const docPath = rvaDocRel(url);
        if (!filename || !docPath) {
            return this.#listDocs(url);
        }
        return this.#readDoc(docPath, filename, url);
    }
    /** The docs root expands to every embedded doc; a single-doc URL yields that doc (or throws when unknown). */
    async enumerate(url, context) {
        const docPath = rvaDocRel(url);
        if (!docPath) {
            const entries = await rvaDocsScopeEntries(context);
            if (entries.length === 0) {
                throw new Error("No documentation files found");
            }
            return entries;
        }
        const resource = await this.#readDoc(docPath, rvaDocFilename(url), url);
        return [{ url: `rva://${docPath}`, content: resource.content }];
    }
    async complete() {
        return getDocFilenames().map(value => ({ value }));
    }
    /**
     * File a doc is read from in a source checkout, so `rva://` links open it.
     * The shipped corpus is embedded, so most installs have nothing to link and
     * the URL stays plain text rather than being materialized on the fly.
     */
    locateSync(url) {
        try {
            return docFileFor(url);
        }
        catch {
            // Malformed URLs locate to nothing, never throw, in a render path.
            return undefined;
        }
    }
    /** Async counterpart of {@link locateSync}; null instead of undefined. */
    async locate(url, _context, _options) {
        // Async filesystem calls: the markdown linkifier awaits this off the
        // render path, so blocking realpath/stat has no place here even though
        // the first call still initializes the memoized corpus synchronously.
        const docPath = rvaDocRel(url);
        if (docPath.length === 0)
            return null;
        const root = getDocsDiskRoot();
        if (root === null || !getDocFilenames().includes(docPath))
            return null;
        const resolution = await resolveContainedPath(root, path.resolve(root, docPath));
        return resolution.status === "ok" ? resolution.realPath : null;
    }
    async #listDocs(url) {
        const filenames = getDocFilenames();
        if (filenames.length === 0) {
            throw new Error("No documentation files found");
        }
        const listing = filenames.map(f => `- [${f}](rva://${f})`).join("\n");
        const content = `# Documentation\n\n${filenames.length} files available:\n\n${listing}\n`;
        return {
            url: url.href,
            content,
            contentType: "text/markdown",
            size: Buffer.byteLength(content, "utf-8"),
        };
    }
    async #readDoc(docPath, filename, url) {
        const content = await getEmbeddedDoc(docPath);
        if (content === undefined) {
            const lookup = docPath.replace(/\.md$/, "");
            const suggestions = getDocFilenames()
                .filter(f => f.includes(lookup) || lookup.includes(f.replace(/\.md$/, "")))
                .slice(0, 5);
            const suffix = suggestions.length > 0
                ? `\nDid you mean: ${suggestions.join(", ")}`
                : "\nUse rva:// to list available files.";
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
