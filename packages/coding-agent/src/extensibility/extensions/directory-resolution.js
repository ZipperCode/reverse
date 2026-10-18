import * as fs from "node:fs";
import * as path from "node:path";
import { hasFsCode, isEacces, isEnoent, isRecord } from "@rva/utils";
function isUnavailable(error) {
    return isEnoent(error) || isEacces(error) || hasFsCode(error, "EPERM") || hasFsCode(error, "ENOTDIR");
}
/** Select the first loadable index file using the caller's suffix and error policy. */
export function findExtensionDirectoryIndex(dir, indexNames, options = {}) {
    for (const name of indexNames) {
        const candidate = path.join(dir, name);
        try {
            if (fs.statSync(candidate).isFile())
                return candidate;
        }
        catch (error) {
            if (options.throwUnexpectedStatErrors && !isUnavailable(error))
                throw error;
        }
    }
    return null;
}
function readDeclaredManifestEntries(dir, options) {
    const packageJsonPath = path.join(dir, "package.json");
    let raw;
    try {
        raw = fs.readFileSync(packageJsonPath, "utf8");
    }
    catch (error) {
        if (!isUnavailable(error))
            options.onReadError?.(packageJsonPath, error);
        return { declared: false, files: [] };
    }
    let pkg;
    try {
        pkg = JSON.parse(raw);
    }
    catch (error) {
        options.onReadError?.(packageJsonPath, error);
        return { declared: false, files: [] };
    }
    const manifest = isRecord(pkg) ? (pkg.omp ?? pkg.pi) : undefined;
    const entries = isRecord(manifest) ? manifest.extensions : undefined;
    if (!Array.isArray(entries) || entries.length === 0) {
        return { declared: false, files: [] };
    }
    const files = [];
    for (const entry of entries) {
        if (typeof entry !== "string")
            continue;
        const candidate = path.resolve(dir, entry);
        let stats;
        try {
            stats = fs.statSync(candidate);
        }
        catch (error) {
            if (options.throwUnexpectedStatErrors && !isUnavailable(error))
                throw error;
            continue;
        }
        if (stats.isDirectory()) {
            const index = findExtensionDirectoryIndex(candidate, options.indexNames, options);
            if (index)
                files.push(index);
        }
        else {
            // Manifest paths are explicit, so they are not restricted by scan suffix policy.
            files.push(candidate);
        }
    }
    return { declared: true, files };
}
/**
 * Resolve an extension directory using manifest, index, then one-level scan
 * precedence. A declared manifest is authoritative even when none of its
 * entries resolve, so convention fallback never hides stale or missing entries.
 */
export function resolveExtensionDirectory(dir, options) {
    const manifest = readDeclaredManifestEntries(dir, options);
    if (manifest.declared)
        return manifest;
    const directIndex = findExtensionDirectoryIndex(dir, options.indexNames, options);
    if (directIndex)
        return { declared: false, files: [directIndex] };
    let children;
    try {
        children = fs.readdirSync(dir);
    }
    catch (error) {
        if (!isUnavailable(error))
            options.onReadError?.(dir, error);
        return { declared: false, files: [] };
    }
    if (options.sortChildren)
        children.sort();
    const files = [];
    for (const child of children) {
        const childPath = path.join(dir, child);
        let stats;
        try {
            // stat follows symlinks, preserving configured and installed package behavior.
            stats = fs.statSync(childPath);
        }
        catch (error) {
            if (options.throwUnexpectedStatErrors && !isUnavailable(error))
                throw error;
            continue;
        }
        if (stats.isDirectory()) {
            const childManifest = readDeclaredManifestEntries(childPath, options);
            if (childManifest.declared) {
                files.push(...childManifest.files);
                continue;
            }
            const index = findExtensionDirectoryIndex(childPath, options.indexNames, options);
            if (index)
                files.push(index);
        }
        else if (options.isScanFile(child)) {
            files.push(childPath);
        }
    }
    return { declared: false, files };
}
