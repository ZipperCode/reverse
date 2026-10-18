/**
 * Read-only dependency checks for skills.
 *
 * A skill declares logical tool ids in `metadata.requires` /
 * `metadata.requiresOptional` (top-level `requires` / `requiresOptional` are
 * accepted for skills outside the Agent Plugins spec). Detection never leaves
 * the machine: it looks at PATH plus catalog-owned directories and returns
 * nothing when everything is present. Install hints come exclusively from
 * {@link SKILL_TOOL_CATALOG}; an unknown id is probed but never yields a hint.
 */
import * as path from "node:path";
import { isRecord, $which, WhichCachePolicy } from "@rva/utils";
import { expandEnvVarsDeep } from "../discovery/helpers";
import { expandTilde } from "../tools/path-utils";
import { SKILL_TOOL_CATALOG } from "./skill-tool-catalog";
/** Most ids read from one skill; keeps untrusted frontmatter from growing context. */
const MAX_REQUIREMENTS = 32;
const REQUIREMENT_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
function requirementIds(value) {
    const entries = Array.isArray(value) ? value : typeof value === "string" ? value.split(/[\s,]+/) : [];
    const ids = [];
    for (const entry of entries) {
        if (typeof entry !== "string")
            continue;
        for (const token of entry.split(/[\s,]+/)) {
            const id = token.trim().toLowerCase();
            if (id.length === 0 || !REQUIREMENT_ID.test(id))
                continue;
            ids.push(id);
        }
    }
    return ids;
}
/**
 * Required ids win over optional ones. `metadata` is the portable location
 * (Agent Skills allows it); top-level keys serve rea-local skills.
 */
export function readSkillRequirements(frontmatter) {
    if (!frontmatter)
        return [];
    const metadata = isRecord(frontmatter.metadata) ? frontmatter.metadata : undefined;
    const required = [...requirementIds(metadata?.requires), ...requirementIds(frontmatter.requires)];
    const optional = [
        ...requirementIds(metadata?.requiresOptional),
        ...requirementIds(metadata?.["requires-optional"]),
        ...requirementIds(frontmatter.requiresOptional),
    ];
    const seen = new Set();
    const requirements = [];
    for (const id of required) {
        if (seen.has(id) || requirements.length >= MAX_REQUIREMENTS)
            continue;
        seen.add(id);
        requirements.push({ id });
    }
    for (const id of optional) {
        if (seen.has(id) || requirements.length >= MAX_REQUIREMENTS)
            continue;
        seen.add(id);
        requirements.push({ id, optional: true });
    }
    return requirements;
}
/** PATH for one descriptor: ambient PATH plus its env- and platform-owned dirs. */
function searchPathFor(descriptor, platform, env) {
    const extras = [];
    const envStrings = {};
    for (const [key, value] of Object.entries(env)) {
        if (typeof value === "string")
            envStrings[key] = value;
    }
    const platformPath = platform === "win32" ? path.win32 : path.posix;
    for (const entry of descriptor.envPaths ?? []) {
        const base = env[entry.env];
        if (base)
            extras.push(platformPath.join(base, entry.suffix ?? ""));
    }
    for (const raw of descriptor.searchPaths?.[platform] ?? []) {
        const expanded = expandTilde(expandEnvVarsDeep(raw, envStrings));
        if (expanded.length === 0 || expanded.includes("${"))
            continue;
        extras.push(platformPath.normalize(expanded));
    }
    const basePath = env.PATH ?? "";
    if (extras.length === 0)
        return basePath.length > 0 ? basePath : undefined;
    // `path.delimiter` follows the host, not the simulated test platform.
    const separator = platform === "win32" ? ";" : path.delimiter;
    return [basePath, ...extras].filter(part => part.length > 0).join(separator);
}
/**
 * Check every declared tool. Synchronous by design (skill reads and prompt
 * rendering are synchronous); PATH lookups bypass the process-wide negative
 * cache so a tool installed earlier in the session is discovered on the next
 * check.
 */
export function checkToolRequirements(requirements, deps = {}) {
    const requestedPlatform = deps.platform ?? process.platform;
    const platform = requestedPlatform === "darwin" || requestedPlatform === "win32" ? requestedPlatform : "linux";
    const env = deps.env ?? process.env;
    const which = deps.which ?? $which;
    return requirements.map(requirement => {
        // Public callers may bypass `readSkillRequirements`; never let a malformed
        // id reach PATH lookup or the model-facing notice.
        if (!REQUIREMENT_ID.test(requirement.id)) {
            return {
                id: requirement.id,
                optional: requirement.optional === true,
                foundPath: null,
                unknown: true,
                invalid: true,
            };
        }
        const descriptor = SKILL_TOOL_CATALOG[requirement.id];
        const options = {
            cache: WhichCachePolicy.Bypass,
            requireAbsolutePaths: true,
        };
        if (!descriptor) {
            return {
                id: requirement.id,
                optional: requirement.optional === true,
                foundPath: which(requirement.id, options),
                unknown: true,
            };
        }
        const searchPath = searchPathFor(descriptor, platform, env);
        if (searchPath !== undefined)
            options.PATH = searchPath;
        let foundPath = descriptor.probe?.() ?? null;
        if (foundPath === null) {
            for (const binary of descriptor.binaries) {
                foundPath = which(binary, options);
                if (foundPath !== null)
                    break;
            }
        }
        const secondaryMissing = foundPath === null ? [] : (descriptor.secondary ?? []).filter(binary => which(binary, options) === null);
        const missing = foundPath === null || secondaryMissing.length > 0;
        return {
            id: requirement.id,
            optional: requirement.optional === true,
            foundPath,
            ...(missing && { hint: descriptor.installHints?.[platform]?.join(" or ") }),
            ...(secondaryMissing.length > 0 && { secondaryMissing }),
        };
    });
}
/**
 * Model-facing notice for missing *required* dependencies. Returns `undefined`
 * when every required tool is present and when only optional tools are missing,
 * which is what keeps the skill text byte-identical on the common path.
 */
export function missingRequirementNotice(statuses) {
    const missing = statuses.filter(status => !status.invalid && (status.foundPath === null || (status.secondaryMissing?.length ?? 0) > 0));
    const required = missing.filter(status => !status.optional);
    if (required.length === 0)
        return undefined;
    const details = required.map(status => {
        const problem = status.foundPath === null
            ? `${status.id} not found on PATH`
            : `${status.id} found, but ${status.secondaryMissing?.join(", ")} missing`;
        return status.hint ? `${problem} (install: ${status.hint})` : problem;
    });
    return `[Missing tool dependencies: ${details.join("; ")}. Install them before running this skill's commands.]`;
}
