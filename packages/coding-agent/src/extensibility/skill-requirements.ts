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
import * as fs from "node:fs";
import * as path from "node:path";
import { isRecord, $which, type WhichOptions, WhichCachePolicy } from "@reverse/utils";
import type { SkillFrontmatter } from "../capability/skill";
import { expandEnvVarsDeep } from "../discovery/helpers";
import { expandTilde } from "../tools/path-utils";
import { SKILL_TOOL_CATALOG, type SkillToolDescriptor, type SkillToolPlatform } from "./skill-tool-catalog";
import type { Settings } from "../config/settings";
/** Most ids read from one skill; keeps untrusted frontmatter from growing context. */
const MAX_REQUIREMENTS = 32;
const REQUIREMENT_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export interface ToolRequirement {
	/** Catalog id, or any command name when the id is not catalogued. */
	id: string;
	optional?: boolean;
}

export type SkillRequirementWhich = (command: string, options?: WhichOptions) => string | null;

export interface RequirementCheckDeps {
	/** Lookup seam for tests; defaults to {@link $which}. */
	which?: SkillRequirementWhich;
	/** Defaults to `process.platform`; tests simulate `win32` paths with it. */
	platform?: NodeJS.Platform;
	/** Defaults to the ambient environment (PATH and catalog `${VAR}` expansion). */
	env?: Record<string, string | undefined>;
	settings?: Settings;
}

export interface RequirementStatus {
	id: string;
	optional: boolean;
	/** Resolved executable (or install directory) when found. */
	foundPath: string | null;
	/** Catalog-owned install hint; absent for unknown ids and found tools. */
	hint?: string;
	/** True when the id is not in the built-in catalog (still probed on PATH). */
	unknown?: boolean;
	/** True when the id is malformed; it is never probed or rendered in notices. */
	invalid?: boolean;
	/** Companion binaries that were required by the catalog but not found. */
	secondaryMissing?: string[];
}

function requirementIds(value: unknown): string[] {
	const entries = Array.isArray(value) ? value : typeof value === "string" ? value.split(/[\s,]+/) : [];
	const ids: string[] = [];
	for (const entry of entries) {
		if (typeof entry !== "string") continue;
		for (const token of entry.split(/[\s,]+/)) {
			const id = token.trim().toLowerCase();
			if (id.length === 0 || !REQUIREMENT_ID.test(id)) continue;
			ids.push(id);
		}
	}
	return ids;
}

/**
 * Required ids win over optional ones. `metadata` is the portable location
 * (Agent Skills allows it); top-level keys serve reverse-local skills.
 */
export function readSkillRequirements(frontmatter?: SkillFrontmatter): ToolRequirement[] {
	if (!frontmatter) return [];
	const metadata = isRecord(frontmatter.metadata) ? frontmatter.metadata : undefined;
	const required = [...requirementIds(metadata?.requires), ...requirementIds(frontmatter.requires)];
	const optional = [
		...requirementIds(metadata?.requiresOptional),
		...requirementIds(metadata?.["requires-optional"]),
		...requirementIds(frontmatter.requiresOptional),
	];

	const seen = new Set<string>();
	const requirements: ToolRequirement[] = [];
	for (const id of required) {
		if (seen.has(id) || requirements.length >= MAX_REQUIREMENTS) continue;
		seen.add(id);
		requirements.push({ id });
	}
	for (const id of optional) {
		if (seen.has(id) || requirements.length >= MAX_REQUIREMENTS) continue;
		seen.add(id);
		requirements.push({ id, optional: true });
	}
	return requirements;
}

function expandWildcardPath(pattern: string, platformPath: typeof path.win32 | typeof path.posix): string[] {
	if (!pattern.includes("*")) return [pattern];
	const isWin = platformPath === path.win32;
	const sep = isWin ? "\\" : "/";
	const normalized = pattern.replaceAll(isWin ? "/" : "\\", sep);
	const parts = normalized.split(sep);
	let currentDirs = [normalized.startsWith(sep) ? sep : ""];
	for (const part of parts) {
		if (!part) continue;
		const nextDirs: string[] = [];
		for (const dir of currentDirs) {
			if (part.includes("*")) {
				try {
					const entries = fs.readdirSync(dir, { withFileTypes: true });
					const regex = new RegExp("^" + part.replaceAll(".", "\\.").replaceAll("*", ".*") + "$");
					for (const entry of entries) {
						if ((entry.isDirectory() || entry.isSymbolicLink()) && regex.test(entry.name)) {
							nextDirs.push(platformPath.join(dir, entry.name));
						}
					}
				} catch {}
			} else {
				nextDirs.push(platformPath.join(dir, part));
			}
		}
		currentDirs = nextDirs;
	}
	return currentDirs.length > 0 ? currentDirs : [pattern];
}
export function findRealDarwinJdk(env?: Record<string, string | undefined>): string | null {
	const javaHome = env?.JAVA_HOME ?? process.env.JAVA_HOME;
	if (javaHome) {
		const candidate = path.posix.join(javaHome, "bin", "java");
		try {
			if (path.isAbsolute(candidate) && fs.existsSync(candidate) && !fs.statSync(candidate).isDirectory()) {
				fs.accessSync(candidate, fs.constants.X_OK);
				return candidate;
			}
		} catch {}
	}
	const candidates = [
		"/opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home/bin/java",
		"/opt/homebrew/opt/openjdk*/bin/java",
		"/usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home/bin/java",
		"/usr/local/opt/openjdk*/bin/java",
		"/Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java",
	];
	for (const pattern of candidates) {
		const expanded = expandWildcardPath(pattern, path.posix);
		for (const p of expanded) {
			try {
				if (path.isAbsolute(p) && fs.existsSync(p) && !fs.statSync(p).isDirectory()) {
					fs.accessSync(p, fs.constants.X_OK);
					return p;
				}
			} catch {}
		}
	}
	return null;
}

/** PATH for one descriptor: ambient PATH plus its env- and platform-owned dirs. */
function searchPathFor(
	descriptor: SkillToolDescriptor,
	platform: SkillToolPlatform,
	env: Record<string, string | undefined>,
): string | undefined {
	const extras: string[] = [];
	const envStrings: Record<string, string> = {};
	for (const [key, value] of Object.entries(env)) {
		if (typeof value === "string") envStrings[key] = value;
	}
	const platformPath = platform === "win32" ? path.win32 : path.posix;
	for (const entry of descriptor.envPaths ?? []) {
		const base = env[entry.env];
		if (base) extras.push(platformPath.join(base, entry.suffix ?? ""));
	}
	for (const raw of descriptor.searchPaths?.[platform] ?? []) {
		const expanded = expandTilde(expandEnvVarsDeep(raw, envStrings));
		if (expanded.length === 0 || expanded.includes("${")) continue;
		const expandedDirs = expandWildcardPath(expanded, platformPath);
		for (const d of expandedDirs) {
			extras.push(platformPath.normalize(d));
		}
	}
	const basePath = env.PATH ?? "";
	if (extras.length === 0) return basePath.length > 0 ? basePath : undefined;
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
export function checkToolRequirements(
	requirements: readonly ToolRequirement[],
	deps: RequirementCheckDeps = {},
): RequirementStatus[] {
	const requestedPlatform = deps.platform ?? process.platform;
	const platform: SkillToolPlatform =
		requestedPlatform === "darwin" || requestedPlatform === "win32" ? requestedPlatform : "linux";
	const env = deps.env ?? process.env;
	const which: SkillRequirementWhich = deps.which ?? $which;

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
		const options: WhichOptions = {
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
		if (searchPath !== undefined) options.PATH = searchPath;

		let foundPath = descriptor.probe?.({ env, platform, which, settings: deps.settings }) ?? null;
		if (foundPath === null) {
			for (const binary of descriptor.binaries) {
				const candidate = which(binary, options);
				if (candidate !== null) {
					try {
						if (fs.existsSync(candidate) && fs.statSync(candidate).isDirectory()) {
							continue;
						}
					} catch {}
					foundPath = candidate;
					break;
				}
			}
		}
		if (
			requirement.id === "java" &&
			foundPath === "/usr/bin/java" &&
			(platform === "darwin" || process.platform === "darwin") &&
			(deps.which === undefined || deps.which === $which)
		) {
			foundPath = findRealDarwinJdk(env);
		}
		const secondaryMissing = (descriptor.secondary ?? []).filter(binary => {
			const secDesc = SKILL_TOOL_CATALOG[binary];
			const secOptions: WhichOptions = {
				...options,
				PATH: secDesc ? (searchPathFor(secDesc, platform, env) ?? options.PATH) : options.PATH,
			};
			let res = secDesc?.probe?.() ?? null;
			if (res === null) {
				res = which(binary, secOptions);
			}
			if (res === null) return true;
			if (
				binary === "java" &&
				res === "/usr/bin/java" &&
				(platform === "darwin" || process.platform === "darwin") &&
				(deps.which === undefined || deps.which === $which)
			) {
				return findRealDarwinJdk(env) === null;
			}
			return false;
		});
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
export function missingRequirementNotice(statuses: readonly RequirementStatus[]): string | undefined {
	const missing = statuses.filter(
		status => !status.invalid && (status.foundPath === null || (status.secondaryMissing?.length ?? 0) > 0),
	);
	const required = missing.filter(status => !status.optional);
	if (required.length === 0) return undefined;
	const details = required.map(status => {
		const problem =
			status.foundPath === null
				? `${status.id} not found on PATH`
				: `${status.id} found, but ${status.secondaryMissing?.join(", ")} missing`;
		return status.hint ? `${problem} (install: ${status.hint})` : problem;
	});
	return `[Missing tool dependencies: ${details.join("; ")}. Install them before running this skill's commands.]`;
}
