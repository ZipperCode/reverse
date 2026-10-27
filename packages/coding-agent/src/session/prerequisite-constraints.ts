/**
 * Explicit prerequisite constraints declared by the agent itself.
 *
 * Issue #17: an agent-authored handoff document declared
 * `- Do not repeat \`elf_inspect\` on libc without installing its missing LIEF prerequisite.`
 * and five later `elf_inspect` calls ignored it. This module binds those explicit
 * directives to the tool-call gate:
 *
 * 1. Sources are limited to harness-owned, agent-authored entries on the active branch
 *    after the latest `reset_boundary`: `compaction` entries with `method: "handoff"`, and
 *    the persisted context-notes ("memory") revision. Tool output, user files and
 *    arbitrary workspace markdown are never constraint sources. The module never lists or
 *    probes workspace paths.
 * 2. Provenance is either physical or explicitly logical:
 *    - `handoff_file`: the document linked by the compaction `details` (`savedPath`) and
 *      proven to be that entry's document — the link must resolve (symlinks resolved)
 *      inside the session's canonical artifacts directory, and the file text must equal
 *      the entry summary exactly once only the known file-operations appendix is removed.
 *      Mismatched, truncated or out-of-tree links are ignored, never trusted by timestamp
 *      or name similarity.
 *    - `handoff_compaction` / `context_notes`: logical origins (`handoff://<entryId>`,
 *      `context-notes://<entryId>`) with the physical line inside that entry text. These
 *      are reported as logical, never as a filesystem `file:line`.
 * 3. The directive grammar is bounded: one line that opens with the prohibition verb
 *    (after an optional bullet/emphasis prefix), a gating phrase (`until` / `unless` /
 *    `before` / `without`, or the Chinese equivalents) and a backticked tool name plus a
 *    catalog dependency id that the trusted native-tool table attributes to that tool.
 *    Fenced code, blockquotes, example sections, inline-quoted directives, retractions and
 *    prose that merely mentions the verb are inactive.
 * 4. Readiness is never guessed: the referenced dependency is resolved by the existing
 *    trusted readiness surfaces — the canonical session {@link DependencyGate} for LIEF
 *    and `checkToolRequirements` (skill catalog) for every other catalog dependency. Only
 *    a confirmed missing dependency blocks, and a confirmed miss is re-verified on every
 *    gated call (that call is blocked, so no backend work happens) while a verified ready
 *    dependency is cached briefly — installing the dependency unlocks the very next call.
 *    A transient probe failure is allow-by-default and never becomes a permanent block.
 * 5. A confirmed block is structured (`sourceFile` / `sourceLine` / `setupCommand` /
 *    `sourceKind`) so the caller can attach the record to the tool result instead of
 *    leaving provenance only in prose.
 *
 * Setup commands are derived from catalog ids (`reverse setup reverse <dep>`); text parsed
 * out of a handoff document is never executed.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { isRecord } from "@reverse/utils";
import { SKILL_TOOL_CATALOG } from "../extensibility/skill-tool-catalog";
import { checkToolRequirements } from "../extensibility/skill-requirements";
import {
	computeLiefReadinessFingerprint,
	type LiefRequirementDeps,
	resolveLiefPythonDetailed,
} from "../extensibility/lief-install";
import { getContextNotes } from "./context-notes";
import {
	getSessionDependencyGate,
	type DependencyGateSessionLike,
	type PrerequisiteFailureKind,
} from "./dependency-gate";
import type { CompactionEntry, SessionEntry } from "./session-entries";

/** `details` key the maintenance handoff commit uses to link its physical document. */
export const HANDOFF_DOCUMENT_DETAILS_KEY = "handoffDocumentPath";

/** Bounded source ingestion: never read the world for one tool call. */
const MAX_SOURCE_BYTES = 256 * 1024;
const MAX_SOURCE_LINES = 8000;
const MAX_SOURCE_TEXT_LENGTH = 400;
const MAX_HANDOFF_SOURCES = 3;
const MAX_CONSTRAINTS = 16;
const SOURCE_CACHE_TTL_MS = 15_000;
/** Verified-ready readiness is cached briefly; a confirmed miss is re-verified every call. */
const READINESS_READY_TTL_MS = 60_000;
const READINESS_UNKNOWN_TTL_MS = 5_000;

/**
 * Trusted native-tool → catalog dependency edges.
 *
 * Each value is a catalog id from `SKILL_TOOL_CATALOG`; readiness always comes from the
 * catalog descriptor, never from a parallel model of the toolchain. The table is what
 * keeps an explicit directive from blocking an unrelated tool: a handoff line that pairs
 * `bash` with `lief` produces no constraint because `bash` has no catalog dependency.
 */
const NATIVE_TOOL_CATALOG_DEPENDENCIES: Readonly<Record<string, readonly string[]>> = {
	elf_inspect: ["lief", "sofixer"],
	r2_inspect: ["radare2"],
	ghidra_inspect: ["ghidra", "ghidra-findcrypt"],
	triton_analyze: ["triton"],
	native_recover: ["triton", "tritondse"],
	native_devirtualize: ["mergen", "novmp"],
	vmp_dump: ["vmpdump"],
	frida: ["frida"],
	ida: ["ida"],
	dex_search: ["dexkit"],
	dex_unpack: ["frida-dexdump", "blackdex"],
	instruction_trace: ["qbdi"],
	deobfuscate: ["d810-ng", "msynth", "simplify", "jadx-string-decrypt"],
};

/** Actions that exist to recover from a missing dependency and must stay reachable. */
const RECOVERY_ACTIONS: Readonly<Record<string, true>> = {
	status: true,
	setup: true,
	install: true,
	check: true,
	verify: true,
	doctor: true,
};

export type PrerequisiteConstraintSourceKind = "handoff_file" | "handoff_compaction" | "context_notes";

export interface PrerequisiteConstraintSource {
	kind: PrerequisiteConstraintSourceKind;
	/**
	 * Physical handoff document path (`handoff_file`), or the logical origin
	 * `handoff://<entryId>` / `context-notes://<entryId>` for entry-carried text.
	 */
	file: string;
	entryId?: string;
	text: string;
}

export interface PrerequisiteConstraint {
	toolName: string;
	dependencyId: string;
	setupCommand: string;
	sourceFile: string;
	sourceLine: number;
	sourceText: string;
	sourceKind: PrerequisiteConstraintSourceKind;
	sourceEntryId?: string;
}

export type PrerequisiteDependencyReadiness =
	| { status: "ready"; fingerprint?: string }
	| {
			status: "missing";
			fingerprint?: string;
			detail?: string;
			failureKind?: PrerequisiteFailureKind;
			sourceToolCallId?: string;
			attemptCount?: number;
	  }
	| { status: "unknown"; detail?: string };

export interface PrerequisiteConstraintBlock {
	deterministicFailure: true;
	status: "blocked_prerequisite_constraint";
	toolName: string;
	action: string;
	missingDependency: string;
	setupCommand: string;
	sourceFile: string;
	sourceLine: number;
	sourceText: string;
	sourceKind: PrerequisiteConstraintSourceKind;
	sourceEntryId?: string;
	failureKind?: PrerequisiteFailureKind;
	readinessFingerprint?: string;
	sourceToolCallId?: string;
	attemptCount?: number;
	reason: string;
}

export interface PrerequisiteConstraintHost {
	cwd?: string;
	getSessionId?: () => string | null | undefined;
	getSessionFile?: () => string | null | undefined;
	getArtifactsDir?: () => string | null | undefined;
	sessionManager?: {
		getSessionId?: () => string | null | undefined;
		getBranch?: () => SessionEntry[];
		getArtifactsDir?: () => string | null | undefined;
	};
}

export interface PrerequisiteConstraintGateDeps {
	/** Test seam replacing every readiness probe (never used in production paths). */
	probeDependency?: (
		dependencyId: string,
		context: { toolName: string; toolCallId?: string },
	) => Promise<PrerequisiteDependencyReadiness>;
	/** LIEF environment override shared with `elf_inspect` probes and fingerprinting. */
	liefOptions?: LiefRequirementDeps;
	now?: () => number;
}

function isPrerequisiteGatedTool(toolName: string): boolean {
	return Object.hasOwn(NATIVE_TOOL_CATALOG_DEPENDENCIES, toolName);
}

/** Trusted catalog setup command for a dependency id; never derived from parsed text. */
export function setupCommandForDependency(dependencyId: string): string {
	return `reverse setup reverse ${dependencyId}`;
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&");
}

const aliasPatternCache = new Map<string, readonly RegExp[]>();

function dependencyAliasPatterns(dependencyId: string): readonly RegExp[] {
	const cached = aliasPatternCache.get(dependencyId);
	if (cached) return cached;
	const forms = new Set<string>([dependencyId, dependencyId.replace(/[-_]/g, " ")]);
	if (dependencyId === "triton") {
		forms.add("triton-library");
		forms.add("triton library");
	}
	const patterns = [...forms]
		.filter(form => form.trim().length > 0)
		.map(form => {
			const body = form.split(/\s+/).map(escapeRegExp).join("\\s+");
			return new RegExp(`(?<![A-Za-z0-9_-])${body}(?![A-Za-z0-9_-])`, "i");
		});
	aliasPatternCache.set(dependencyId, patterns);
	return patterns;
}

const INLINE_TOOL_PATTERN = /`([A-Za-z][A-Za-z0-9_.-]{1,63})`/g;
/** A directive starts the line, optionally behind a bullet/checkbox/emphasis prefix. */
const DIRECTIVE_PREFIX_PATTERN = /^(?:[-*+]\s+|\d+[.)]\s+)?(?:\*\*)?/;
const ENGLISH_DIRECTIVE_PATTERN = /^(?:do not|don'?t|must not|never|avoid)\b/i;
const GATING_PHRASE_PATTERN = /\b(?:until|unless|before|without|only\s+after)\b/i;
const CHINESE_PROHIBITION_PATTERN = /(?:不要|不得|禁止|勿|避免|严禁|不可)/;
const CHINESE_GATING_PATTERN = /(?:之前|以前|直到|直至|未安装|尚未|没有安装|未就绪|就绪前)/;
/** A directive quoted inline (``- Do not ...``) is documentation, not a contract. */
const QUOTED_DIRECTIVE_PATTERN = /`[^`\n]{0,4}(?:do\s+not|don'?t|must\s+not|never|不要|不得|禁止)/i;
const RETRACTION_PATTERN =
	/(?:no\s+longer\s+(?:appl(?:y|ies)|required|necessary|active)|not\s+(?:a|an)\s+(?:constraint|prohibition|requirement|restriction)|(?:解除|取消|不再是)[^。\n]{0,8}?(?:约束|禁令|限制)|(?:约束|禁令|限制)[^。\n]{0,6}?(?:已?解除|已?取消|不再生效))/i;
const EXAMPLE_LINE_PATTERN = /^(?:example|e\.g\.|for example|示例|例如|反例)[:：\s]/i;
const HEADING_PATTERN = /^(#{1,6})\s+/;
const EXAMPLE_HEADING_PATTERN = /(?:example|examples|示例|反例|引用|quote|anti-?pattern|错误示范)/i;
const FENCE_PATTERN = /^\s*(?:```|~~~)/;

/**
 * Parse bounded explicit-prerequisite directives out of one trusted handoff document.
 *
 * Inactive by construction: fenced code blocks, blockquote lines, example sections and
 * headings, inline-quoted directives, retractions, and over-long lines.
 */
export function parseHandoffConstraintDirectives(
	source: PrerequisiteConstraintSource,
	options: { maxConstraints?: number } = {},
): PrerequisiteConstraint[] {
	const maxConstraints = options.maxConstraints ?? MAX_CONSTRAINTS;
	const constraints: PrerequisiteConstraint[] = [];
	if (maxConstraints <= 0 || source.text.length === 0) return constraints;

	let inFence = false;
	let exampleHeadingLevel: number | null = null;
	const lines = source.text.split(/\r?\n/);

	for (let index = 0; index < lines.length && index < MAX_SOURCE_LINES; index++) {
		const rawLine = lines[index] ?? "";
		if (FENCE_PATTERN.test(rawLine)) {
			inFence = !inFence;
			continue;
		}
		if (inFence) continue;

		const headingMatch = HEADING_PATTERN.exec(rawLine);
		if (headingMatch) {
			const level = headingMatch[1]?.length ?? 0;
			if (EXAMPLE_HEADING_PATTERN.test(rawLine)) {
				exampleHeadingLevel = level;
			} else if (exampleHeadingLevel !== null && level <= exampleHeadingLevel) {
				exampleHeadingLevel = null;
			}
			continue;
		}
		if (exampleHeadingLevel !== null) continue;

		const trimmed = rawLine.trim();
		if (trimmed.length === 0 || trimmed.startsWith(">")) continue;
		if (trimmed.length > MAX_SOURCE_TEXT_LENGTH) continue;
		if (EXAMPLE_LINE_PATTERN.test(trimmed)) continue;
		if (QUOTED_DIRECTIVE_PATTERN.test(trimmed)) continue;
		if (RETRACTION_PATTERN.test(trimmed)) continue;

		// English directives must open the line (after an optional bullet/emphasis prefix), so
		// prose that merely mentions the verb, or a quoted sample, never becomes a contract.
		const english =
			ENGLISH_DIRECTIVE_PATTERN.test(trimmed.replace(DIRECTIVE_PREFIX_PATTERN, "")) &&
			GATING_PHRASE_PATTERN.test(trimmed);
		const chinese = CHINESE_PROHIBITION_PATTERN.test(trimmed) && CHINESE_GATING_PATTERN.test(trimmed);
		if (!english && !chinese) continue;

		const toolName = findGatedToolToken(trimmed);
		if (!toolName) continue;
		const dependencyIds = NATIVE_TOOL_CATALOG_DEPENDENCIES[toolName] ?? [];
		const dependencyId = findDependencyMention(trimmed, dependencyIds);
		if (!dependencyId) continue;

		constraints.push({
			toolName,
			dependencyId,
			setupCommand: setupCommandForDependency(dependencyId),
			sourceFile: source.file,
			sourceLine: index + 1,
			sourceText: trimmed,
			sourceKind: source.kind,
			sourceEntryId: source.entryId,
		});
		if (constraints.length >= maxConstraints) break;
	}
	return constraints;
}

function findGatedToolToken(line: string): string | undefined {
	INLINE_TOOL_PATTERN.lastIndex = 0;
	for (let match = INLINE_TOOL_PATTERN.exec(line); match; match = INLINE_TOOL_PATTERN.exec(line)) {
		const candidate = match[1]?.toLowerCase().replace(/\(\)$/, "");
		if (candidate && isPrerequisiteGatedTool(candidate)) return candidate;
	}
	return undefined;
}

function findDependencyMention(line: string, dependencyIds: readonly string[]): string | undefined {
	// Longest id first so `frida-dexdump` wins over `frida` when both could match.
	const ordered = [...dependencyIds].sort((a, b) => b.length - a.length);
	for (const dependencyId of ordered) {
		if (!Object.hasOwn(SKILL_TOOL_CATALOG, dependencyId)) continue;
		for (const pattern of dependencyAliasPatterns(dependencyId)) {
			if (pattern.test(line)) return dependencyId;
		}
	}
	return undefined;
}

function isHandoffCompactionEntry(entry: SessionEntry): entry is CompactionEntry {
	return entry.type === "compaction" && (entry as CompactionEntry).method === "handoff";
}

function handoffEntryDetails(entry: CompactionEntry): Record<string, unknown> | undefined {
	return isRecord(entry.details) ? entry.details : undefined;
}

function statRegularFile(file: string): { size: number } | undefined {
	try {
		const stat = fs.statSync(file);
		return stat.isFile() ? { size: stat.size } : undefined;
	} catch {
		return undefined;
	}
}

function readBoundedSourceText(file: string): string | undefined {
	const stat = statRegularFile(file);
	if (!stat || stat.size > MAX_SOURCE_BYTES) return undefined;
	try {
		return fs.readFileSync(file, "utf8");
	} catch {
		return undefined;
	}
}

const FILE_OPERATIONS_TAG_PATTERN =
	/<files>[\s\S]*?<\/files>|<read-files>[\s\S]*?<\/read-files>|<modified-files>[\s\S]*?<\/modified-files>/g;

/**
 * Ownership proof for a linked handoff document: the summary the entry committed is the
 * document plus an appended file-operations tag, so the two texts must be exactly equal
 * once only that known appendix (and trailing newline) is removed. Prefix containment is
 * deliberately not accepted — a truncated or unrelated document must not borrow the
 * entry's provenance. Path names, timestamps and mtimes are never treated as proof, and
 * parsed `sourceLine` values always come from the raw text split on its own newlines.
 */
function handoffDocumentMatchesSummary(fileText: string, summary: string): boolean {
	const stripKnownAppendix = (text: string) => text.replace(FILE_OPERATIONS_TAG_PATTERN, "").trimEnd();
	const document = stripKnownAppendix(fileText);
	return document.length > 0 && document === stripKnownAppendix(summary);
}

/**
 * Resolve a linked document to its real path and require it to live inside the real
 * artifacts directory. `realpathSync` runs on both sides so a symlink cannot smuggle an
 * outside file into provenance; anything non-regular or unresolvable is rejected.
 */
function resolveDocumentInsideArtifactsDir(file: string, artifactsDir: string): string | undefined {
	try {
		const realDir = fs.realpathSync(artifactsDir);
		const realFile = fs.realpathSync(file);
		const relative = path.relative(realDir, realFile);
		if (relative.length === 0 || relative.startsWith("..") || path.isAbsolute(relative)) return undefined;
		return fs.statSync(realFile).isFile() ? realFile : undefined;
	} catch {
		return undefined;
	}
}

export class PrerequisiteConstraintGate {
	readonly #host: PrerequisiteConstraintHost;
	readonly #deps: PrerequisiteConstraintGateDeps;
	readonly #now: () => number;
	#sourceCache?: { signature: string; at: number; constraints: PrerequisiteConstraint[] };
	readonly #readinessCache = new Map<
		string,
		{ readiness: PrerequisiteDependencyReadiness; at: number; ttl: number }
	>();
	readonly #readinessInFlight = new Map<string, Promise<PrerequisiteDependencyReadiness>>();

	constructor(host: PrerequisiteConstraintHost, deps: PrerequisiteConstraintGateDeps = {}) {
		this.#host = host;
		this.#deps = deps;
		this.#now = deps.now ?? Date.now;
	}

	/** Active constraints parsed from trusted agent-authored sources, newest first. */
	listConstraints(): PrerequisiteConstraint[] {
		const branch = this.#host.sessionManager?.getBranch?.() ?? [];
		// A `/clear` boundary ends the transcript the agent can still see, so pre-reset handoff
		// directives stop being contracts exactly like the context notes they sit next to.
		let scopeStart = 0;
		for (let index = branch.length - 1; index >= 0; index--) {
			if (branch[index]?.type === "reset_boundary") {
				scopeStart = index + 1;
				break;
			}
		}
		const activeBranch = scopeStart === 0 ? branch : branch.slice(scopeStart);
		const entries = activeBranch.filter(isHandoffCompactionEntry).slice(-MAX_HANDOFF_SOURCES);
		const notes = getContextNotes(branch);
		const signature = [
			activeBranch.length,
			activeBranch[activeBranch.length - 1]?.id ?? "",
			notes?.entryId ?? "",
			...entries.map(entry => `${entry.id}@${entry.timestamp}`),
		].join("|");
		const now = this.#now();
		const cached = this.#sourceCache;
		if (cached && cached.signature === signature && now - cached.at < SOURCE_CACHE_TTL_MS) {
			return cached.constraints;
		}

		const artifactsDir = this.#artifactsDir();
		const constraints: PrerequisiteConstraint[] = [];
		const seen = new Set<string>();
		const absorb = (source: PrerequisiteConstraintSource, entryId: string) => {
			for (const constraint of parseHandoffConstraintDirectives(source, {
				maxConstraints: MAX_CONSTRAINTS - constraints.length,
			})) {
				const key = `${constraint.toolName}|${constraint.dependencyId}`;
				if (seen.has(key)) continue;
				seen.add(key);
				constraints.push({ ...constraint, sourceEntryId: constraint.sourceEntryId ?? entryId });
				if (constraints.length >= MAX_CONSTRAINTS) return;
			}
		};

		for (let index = entries.length - 1; index >= 0 && constraints.length < MAX_CONSTRAINTS; index--) {
			const entry = entries[index];
			if (!entry) continue;
			const source = this.#resolveHandoffSource(entry, artifactsDir);
			if (!source) continue;
			absorb(source, entry.id);
		}
		// The agent's persisted context notes are the other agent-authored memory surface.
		if (notes && notes.text.length > 0 && constraints.length < MAX_CONSTRAINTS) {
			absorb(
				{
					kind: "context_notes",
					file: `context-notes://${notes.entryId}`,
					entryId: notes.entryId,
					text: notes.text,
				},
				notes.entryId,
			);
		}

		this.#sourceCache = { signature, at: now, constraints };
		return constraints;
	}

	/**
	 * Gate one attempted tool call. Returns a structured block only when a trusted handoff
	 * directive forbids that exact tool and its catalog dependency is confirmed missing.
	 */
	async check(options: {
		toolName: string;
		args?: Record<string, unknown>;
		toolCallId?: string;
	}): Promise<PrerequisiteConstraintBlock | undefined> {
		const toolName = options.toolName;
		if (!isPrerequisiteGatedTool(toolName)) return undefined;

		const rawAction = options.args?.action;
		const action = typeof rawAction === "string" ? rawAction.toLowerCase() : undefined;
		// Recovery surfaces stay reachable, otherwise the constraint could never be lifted.
		if (action !== undefined && RECOVERY_ACTIONS[action] === true) return undefined;

		const constraints = this.listConstraints().filter(constraint => constraint.toolName === toolName);
		if (constraints.length === 0) return undefined;

		for (const constraint of constraints) {
			const readiness = await this.#resolveReadiness(constraint.dependencyId, {
				toolName,
				toolCallId: options.toolCallId,
			});
			// Anything short of a confirmed missing dependency keeps the call dispatchable.
			if (readiness.status !== "missing") continue;
			return buildConstraintBlock(constraint, action ?? "execute", readiness);
		}
		return undefined;
	}

	#artifactsDir(): string | null {
		const fromHost = this.#host.getArtifactsDir?.() ?? this.#host.sessionManager?.getArtifactsDir?.();
		return typeof fromHost === "string" && fromHost.length > 0 ? fromHost : null;
	}

	#resolveHandoffSource(
		entry: CompactionEntry,
		artifactsDir: string | null,
	): PrerequisiteConstraintSource | undefined {
		const summary = typeof entry.summary === "string" ? entry.summary : "";
		const linked = this.#resolveLinkedDocument(entry, artifactsDir);
		if (linked) {
			const text = readBoundedSourceText(linked);
			// Physical `file:line` provenance requires the entry's actual committed summary to
			// match the file exactly; no summary means no proof.
			if (text !== undefined && handoffDocumentMatchesSummary(text, summary)) {
				return { kind: "handoff_file", file: linked, entryId: entry.id, text };
			}
		}
		if (summary.trim().length === 0) return undefined;
		return {
			kind: "handoff_compaction",
			file: `handoff://${entry.id}`,
			entryId: entry.id,
			text: summary,
		};
	}

	/**
	 * Resolve the document a compaction entry links through `details` (`savedPath`). The
	 * link must resolve (symlinks included) inside the session's canonical artifacts
	 * directory, and the caller additionally proves the file content is that entry's
	 * document.
	 */
	#resolveLinkedDocument(entry: CompactionEntry, artifactsDir: string | null): string | undefined {
		const details = handoffEntryDetails(entry);
		if (!details || !artifactsDir) return undefined;
		const value = details[HANDOFF_DOCUMENT_DETAILS_KEY];
		if (typeof value !== "string" || value.trim().length === 0) return undefined;
		return resolveDocumentInsideArtifactsDir(path.resolve(artifactsDir, value), artifactsDir);
	}

	async #resolveReadiness(
		dependencyId: string,
		context: { toolName: string; toolCallId?: string },
	): Promise<PrerequisiteDependencyReadiness> {
		const now = this.#now();
		const cached = this.#readinessCache.get(dependencyId);
		if (cached && now - cached.at < cached.ttl) return cached.readiness;

		const inFlight = this.#readinessInFlight.get(dependencyId);
		if (inFlight) return inFlight;

		const promise = this.#probeReadiness(dependencyId, context)
			.then(readiness => {
				// A confirmed miss is never cached: the blocked call performs no backend work,
				// so re-verifying it keeps an install effective on the very next call.
				const ttl =
					readiness.status === "ready"
						? READINESS_READY_TTL_MS
						: readiness.status === "unknown"
							? READINESS_UNKNOWN_TTL_MS
							: 0;
				if (ttl > 0) this.#readinessCache.set(dependencyId, { readiness, at: this.#now(), ttl });
				return readiness;
			})
			.catch((error: unknown) => {
				// A probe that cannot run is an environment problem, never a missing dependency.
				const unknown: PrerequisiteDependencyReadiness = {
					status: "unknown",
					detail: error instanceof Error ? error.message : String(error),
				};
				this.#readinessCache.set(dependencyId, {
					readiness: unknown,
					at: this.#now(),
					ttl: READINESS_UNKNOWN_TTL_MS,
				});
				return unknown;
			})
			.finally(() => {
				this.#readinessInFlight.delete(dependencyId);
			});
		this.#readinessInFlight.set(dependencyId, promise);
		return promise;
	}

	async #probeReadiness(
		dependencyId: string,
		context: { toolName: string; toolCallId?: string },
	): Promise<PrerequisiteDependencyReadiness> {
		if (this.#deps.probeDependency) {
			return await this.#deps.probeDependency(dependencyId, context);
		}
		if (dependencyId === "lief") return await this.#probeLiefReadiness(context);
		return this.#probeCatalogReadiness(dependencyId);
	}

	async #probeLiefReadiness(context: {
		toolName: string;
		toolCallId?: string;
	}): Promise<PrerequisiteDependencyReadiness> {
		const liefOptions: LiefRequirementDeps = { cwd: this.#host.cwd, ...this.#deps.liefOptions };
		const gate = getSessionDependencyGate(this.#host as DependencyGateSessionLike);
		const getFingerprint = () => computeLiefReadinessFingerprint(liefOptions);

		// A recorded deterministic block from this session is already the canonical answer.
		const known = gate.blockIfKnown({
			toolName: "prerequisite_constraint",
			action: "query",
			missingDependency: "lief",
			getReadinessFingerprint: getFingerprint,
		});
		if (known) {
			return {
				status: "missing",
				fingerprint: known.readinessFingerprint,
				detail: known.reason,
				failureKind: known.failureKind,
				sourceToolCallId: known.sourceToolCallId,
				attemptCount: known.attemptCount,
			};
		}

		const outcome = await gate.acquireOrProbe<{ available: true }>({
			toolName: context.toolName,
			action: "constraint_check",
			missingDependency: "lief",
			setupCommand: setupCommandForDependency("lief"),
			toolCallId: context.toolCallId ?? `prerequisite-constraint:${context.toolName}`,
			getReadinessFingerprint: getFingerprint,
			runProbe: async () => {
				const detailed = resolveLiefPythonDetailed(liefOptions);
				if (detailed.status === "available") {
					return {
						status: "available",
						value: { available: true as const },
						fingerprint: detailed.readinessFingerprint,
					};
				}
				if (detailed.status === "probe_failed") {
					return {
						status: "probe_failed",
						error: detailed.error ?? "LIEF subprocess probe failed",
						fingerprint: detailed.readinessFingerprint,
					};
				}
				return {
					status: "deterministic_missing",
					failureKind: detailed.status === "missing_interpreter" ? "missing_interpreter" : "missing_module",
					reason: "LIEF Python library is not available.",
					fingerprint: detailed.readinessFingerprint,
				};
			},
		});

		if (outcome.status === "available") {
			return { status: "ready", fingerprint: getFingerprint() };
		}
		if (outcome.status === "probe_failed") {
			return { status: "unknown", detail: outcome.error };
		}
		return {
			status: "missing",
			fingerprint: outcome.block.readinessFingerprint,
			detail: outcome.block.reason,
			failureKind: outcome.block.failureKind,
			sourceToolCallId: outcome.block.sourceToolCallId,
			attemptCount: outcome.block.attemptCount,
		};
	}

	#probeCatalogReadiness(dependencyId: string): PrerequisiteDependencyReadiness {
		if (!Object.hasOwn(SKILL_TOOL_CATALOG, dependencyId)) {
			return { status: "unknown", detail: `No trusted catalog descriptor for '${dependencyId}'.` };
		}
		const env = process.env;
		const fingerprint = [
			dependencyId,
			process.platform,
			env.PATH ?? "",
			env.TRITON_PYTHON ?? "",
			env.VIRTUAL_ENV ?? "",
			env.CONDA_PREFIX ?? "",
		].join("|");
		const [status] = checkToolRequirements([{ id: dependencyId }], { cwd: this.#host.cwd });
		if (!status || status.invalid) {
			return { status: "unknown", detail: `Dependency '${dependencyId}' could not be probed.` };
		}
		// Adapter errors describe an execution problem, not a confirmed absence: allow the call.
		if (status.adapterError) {
			return { status: "unknown", detail: status.adapterError };
		}
		const missingCompanions = status.secondaryMissing ?? [];
		if (status.foundPath === null || missingCompanions.length > 0) {
			return {
				status: "missing",
				fingerprint,
				detail:
					status.foundPath === null
						? `'${dependencyId}' was not found.`
						: `'${dependencyId}' is present but ${missingCompanions.join(", ")} is missing.`,
			};
		}
		return { status: "ready", fingerprint };
	}
}

function buildConstraintBlock(
	constraint: PrerequisiteConstraint,
	action: string,
	readiness: Extract<PrerequisiteDependencyReadiness, { status: "missing" }>,
): PrerequisiteConstraintBlock {
	const reason = `'${constraint.toolName}' is blocked by an explicit handoff constraint at ${constraint.sourceFile}:${constraint.sourceLine} ("${constraint.sourceText}"). '${constraint.dependencyId}' is not installed: run '${constraint.setupCommand}'. The constraint lifts automatically once '${constraint.dependencyId}' is verified ready.`;
	return {
		deterministicFailure: true,
		status: "blocked_prerequisite_constraint",
		toolName: constraint.toolName,
		action,
		missingDependency: constraint.dependencyId,
		setupCommand: constraint.setupCommand,
		sourceFile: constraint.sourceFile,
		sourceLine: constraint.sourceLine,
		sourceText: constraint.sourceText,
		sourceKind: constraint.sourceKind,
		sourceEntryId: constraint.sourceEntryId,
		failureKind: readiness.failureKind,
		readinessFingerprint: readiness.fingerprint,
		sourceToolCallId: readiness.sourceToolCallId,
		attemptCount: readiness.attemptCount,
		reason,
	};
}

interface ScopedPrerequisiteConstraintGateEntry {
	sessionId?: string | null;
	sessionFile?: string | null;
	gate: PrerequisiteConstraintGate;
}

const sessionConstraintGates = new WeakMap<object, ScopedPrerequisiteConstraintGateEntry>();

/**
 * Retrieve or create the canonical session-scoped constraint gate.
 *
 * Keyed by `host.sessionManager ?? host` so the central agent-session preflight, direct
 * tool calls, `write xd://<tool>` bridges and `eval` share one gate; a session switch
 * (`sessionId` / `sessionFile` change) isolates state exactly like {@link DependencyGate}.
 * `deps` (test seams, LIEF environment) apply when the gate is created; a live gate is
 * returned as-is so every caller keeps identical readiness state.
 */
export function getSessionPrerequisiteConstraintGate(
	host: PrerequisiteConstraintHost,
	deps?: PrerequisiteConstraintGateDeps,
): PrerequisiteConstraintGate {
	const keyObj: object = host.sessionManager && typeof host.sessionManager === "object" ? host.sessionManager : host;
	const currentId = host.sessionManager?.getSessionId?.() ?? host.getSessionId?.() ?? null;
	const currentFile = host.getSessionFile?.() ?? null;

	const existing = sessionConstraintGates.get(keyObj);
	if (existing && existing.sessionId === currentId && existing.sessionFile === currentFile) {
		return existing.gate;
	}

	const gate = new PrerequisiteConstraintGate(host, deps ?? {});
	sessionConstraintGates.set(keyObj, { sessionId: currentId, sessionFile: currentFile, gate });
	return gate;
}
