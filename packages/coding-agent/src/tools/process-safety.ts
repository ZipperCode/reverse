/**
 * Process termination safety guard.
 *
 * Enforces an always-on guard against broad, global executable-name process termination
 * (e.g. `taskkill /IM`, `killall`, `pkill`, `Get-Process | Stop-Process`, `Stop-Process -Name`).
 *
 * Prevents collateral damage to host, IDE, or unrelated worker processes (e.g. killing all Java/Node instances).
 * Preserves inert text, quoted docs, and legitimate process listing (`ps`, `pgrep`, `tasklist`, read-only `Get-Process`).
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { extractFlatShellCommandSegments, readShellWord } from "./shell-tokenize";
import { ReverseWorkflowStore } from "../reverse-workflow/store";

export interface ProcessSafetyViolation {
	blocked: true;
	command: string;
	matchedPattern: string;
	reason: string;
	guidance: string;
	unexecuted: true;
	matchedProtected?: string[];
}

export interface ProcessSafetyAllowed {
	blocked: false;
}

export type ProcessSafetyCheckResult = ProcessSafetyViolation | ProcessSafetyAllowed;

export const MANAGED_CANCELLATION_GUIDANCE =
	"Global process termination by executable name is prohibited because it terminates all matching processes " +
	"system-wide without verifying task ownership. PID arguments alone without session tracking do not establish " +
	"ownership. To terminate processes safely, use session-managed job or service cancellation (such as " +
	"`proc://<id>/kill` or cancellation handles for jobs started by this agent).";

export const WORKSPACE_CLEAN_GUIDANCE =
	"Direct recursive shell deletion of reverse-engineering workspace directories or tracked protected " +
	"artifacts (such as verified baselines, evidence, rollback archives, or user scripts) is prohibited. " +
	"Use the 'reverse_workspace' tool with action 'clean' to safely classify and clean experimental artifacts " +
	"while preserving core reproducibility materials.";

/**
 * Tokenizes a shell argument string into words while stripping outer quotes.
 */
function parseShellWords(text: string): string[] {
	const words: string[] = [];
	let remaining = text.trim();
	while (remaining.length > 0) {
		const res = readShellWord(remaining);
		if (!res || res === "unterminated") {
			const match = remaining.match(/^([^\s]+)(.*)$/s);
			if (match) {
				words.push(match[1]);
				remaining = match[2].trim();
			} else {
				break;
			}
		} else {
			words.push(res.value);
			remaining = res.rest.trim();
		}
	}
	return words;
}
/**
 * Strips leading execution wrappers (sudo, env, nohup, exec, etc.) without altering command arguments.
 */
function stripExecutionPrefixes(cmd: string): string {
	let trimmed = cmd.trim();
	while (true) {
		const next = trimmed
			.replace(/^(?:sudo|nohup|exec|command|builtin)\s+/i, "")
			.replace(/^env(?:\s+-[a-zA-Z0-9]+|\s+[A-Za-z_][A-Za-z0-9_]*=[^\s]*)*\s+/i, "");
		if (next === trimmed) break;
		trimmed = next.trim();
	}
	return trimmed;
}

/**
 * Extracts the first shell word (argv[0]) and the rest of the command string.
 */
function extractCommandWord(text: string): { cmdWord: string; rest: string } {
	const stripped = stripExecutionPrefixes(text);
	const wordResult = readShellWord(stripped);
	if (wordResult && wordResult !== "unterminated") {
		return { cmdWord: wordResult.value, rest: wordResult.rest };
	}
	const match = stripped.match(/^([^\s]+)(.*)$/s);
	return { cmdWord: match ? match[1] : "", rest: match ? match[2] : "" };
}

/**
 * Extracts the canonical base command name, handling Windows/POSIX absolute paths and backslashes.
 */
function resolveBaseCommand(cmdWord: string): string {
	const match = cmdWord.match(
		/(?:^|[/\\]|(?<=[a-z0-9]))(powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|bash(?:\.exe)?|sh(?:\.exe)?|zsh(?:\.exe)?|dash(?:\.exe)?|ksh(?:\.exe)?|taskkill(?:\.exe)?|killall(?:\.exe)?|pkill(?:\.exe)?|stop-process|spps|rm|rmdir|rd|remove-item|ri|del|erase)$/i,
	);
	if (match) return match[1].toLowerCase();
	return cmdWord
		.replace(/^[a-zA-Z]:[/\\]/, "")
		.replace(/^.*[/\\]/, "")
		.toLowerCase();
}

/**
 * Detects if a command wraps another shell invocation (e.g. `bash -c "..."`, `powershell -Command "..."`, `cmd /c "..."`).
 * Parses flags and handles absolute Windows/POSIX executable paths.
 */
function extractWrappedShellCommand(cmdWord: string, rest: string): string | null {
	const baseCmd = resolveBaseCommand(cmdWord);
	const words = parseShellWords(rest);

	if (baseCmd === "powershell" || baseCmd === "powershell.exe" || baseCmd === "pwsh" || baseCmd === "pwsh.exe") {
		for (let i = 0; i < words.length; i++) {
			const w = words[i].toLowerCase();
			if ((w === "-c" || w === "-command" || w === "/c" || w === "/command") && i + 1 < words.length) {
				return words.slice(i + 1).join(" ");
			}
		}
	}

	if (baseCmd === "cmd" || baseCmd === "cmd.exe") {
		for (let i = 0; i < words.length; i++) {
			const w = words[i].toLowerCase();
			if ((w === "/c" || w === "-c") && i + 1 < words.length) {
				return words.slice(i + 1).join(" ");
			}
		}
	}

	if (["bash", "sh", "zsh", "dash", "ksh"].includes(baseCmd)) {
		for (let i = 0; i < words.length; i++) {
			const w = words[i];
			if ((w === "-c" || w === "--command" || /^-[a-zA-Z]*c[a-zA-Z]*/.test(w)) && i + 1 < words.length) {
				return words.slice(i + 1).join(" ");
			}
		}
	}

	return null;
}

/**
 * Returns true if a string is a valid filesystem path rather than an internal/external URI scheme.
 */
function isFsPath(candidate?: string): candidate is string {
	if (!candidate || typeof candidate !== "string") return false;
	const trimmed = candidate.trim();
	if (trimmed.length === 0) return false;
	if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) return false;
	return true;
}

/**
 * Collects all known protected workflow and workspace artifact paths for a project.
 */
export async function collectProtectedWorkflowPaths(projectDir: string): Promise<string[]> {
	const protectedPaths = new Set<string>();

	const wsDir = path.resolve(projectDir, ".reverse");
	const reaDir = path.resolve(projectDir, ".rea");
	protectedPaths.add(wsDir);
	protectedPaths.add(reaDir);
	protectedPaths.add(path.resolve(projectDir, "patch_artifacts"));

	// 1. Read workspace manifest if present
	try {
		const manifestFile = path.join(wsDir, "manifest.json");
		const manifestText = await fs.readFile(manifestFile, "utf8");
		const manifest = JSON.parse(manifestText);
		if (manifest && typeof manifest === "object") {
			if (isFsPath(manifest.target?.path)) {
				protectedPaths.add(path.resolve(projectDir, manifest.target.path));
			}
			if (Array.isArray(manifest.artifacts)) {
				for (const art of manifest.artifacts) {
					const isProtected =
						art.protected === true ||
						(art.classification && art.classification !== "experiment") ||
						(!art.classification && art.kind === "script");
					if (isProtected) {
						if (isFsPath(art.source_path)) protectedPaths.add(path.resolve(projectDir, art.source_path));
						if (isFsPath(art.destination_path)) protectedPaths.add(path.resolve(wsDir, art.destination_path));
					}
				}
			}
		}
	} catch (err: unknown) {
		const isNotFound = err && typeof err === "object" && "code" in err && err.code === "ENOENT";
		if (!isNotFound) {
			throw new Error(
				`Cannot verify process safety: workspace manifest at '${wsDir}' is corrupted: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}

	// 2. Read stored workflows from ReverseWorkflowStore
	try {
		const store = ReverseWorkflowStore.forSession(projectDir);
		const workflows = await store.list({ readOnly: true });
		for (const wf of workflows) {
			if (isFsPath(wf.target)) {
				protectedPaths.add(path.resolve(projectDir, wf.target));
			}
			if (isFsPath(wf.target_abs_path)) {
				protectedPaths.add(path.resolve(wf.target_abs_path));
			}
			// Build lineage: verified baselines and outputs (#14 exact protection)
			if (Array.isArray(wf.build_lineage)) {
				for (const b of wf.build_lineage) {
					if (isFsPath(b.target_path)) {
						protectedPaths.add(path.resolve(projectDir, b.target_path));
					}
				}
			}
			if (Array.isArray(wf.steps)) {
				for (const s of wf.steps) {
					if (Array.isArray(s.artifact_refs)) {
						for (const ref of s.artifact_refs) {
							if (isFsPath(ref)) {
								protectedPaths.add(path.resolve(projectDir, ref));
							}
						}
					}
				}
			}
		}
	} catch (err: unknown) {
		const isNotFound = err && typeof err === "object" && "code" in err && err.code === "ENOENT";
		if (!isNotFound) {
			throw new Error(
				`Cannot verify process safety: workflow store at '${projectDir}' is unreadable: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}

	return Array.from(protectedPaths);
}

function findProtectedDescendants(resolvedTarget: string, protectedPaths: readonly string[]): string[] {
	const matches: string[] = [];
	for (const p of protectedPaths) {
		const resolvedP = path.resolve(p);
		if (
			resolvedP === resolvedTarget ||
			resolvedP.startsWith(resolvedTarget + path.sep) ||
			resolvedTarget.startsWith(resolvedP + path.sep)
		) {
			matches.push(p);
		}
	}
	return matches;
}

/**
 * Intercepts direct shell deletion of reverse workspace directory or tracked artifact paths.
 * Protects against both recursive deletion of directories and single-file deletion of protected artifacts.
 */
function checkWorkspaceDeletionSegment(
	baseCmd: string,
	words: string[],
	fullText: string,
	protectedPaths: readonly string[],
	cwd: string,
): ProcessSafetyCheckResult {
	const isRm = baseCmd === "rm";
	const isRmdir = baseCmd === "rmdir" || baseCmd === "rd";
	const isPowerShellRm = baseCmd === "remove-item" || baseCmd === "ri";
	const isDel = baseCmd === "del" || baseCmd === "erase";

	if (!isRm && !isRmdir && !isPowerShellRm && !isDel) return { blocked: false };

	const isRecursive = words.some(
		w =>
			(isRm && /^-[a-zA-Z]*[rR]/.test(w)) ||
			(isRm && w === "--recursive") ||
			(isRmdir && (w.toLowerCase() === "/s" || w.toLowerCase() === "-s")) ||
			(isPowerShellRm && (w.toLowerCase() === "-r" || w.toLowerCase() === "-recurse")) ||
			(isDel && w.toLowerCase() === "/s"),
	);

	let targets: string[] = [];
	if (isRm || isPowerShellRm) {
		// In POSIX rm and PowerShell, options start with '-', targets can start with '/' (absolute paths)
		targets = words.slice(1).filter(w => !w.startsWith("-"));
	} else if (isRmdir || isDel) {
		targets = words.slice(1).filter(w => !/^[/-][a-zA-Z]$/.test(w));
	}

	for (const t of targets) {
		const resolvedTarget = path.resolve(cwd, t);
		if (isRecursive) {
			const matches = findProtectedDescendants(resolvedTarget, protectedPaths);
			if (matches.length > 0) {
				return {
					blocked: true,
					command: fullText,
					matchedPattern: `recursive delete '${t}'`,
					matchedProtected: matches,
					reason: `Direct recursive shell deletion of '${t}' containing protected reverse-engineering artifacts is prohibited.`,
					guidance: WORKSPACE_CLEAN_GUIDANCE,
					unexecuted: true,
				};
			}
		} else {
			const isExactMatch = protectedPaths.some(p => path.resolve(p) === resolvedTarget);
			if (isExactMatch) {
				return {
					blocked: true,
					command: fullText,
					matchedPattern: `delete '${t}'`,
					matchedProtected: [resolvedTarget],
					reason: `Direct shell deletion of protected reverse-engineering artifact '${t}' is prohibited.`,
					guidance: WORKSPACE_CLEAN_GUIDANCE,
					unexecuted: true,
				};
			}
		}
	}

	return { blocked: false };
}

/**
 * Checks a single flat shell command segment for prohibited global name kills or protected deletions.
 */
async function checkSegmentSafety(
	seg: { text: string; pipedStdin: boolean },
	depth: number,
	resolveProtectedPaths: () => Promise<readonly string[]>,
	cwd: string,
): Promise<ProcessSafetyCheckResult> {
	const { cmdWord, rest } = extractCommandWord(seg.text);
	const baseCmd = resolveBaseCommand(cmdWord);
	const words = parseShellWords(rest);

	// 1. Check wrapped shell command (bounded recursion, splitting on pipes/chains via checkProcessTerminationSafety)
	if (depth < 3) {
		const inner = extractWrappedShellCommand(cmdWord, rest);
		if (inner) {
			const innerRes = await checkProcessTerminationSafety(
				inner,
				undefined,
				depth + 1,
				undefined,
				cwd,
				await resolveProtectedPaths(),
			);
			if (innerRes.blocked) {
				return innerRes;
			}
		}
	}

	// 2. Namekill patterns: fast in-memory checks, ZERO store IO!
	// 2a. taskkill: image-name termination (/IM or -im or /im:)
	if (baseCmd === "taskkill" || baseCmd === "taskkill.exe") {
		const hasImSwitch = words.some(w => {
			const lw = w.toLowerCase();
			return lw === "/im" || lw === "-im" || lw.startsWith("/im:") || lw.startsWith("-im:");
		});
		if (hasImSwitch) {
			return {
				blocked: true,
				command: seg.text,
				matchedPattern: "taskkill /IM",
				reason: "Global executable-name process termination with 'taskkill /IM' is prohibited.",
				guidance: MANAGED_CANCELLATION_GUIDANCE,
				unexecuted: true,
			};
		}
	}

	// 2b. killall: terminates all instances of a process by name
	if (baseCmd === "killall" || baseCmd === "killall.exe") {
		return {
			blocked: true,
			command: seg.text,
			matchedPattern: "killall",
			reason: "Global executable-name process termination with 'killall' is prohibited.",
			guidance: MANAGED_CANCELLATION_GUIDANCE,
			unexecuted: true,
		};
	}

	// 2c. pkill: unconditionally prohibited (no signal 0 bypass)
	if (baseCmd === "pkill" || baseCmd === "pkill.exe") {
		return {
			blocked: true,
			command: seg.text,
			matchedPattern: "pkill",
			reason: "Global process-name termination with 'pkill' is prohibited.",
			guidance: MANAGED_CANCELLATION_GUIDANCE,
			unexecuted: true,
		};
	}

	// 2d. PowerShell Stop-Process / spps
	if (baseCmd === "stop-process" || baseCmd === "spps") {
		const hasNameSwitch = words.some(w => {
			const lw = w.toLowerCase();
			return lw === "-name" || lw === "-processname" || lw.startsWith("-name:") || lw.startsWith("-processname:");
		});
		if (hasNameSwitch) {
			return {
				blocked: true,
				command: seg.text,
				matchedPattern: "Stop-Process -Name",
				reason: "Global process termination with 'Stop-Process -Name' is prohibited.",
				guidance: MANAGED_CANCELLATION_GUIDANCE,
				unexecuted: true,
			};
		}
		if (seg.pipedStdin) {
			return {
				blocked: true,
				command: seg.text,
				matchedPattern: "Get-Process | Stop-Process",
				reason: "Piping processes into Stop-Process without verified task ownership is prohibited.",
				guidance: MANAGED_CANCELLATION_GUIDANCE,
				unexecuted: true,
			};
		}
		const nonFlagTokens = words.filter(t => !t.startsWith("-"));
		if (nonFlagTokens.length > 0 && !/^\d+$/.test(nonFlagTokens[0])) {
			return {
				blocked: true,
				command: seg.text,
				matchedPattern: "Stop-Process <name>",
				reason: "Process termination by process name with 'Stop-Process' is prohibited.",
				guidance: MANAGED_CANCELLATION_GUIDANCE,
				unexecuted: true,
			};
		}
	}

	// 3. Direct shell deletion guard (lazily loads protected paths only for destructive commands)
	const isDeletionCmd =
		baseCmd === "rm" ||
		baseCmd === "rmdir" ||
		baseCmd === "rd" ||
		baseCmd === "remove-item" ||
		baseCmd === "ri" ||
		baseCmd === "del" ||
		baseCmd === "erase";

	if (isDeletionCmd) {
		const protectedPaths = await resolveProtectedPaths();
		const delRes = checkWorkspaceDeletionSegment(baseCmd, [baseCmd, ...words], seg.text, protectedPaths, cwd);
		if (delRes.blocked) return delRes;
	}

	return { blocked: false };
}

/**
 * Checks a shell command line for broad process termination patterns before actual execution.
 *
 * Always-on: returns unexecuted safety violation regardless of yolo mode or interceptor configuration.
 * Does not block inert echoed/quoted text, documentation, or legitimate inspection commands.
 *
 * @param command - The shell command to inspect.
 * @param secondaryCommand - Optional normalized command string to check as well.
 */
export async function checkProcessTerminationSafety(
	command: string,
	secondaryCommand?: string,
	depth = 0,
	projectDir?: string,
	commandCwd?: string,
	providedProtectedPaths?: readonly string[],
): Promise<ProcessSafetyCheckResult> {
	if (depth > 3) return { blocked: false };

	const cwd = commandCwd ?? projectDir ?? process.cwd();
	let cachedPaths: readonly string[] | undefined = providedProtectedPaths;
	const resolveProtectedPaths = async (): Promise<readonly string[]> => {
		if (cachedPaths) return cachedPaths;
		if (projectDir) {
			cachedPaths = await collectProtectedWorkflowPaths(projectDir);
		} else {
			cachedPaths = [path.resolve(cwd, ".reverse"), path.resolve(cwd, ".rea"), path.resolve(cwd, "patch_artifacts")];
		}
		return cachedPaths;
	};

	const commandsToCheck = secondaryCommand && secondaryCommand !== command ? [command, secondaryCommand] : [command];

	for (const cmd of commandsToCheck) {
		if (!cmd || typeof cmd !== "string" || cmd.trim().length === 0) continue;

		const segments = extractFlatShellCommandSegments(cmd);
		if (segments.length > 0) {
			for (const seg of segments) {
				const res = await checkSegmentSafety(seg, depth, resolveProtectedPaths, cwd);
				if (res.blocked) return res;
			}
		} else {
			const fallbackRes = await checkSegmentSafety(
				{ text: cmd, pipedStdin: false },
				depth,
				resolveProtectedPaths,
				cwd,
			);
			if (fallbackRes.blocked) return fallbackRes;
		}
	}

	return { blocked: false };
}
