/**
 * Bash intent interceptor - redirects common shell patterns to proper tools.
 *
 * When an LLM calls bash with patterns like `grep`, `cat`, `find`, etc.,
 * this interceptor provides helpful error messages directing them to use
 * the specialized tools instead.
 */
import { extractFlatShellCommandSegments, readShellWord } from "./shell-tokenize";
import { type BashInterceptorRule, DEFAULT_BASH_INTERCEPTOR_RULES } from "../exec/settings";

export interface InterceptionResult {
	/** If true, the bash command should be blocked */
	block: boolean;
	/** Error message to return instead of executing */
	message?: string;
	/** Suggested tool to use instead */
	suggestedTool?: string;
}

/**
 * Compile bash interceptor rules into regexes, skipping invalid patterns.
 */
function compileRules(rules: BashInterceptorRule[]): Array<{ rule: BashInterceptorRule; regex: RegExp }> {
	const compiled: Array<{ rule: BashInterceptorRule; regex: RegExp }> = [];
	for (const rule of rules) {
		const flags = rule.flags ?? "";
		try {
			compiled.push({ rule, regex: new RegExp(rule.pattern, flags) });
		} catch {
			// Skip invalid regex patterns
		}
	}
	return compiled;
}

/** Finds the end of a shell word, respecting quotes and escapes; returns null for incomplete syntax. */
function skipShellWord(command: string, start: number): number | null {
	let inSingle = false;
	let inDouble = false;
	for (let i = start; i < command.length; i++) {
		const ch = command[i];
		if (inSingle) {
			if (ch === "'") inSingle = false;
			continue;
		}
		if (inDouble) {
			if (ch === "\\") {
				if (i + 1 >= command.length) return null;
				i++;
				continue;
			}
			if (ch === '"') inDouble = false;
			continue;
		}
		if (ch === "'") {
			inSingle = true;
			continue;
		}
		if (ch === '"') {
			inDouble = true;
			continue;
		}
		if (ch === "\\") {
			if (i + 1 >= command.length) return null;
			i++;
			continue;
		}
		if (ch === " " || ch === "\t") return i;
	}
	return inSingle || inDouble ? null : command.length;
}

/** Removes leading `NAME=value` assignments without interpreting shell syntax. */
function withoutLeadingEnvironmentAssignments(command: string): string | null {
	let index = 0;
	let foundAssignment = false;
	while (index < command.length) {
		while (command[index] === " " || command[index] === "\t") index++;
		const assignmentStart = index;
		if (!/[A-Za-z_]/.test(command[index] ?? "")) break;
		let nameEnd = index + 1;
		while (/[A-Za-z0-9_]/.test(command[nameEnd] ?? "")) nameEnd++;
		if (command[nameEnd] !== "=") {
			return foundAssignment ? command.slice(assignmentStart).trimStart() : null;
		}
		const wordEnd = skipShellWord(command, nameEnd + 1);
		if (wordEnd === null) return null;
		foundAssignment = true;
		index = wordEnd;
		if (index === command.length) return null;
	}
	if (!foundAssignment) return null;
	const commandWithoutAssignments = command.slice(index).trimStart();
	return commandWithoutAssignments.length > 0 ? commandWithoutAssignments : null;
}

/**
 * Unwraps command invocation wrappers for bash interception:
 * 1. `command [-p] [--]` wrapper
 * 2. Standard executable paths: `/bin/<cmd>` or `/usr/bin/<cmd>`
 * 3. Quoting or backslash-escaping on the first command word (e.g. `"grep"`, `'grep'`, `\grep`)
 *
 * Does not unwrap custom paths (e.g. `./custom/grep`), does not interpret eval/env/subshells,
 * and preserves the original command for display.
 * Returns the normalized equivalent command string if unwrapped, or null if no unwrapping occurred.
 */
export function unwrapCommandInvocation(command: string): string | null {
	let current = command.trimStart();
	if (current.length === 0) return null;

	let unwrapped = false;
	const firstWord = readShellWord(current);
	if (!firstWord || firstWord === "unterminated") return null;

	if (firstWord.value === "command") {
		let rest = firstWord.rest;
		while (rest.length > 0) {
			const next = readShellWord(rest);
			if (!next || next === "unterminated") return null;
			if (next.value === "-p") {
				rest = next.rest;
			} else if (next.value === "--") {
				rest = next.rest;
				break;
			} else if (next.value.startsWith("-")) {
				// Unsupported flags for `command` (e.g. -v, -V) - do not unwrap
				return null;
			} else {
				// Reached command name
				break;
			}
		}
		if (rest.length === 0) return null;
		current = rest.trimStart();
		unwrapped = true;
	}

	const cmdWord = readShellWord(current);
	if (!cmdWord || cmdWord === "unterminated") return null;

	let baseName = cmdWord.value;
	let isStandardPath = false;

	if (baseName.startsWith("/bin/") || baseName.startsWith("\\bin\\")) {
		const sub = baseName.slice(5);
		if (sub.length > 0 && !sub.includes("/") && !sub.includes("\\")) {
			baseName = sub;
			isStandardPath = true;
		}
	} else if (baseName.startsWith("/usr/bin/") || baseName.startsWith("\\usr\\bin\\")) {
		const sub = baseName.slice(9);
		if (sub.length > 0 && !sub.includes("/") && !sub.includes("\\")) {
			baseName = sub;
			isStandardPath = true;
		}
	}

	// Do not treat custom or non-standard paths (e.g. ./custom/grep, /opt/bin/grep) as standard commands
	if (!isStandardPath && (cmdWord.value.includes("/") || cmdWord.value.includes("\\"))) {
		return null;
	}

	// Check if the command word in `current` was quoted or escaped
	const isBareWord =
		current.startsWith(baseName) &&
		(current.length === baseName.length || /[\s\t\n\r]/.test(current[baseName.length]));
	const isQuotedOrEscaped = !isBareWord;

	if (!unwrapped && !isStandardPath && !isQuotedOrEscaped) {
		return null;
	}

	return cmdWord.rest.length > 0 ? `${baseName} ${cmdWord.rest}` : baseName;
}

function interceptionCandidates(command: string): string[] {
	const candidates: string[] = [];
	const seen = new Set<string>();

	const addCandidate = (text: string | null | undefined) => {
		if (!text) return;
		const trimmed = text.trim();
		if (trimmed.length === 0 || seen.has(trimmed)) return;
		seen.add(trimmed);
		candidates.push(trimmed);

		const unwrapped = unwrapCommandInvocation(trimmed);
		if (unwrapped && !seen.has(unwrapped)) {
			seen.add(unwrapped);
			candidates.push(unwrapped);
		}
	};

	addCandidate(command);
	for (const segment of extractFlatShellCommandSegments(command)) {
		// A segment that consumes the previous stage's stdout via `|` reads piped
		// stdin, which no path-based dedicated tool (read/grep/glob) — nor any
		// other dedicated tool — can replace, so it is not an interception
		// candidate. Standalone and first-stage commands still match.
		if (segment.pipedStdin) continue;
		addCandidate(segment.text);
		const withoutAssignments = withoutLeadingEnvironmentAssignments(segment.text);
		if (withoutAssignments) addCandidate(withoutAssignments);
	}
	return candidates;
}

/**
 * Check if a bash command should be intercepted.
 *
 * @param command The bash command to check
 * @param availableTools Set of tool names that are available
 * @returns InterceptionResult indicating if the command should be blocked
 */
export function checkBashInterception(
	command: string,
	availableTools: string[],
	rules: BashInterceptorRule[] = DEFAULT_BASH_INTERCEPTOR_RULES,
	originalCommand = command,
): InterceptionResult {
	const compiled = compileRules(rules);
	const candidates = interceptionCandidates(command);

	for (const { rule, regex } of compiled) {
		// Only block if the suggested tool is actually available
		if (!availableTools.includes(rule.tool)) {
			continue;
		}

		for (const candidate of candidates) {
			// A configured global or sticky regex carries state across calls.
			regex.lastIndex = 0;
			if (regex.test(candidate)) {
				return {
					block: true,
					message: `Blocked: ${rule.message}\n\nOriginal command: ${originalCommand}`,
					suggestedTool: rule.tool,
				};
			}
		}
	}

	return { block: false };
}
