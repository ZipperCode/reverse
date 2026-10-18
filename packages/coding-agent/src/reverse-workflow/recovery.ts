import type {
	FailureAttribution,
	FailureCategory,
	RecoveryAuditEntry,
	RecoveryPlan,
	ReverseWorkflowRecord,
	WorkflowStepRecord,
} from "./contracts";
import { DEFAULT_MAX_ATTEMPTS, HARD_MAX_ATTEMPTS } from "./contracts";

export interface ToolInstallHint {
	macos: string;
	linux: string;
	windows: string;
	fallback: string;
}

export const TOOL_INSTALL_HINTS: Record<string, ToolInstallHint> = {
	radare2: {
		macos: "brew install radare2",
		linux: "apt install radare2",
		windows: "choco install radare2",
		fallback: "r2_inspect -> ghidra_inspect or triage",
	},
	r2: {
		macos: "brew install radare2",
		linux: "apt install radare2",
		windows: "choco install radare2",
		fallback: "r2_inspect -> ghidra_inspect or triage",
	},
	ghidra: {
		macos: "brew install --cask ghidra",
		linux: "apt install ghidra",
		windows: "choco install ghidra",
		fallback: "ghidra_inspect -> r2_inspect or triage",
	},
	droidasc: {
		macos: "pip install droidasc",
		linux: "pip install droidasc",
		windows: "pip install droidasc",
		fallback: "droidasc -> android_package_inspect",
	},
	jadx: {
		macos: "brew install jadx",
		linux: "apt install jadx",
		windows: "choco install jadx",
		fallback: "jadx -> android_package_inspect",
	},
	apktool: {
		macos: "brew install apktool",
		linux: "apt install apktool",
		windows: "choco install apktool",
		fallback: "apktool -> android_package_inspect",
	},
	adb: {
		macos: "brew install --cask android-platform-tools",
		linux: "apt install android-tools-adb",
		windows: "choco install adb",
		fallback: "adb_observe -> static inspection",
	},
	frida: {
		macos: "pipx install frida-tools",
		linux: "pipx install frida-tools",
		windows: "py -m pip install --user frida-tools",
		fallback: "frida -> static inspection",
	},
	wabt: {
		macos: "brew install wabt",
		linux: "apt install wabt",
		windows: "choco install wabt",
		fallback: "wasm2wat -> wasm_inspect",
	},
	tshark: {
		macos: "brew install wireshark",
		linux: "apt install tshark",
		windows: "choco install wireshark",
		fallback: "tshark -> pcap_inspect",
	},
	vbindiff: {
		macos: "brew install vbindiff",
		linux: "apt install vbindiff",
		windows: "choco install vbindiff",
		fallback: "vbindiff -> binary_diff",
	},
	"ast-grep": {
		macos: "brew install ast-grep",
		linux: "apt install ast-grep",
		windows: "cargo install ast-grep",
		fallback: "ast-grep -> ast_grep or grep",
	},
};

export function getPlatformInstallCommand(toolName: string, platform: NodeJS.Platform = process.platform): string | undefined {
	const normalized = toolName.toLowerCase().trim();
	const hint = TOOL_INSTALL_HINTS[normalized];
	if (!hint) return undefined;
	if (platform === "darwin") return hint.macos;
	if (platform === "win32") return hint.windows;
	return hint.linux;
}

export interface FailureClassificationContext {
	tool?: string;
	stepId?: string;
	gate?: string;
	targetPath?: string;
	targetFormat?: string;
	paramsSummary?: Record<string, unknown> | string;
}

/**
 * Classify a step failure into deterministic categories:
 * - missing_dependency
 * - invalid_format
 * - timeout
 * - truncated
 * - device_required
 * - unsupported
 * - unknown
 */
export function classifyFailure(
	errorMessage: string,
	context: FailureClassificationContext = {},
): FailureAttribution {
	const rawError = errorMessage.trim();
	const errLower = rawError.toLowerCase();

	// 1. Missing Dependency Check
	// Specific tools first
	const toolPatterns: Array<{ name: string; pattern: RegExp }> = [
		{ name: "radare2", pattern: /\b(?:r2|radare2)\b.*(?:not found|cannot find|no such file|command not found|enoent)|(?:cannot find|no such command).*\b(?:r2|radare2)\b|r2: command not found/i },
		{ name: "ghidra", pattern: /\bghidra\b.*(?:not found|cannot find|no such file|command not found)|ghidra_install_dir|analyzeheadless/i },
		{ name: "droidasc", pattern: /\bdroidasc\b.*(?:not found|cannot find|no such file|command not found|cannot find module)/i },
		{ name: "jadx", pattern: /\bjadx\b.*(?:not found|cannot find|no such file|command not found|please install jadx)/i },
		{ name: "apktool", pattern: /\bapktool\b.*(?:not found|cannot find|no such file|command not found)/i },
		{ name: "adb", pattern: /\badb\b.*(?:not found|cannot find|no such file|command not found)|failed to execute adb.*(?:enoent|not found)/i },
		{ name: "frida", pattern: /\bfrida\b.*(?:not found|cannot find|no such file|command not found|frida-tools)/i },
		{ name: "wabt", pattern: /\b(?:wabt|wasm2wat|wat2wasm)\b.*(?:not found|cannot find|command not found)/i },
		{ name: "tshark", pattern: /\btshark\b.*(?:not found|cannot find|command not found)/i },
		{ name: "vbindiff", pattern: /\bvbindiff\b.*(?:not found|cannot find|command not found)/i },
		{ name: "ast-grep", pattern: /\bast-grep\b.*(?:not found|cannot find|command not found)/i },
	];

	for (const tp of toolPatterns) {
		if (tp.pattern.test(rawError)) {
			const installCmd = getPlatformInstallCommand(tp.name);
			return {
				category: "missing_dependency",
				cause: `Required tool or dependency '${tp.name}' is not installed or not found on PATH.`,
				confidence: "high",
				raw_error: rawError,
				matched_pattern: tp.name,
				missing_tool: tp.name,
				install_hint: installCmd,
			};
		}
	}

	// Generic missing dependency
	if (
		/\b(?:command not found|not found on path|is not installed|not installed on the system|spawn .* enoent|executable not found|no such file or directory)\b/i.test(rawError) ||
		/cannot find executable|binary not found|please install/i.test(rawError)
	) {
		const toolName = context.tool ?? "required tool";
		const installCmd = context.tool ? getPlatformInstallCommand(context.tool) : undefined;
		return {
			category: "missing_dependency",
			cause: `Required executable or external dependency for '${toolName}' was not found in the environment.`,
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "generic_missing_dependency",
			missing_tool: context.tool,
			install_hint: installCmd,
		};
	}

	// 2. Device Required Check
	if (
		/\b(?:no (?:usable )?(?:android )?device|device (?:offline|not found|unauthorized)|no emulator|adb server not running|cannot connect to daemon|unable to connect to.*frida|device not connected|no target device|usb device not detected|device unauthorized)\b/i.test(rawError)
	) {
		return {
			category: "device_required",
			cause: "Dynamic analysis tool requires an attached Android device or running emulator, but none was detected.",
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "device_required",
		};
	}

	// 3. Timeout Check
	if (
		/\b(?:timed? out|timeout|etimedout|deadline exceeded|killed after \d+m?s|execution time exceeded|took too long)\b/i.test(rawError)
	) {
		return {
			category: "timeout",
			cause: "Tool execution timed out before completion, likely due to large binary size or exhaustive decompilation/analysis.",
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "timeout",
		};
	}

	// 4. Truncated Check
	if (
		/\b(?:truncated|output limit exceeded|buffer (?:overflow|full|limit)|response clipped|maximum .* limit of \d+ bytes|exceeds maximum .* limit|too large)\b/i.test(rawError)
	) {
		return {
			category: "truncated",
			cause: "Tool output exceeded buffer or inline capacity. Paging, filtering, or artifact output is required.",
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "truncated",
		};
	}

	// 5. Invalid Format Check
	if (
		/\b(?:invalid (?:magic|header|format|signature|elf|pe|mach-o|apk|dex|zip|wasm|pcap|sqlite)|not a valid (?:elf|pe|mach-o|apk|dex|zip|wasm|pcap|sqlite)|corrupt(?:ed)?|bad magic|unrecognized file format|file format not recognized|unexpected file format|malformed|not an elf binary|not a pe file|not an apk|not a valid sqlite|failed to parse|file is encrypted|packed with unknown packer)\b/i.test(rawError)
	) {
		return {
			category: "invalid_format",
			cause: "Target file format does not match expected structure or header is corrupted/packed/encrypted.",
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "invalid_format",
		};
	}

	// 6. Unsupported Check
	if (
		/\b(?:unsupported (?:architecture|arch|format|feature|version|encoding|platform)|not supported|not implemented|unknown architecture|symbol not found|stripped binary|no section table|no debugging symbols|entrypoint not found)\b/i.test(rawError)
	) {
		return {
			category: "unsupported",
			cause: "Target contains an unsupported architecture, stripped symbol table, or unimplemented analysis feature.",
			confidence: "high",
			raw_error: rawError,
			matched_pattern: "unsupported",
		};
	}

	// 7. Unknown
	return {
		category: "unknown",
		cause: rawError || "Unclassified failure encountered during step execution.",
		confidence: "low",
		raw_error: rawError,
	};
}

export interface RecoveryPlanOptions {
	error?: string;
	fallbackToolOverride?: string;
	nextParamsOverride?: Record<string, unknown> | string;
	maxAttempts?: number;
}

/**
 * Generate a deterministic recovery plan for a failed step.
 * Proposes bounded next attempts, parameter correction, and native tool fallback.
 */
export function generateRecoveryPlan(
	step: WorkflowStepRecord,
	workflow: ReverseWorkflowRecord,
	options: RecoveryPlanOptions = {},
): RecoveryPlan {
	const rawError = options.error ?? step.error ?? step.recovery_metadata?.failure_reason ?? "Step execution failed";
	const targetPath = workflow.target_abs_path || workflow.target;
	const originalTool = step.tool;
	const originalParams = step.params_summary;
	let parsedOriginalParams: Record<string, unknown> = {};
	if (typeof originalParams === "object" && originalParams !== null) {
		parsedOriginalParams = { ...originalParams };
	} else if (typeof originalParams === "string") {
		try {
			const parsed = JSON.parse(originalParams);
			if (typeof parsed === "object" && parsed !== null) {
				parsedOriginalParams = parsed;
			}
		} catch {
			// Not valid JSON string
		}
	}

	const maxAttempts =
		typeof options.maxAttempts === "number" && options.maxAttempts > 0
			? Math.min(options.maxAttempts, HARD_MAX_ATTEMPTS)
			: step.max_attempts || DEFAULT_MAX_ATTEMPTS;

	const currentAttempts = step.attempts ?? 0;
	const exhausted = currentAttempts >= maxAttempts;

	const attribution = classifyFailure(rawError, {
		tool: originalTool,
		stepId: step.id,
		gate: step.gate,
		targetPath,
		targetFormat: workflow.format,
		paramsSummary: originalParams,
	});

	// If exhausted, bounded recovery stops here
	if (exhausted) {
		return {
			attribution,
			suggested_action: "abort",
			original_tool: originalTool,
			next_tool: originalTool,
			original_params: originalParams,
			next_params: originalParams,
			alternatives: [],
			reasoning: `Maximum retry limit reached (${currentAttempts}/${maxAttempts} attempts). Automated retries are bounded to prevent infinite recovery loops.`,
			can_retry: false,
			current_attempts: currentAttempts,
			max_attempts: maxAttempts,
			exhausted: true,
			install_hint: attribution.install_hint,
		};
	}

	// Caller overrides take highest priority
	if (options.fallbackToolOverride || options.nextParamsOverride !== undefined) {
		const nextTool = options.fallbackToolOverride ?? originalTool;
		const nextParams = options.nextParamsOverride ?? originalParams;
		return {
			attribution,
			suggested_action: nextTool !== originalTool ? "fallback" : "retry",
			original_tool: originalTool,
			next_tool: nextTool,
			original_params: originalParams,
			next_params: nextParams,
			alternatives: [nextTool],
			reasoning: `Applying caller-provided recovery configuration: tool='${nextTool}'.`,
			can_retry: true,
			current_attempts: currentAttempts,
			max_attempts: maxAttempts,
			exhausted: false,
			install_hint: attribution.install_hint,
		};
	}

	// Deterministic recovery proposals based on attribution category
	let nextTool = originalTool;
	let nextParams: Record<string, unknown> | string = { ...parsedOriginalParams };
	let alternatives: string[] = [];
	let reasoning = "";
	let suggestedAction: "retry" | "fallback" | "adjust_params" | "abort" = "retry";

	switch (attribution.category) {
		case "missing_dependency": {
			suggestedAction = "fallback";
			if (originalTool === "droidasc" || originalTool === "jadx" || originalTool === "apktool") {
				nextTool = "android_package_inspect";
				nextParams = { path: targetPath, action: "dex" };
				alternatives = ["android_package_inspect", "jadx", "apktool"];
				reasoning = `Primary Android decompilation tool '${originalTool}' is missing. Degraded smoothly to zero-prep built-in tool 'android_package_inspect' for DEX bytecode and package inspection.`;
			} else if (originalTool === "r2_inspect") {
				// If radare2 is missing on PE/ELF/Mach-O
				nextTool = "triage";
				nextParams = { path: targetPath, strings: true, limit: 50 };
				alternatives = ["ghidra_inspect", "triage", "binary_metadata_inspect", "read"];
				reasoning = `Primary disassembly tool 'r2_inspect' is missing. Degraded to built-in 'triage' for section headers and strings inspection.`;
			} else if (originalTool === "ghidra_inspect") {
				nextTool = "r2_inspect";
				nextParams = { path: targetPath, action: "functions" };
				alternatives = ["r2_inspect", "triage", "read-binary"];
				reasoning = `Primary decompiler 'ghidra_inspect' is missing. Degraded to 'r2_inspect' for function and section analysis.`;
			} else if (originalTool === "tshark") {
				nextTool = "pcap_inspect";
				nextParams = { path: targetPath, action: "endpoints", limit: 30 };
				alternatives = ["pcap_inspect", "grep"];
				reasoning = `Packet analyzer 'tshark' is missing. Degraded to native zero-dependency 'pcap_inspect'.`;
			} else if (originalTool === "wabt" || originalTool === "wasm2wat") {
				nextTool = "wasm_inspect";
				nextParams = { path: targetPath, action: "wat", limit: 50 };
				alternatives = ["wasm_inspect", "read"];
				reasoning = `WASM disassembler 'wabt' is missing. Degraded to built-in 'wasm_inspect'.`;
			} else if (originalTool === "vbindiff") {
				nextTool = "binary_diff";
				nextParams = { fileA: parsedOriginalParams.fileA ?? targetPath, fileB: parsedOriginalParams.fileB ?? targetPath, mode: "summary" };
				alternatives = ["binary_diff"];
				reasoning = `Visual diff utility 'vbindiff' is missing. Degraded to built-in 'binary_diff'.`;
			} else if (originalTool === "ast-grep") {
				nextTool = "grep";
				nextParams = { path: targetPath, pattern: String(parsedOriginalParams.pattern ?? "function") };
				alternatives = ["ast_grep", "grep"];
				reasoning = `External CLI 'ast-grep' is missing. Degraded to regex search via 'grep'.`;
			} else {
				// Fallback to built-in triage or format inspector
				nextTool = "triage";
				nextParams = { path: targetPath, strings: true, limit: 30 };
				alternatives = ["triage", "binary_metadata_inspect"];
				reasoning = `Tool '${originalTool}' is missing dependency. Degraded to zero-dependency binary triage.`;
			}
			break;
		}

		case "invalid_format": {
			suggestedAction = "fallback";
			nextTool = "triage";
			nextParams = { path: targetPath, strings: true, limit: 50 };
			alternatives = ["triage", "binary_metadata_inspect", "read"];
			reasoning = `Target format mismatch or corrupted/packed structure detected. Falling back to multi-format triage and entropy analysis to inspect raw headers and determine true format.`;
			break;
		}

		case "timeout": {
			suggestedAction = "adjust_params";
			nextTool = originalTool;
			const adjusted = { ...parsedOriginalParams };
			if (typeof adjusted.limit === "number" && adjusted.limit > 20) {
				adjusted.limit = 20;
			} else if (!("limit" in adjusted)) {
				adjusted.limit = 20;
			}
			if (originalTool === "r2_inspect" && adjusted.action === "decompile") {
				adjusted.action = "disasm";
				adjusted.limit = 30;
			} else if (originalTool === "triage") {
				adjusted.strings = false;
				adjusted.limit = 30;
			}
			nextParams = adjusted;
			alternatives = ["adjust_params", "triage", "binary_metadata_inspect"];
			reasoning = `Tool execution timed out. Adjusted parameters to bound analysis scope (reduced limit to 20, lighter action) to avoid subsequent timeout.`;
			break;
		}

		case "truncated": {
			suggestedAction = "adjust_params";
			nextTool = originalTool;
			const adjusted = { ...parsedOriginalParams };
			adjusted.limit = 25;
			adjusted.offset = 0;
			nextParams = adjusted;
			alternatives = ["adjust_params", "to_artifact"];
			reasoning = `Tool output exceeded inline capacity. Adjusted parameters to use bounded paging (limit: 25, offset: 0).`;
			break;
		}

		case "device_required": {
			suggestedAction = "fallback";
			if (workflow.format === "APK") {
				nextTool = "android_package_inspect";
				nextParams = { path: targetPath, action: "manifest" };
				alternatives = ["android_package_inspect", "droidasc"];
				reasoning = `Dynamic analysis requires an attached device or emulator, but none was detected. Degraded to offline static package inspection.`;
			} else {
				nextTool = "triage";
				nextParams = { path: targetPath, strings: true, limit: 30 };
				alternatives = ["triage", "r2_inspect"];
				reasoning = `Dynamic analysis requires a live device environment. Degraded to offline static binary triage.`;
			}
			break;
		}

		case "unsupported": {
			suggestedAction = "fallback";
			nextTool = "triage";
			nextParams = { path: targetPath, strings: true, limit: 50 };
			alternatives = ["triage", "binary_metadata_inspect", "grep"];
			reasoning = `Unsupported architecture or feature encountered in '${originalTool}'. Falling back to multi-format binary triage for raw symbol and string reconnaissance.`;
			break;
		}

		default: {
			suggestedAction = "retry";
			nextTool = originalTool;
			nextParams = parsedOriginalParams;
			alternatives = [originalTool, "triage"];
			reasoning = `Unclassified failure. Proposing retry with current parameters (Attempt ${currentAttempts + 1}/${maxAttempts}).`;
			break;
		}
	}

	return {
		attribution,
		suggested_action: suggestedAction,
		original_tool: originalTool,
		next_tool: nextTool,
		original_params: originalParams,
		next_params: nextParams,
		alternatives,
		reasoning,
		can_retry: true,
		current_attempts: currentAttempts,
		max_attempts: maxAttempts,
		exhausted: false,
		install_hint: attribution.install_hint,
	};
}
