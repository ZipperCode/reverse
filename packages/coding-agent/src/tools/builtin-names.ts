export const BUILTIN_TOOL_NAMES = [
	"read",
	"bash",
	"edit",
	"ast_grep",
	"ast_edit",
	"ask",
	"debug",
	"ida",
	"eval",
	"github",
	"glob",
	"grep",
	"find",
	"lsp",
	"checkpoint",
	"rewind",
	"context_notes",
	"new_context",
	"security_scan",
	"wasm_inspect",
	"r2_inspect",
	"dotnet_inspect",
	"ghidra_inspect",
	"droidasc",
	"android_package_inspect",
	"android_native_workflow",
	"adb_observe",
	"frida",
	"frida_session",
	"websocket_observe",
	"windows_observe",
	"triage",
	"evidence",
	"javascript_application",
	"js_hook_preset",
	"browser_reverse_session",
	"sourcemap_inspect",
	"pcap_inspect",
	"sqlite_inspect",
	"firmware_inspect",
	"crashdump_inspect",
	"binary_metadata_inspect",
	"evm_inspect",
	"binary_diff",
	"reverse_workflow",
	"reverse_runtime_session",
	"reverse_knowledge",
	"reverse_workspace",
	"reverse_dynamic_evidence",
	"reverse_capability",
	"task",
	"wait",
	"todo",
	"web_search",
	"write",
	"memory_edit",
	"retain",
	"recall",
	"reflect",
	"learn",
	"manage_skill",
] as const;

export type BuiltinToolName = (typeof BUILTIN_TOOL_NAMES)[number];

export const HIDDEN_TOOL_NAMES = ["yield", "goal", "think"] as const;

export type HiddenToolName = (typeof HIDDEN_TOOL_NAMES)[number];

const LEGACY_BUILTIN_TOOL_NAME_ALIASES: ReadonlyMap<string, BuiltinToolName> = new Map([
	["search", "grep"],
	["android_analyze", "droidasc"],
	["binary_triage", "triage"],
	["evidence_ledger", "evidence"],
	["frida_observe", "frida"],
	["frida_exec", "frida"],
	["frida-session", "frida_session"],
	["frida_sessions", "frida_session"],
	["reverse_dynamic_session", "frida_session"],
	["reverse-dynamic-session", "frida_session"],
	["dynamic_session", "frida_session"],
	["analyze_javascript_application", "javascript_application"],
	["dotnet_analyze", "dotnet_inspect"],
	["dotnet", "dotnet_inspect"],
	["ghidra", "ghidra_inspect"],
	["ghidra_bridge", "ghidra_inspect"],
	["jshook", "js_hook_preset"],
	["jshook_preset", "js_hook_preset"],
	["generate_js_hook", "js_hook_preset"],
	["browser_reverse", "browser_reverse_session"],
	["browser_hook", "browser_reverse_session"],
	["browser_session", "browser_reverse_session"],
	["sourcemap", "sourcemap_inspect"],
	["sourcemap_recover", "sourcemap_inspect"],
	["source_map_inspect", "sourcemap_inspect"],
	["apk_inspect", "android_package_inspect"],
	["dex_inspect", "android_package_inspect"],
	["android_inspect", "android_package_inspect"],
	["pcap", "pcap_inspect"],
	["pcapng", "pcap_inspect"],
	["pcap_analyze", "pcap_inspect"],
	["packet_inspect", "pcap_inspect"],
	["sqlite", "sqlite_inspect"],
	["sqlite3", "sqlite_inspect"],
	["sqlite_analyze", "sqlite_inspect"],
	["db_inspect", "sqlite_inspect"],
	["firmware", "firmware_inspect"],
	["firmware_analyze", "firmware_inspect"],
	["binwalk", "firmware_inspect"],
	["rom_inspect", "firmware_inspect"],
	["crashdump", "crashdump_inspect"],
	["crash_dump", "crashdump_inspect"],
	["coredump", "crashdump_inspect"],
	["core_dump", "crashdump_inspect"],
	["minidump", "crashdump_inspect"],
	["crash_inspect", "crashdump_inspect"],
	["core_inspect", "crashdump_inspect"],
	["go_metadata", "binary_metadata_inspect"],
	["rust_metadata", "binary_metadata_inspect"],
	["binary_metadata", "binary_metadata_inspect"],
	["metadata_inspect", "binary_metadata_inspect"],
	["evm", "evm_inspect"],
	["evm_disasm", "evm_inspect"],
	["bytecode_inspect", "evm_inspect"],
	["bindiff", "binary_diff"],
	["bin_diff", "binary_diff"],
	["binary_compare", "binary_diff"],
	["workflow", "reverse_workflow"],
	["reverse_orchestrator", "reverse_workflow"],
	["rev_workflow", "reverse_workflow"],
	["reverse_recovery", "reverse_workflow"],
	["workflow_recovery", "reverse_workflow"],
	["retry_plan", "reverse_workflow"],
	["auto_advance", "reverse_workflow"],
	["reverse_advance", "reverse_workflow"],
	["runtime_session", "reverse_runtime_session"],
	["reverse_session", "reverse_runtime_session"],
	["runtime_registry", "reverse_runtime_session"],
	["reverse_runtime_registry", "reverse_runtime_session"],
	["reverse-knowledge", "reverse_knowledge"],
	["rev_knowledge", "reverse_knowledge"],
	["knowledge_store", "reverse_knowledge"],
	["knowledge_audit", "reverse_knowledge"],
	["knowledge_governance", "reverse_knowledge"],
	["reverse-workspace", "reverse_workspace"],
	["rea_workspace", "reverse_workspace"],
	["workspace", "reverse_workspace"],
	["dynamic_evidence", "reverse_dynamic_evidence"],
	["reverse-dynamic-evidence", "reverse_dynamic_evidence"],
	["dynamic_closure", "reverse_dynamic_evidence"],
	["reverse_dynamic_closure", "reverse_dynamic_evidence"],
	["capability", "reverse_capability"],
	["capabilities", "reverse_capability"],
	["reverse-capability", "reverse_capability"],
	["reverse_capabilities", "reverse_capability"],
]);
const CANONICAL_TOOL_NAMES: Record<string, true> = Object.fromEntries(
	[...BUILTIN_TOOL_NAMES, ...HIDDEN_TOOL_NAMES].map(name => [name, true]),
);

/** Canonicalize built-in IDs and legacy aliases. Leave plugin names unchanged. */
export function normalizeToolName(name: string): string {
	const lower = name.toLowerCase();
	return LEGACY_BUILTIN_TOOL_NAME_ALIASES.get(lower) ?? (Object.hasOwn(CANONICAL_TOOL_NAMES, lower) ? lower : name);
}

/** Normalize and deduplicate tool names while preserving first-seen order. */
export function normalizeToolNames(names: Iterable<string>): string[] {
	const out: string[] = [];
	const seen = new Set<string>();
	for (const name of names) {
		const normalized = normalizeToolName(name);
		if (seen.has(normalized)) continue;
		seen.add(normalized);
		out.push(normalized);
	}
	return out;
}

/** MCP tool names carry the `mcp__<server>_<tool>` prefix minted by `createMCPToolName`. */
export function isMCPToolName(name: string): boolean {
	return name.startsWith("mcp__");
}
