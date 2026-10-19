import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/omptype";
import { prompt, getProjectDir } from "@reverse/utils";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import type { ToolSession } from "./index";
import reverseCapabilityDescription from "../prompts/tools/reverse-capability.md" with { type: "text" };
import { checkReverseTools } from "../cli/setup-reverse";
import {
	getReverseCapabilities,
	type CapabilityDescriptor,
	type ReverseCapabilityStatus,
} from "../extensibility/skill-tool-catalog";

const reverseCapabilitySchema = type({
	action: type
		.enumerated("list", "resolve", "get")
		.describe(
			"Capability action: 'list' (enumerate all canonical reverse engineering capabilities), 'resolve' (evaluate host system availability, recommended native tools, fallbacks, and setup commands), 'get' (inspect a specific capability in detail by canonical ID)",
		),
	"capability?": type("string").describe(
		"Canonical capability ID (e.g. 'apk_unpacking', 'native_debugger', 'android_native_emulation', 'browser_debugger', 'websocket_capture', 'js_deobfuscation', 'traffic_interception')",
	),
	"id?": type("string").describe("Alias for capability"),
	"refresh?": type("boolean").describe(
		"Bypass cached tool checks when resolving host capabilities (defaults to false)",
	),
});

export type ReverseCapabilityParams = typeof reverseCapabilitySchema.infer;

export interface ReverseCapabilityDetails {
	action: "list" | "resolve" | "get";
	total?: number;
	capability?: ReverseCapabilityStatus | CapabilityDescriptor;
	capabilities?: ReverseCapabilityStatus[] | CapabilityDescriptor[];
	platform?: string;
}

export class ReverseCapabilityTool implements AgentTool<typeof reverseCapabilitySchema, ReverseCapabilityDetails> {
	readonly name = "reverse_capability";
	readonly label = "Reverse Engineering Capability Resolver";
	readonly summary =
		"Capability-driven runtime dispatch and host environment capability query tool: discovers, resolves, and inspects reverse engineering capabilities, recommended native tools, fallbacks, and trusted setup commands.";
	readonly description: string;
	readonly parameters = reverseCapabilitySchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approval = (): ToolTier => "read";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(reverseCapabilityDescription);
	}

	async execute(
		toolCallIdOrParams: string | ReverseCapabilityParams,
		paramsOrContext?: ReverseCapabilityParams | { abortSignal?: AbortSignal },
		signal?: AbortSignal,
	): Promise<AgentToolResult<ReverseCapabilityDetails>> {
		let params: ReverseCapabilityParams;
		let abortSignal: AbortSignal | undefined;

		if (typeof toolCallIdOrParams === "string") {
			params = paramsOrContext as ReverseCapabilityParams;
			abortSignal = signal;
		} else {
			params = toolCallIdOrParams;
			if (paramsOrContext && "abortSignal" in paramsOrContext) {
				abortSignal = paramsOrContext.abortSignal;
			}
		}

		throwIfAborted(abortSignal);

		const projectDir = this.session.cwd ?? getProjectDir();
		const capId = (params.capability ?? params.id)?.trim().toLowerCase();

		switch (params.action) {
			case "list": {
				const capabilities = getReverseCapabilities();
				const lines: string[] = [`### Reverse Engineering Capabilities (${capabilities.length} total)`, ""];
				for (const cap of capabilities) {
					lines.push(`- **\`${cap.id}\`**: ${cap.name} [${cap.category}]`);
					lines.push(`  - Scenario: ${cap.scenario}`);
					if (cap.recommendedNativeTool) {
						lines.push(`  - Recommended Native Tool: \`${cap.recommendedNativeTool}\``);
					}
					lines.push(`  - Optional External Tools: ${cap.optionalExternalTools.join(", ")}`);
					lines.push(`  - Fallbacks: ${cap.fallbacks.join(", ")}`);
					lines.push(`  - Trusted Setup Command: \`${cap.setupCommand}\``);
					lines.push(`  - Post-Install Invocation: \`${cap.postInstallInvocation}\``);
					lines.push("");
				}
				lines.push(
					'Call `reverse_capability(action: "resolve")` to evaluate host system tool availability and readiness.',
				);

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "list",
						total: capabilities.length,
						capabilities: [...capabilities],
					},
				};
			}

			case "resolve": {
				const report = checkReverseTools({ cwd: projectDir });
				let targetCaps = report.capabilities;
				if (capId) {
					const matched = report.capabilities.filter(c => c.id.toLowerCase() === capId);
					if (matched.length === 0) {
						const available = report.capabilities.map(c => c.id).join(", ");
						throw new ToolError(`Capability '${capId}' not found. Available capabilities: ${available}`);
					}
					targetCaps = matched;
				}

				const lines: string[] = [
					`### Resolved Reverse Capabilities (${targetCaps.length} evaluated, Platform: ${report.platform})`,
					"",
				];

				for (const cap of targetCaps) {
					const statusBadge =
						cap.status === "ready"
							? "READY"
							: cap.status === "available_with_fallbacks"
								? "AVAILABLE_WITH_FALLBACKS"
								: "MISSING";

					lines.push(`#### [${statusBadge}] \`${cap.id}\`: ${cap.name}`);
					lines.push(`- **Status**: ${cap.status} (Ready: ${cap.ready ? "true" : "false"})`);
					lines.push(`- **Category**: ${cap.category}`);
					lines.push(`- **Scenario**: ${cap.scenario}`);
					if (cap.recommendedNativeTool) {
						lines.push(`- **Recommended Native Tool**: \`${cap.recommendedNativeTool}\``);
					}
					const toolSummary =
						cap.optionalExternalTools.length > 0
							? cap.optionalExternalTools.map(t => `${t.id} (${t.status})`).join(", ")
							: "none";
					lines.push(`- **Optional External Tools**: ${toolSummary}`);
					const availableFbStr = cap.availableFallbacks.length > 0 ? cap.availableFallbacks.join(", ") : "none";
					lines.push(`- **Available Fallbacks**: ${availableFbStr} (All: ${cap.fallbacks.join(", ")})`);
					lines.push(`- **Trusted Setup Command**: \`${cap.setupCommand}\``);
					lines.push(`- **Post-Install Invocation**: \`${cap.postInstallInvocation}\``);
					lines.push("");
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "resolve",
						total: targetCaps.length,
						capabilities: targetCaps,
						platform: report.platform,
					},
				};
			}

			case "get": {
				if (!capId) {
					const valid = getReverseCapabilities()
						.map(c => c.id)
						.join(", ");
					throw new ToolError(`capability parameter is required for 'get' action. Valid capabilities: ${valid}`);
				}

				const report = checkReverseTools({ cwd: projectDir });
				const capStatus = report.capabilities.find(c => c.id.toLowerCase() === capId);
				if (!capStatus) {
					const valid = report.capabilities.map(c => c.id).join(", ");
					throw new ToolError(`Capability '${capId}' not found. Valid capabilities: ${valid}`);
				}

				const statusBadge =
					capStatus.status === "ready"
						? "READY"
						: capStatus.status === "available_with_fallbacks"
							? "AVAILABLE_WITH_FALLBACKS"
							: "MISSING";

				const lines: string[] = [
					`### Capability: \`${capStatus.id}\` [${statusBadge}]`,
					`**${capStatus.name}** (${capStatus.category})`,
					"",
					`**Scenario**: ${capStatus.scenario}`,
					"",
					`**Description**: ${capStatus.description}`,
					"",
					`**Why**: ${capStatus.why}`,
					"",
					`- **Readiness Status**: ${capStatus.status} (Fully Ready: ${capStatus.ready ? "Yes" : "No"})`,
				];

				if (capStatus.recommendedNativeTool) {
					lines.push(`- **Recommended Native Tool**: \`${capStatus.recommendedNativeTool}\``);
				}

				const extToolsStr =
					capStatus.optionalExternalTools.length > 0
						? capStatus.optionalExternalTools
								.map(
									t =>
										`${t.name ?? t.id} [${t.status}]${t.installCommand ? ` (install: ${t.installCommand})` : ""}`,
								)
								.join("; ")
						: "none";
				lines.push(`- **Optional External Tools**: ${extToolsStr}`);

				if (capStatus.prerequisites && capStatus.prerequisites.length > 0) {
					lines.push(`- **Prerequisites**: ${capStatus.prerequisites.join(", ")}`);
				}

				const availFbStr =
					capStatus.availableFallbacks.length > 0 ? capStatus.availableFallbacks.join(", ") : "none";
				lines.push(`- **Available Fallbacks**: ${availFbStr}`);
				lines.push(`- **All Defined Fallbacks**: ${capStatus.fallbacks.join(", ")}`);
				lines.push(`- **Trusted Setup Command**: \`${capStatus.setupCommand}\``);
				lines.push(`- **Post-Install Invocation**: \`${capStatus.postInstallInvocation}\``);

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "get",
						capability: capStatus,
						platform: report.platform,
					},
				};
			}

			default:
				throw new ToolError(`Unknown reverse_capability action: '${String(params.action)}'`);
		}
	}
}
