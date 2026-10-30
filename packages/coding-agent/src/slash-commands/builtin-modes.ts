import { clearSubmittedText, runWithDetachedDraft } from "./helpers/draft";
import * as path from "node:path";
import { AgentBusyError } from "@reverse/agent";
import { formatKeyHint } from "@reverse/tui/app-keybindings";
import { APP_NAME, prompt } from "@reverse/utils";
import { Markdown } from "@reverse/tui";
import { getMarkdownTheme } from "@reverse/tui/theme";
import {
	checkReverseTools,
	type ReverseCheckReport,
	type ReverseServiceStatus,
	type ReverseToolStatus,
} from "../cli/setup-reverse";
import {
	canInstallReverseItem,
	getReverseInstallPlan,
	type ReverseInstallPlan,
} from "../extensibility/reverse-tool-install";
import { buildSpeechComponents, checkPythonSetup, type SpeechComponent } from "../cli/setup-cli";
import { getAllLocalizedPanels } from "../cli/setup-panels";
import { enumeratePythonRuntimes } from "../eval/py/runtime";
import { cfgPythonInterpreter } from "../eval/settings";
import { STT_MODEL_OPTIONS } from "../stt/models";
import { TTS_LOCAL_MODELS } from "../tts";
import { getEffectiveLocale } from "../config/persisted-locale";
import { CLI_TRANSLATIONS_ZH_CN } from "../i18n/zh-CN/cli";
import {
	formatModelString,
	getModelMatchPreferences,
	resolveCliModel,
	type ResolveCliModelResult,
} from "../config/model-resolver";
import type { Settings } from "../config/settings";
import {
	applyModelPreset,
	deleteModelPreset,
	formatModelPresetSwitch,
	getModelPresetNames,
	isCleanModelPresetSwitch,
	isValidModelPresetName,
	modelPresetSavedMessage,
	type ModelPresetSession,
	saveModelPreset,
} from "../config/model-presets";
import { describeLoopCondition } from "../modes/loop-condition";
import { describeLoopLimitRuntime } from "../modes/loop-limit";
import type { InteractiveModeContext } from "../modes/types";
import ratchetKickoffPrompt from "../prompts/ratchet-kickoff.md" with { type: "text" };
import type { AgentSession } from "../session/agent-session";
import { CLI_THINKING_LEVELS, getConfiguredThinkingLevelMetadata } from "@reverse/tui/thinking";
import { noThinkingMessage, resolveThinkingArgument } from "./helpers/effort";
import { commandConsumed, errorMessage, usage } from "./helpers/parse";
import { handleSecurityCommand } from "./helpers/security";
import type { SlashCommandSpec } from "./types";

import {
	cfgComputerBackgroundFallback,
	cfgComputerDisplay,
	cfgComputerEnabled,
	cfgComputerMaxHeight,
	cfgComputerMaxWidth,
	cfgRatchetEnabled,
} from "../tools/settings";
import { cfgPrewalkFrom, cfgPrewalkInto, cfgSkillful } from "../session/settings";
import { formatSlowModeResetClock } from "../session/anthropic-slow-mode";
import { cfgExtendedContext } from "../session/context-settings";
import { cfgGoalEnabled } from "../goals/settings";
import { cfgPlanEnabled } from "../plan-mode/settings";

export function refreshStatusLine(ctx: InteractiveModeContext): void {
	ctx.statusLine.invalidate();
	ctx.ui.requestRender();
}

/**
 * Resolve a `/model` / `/switch` selector the way `reverse bench` and `--model`
 * do: exact `provider/id`, fuzzy ids (`opus`), role aliases (`@smol`, `smol`),
 * and `:level` thinking suffixes. Unqualified selectors prefer the session's
 * `--models` scope, else the authenticated set, before the full catalog.
 */
function resolveSessionModelSelector(
	selector: string,
	session: AgentSession,
	settings: Settings,
): ResolveCliModelResult {
	const scoped = session.scopedModels.map(entry => entry.model);
	return resolveCliModel({
		cliModel: selector,
		modelRegistry: session.modelRegistry,
		availableModels: scoped.length > 0 ? scoped : undefined,
		settings,
		preferences: getModelMatchPreferences(settings),
	});
}

/** `/fast status` label for the active model: "ultra" for the Ultrafast tier, "on" for priority, else "off". */
function formatFastModeStatus(session: AgentSession): string {
	if (session.isUltrafastModeEnabled()) return "ultra";
	return session.isFastModeEnabled() ? "on" : "off";
}

const FAST_USAGE = "Usage: /fast [on|ultra|off|status]";

/**
 * `/fast [on|ultra|off|status]` for the active model: `on` selects the
 * family's `priority` tier, `ultra` the OpenAI `ultrafast` tier, `off` clears
 * either. Bare invocation toggles between off and priority. Returns the
 * user-facing reply, or `undefined` for an unknown argument.
 */
function runFastCommand(arg: string, session: AgentSession): string | undefined {
	switch (arg) {
		case "":
		case "toggle":
			return `Fast mode ${session.toggleFastMode() ? "enabled" : "disabled"}.`;
		case "on":
			return session.setFastMode(true) ? "Fast mode enabled." : "Fast mode is unavailable for the current model.";
		case "ultra":
		case "ultrafast":
			return session.setUltrafastMode(true)
				? "Ultrafast mode enabled."
				: "Ultrafast is unavailable for the current model.";
		case "off":
			session.setFastMode(false);
			return "Fast mode disabled.";
		case "status":
			return `Fast mode is ${formatFastModeStatus(session)}.`;
		default:
			return undefined;
	}
}

const SLOW_UNSUPPORTED =
	"The current model has no slow mode: /slow uses the flex tier on OpenAI/Google models and low priority on Anthropic subscriptions.";

/**
 * `/slow [on|off|status]` for the active model: the `flex` service tier on
 * OpenAI/Google, subscription low priority (`providers.anthropic.slowMode`
 * `auto`/`off`) on Anthropic. Bare invocation toggles. Returns the user-facing
 * reply, or `undefined` for an unknown argument.
 */
function runSlowCommand(arg: string, session: AgentSession): string | undefined {
	if (arg !== "" && arg !== "toggle" && arg !== "on" && arg !== "off" && arg !== "status") return undefined;
	const anthropic = session.model?.provider === "anthropic";
	if (arg === "status") {
		const label = anthropic ? session.getAnthropicSlowModeLabel() : undefined;
		if (!session.isSlowModeEnabled()) return label ? `Slow mode is off (${label}).` : "Slow mode is off.";
		if (!anthropic) return "Slow mode is on (flex tier).";
		return label ? `Slow mode is on (${label}).` : "Slow mode is on (low priority at the Claude session limit).";
	}
	const enabled = arg === "on" || (arg !== "off" && !session.isSlowModeEnabled());
	if (!session.setSlowMode(enabled)) return SLOW_UNSUPPORTED;
	if (!session.isSlowModeEnabled()) {
		return anthropic
			? "Slow mode off: at your Claude usage limit, requests may get a short wrap-up allowance, then wait for the limit to reset."
			: "Slow mode off.";
	}
	if (!anthropic) return "Slow mode on: requests use the flex tier (lower cost, higher latency).";
	const resetsAtSec = session.getAnthropicSlowModeLane()?.activeResetsAtSec();
	return resetsAtSec !== undefined
		? `Slow mode on: continuing at low priority until your limit resets at ${formatSlowModeResetClock(resetsAtSec)}. Your weekly limit still applies, and responses may pause while waiting for spare capacity.`
		: "Slow mode on: when your Claude subscription hits its session limit and Anthropic offers low priority, requests switch to it after any wrap-up allowance.";
}

/** `/extended-context status` label for the premium long-context window setting. */
function formatExtendedContextStatus(settings: Settings): string {
	return cfgExtendedContext.get(settings) ? "on" : "off";
}

/** Applies an `/extended-context` argument and returns its operator feedback. */
function applyExtendedContextCommand(settings: Settings, args: string): string | undefined {
	const arg = args.trim().toLowerCase();
	const current = cfgExtendedContext.get(settings);
	if (!arg || arg === "toggle") {
		const enabled = !current;
		cfgExtendedContext.set(settings, enabled);
		return `Extended context ${enabled ? "enabled" : "disabled"}.`;
	}
	if (arg === "on") {
		cfgExtendedContext.set(settings, true);
		return "Extended context enabled.";
	}
	if (arg === "off") {
		cfgExtendedContext.set(settings, false);
		return "Extended context disabled.";
	}
	if (arg === "status") return `Extended context is ${formatExtendedContextStatus(settings)}.`;
	return undefined;
}

/** Detailed, session-effective `/computer status` diagnostics. */
function formatComputerUseStatus(session: AgentSession): string {
	const enabled = cfgComputerEnabled.get(session.settings);
	const active = session.getEvalPreludes().some(definition => definition.name === "computer");
	const configured = {
		display: cfgComputerDisplay.get(session.settings),
		maxWidth: cfgComputerMaxWidth.get(session.settings),
		maxHeight: cfgComputerMaxHeight.get(session.settings),
		backgroundFallback: cfgComputerBackgroundFallback.get(session.settings),
	};
	return [
		`Computer use: ${enabled ? "enabled" : "disabled"}`,
		`prelude: ${active ? "active" : "inactive"}`,
		`configured: display=${configured.display}, maxWidth=${configured.maxWidth}, maxHeight=${configured.maxHeight}, backgroundFallback=${configured.backgroundFallback}`,
	].join(" · ");
}

/**
 * Apply a session-scoped computer-use toggle; the session's setting listener
 * reconciles the prompt without a mid-session cache-busting rebuild.
 * The override is never persisted to settings.json.
 */
function applyComputerUseToggle(session: AgentSession, enable: boolean): string {
	const previous = cfgComputerEnabled.get(session.settings);
	cfgComputerEnabled.override(session.settings, enable);
	if (enable && !session.getEvalPreludes().some(definition => definition.name === "computer")) {
		cfgComputerEnabled.override(session.settings, previous);
		return "Computer use is unavailable in this session.";
	}
	return enable
		? `Computer use enabled for this session. ${formatComputerUseStatus(session)}`
		: "Computer use disabled for this session.";
}

/** Tools the ratchet loop needs: the eval kernel hosts `ratchet()`, `task` runs its analyzer. */
const RATCHET_REQUIRED_TOOLS = ["eval", "task"] as const;

/**
 * Arm `/ratchet`: enable the ratchet prelude for this session (override, never persisted) and
 * render the kickoff prompt carrying the user's request as data.
 */
function prepareRatchet(session: AgentSession, request: string): { kickoff: string } | { error: string } {
	const tools = session.getEnabledToolNames();
	const missing = RATCHET_REQUIRED_TOOLS.filter(tool => !tools.includes(tool));
	if (missing.length > 0) return { error: `/ratchet needs the ${missing.join(" and ")} tool active.` };
	const previous = cfgRatchetEnabled.get(session.settings);
	if (!previous) cfgRatchetEnabled.override(session.settings, true);
	if (!session.getEvalPreludes().some(definition => definition.name === "ratchet")) {
		if (!previous) cfgRatchetEnabled.override(session.settings, previous);
		return { error: "The ratchet eval prelude is unavailable in this session." };
	}
	const kickoff = prompt.render(ratchetKickoffPrompt, { request: request.trim() || undefined, tools }).trim();
	return { kickoff };
}

const AUTOCOMPLETE_DETAIL_LIMIT = 48;

function shortDetail(value: string, limit = AUTOCOMPLETE_DETAIL_LIMIT): string {
	const singleLine = value.replace(/\s+/g, " ").trim();
	return singleLine.length <= limit ? singleLine : `${singleLine.slice(0, limit - 1)}…`;
}

export function formatTokenCount(value: number): string {
	return value.toLocaleString();
}
function formatCompactReverseReport(report: ReverseCheckReport, targetTool?: string, isZh = false): string {
	const lines: string[] = [];
	const installedCount = report.tools.filter(t => t.status === "installed").length;
	const missingCount = report.tools.filter(t => t.status === "missing").length;

	if (targetTool) {
		const match = report.tools.find(
			t =>
				t.id.toLowerCase() === targetTool.toLowerCase() ||
				t.name.toLowerCase() === targetTool.toLowerCase() ||
				t.name.toLowerCase().includes(targetTool.toLowerCase()),
		);
		if (match) {
			const isOk = match.status === "installed";
			lines.push(`# ${match.name} (\`${match.id}\`)`);
			lines.push("");
			lines.push(
				`- **${isZh ? "状态" : "Status"}**: ${
					isOk
						? isZh
							? `✅ 已安装 (${match.foundPath ? `\`${match.foundPath}\`` : "已就绪"})`
							: `✅ Installed (${match.foundPath ? `\`${match.foundPath}\`` : "ready"})`
						: isZh
							? "❌ 未安装"
							: "❌ Missing"
				}`,
			);
			lines.push(`- **${isZh ? "分类" : "Category"}**: ${match.category}`);
			lines.push(
				`- **${isZh ? "类型" : "Type"}**: ${
					match.optional ? (isZh ? "可选逆向工具" : "optional") : isZh ? "核心系统基础工具（必需）" : "required"
				}`,
			);
			if (match.installCommand) {
				lines.push("");
				lines.push(`### ${isZh ? "推荐安装命令" : "Recommended Install Command"}`);
				lines.push("```bash");
				lines.push(match.installCommand);
				lines.push("```");
			}
			if (match.secondaryMissing && match.secondaryMissing.length > 0) {
				lines.push("");
				lines.push(
					`> ⚠️ ${isZh ? `缺少前置依赖: ${match.secondaryMissing.join(", ")}` : `Missing prerequisite: ${match.secondaryMissing.join(", ")}`}`,
				);
			}
			if (match.manualUrl) {
				lines.push("");
				lines.push(`- **${isZh ? "官方链接" : "URL"}**: ${match.manualUrl}`);
			}
			if (match.manualInstructions) {
				lines.push(`- **${isZh ? "安装说明" : "Guide"}**: ${match.manualInstructions}`);
			}
			lines.push("");
			lines.push("---");
			lines.push(
				isZh
					? `*提示：在终端中运行 \`${APP_NAME} setup reverse --execute\` 可交互式确认并执行安装。*`
					: `*Tip: Run \`${APP_NAME} setup reverse --execute\` in terminal to install with interactive confirmation.*`,
			);
			return lines.join("\n");
		}

		const serviceMatch = report.services.find(
			service =>
				service.id.toLowerCase() === targetTool.toLowerCase() ||
				service.serverName.toLowerCase() === targetTool.toLowerCase() ||
				service.name.toLowerCase().includes(targetTool.toLowerCase()),
		);
		if (serviceMatch) {
			lines.push(`# ${serviceMatch.name} (\`${serviceMatch.id}\`) — MCP`);
			lines.push("");
			lines.push(
				`- **${isZh ? "状态" : "Status"}**: ${
					serviceMatch.ready
						? isZh
							? "✅ 前置依赖已就绪"
							: "✅ Prerequisites ready"
						: isZh
							? `⚠️ 缺少前置依赖：${serviceMatch.missingPrerequisites.join(", ")}`
							: `⚠️ Missing prerequisites: ${serviceMatch.missingPrerequisites.join(", ")}`
				}`,
			);
			lines.push(`- **${isZh ? "分类" : "Category"}**: ${serviceMatch.category}`);
			lines.push(`- **${isZh ? "许可证" : "License"}**: ${serviceMatch.license}`);
			lines.push(`- **${isZh ? "启动命令" : "Start command"}**: \`${serviceMatch.startCommand}\``);
			lines.push(`- **${isZh ? "配置路径" : "Config path"}**: ${serviceMatch.configPath}`);
			if (serviceMatch.installCommand) {
				lines.push("");
				lines.push(`### ${isZh ? "推荐安装命令" : "Recommended Install Command"}`);
				lines.push("```bash");
				lines.push(serviceMatch.installCommand);
				lines.push("```");
			}
			lines.push("");
			lines.push(`### ${isZh ? "MCP 配置片段" : "MCP Config Snippet"}`);
			lines.push("```json");
			lines.push(JSON.stringify(serviceMatch.configSnippet, null, 2));
			lines.push("```");
			lines.push("");
			lines.push(`### ${isZh ? "规范用法" : "Canonical Usage"}`);
			lines.push(`- **${isZh ? "入口" : "Canonical"}**: \`${serviceMatch.usage.canonical}\``);
			lines.push(`- **${isZh ? "何时使用" : "When to use"}**: ${serviceMatch.usage.whenToUse}`);
			lines.push(`- **${isZh ? "输出限制" : "Output limits"}**: ${serviceMatch.usage.outputLimits ?? "—"}`);
			lines.push(`- **${isZh ? "回退方案" : "Fallback"}**: ${serviceMatch.usage.fallback ?? "—"}`);
			lines.push("");
			lines.push(`- **${isZh ? "官方链接" : "URL"}**: ${serviceMatch.manualUrl}`);
			lines.push(`- **${isZh ? "安装说明" : "Guide"}**: ${serviceMatch.manualInstructions}`);
			lines.push("");
			lines.push("---");
			lines.push(
				isZh
					? `*提示：MCP 服务不是 PATH 二进制。安装后需将配置片段写入 ${serviceMatch.configPath}，再重启客户端。*`
					: `*Tip: MCP services are not PATH binaries. After install, merge the snippet into ${serviceMatch.configPath} and restart the client.*`,
			);
			return lines.join("\n");
		}
		lines.push(
			isZh
				? `> ⚠️ 未在工具或 MCP 服务目录中找到 "${targetTool}"。以下为全部状态列表：\n`
				: `> ⚠️ Tool/service "${targetTool}" not found in catalog. Listing all entries:\n`,
		);
	}

	lines.push(isZh ? "# 逆向工程工具链状态" : "# Reverse Engineering Toolchain");
	lines.push("");
	const pmStr =
		report.detectedPackageManagers.length > 0
			? report.detectedPackageManagers.join(", ")
			: isZh
				? "无（仅手动安装）"
				: "none";
	lines.push(
		isZh
			? `**平台**: \`${report.platform}\` | **包管理器**: ${pmStr}`
			: `**Platform**: \`${report.platform}\` | **Package Managers**: ${pmStr}`,
	);
	lines.push(
		isZh
			? `**状态概览**: 已安装 ${installedCount}/${report.tools.length} 项（缺少 ${missingCount} 项）`
			: `**Status**: ${installedCount}/${report.tools.length} installed (${missingCount} missing)`,
	);
	lines.push("");
	lines.push(
		isZh
			? "| 状态 | 工具 | 分类 | 类型 | 路径 / 安装方法 |"
			: "| Status | Tool | Category | Type | Path / Install Command |",
	);
	lines.push("|:---:|:---|:---|:---|:---|");
	for (const tool of report.tools) {
		const isOk = tool.status === "installed";
		const badge = isOk ? "✅" : tool.optional ? "⚠️" : "❌";
		const detail = isOk
			? `\`${tool.foundPath ?? "installed"}\``
			: tool.installCommand
				? `\`${tool.installCommand}\``
				: tool.manualUrl || (isZh ? "手动安装" : "manual");
		const typeStr = tool.optional ? (isZh ? "可选" : "optional") : isZh ? "必需" : "required";
		lines.push(`| ${badge} | \`${tool.id}\` | ${tool.category} | ${typeStr} | ${detail} |`);
	}
	lines.push("");
	if (report.services.length > 0) {
		lines.push(isZh ? "### 可选 MCP 辅助服务" : "### Optional MCP Helper Services");
		lines.push(
			isZh
				? "> MCP 服务不是 PATH 二进制；下表只检查前置 CLI 依赖和配置文件条目，不会启动服务或验证连接。"
				: "> MCP services are not PATH binaries; the table only checks prerequisite CLI tools and config entries. It never starts a server or verifies a connection.",
		);
		lines.push("");
		lines.push(
			isZh
				? "| 状态 | 服务 | 分类 | 传输 | 前置依赖 / 安装 |"
				: "| Status | Service | Category | Transport | Prerequisites / Install |",
		);
		lines.push("|:---:|:---|:---|:---|:---|");
		for (const service of report.services) {
			const badge = service.ready ? "✅" : "⚠️";
			const config = service.configured
				? isZh
					? `配置: ${service.configuredScopes.join(", ")}`
					: `configured: ${service.configuredScopes.join(", ")}`
				: isZh
					? "未配置"
					: "not configured";
			const prerequisites = service.prerequisites.map(p => `\`${p.id}\``).join(", ") || "none";
			const detail = service.ready
				? `${prerequisites}; ${config}`
				: service.installCommand
					? `\`${service.installCommand}\`; ${config}`
					: `${service.manualUrl}; ${config}`;
			lines.push(`| ${badge} | \`${service.id}\` | ${service.category} | ${service.transport} | ${detail} |`);
		}
		lines.push("");
		lines.push(
			isZh
				? `> 配置路径（实际解析）：项目 \`${report.services[0].configPaths.project}\`，用户 \`${report.services[0].configPaths.user}\`。连接状态未知，需重启客户端后自行验证。`
				: `> Resolved config paths: project \`${report.services[0].configPaths.project}\`, user \`${report.services[0].configPaths.user}\`. Connection is unverified; restart the client and check it yourself.`,
		);
		lines.push("");
	}
	const missingCmds = report.tools.filter(t => t.status === "missing" && t.installCommand);
	if (missingCmds.length > 0) {
		lines.push(isZh ? "### 待安装工具推荐命令" : "### Missing Tools Commands");
		lines.push("```bash");
		for (const t of missingCmds) {
			lines.push(t.installCommand!);
		}
		lines.push("```");
		lines.push("");
	}
	lines.push(
		isZh
			? `> 提示：在终端中运行 \`${APP_NAME} setup reverse\` 可交互式选择并确认安装工具。运行 \`/setup reverse <工具名>\` 查看具体工具说明。`
			: `> Tip: Run \`${APP_NAME} setup reverse\` in terminal to select and install tools with interactive confirmation. Run \`/setup reverse <tool>\` to view a specific tool.`,
	);
	return lines.join("\n");
}

export type ReverseInstallCallback = (
	item: ReverseToolStatus | ReverseServiceStatus,
	options?: { plan?: ReverseInstallPlan },
) => Promise<{ success: boolean; message?: string } | void>;

function getInstallCallback(source: unknown): ReverseInstallCallback | undefined {
	if (
		source &&
		typeof source === "object" &&
		"installReverseItem" in source &&
		typeof (source as Record<string, unknown>).installReverseItem === "function"
	) {
		const fn = (source as Record<string, unknown>).installReverseItem as Function;
		return fn.bind(source) as ReverseInstallCallback;
	}
	return undefined;
}

function reverseSelectionDescription(
	item: ReverseToolStatus | ReverseServiceStatus,
	status: string,
	isZh: boolean,
): string {
	const localize = (key: string, fallback: string) => (isZh ? (CLI_TRANSLATIONS_ZH_CN[key] ?? fallback) : fallback);
	const description = localize(`cli.setup.reverse.tool.${item.id}.description`, item.description);
	const purpose = item.usage?.whenToUse
		? localize(`cli.setup.reverse.tool.${item.id}.purpose`, item.usage.whenToUse)
		: undefined;
	return [
		`${localize("cli.setup.reverse.selection.description", "Description")}: ${description}`,
		...(purpose ? [`${localize("cli.setup.reverse.selection.purpose", "When to use")}: ${purpose}`] : []),
		`${localize("cli.setup.reverse.selection.status", "Status")}: ${status}`,
	].join("\n");
}

export async function runInteractiveReverseSetup(
	ctx: InteractiveModeContext,
	targetTool?: string,
	installCallback?: (
		item: ReverseToolStatus | ReverseServiceStatus,
	) => Promise<{ success: boolean; message?: string } | void>,
	options?: { isTTY?: boolean },
): Promise<void> {
	const isZh = getEffectiveLocale() === "zh-CN";

	const isInteractive = Boolean(
		(options?.isTTY ?? ctx.isTTY ?? process.stdin.isTTY) && typeof ctx.showHookSelector === "function",
	);

	if (!isInteractive) {
		const report = checkReverseTools();
		const title = isZh
			? targetTool
				? `逆向工具 — ${targetTool}`
				: "逆向工程工具链状态"
			: targetTool
				? `Reverse Tool — ${targetTool}`
				: "Reverse Engineering Toolchain";
		const markdown = formatCompactReverseReport(report, targetTool, isZh);
		ctx.showCommandReport({
			title,
			body: new Markdown(markdown.trim(), 0, 0, getMarkdownTheme()),
		});
		return;
	}

	let report: ReverseCheckReport | undefined;
	const selectedIds = new Set<string>();
	let currentFilter: "all" | "missing" | "services" = "all";

	if (targetTool) {
		report = checkReverseTools();
		const norm = targetTool.toLowerCase();
		// 1. Exact ID match first (prevents "ida" matching "frida")
		let targetItem: ReverseToolStatus | ReverseServiceStatus | undefined =
			report.tools.find(t => t.id.toLowerCase() === norm) ??
			report.services.find(s => s.id.toLowerCase() === norm || s.serverName.toLowerCase() === norm);
		// 2. Exact name match second
		if (!targetItem) {
			targetItem =
				report.tools.find(t => t.name.toLowerCase() === norm) ??
				report.services.find(s => s.name.toLowerCase() === norm);
		}
		// 3. Substring match last
		if (!targetItem) {
			targetItem =
				report.tools.find(t => t.id.toLowerCase().includes(norm) || t.name.toLowerCase().includes(norm)) ??
				report.services.find(
					s =>
						s.id.toLowerCase().includes(norm) ||
						s.serverName.toLowerCase().includes(norm) ||
						s.name.toLowerCase().includes(norm),
				);
		}
		if (targetItem) {
			await showItemDetails(
				ctx,
				targetItem,
				() => {
					report = checkReverseTools();
					return report;
				},
				installCallback,
				isZh,
				report,
			);
			return;
		}
		ctx.showWarning?.(
			isZh ? `未在目录中找到工具或服务: "${targetTool}"` : `Tool/service "${targetTool}" not found in catalog.`,
		);
	}

	let isFirstRound = true;
	while (true) {
		if (!isFirstRound || !report) {
			report = checkReverseTools();
		}
		isFirstRound = false;
		const allItems: Array<ReverseToolStatus | ReverseServiceStatus> = [...report.tools, ...report.services];
		const missingTools = report.tools.filter(t => t.status === "missing");
		const missingServices = report.services.filter(s => !s.ready || !s.configured);
		const totalMissing = missingTools.length + missingServices.length;

		const missingSupportedItems = allItems.filter(item => {
			const isMissing = item.kind === "cli" ? item.status === "missing" : !item.ready || !item.configured;
			return isMissing && canInstallReverseItem(item, { report });
		});

		const filterLabelAll =
			currentFilter === "all"
				? isZh
					? `● 全部 (${report.tools.length + report.services.length})`
					: `● All (${report.tools.length + report.services.length})`
				: isZh
					? `○ 切换筛选：全部 (${report.tools.length + report.services.length})`
					: `○ Filter: All (${report.tools.length + report.services.length})`;
		const filterLabelMissing =
			currentFilter === "missing"
				? isZh
					? `● 仅缺失 (${totalMissing})`
					: `● Missing only (${totalMissing})`
				: isZh
					? `○ 切换筛选：仅缺失 (${totalMissing})`
					: `○ Filter: Missing only (${totalMissing})`;
		const filterLabelServices =
			currentFilter === "services"
				? isZh
					? `● 仅辅助服务 (${report.services.length})`
					: `● MCP services only (${report.services.length})`
				: isZh
					? `○ 切换筛选：仅辅助服务 (${report.services.length})`
					: `○ Filter: MCP services only (${report.services.length})`;

		const items: Array<{ label: string; description?: string }> = [
			{
				label: filterLabelAll,
				description: isZh ? "显示所有 CLI 工具与 MCP 辅助服务" : "Show all CLI tools and MCP services",
			},
			{
				label: filterLabelMissing,
				description: isZh
					? "仅显示未安装的 CLI 工具或缺少依赖的 MCP 服务"
					: "Show only missing tools or unready services",
			},
			{
				label: filterLabelServices,
				description: isZh ? "仅显示 MCP 辅助服务" : "Show only MCP services",
			},
		];

		if (selectedIds.size > 0) {
			items.push({
				label: isZh ? `🚀 执行安装已选项目 (${selectedIds.size})` : `🚀 Install selected (${selectedIds.size})`,
				description: isZh
					? `一键安装或配置选中的 ${selectedIds.size} 个工具/服务（单次确认）`
					: `Install or configure ${selectedIds.size} selected item(s) with single confirmation`,
			});
			items.push({
				label: isZh ? "✕ 清空所选" : "✕ Clear selection",
				description: isZh ? "取消所有已勾选的工具和服务" : "Deselect all selected items",
			});
		}

		if (missingSupportedItems.length > 0) {
			items.push({
				label: isZh
					? `⚡ 一键安装全部缺失 (${missingSupportedItems.length})`
					: `⚡ Install all missing supported (${missingSupportedItems.length})`,
				description: isZh
					? `安装/配置所有支持自动化的缺失工具与服务 (${missingSupportedItems.length} 个)`
					: `Install/configure all ${missingSupportedItems.length} missing supported item(s)`,
			});
		}

		items.push({
			label: isZh ? "📖 查看工具详情与指南..." : "📖 View item details & guides...",
			description: isZh
				? "查看具体工具的详细说明、安装指南与 MCP 配置片段"
				: "Inspect detailed descriptions, guides, and MCP config snippets",
		});

		const visibleTools =
			currentFilter === "services" ? [] : currentFilter === "missing" ? missingTools : report.tools;
		const visibleServices = currentFilter === "missing" ? missingServices : report.services;

		for (const tool of visibleTools) {
			const isOk = tool.status === "installed";
			const badge = isOk ? "✅" : "❌";
			const installable = canInstallReverseItem(tool, { report });
			const isSelected = selectedIds.has(tool.id);
			const checkmark = isSelected ? "[✓]" : installable ? "[ ]" : "[-]";
			items.push({
				label: `${checkmark} ${badge} [CLI] ${tool.name} (${tool.id})`,
				description: reverseSelectionDescription(
					tool,
					`[${tool.category}] ${
						isOk
							? isZh
								? `已安装 (${tool.foundPath ?? "已就绪"})`
								: `Installed (${tool.foundPath ?? "ready"})`
							: installable
								? tool.installCommand
									? `${isZh ? "支持自动安装" : "Install"}: ${tool.installCommand}`
									: isZh
										? "支持自动安装"
										: "Supported auto-install"
								: isZh
									? "需手动下载安装（选择查看指南）"
									: "Manual install required (select for guide)"
					}${isSelected ? (isZh ? " • 已加入安装篮" : " • Selected for install") : ""}`,
					isZh,
				),
			});
		}

		if (currentFilter !== "all" || visibleServices.length > 0) {
			for (const service of visibleServices) {
				const badge = service.ready ? "✅" : "⚠️";
				const installable = canInstallReverseItem(service, { report });
				const isSelected = selectedIds.has(service.id);
				const checkmark = isSelected ? "[✓]" : installable ? "[ ]" : "[-]";
				const configState = service.configured
					? isZh
						? `已配置(${service.configuredScopes.join(", ")})`
						: `configured (${service.configuredScopes.join(", ")})`
					: isZh
						? "未配置"
						: "not configured";
				const connectionState = isZh ? "连接未验证" : "connection unverified";
				items.push({
					label: `${checkmark} ${badge} [MCP] ${service.name} (${service.id})`,
					description: reverseSelectionDescription(
						service,
						`[${service.category}] ${
							service.missingPrerequisites.length > 0
								? isZh
									? `缺少依赖: ${service.missingPrerequisites.join(", ")}`
									: `Missing: ${service.missingPrerequisites.join(", ")}`
								: service.installed === false
									? isZh
										? "服务包未安装"
										: "Service package not installed"
									: isZh
										? "前置依赖已就绪"
										: "Prerequisites ready"
						} • ${configState} • ${connectionState}${isSelected ? (isZh ? " • 已加入安装篮" : " • Selected for install") : ""}`,
						isZh,
					),
				});
			}
		}

		items.push({
			label: isZh ? "← 退出面板" : "← Exit",
			description: isZh ? "关闭逆向工程工具链面板" : "Close reverse engineering setup panel",
		});

		const title = isZh ? "逆向工程工具链" : "Reverse Engineering Toolchain";
		const selected = await ctx.showHookSelector(title, items, { selectedDescriptionRows: 5 });
		if (!selected || selected.includes("← Exit") || selected.includes("← 退出")) {
			break;
		}

		if (
			selected === filterLabelAll ||
			selected.includes("Filter: All") ||
			(selected.includes("全部") && selected.includes("筛选"))
		) {
			currentFilter = "all";
			continue;
		}
		if (
			selected === filterLabelMissing ||
			selected.includes("Filter: Missing only") ||
			(selected.includes("仅缺失") && selected.includes("筛选"))
		) {
			currentFilter = "missing";
			continue;
		}
		if (
			selected === filterLabelServices ||
			selected.includes("Filter: MCP services only") ||
			(selected.includes("仅辅助服务") && selected.includes("筛选"))
		) {
			currentFilter = "services";
			continue;
		}

		if (selected.includes("Clear selection") || selected.includes("清空所选")) {
			selectedIds.clear();
			ctx.showStatus?.(isZh ? "已清空所选项。" : "Cleared selection.");
			continue;
		}

		if (selected.includes("Install selected") || selected.includes("安装已选项目")) {
			const targets = allItems.filter(item => selectedIds.has(item.id) && canInstallReverseItem(item, { report }));
			if (targets.length === 0) {
				ctx.showWarning?.(isZh ? "未选择任何可安装的工具或服务。" : "No installable items selected.");
				continue;
			}
			await runBatchInstall(
				ctx,
				targets,
				selectedIds,
				() => {
					report = checkReverseTools();
					return report;
				},
				installCallback,
				isZh,
				report,
			);
			continue;
		}

		if (
			selected.includes("Install all missing supported") ||
			selected.includes("一键安装全部缺失") ||
			selected.includes("安装全部缺失")
		) {
			if (missingSupportedItems.length === 0) {
				ctx.showWarning?.(isZh ? "没有缺失的可安装工具或服务。" : "No missing installable items.");
				continue;
			}
			await runBatchInstall(
				ctx,
				missingSupportedItems,
				selectedIds,
				() => {
					report = checkReverseTools();
					return report;
				},
				installCallback,
				isZh,
				report,
			);
			continue;
		}

		if (selected.includes("View item details & guides") || selected.includes("查看工具详情与指南")) {
			await showGuidePicker(
				ctx,
				allItems,
				() => {
					report = checkReverseTools();
					return report;
				},
				installCallback,
				isZh,
				report,
			);
			continue;
		}

		const match = /\(([^)]+)\)$/.exec(selected.trim());
		const chosenId = match ? match[1] : undefined;
		if (!chosenId) continue;

		const chosenTool = report.tools.find(t => t.id === chosenId);
		const chosenService = chosenTool ? undefined : report.services.find(s => s.id === chosenId);
		const item = chosenTool ?? chosenService;
		if (!item) continue;

		if (!canInstallReverseItem(item, { report })) {
			ctx.showStatus?.(isZh ? `${item.name} 仅支持手动安装。` : `${item.name} requires manual installation.`);
			await showItemDetails(
				ctx,
				item,
				() => {
					report = checkReverseTools();
					return report;
				},
				installCallback,
				isZh,
				report,
			);
			continue;
		}

		if (selectedIds.has(chosenId)) {
			selectedIds.delete(chosenId);
			ctx.showStatus?.(isZh ? `已取消选择: ${item.name}` : `Deselected: ${item.name}`);
		} else {
			selectedIds.add(chosenId);
			ctx.showStatus?.(isZh ? `已加入待安装列表: ${item.name}` : `Added to install basket: ${item.name}`);
		}
	}
}

function buildInstallConfirmationMessage(
	targetPlans: Array<{ item: ReverseToolStatus | ReverseServiceStatus; plan: ReverseInstallPlan }>,
	isZh: boolean,
): { title: string; message: string } {
	const count = targetPlans.length;
	const title =
		count === 1
			? isZh
				? `确认执行安装: ${targetPlans[0]!.item.name}`
				: `Confirm Installation: ${targetPlans[0]!.item.name}`
			: isZh
				? `确认批量安装/配置 (${count} 项)`
				: `Confirm Batch Installation (${count} items)`;

	const lines: string[] = [
		count === 1
			? isZh
				? `即将安装或配置以下工具/服务：`
				: `Ready to install or configure:`
			: isZh
				? `即将安装或配置以下 ${count} 个逆向工程工具/服务：`
				: `Ready to install or configure ${count} reverse engineering tool(s)/service(s):`,
		"",
	];

	for (const { item, plan } of targetPlans) {
		const typeTag = item.kind === "cli" ? "CLI" : "MCP";
		lines.push(`• ${item.name} (${item.id}) [${typeTag}]`);

		for (const step of plan.steps) {
			if (step.isDependency) {
				lines.push(`    - ${isZh ? "前置依赖" : "Prerequisite"}: ${step.name} (${step.command ?? "install"})`);
			} else if (step.command) {
				lines.push(`    - ${isZh ? "执行命令" : "Command"}: ${step.command}`);
			}
			if (step.riskNote) {
				lines.push(`      ${isZh ? "风险与许可说明" : "Risk / License note"}: ${step.riskNote}`);
			}
		}

		if (plan.missingDependencies.length > 0) {
			lines.push(`    - ${isZh ? "前置依赖要求" : "Dependencies"}: ${plan.missingDependencies.join(", ")}`);
		}

		if (item.riskNote && !plan.steps.some(s => s.riskNote === item.riskNote)) {
			lines.push(`    - ${isZh ? "风险提示" : "Risk / Notes"}: ${item.riskNote}`);
		}
		if (item.kind === "mcp") {
			lines.push(
				`    - ${isZh ? "目标配置路径" : "Config Scope"}: ${item.configPath} (${isZh ? "自动配置并热连接" : "auto-configured & hot connected"})`,
			);
		}
	}

	lines.push("");
	lines.push(
		count === 1
			? isZh
				? "是否现在开始执行安装？"
				: "Do you want to run this installation command now?"
			: isZh
				? "是否现在确认并执行以上所有安装与配置？"
				: "Do you want to confirm and execute all installations and configurations now?",
	);

	return { title, message: lines.join("\n") };
}

async function runBatchInstall(
	ctx: InteractiveModeContext,
	targets: Array<ReverseToolStatus | ReverseServiceStatus>,
	selectedIds: Set<string>,
	refreshReport: () => ReverseCheckReport,
	installCallback: ReverseInstallCallback | undefined,
	isZh: boolean,
	report?: ReverseCheckReport,
): Promise<void> {
	if (targets.length === 0) {
		ctx.showWarning?.(isZh ? "未选择任何可安装的工具或服务。" : "No installable items selected.");
		return;
	}

	const callback =
		installCallback ??
		(typeof ctx.installReverseItem === "function" ? ctx.installReverseItem.bind(ctx) : getInstallCallback(ctx));

	if (!callback) {
		ctx.showWarning?.(
			isZh
				? "当前环境未配置安装执行器。无法执行自动安装。"
				: "No installer executor available in current environment.",
		);
		return;
	}

	const validTargets: Array<{ item: ReverseToolStatus | ReverseServiceStatus; plan: ReverseInstallPlan }> = [];
	for (const target of targets) {
		let plan: ReverseInstallPlan;
		try {
			plan = getReverseInstallPlan(target, { report });
		} catch (err) {
			ctx.showError?.(
				isZh
					? `无法生成 ${target.name} 的安全安装方案: ${err instanceof Error ? err.message : String(err)}`
					: `Cannot resolve installation plan for ${target.name}: ${err instanceof Error ? err.message : String(err)}`,
			);
			continue;
		}
		if (!plan.canInstall) {
			ctx.showError?.(
				isZh
					? `${target.name} 不支持自动安装: ${plan.reason ?? "缺少有效安装指令"}`
					: `${target.name} cannot be installed automatically: ${plan.reason ?? "no valid recipe"}`,
			);
			continue;
		}
		validTargets.push({ item: target, plan });
	}

	if (validTargets.length === 0) {
		ctx.showWarning?.(
			isZh ? "没有可通过方案自动安装的有效项目。" : "No valid installable items with an actionable plan.",
		);
		return;
	}

	if (typeof ctx.showHookConfirm !== "function") {
		ctx.showWarning?.(
			isZh
				? "当前环境缺少交互式确认界面，已拒绝执行安装。"
				: "Interactive confirmation interface not available; installation refused.",
		);
		return;
	}

	const { title: confirmTitle, message: confirmMessage } = buildInstallConfirmationMessage(validTargets, isZh);
	const confirmed = await ctx.showHookConfirm(confirmTitle, confirmMessage);
	if (!confirmed) {
		ctx.showStatus?.(isZh ? "已取消批量安装。" : "Batch installation cancelled.");
		return;
	}

	let successCount = 0;
	let failCount = 0;
	const failureMessages: string[] = [];
	const executedStepIds = new Set<string>();

	for (const { item: target, plan } of validTargets) {
		if (executedStepIds.has(target.id)) {
			// Already installed and verified as a prerequisite dependency of an earlier item in this batch
			successCount++;
			selectedIds.delete(target.id);
			ctx.showStatus?.(
				isZh
					? `✅ ${target.name} 已在前置依赖中安装并就绪。`
					: `✅ ${target.name} was already installed and ready as a prerequisite dependency.`,
			);
			continue;
		}

		ctx.showStatus?.(
			isZh ? `正在处理 ${target.name} (${target.id})...` : `Processing ${target.name} (${target.id})...`,
		);
		try {
			const res = await callback(target, { plan });
			if (res && typeof res === "object" && "success" in res) {
				if (res.success) {
					successCount++;
					selectedIds.delete(target.id);
					for (const step of plan.steps) {
						executedStepIds.add(step.id);
					}
					executedStepIds.add(target.id);
					ctx.showStatus?.(
						res.message ?? (isZh ? `✅ ${target.name} 安装成功。` : `✅ Successfully installed ${target.name}.`),
					);
				} else {
					failCount++;
					const msg = res.message ?? (isZh ? "安装失败" : "Installation failed");
					failureMessages.push(`${target.name}: ${msg}`);
					ctx.showError?.(
						isZh ? `❌ ${target.name} 安装失败: ${msg}` : `❌ ${target.name} installation failed: ${msg}`,
					);
				}
			} else {
				successCount++;
				selectedIds.delete(target.id);
				for (const step of plan.steps) {
					executedStepIds.add(step.id);
				}
				executedStepIds.add(target.id);
				ctx.showStatus?.(
					isZh ? `✅ ${target.name} 安装命令已触发。` : `✅ Installation triggered for ${target.name}.`,
				);
			}
		} catch (err) {
			failCount++;
			const msg = err instanceof Error ? err.message : String(err);
			failureMessages.push(`${target.name}: ${msg}`);
			ctx.showError?.(isZh ? `❌ ${target.name} 执行出错: ${msg}` : `❌ Error installing ${target.name}: ${msg}`);
		}
	}

	refreshReport();

	if (failCount > 0) {
		ctx.showWarning?.(
			isZh
				? `批量安装完成：${successCount} 项成功，${failCount} 项失败。\n失败详情：\n${failureMessages.join("\n")}`
				: `Batch installation complete: ${successCount} succeeded, ${failCount} failed.\nFailures:\n${failureMessages.join("\n")}`,
		);
	} else {
		ctx.showStatus?.(
			isZh
				? `✅ 批量安装全部成功 (${successCount} 项)`
				: `✅ Successfully completed batch installation (${successCount} item(s))`,
		);
	}
}

async function showGuidePicker(
	ctx: InteractiveModeContext,
	allItems: Array<ReverseToolStatus | ReverseServiceStatus>,
	refreshReport: () => ReverseCheckReport,
	installCallback: ReverseInstallCallback | undefined,
	isZh: boolean,
	report?: ReverseCheckReport,
): Promise<void> {
	const guideItems: Array<{ label: string; description?: string }> = allItems.map(item => {
		const isOk = item.kind === "cli" ? item.status === "installed" : item.ready;
		const badge = isOk ? "✅" : item.kind === "cli" ? "❌" : "⚠️";
		const kindTag = item.kind === "cli" ? "[CLI]" : "[MCP]";
		const statusText =
			item.kind === "cli"
				? isOk
					? isZh
						? "已安装"
						: "Installed"
					: isZh
						? "未安装"
						: "Missing"
				: item.ready
					? isZh
						? "就绪"
						: "Ready"
					: isZh
						? "未就绪"
						: "Not ready";
		return {
			label: `${badge} ${kindTag} ${item.name} (${item.id})`,
			description: reverseSelectionDescription(item, statusText, isZh),
		};
	});
	guideItems.push({
		label: isZh ? "← 返回列表" : "← Back to list",
		description: isZh ? "返回逆向工具与服务列表" : "Return to tools and services list",
	});

	const choice = await ctx.showHookSelector(
		isZh ? "查看工具详情与完整指南" : "Inspect Tool Details & Guide",
		guideItems,
		{ selectedDescriptionRows: 5 },
	);
	if (!choice || choice.includes("← Back") || choice.includes("← 返回")) {
		return;
	}

	const match = /\(([^)]+)\)$/.exec(choice.trim());
	const id = match ? match[1] : undefined;
	const item = id ? allItems.find(i => i.id === id) : undefined;
	if (item) {
		await showItemDetails(ctx, item, refreshReport, installCallback, isZh, report);
	}
}

async function showItemDetails(
	ctx: InteractiveModeContext,
	initialItem: ReverseToolStatus | ReverseServiceStatus,
	refreshReport: () => ReverseCheckReport,
	installCallback: ReverseInstallCallback | undefined,
	isZh: boolean,
	initialReport?: ReverseCheckReport,
): Promise<void> {
	let currentItem = initialItem;
	let currentReport = initialReport;

	while (true) {
		const isInstalled = currentItem.kind === "cli" ? currentItem.status === "installed" : currentItem.ready;
		const canInstall = canInstallReverseItem(currentItem, { report: currentReport });
		const options: Array<{ label: string; description?: string }> = [];

		if (canInstall) {
			if (currentItem.kind === "cli") {
				options.push({
					label: isInstalled
						? isZh
							? `重新安装: ${currentItem.installCommand ?? currentItem.name}`
							: `Reinstall: ${currentItem.installCommand ?? currentItem.name}`
						: isZh
							? `安装: ${currentItem.installCommand ?? currentItem.name}`
							: `Install: ${currentItem.installCommand ?? currentItem.name}`,
					description: currentItem.packageManager
						? `[${currentItem.packageManager}] ${currentItem.riskNote ?? ""}`
						: (currentItem.riskNote ?? undefined),
				});
			} else {
				const isManaged = currentItem.installer === "jshookmcp" || currentItem.installer === "native-mcp";
				const isInstalled = currentItem.installed === true;
				options.push({
					label: isManaged
						? isInstalled
							? isZh
								? `检查/连接服务: ${currentItem.name}`
								: `Verify/Connect Service: ${currentItem.name}`
							: isZh
								? `安装受信任服务: ${currentItem.name}`
								: `Install Trusted Service: ${currentItem.name}`
						: currentItem.installCommand
							? isZh
								? `安装服务包: ${currentItem.installCommand}`
								: `Install Server Package: ${currentItem.installCommand}`
							: isZh
								? `配置并连接服务: ${currentItem.name}`
								: `Configure & Connect Service: ${currentItem.name}`,
					description: isManaged
						? isZh
							? `[内置管理] ${currentItem.riskNote}`
							: `[managed] ${currentItem.riskNote}`
						: currentItem.packageManager
							? `[${currentItem.packageManager}] ${currentItem.riskNote}`
							: currentItem.riskNote,
				});
			}
		} else {
			options.push({
				label: isZh ? `⚠️ [仅支持手动安装] ${currentItem.name}` : `⚠️ [Manual Install Only] ${currentItem.name}`,
				description:
					currentItem.manualInstructions ||
					(isZh
						? "此工具需手动下载和配置，无法自动安装"
						: "This tool requires manual download and setup; automatic installation is not supported."),
			});
		}

		if (currentItem.kind === "mcp") {
			options.push({
				label: isZh ? "查看 MCP 配置片段" : "Show MCP Config Snippet",
				description: isZh
					? `项目路径: ${currentItem.configPaths.project}`
					: `Project path: ${currentItem.configPaths.project}`,
			});
		}

		options.push({
			label: isZh ? "查看完整指南" : "View Full Guide",
			description: isZh ? "在独立面板中查看详细指南与说明" : "Show full description, links, and instructions",
		});

		options.push({
			label: isZh ? "← 返回列表" : "← Back to list",
			description: isZh ? "返回逆向工具与服务列表" : "Return to tools and services list",
		});

		const title =
			currentItem.kind === "cli"
				? `${currentItem.name} (${currentItem.id}) — ${
						isInstalled ? (isZh ? "已安装/就绪" : "Installed/Ready") : isZh ? "未安装/缺失" : "Missing"
					}`
				: `${currentItem.name} (${currentItem.id}) — ${
						currentItem.prerequisitesReady
							? isZh
								? "前置依赖就绪"
								: "Prerequisites ready"
							: isZh
								? "前置依赖缺失"
								: "Prerequisites missing"
					}${currentItem.configured ? (isZh ? " / 已配置" : " / configured") : isZh ? " / 未配置" : " / not configured"}`;

		const action = await ctx.showHookSelector(title, options);
		if (!action || action.includes("← Back") || action.includes("← 返回")) {
			break;
		}

		if (action.includes("Manual Install Only") || action.includes("仅支持手动安装")) {
			const report = refreshReport();
			const markdown = formatCompactReverseReport(report, currentItem.id, isZh);
			ctx.showCommandReport({
				title: `${currentItem.name} (${isZh ? "手动安装说明" : "Manual Installation"})`,
				body: new Markdown(markdown.trim(), 0, 0, getMarkdownTheme()),
			});
			ctx.showWarning?.(
				isZh
					? `${currentItem.name} 仅支持手动安装。请参考下方指南中的手动步骤。`
					: `${currentItem.name} requires manual installation. Please follow manual guide.`,
			);
			continue;
		}

		if (action.includes("View Full Guide") || action.includes("查看完整指南")) {
			const report = refreshReport();
			const markdown = formatCompactReverseReport(report, currentItem.id, isZh);
			ctx.showCommandReport({
				title: currentItem.name,
				body: new Markdown(markdown.trim(), 0, 0, getMarkdownTheme()),
			});
			continue;
		}

		if (action.includes("Show MCP Config Snippet") || action.includes("查看 MCP 配置片段")) {
			if (currentItem.kind === "mcp") {
				const service = currentItem;
				const snippetLines = [
					`# ${service.name} (\`${service.id}\`) — MCP`,
					"",
					`- **${isZh ? "项目配置路径" : "Project config path"}**: \`${service.configPaths.project}\``,
					`- **${isZh ? "用户配置路径" : "User config path"}**: \`${service.configPaths.user}\``,
					`- **${isZh ? "配置状态" : "Configured"}**: ${service.configured ? service.configuredScopes.join(", ") + (service.enabled === false ? (isZh ? "（已禁用）" : " (disabled)") : "") : isZh ? "否" : "no"}`,
					`- **${isZh ? "连接状态" : "Connection"}**: ${isZh ? "未验证（只读检查不会启动服务）" : "unverified (read-only inspection never starts the server)"}`,
					`- **${isZh ? "启动命令" : "Start command"}**: \`${service.startCommand}\``,
					`- **${isZh ? "规范用法" : "Canonical usage"}**: \`${service.usage.canonical}\``,
					"",
					`### ${isZh ? "MCP 配置片段" : "MCP Config Snippet"}`,
					"```json",
					JSON.stringify(service.configSnippet, null, 2),
					"```",
					"",
					`> ${isZh ? "提示：MCP 服务不是 PATH 二进制；片段需手动合并到上述配置文件。检查过程不会写入 mcp.json，也不会验证连接。" : "Tip: MCP services are not PATH binaries; merge the snippet into one of the paths above manually. Inspection never writes mcp.json or verifies a connection."}`,
				];
				ctx.showCommandReport({
					title: `${service.name} — MCP Config`,
					body: new Markdown(snippetLines.join("\n"), 0, 0, getMarkdownTheme()),
				});
				ctx.showStatus?.(
					isZh ? `已显示 ${service.name} 的 MCP 配置片段` : `Displayed MCP config snippet for ${service.name}`,
				);
			}
			continue;
		}

		if (
			action.startsWith("Install") ||
			action.startsWith("安装") ||
			action.startsWith("Reinstall") ||
			action.startsWith("重新安装") ||
			action.startsWith("检查/连接服务") ||
			action.startsWith("Verify/Connect Service") ||
			action.includes("安装服务包") ||
			action.includes("安装受信任服务") ||
			action.includes("Install Trusted Service") ||
			action.includes("配置并连接服务") ||
			action.includes("Configure & Connect Service")
		) {
			let plan: ReverseInstallPlan;
			try {
				plan = getReverseInstallPlan(currentItem, { report: currentReport });
			} catch (err) {
				ctx.showError?.(
					isZh
						? `无法生成 ${currentItem.name} 的安全安装方案: ${err instanceof Error ? err.message : String(err)}`
						: `Cannot resolve installation plan for ${currentItem.name}: ${err instanceof Error ? err.message : String(err)}`,
				);
				continue;
			}

			if (!plan.canInstall) {
				ctx.showError?.(
					isZh
						? `${currentItem.name} 不支持自动安装: ${plan.reason ?? "缺少有效安装指令"}`
						: `${currentItem.name} cannot be installed automatically: ${plan.reason ?? "no valid recipe"}`,
				);
				continue;
			}

			if (typeof ctx.showHookConfirm !== "function") {
				ctx.showWarning?.(
					isZh
						? "当前环境缺少交互式确认界面，已拒绝执行安装。"
						: "Interactive confirmation interface not available; installation refused.",
				);
				continue;
			}

			const { title: confirmTitle, message: confirmMessage } = buildInstallConfirmationMessage(
				[{ item: currentItem, plan }],
				isZh,
			);

			const confirmed = await ctx.showHookConfirm(confirmTitle, confirmMessage);
			if (!confirmed) {
				ctx.showStatus?.(
					isZh ? `已取消 ${currentItem.name} 的安装。` : `Installation cancelled for ${currentItem.name}.`,
				);
				continue;
			}

			const callback =
				installCallback ??
				(typeof ctx.installReverseItem === "function" ? ctx.installReverseItem.bind(ctx) : getInstallCallback(ctx));
			if (callback) {
				const res = await callback(currentItem, { plan });
				if (res && typeof res === "object" && "success" in res) {
					if (res.success) {
						ctx.showStatus?.(
							res.message ??
								(isZh ? `✅ ${currentItem.name} 安装成功。` : `✅ Successfully installed ${currentItem.name}.`),
						);
					} else {
						ctx.showError?.(
							res.message ??
								(isZh
									? `❌ ${currentItem.name} 安装失败。`
									: `❌ Installation failed for ${currentItem.name}.`),
						);
					}
				} else {
					ctx.showStatus?.(
						isZh
							? `✅ ${currentItem.name} 安装命令已触发。`
							: `✅ Installation triggered for ${currentItem.name}.`,
					);
				}
				const refreshedReport = refreshReport();
				currentReport = refreshedReport;
				const refreshedItem =
					currentItem.kind === "cli"
						? refreshedReport.tools.find(t => t.id === currentItem.id)
						: refreshedReport.services.find(s => s.id === currentItem.id);
				if (refreshedItem) currentItem = refreshedItem;
			} else {
				ctx.showWarning?.(
					isZh
						? `当前环境未配置安装执行器。请在终端中运行：\n${currentItem.installCommand ?? currentItem.name}`
						: `No installer executor available. Please run in terminal:\n${currentItem.installCommand ?? currentItem.name}`,
				);
			}
		}
	}
}

export async function runInteractiveSetupMenu(
	ctx: InteractiveModeContext,
	installCallback?: ReverseInstallCallback,
	options?: { isTTY?: boolean },
): Promise<void> {
	const isZh = getEffectiveLocale() === "zh-CN";
	const isInteractive = Boolean(
		(options?.isTTY ?? ctx.isTTY ?? process.stdin.isTTY) && typeof ctx.showHookSelector === "function",
	);

	if (!isInteractive) {
		await ctx.showProviderSetup();
		return;
	}

	const panels = getAllLocalizedPanels(isZh);
	const exitLabel = isZh ? "← 退出" : "← Exit";
	const exitDesc = isZh ? "关闭设置菜单" : "Close setup menu";

	const selectorOptions = [
		...panels.map(p => ({
			label: p.label,
			description: p.description,
		})),
		{ label: exitLabel, description: exitDesc },
	];

	const title = isZh ? "系统与工具链配置 (Setup)" : "System & Toolchain Setup";
	const choice = await ctx.showHookSelector(title, selectorOptions);

	if (!choice || choice.includes("← Exit") || choice.includes("← 退出")) {
		return;
	}

	if (choice.includes("providers") || choice.includes("Providers") || choice.includes("模型服务商")) {
		await ctx.showProviderSetup();
	} else if (choice.includes("add") || choice.includes("Add") || choice.includes("添加自定义服务商")) {
		await ctx.showCustomProviderWizard();
	} else if (choice.includes("reverse") || choice.includes("Reverse") || choice.includes("逆向工程工具链")) {
		await runInteractiveReverseSetup(ctx, undefined, installCallback, options);
	} else if (choice.includes("python") || choice.includes("Python") || choice.includes("执行环境")) {
		await runInteractivePythonSetup(ctx, options);
	} else if (choice.includes("speech") || choice.includes("Speech") || choice.includes("语音识别与合成")) {
		await runInteractiveSpeechSetup(ctx, options);
	}
}

export async function runInteractivePythonSetup(
	ctx: InteractiveModeContext,
	options?: { isTTY?: boolean },
): Promise<void> {
	const isZh = getEffectiveLocale() === "zh-CN";
	const isInteractive = Boolean(
		(options?.isTTY ?? ctx.isTTY ?? process.stdin.isTTY) && typeof ctx.showHookSelector === "function",
	);

	const configuredInterpreter = ctx.settings ? cfgPythonInterpreter.get(ctx.settings)?.trim() || undefined : undefined;
	const check = await checkPythonSetup(process.cwd(), configuredInterpreter);

	if (!isInteractive) {
		const title = isZh ? "Python 执行环境状态" : "Python Execution Environment Status";
		const lines = [
			`# ${title}`,
			"",
			check.available
				? isZh
					? "✅ **Python 3 解释器已就绪**"
					: "✅ **Python 3 interpreter is ready**"
				: isZh
					? "❌ **未检测到有效的 Python 3 解释器**"
					: "❌ **No valid Python 3 interpreter detected**",
			"",
			`- **${isZh ? "当前解释器路径" : "Interpreter Path"}**: \`${check.pythonPath ?? (isZh ? "未找到" : "Not found")}\``,
			`- **${isZh ? "托管虚拟环境" : "Managed Environment"}**: \`${check.usingManagedEnv ? check.managedEnvPath : isZh ? "否" : "No"}\``,
			`- **${isZh ? "配置项 (python.interpreter)" : "Setting (python.interpreter)"}**: \`${configuredInterpreter ?? (isZh ? "自动探测" : "auto-probe")}\``,
		];
		if (!check.available) {
			lines.push(
				"",
				isZh
					? "> **提示**：系统未找到可用的 Python 3 解释器。可在终端中运行 `reverse setup python` 诊断，或在设置中配置 `python.interpreter`。"
					: "> **Action**: No working Python 3 found. Run `reverse setup python` in terminal or configure `python.interpreter` in settings.",
			);
		}
		if (typeof ctx.showCommandReport === "function") {
			ctx.showCommandReport({
				title,
				body: new Markdown(lines.join("\n"), 0, 0, getMarkdownTheme()),
			});
		} else {
			ctx.showStatus?.(check.available ? "Python ready" : "Python not found");
		}
		return;
	}

	while (true) {
		const currentInterp = ctx.settings ? cfgPythonInterpreter.get(ctx.settings)?.trim() || undefined : undefined;
		const currentCheck = await checkPythonSetup(process.cwd(), currentInterp);
		const runtimes = enumeratePythonRuntimes(process.cwd(), process.env);

		const title = isZh
			? `Python 执行环境 — ${currentCheck.available ? "已就绪" : "未就绪"}`
			: `Python Environment — ${currentCheck.available ? "Ready" : "Not Ready"}`;

		const menuItems = [
			{
				label: `${currentCheck.available ? "✅" : "❌"} ${isZh ? "解释器状态" : "Interpreter Status"}: ${currentCheck.pythonPath ?? (isZh ? "未检测到" : "Not found")}`,
				description: currentCheck.usingManagedEnv
					? isZh
						? "使用托管虚拟环境"
						: "Using managed virtualenv"
					: currentInterp
						? isZh
							? `配置项指定: ${currentInterp}`
							: `Configured: ${currentInterp}`
						: isZh
							? "PATH 自动发现"
							: "Discovered on PATH",
			},
			{
				label: isZh
					? `🔄 切换 / 选择 Python 解释器 (${runtimes.length} 个候选)`
					: `🔄 Select / Switch Python Interpreter (${runtimes.length} candidates)`,
				description: isZh
					? "从发现的系统解释器或虚拟环境中选择"
					: "Select from detected system runtimes or virtual environments",
			},
			{
				label: isZh ? "📄 查看完整诊断报告" : "📄 View Full Diagnostic Report",
				description: isZh ? "查看详细的解释器与环境配置信息" : "View detailed environment diagnostics",
			},
			{
				label: isZh ? "← 返回设置菜单" : "← Back to Setup Menu",
				description: isZh ? "返回主设置菜单" : "Return to setup menu",
			},
		];

		const choice = await ctx.showHookSelector(title, menuItems);
		if (!choice || choice.includes("← Back") || choice.includes("← 返回")) {
			break;
		}

		if (choice.includes("查看完整诊断报告") || choice.includes("View Full Diagnostic Report")) {
			const reportLines = [
				`# ${isZh ? "Python 执行环境详细报告" : "Python Execution Environment Report"}`,
				"",
				`- **${isZh ? "状态" : "Status"}**: ${currentCheck.available ? "✅ " + (isZh ? "就绪" : "Ready") : "❌ " + (isZh ? "不可用" : "Unavailable")}`,
				`- **${isZh ? "解释器" : "Interpreter"}**: \`${currentCheck.pythonPath ?? (isZh ? "无" : "none")}\``,
				`- **${isZh ? "托管虚拟环境" : "Managed Env"}**: \`${currentCheck.managedEnvPath ?? (isZh ? "无" : "none")}\``,
				`- **${isZh ? "配置项" : "Configuration"}**: \`${currentInterp ?? (isZh ? "（未配置，自动检测）" : "(not set, auto-detect)")}\``,
				"",
				`### ${isZh ? "发现的候选 Python 运行时" : "Discovered Candidate Runtimes"}`,
				...runtimes.map((r, i) => `${i + 1}. \`${r.pythonPath}\`${r.venvPath ? ` (venv: \`${r.venvPath}\`)` : ""}`),
			];
			if (typeof ctx.showCommandReport === "function") {
				ctx.showCommandReport({
					title: isZh ? "Python 执行环境报告" : "Python Diagnostic Report",
					body: new Markdown(reportLines.join("\n"), 0, 0, getMarkdownTheme()),
				});
			}
			continue;
		}

		if (choice.includes("切换 / 选择") || choice.includes("Select / Switch")) {
			if (runtimes.length === 0) {
				ctx.showWarning?.(
					isZh
						? "未在系统中发现任何 Python 3 解释器候选。"
						: "No Python 3 interpreter candidates discovered on system.",
				);
				continue;
			}
			const runtimeOptions = [
				...runtimes.map(r => ({
					label: r.pythonPath,
					description: r.venvPath
						? isZh
							? `虚拟环境: ${r.venvPath}`
							: `Virtualenv: ${r.venvPath}`
						: isZh
							? "系统 Python"
							: "System Python",
				})),
				{
					label: isZh ? "← 返回" : "← Back",
					description: isZh ? "取消并返回上一层" : "Cancel and go back",
				},
			];
			const picked = await ctx.showHookSelector(
				isZh ? "选择要配置的 Python 解释器" : "Select Python Interpreter",
				runtimeOptions,
			);
			if (!picked || picked.includes("← Back") || picked.includes("← 返回")) {
				continue;
			}
			const selectedRuntime = runtimes.find(r => r.pythonPath === picked);
			if (selectedRuntime) {
				const confirmMsg = isZh
					? `是否确认将 Python 解释器设置为:\n${selectedRuntime.pythonPath}`
					: `Set python.interpreter to:\n${selectedRuntime.pythonPath}?`;
				const confirmed =
					typeof ctx.showHookConfirm === "function"
						? await ctx.showHookConfirm(isZh ? "确认配置解释器" : "Confirm Python Interpreter", confirmMsg)
						: true;
				if (confirmed) {
					if (ctx.settings) {
						cfgPythonInterpreter.set(ctx.settings, selectedRuntime.pythonPath);
						await ctx.settings.flush();
					}
					ctx.showStatus?.(
						isZh
							? `✅ Python 解释器已设置为 ${selectedRuntime.pythonPath}`
							: `✅ Python interpreter set to ${selectedRuntime.pythonPath}`,
					);
				}
			}
		}
	}
}

export async function runInteractiveSpeechSetup(
	ctx: InteractiveModeContext,
	options?: { isTTY?: boolean },
): Promise<void> {
	const isZh = getEffectiveLocale() === "zh-CN";
	const isInteractive = Boolean(
		(options?.isTTY ?? ctx.isTTY ?? process.stdin.isTTY) && typeof ctx.showHookSelector === "function",
	);

	let components: SpeechComponent[] = [];
	if (ctx.settings && ctx.session?.modelRegistry) {
		try {
			components = buildSpeechComponents(ctx.settings, ctx.session.modelRegistry);
		} catch {
			components = [];
		}
	}
	if (components.length === 0) {
		components = [
			{
				name: "Speech-to-Text model",
				isReady: async () => false,
				status: async () => "whisper-base — not downloaded",
				ensure: async () => {},
			},
			{
				name: "Text-to-Speech model",
				isReady: async () => false,
				status: async () => "kokoro — model/runtime not installed",
				ensure: async () => {},
			},
		];
	}

	if (!isInteractive) {
		const title = isZh ? "语音识别与合成模型状态" : "Speech STT & TTS Model Status";
		const lines = [`# ${title}`, ""];
		for (const comp of components) {
			const ready = await comp.isReady();
			const status = await comp.status();
			lines.push(`- **${comp.name}**: ${ready ? "✅ " : "⚠️ "}${status}`);
		}
		if (typeof ctx.showCommandReport === "function") {
			ctx.showCommandReport({
				title,
				body: new Markdown(lines.join("\n"), 0, 0, getMarkdownTheme()),
			});
		} else {
			ctx.showStatus?.("Speech setup inspected.");
		}
		return;
	}

	while (true) {
		const sttComp = components[0];
		const ttsComp = components[1];
		const sttReady = await sttComp.isReady();
		const ttsReady = await ttsComp.isReady();
		const sttStatus = await sttComp.status();
		const ttsStatus = await ttsComp.status();

		const title = isZh ? "语音识别与合成配置 (Speech)" : "Speech Recognition & Synthesis (Speech)";

		const menuItems = [
			{
				label: `${sttReady ? "✅" : "⚠️"} [STT] ${sttComp.name}: ${sttStatus}`,
				description: isZh
					? sttReady
						? "语音转文字模型已就绪，点击可切换或重新下载"
						: "语音转文字模型未下载，点击下载"
					: sttReady
						? "STT model ready; click to switch or re-download"
						: "STT model missing; click to download",
			},
			{
				label: `${ttsReady ? "✅" : "⚠️"} [TTS] ${ttsComp.name}: ${ttsStatus}`,
				description: isZh
					? ttsReady
						? "文字转语音模型已就绪，点击可切换或重新下载"
						: "文字转语音模型未就绪，点击下载"
					: ttsReady
						? "TTS model ready; click to switch or re-download"
						: "TTS model missing; click to download",
			},
		];

		if (!sttReady || !ttsReady) {
			menuItems.push({
				label: isZh ? "⬇️ 下载所有缺失的语音模型" : "⬇️ Download All Missing Speech Models",
				description: isZh ? "批量下载并准备未就绪的 STT / TTS 模型" : "Download and prepare all missing models",
			});
		}

		menuItems.push(
			{
				label: isZh ? "📄 查看语音模型说明与指南" : "📄 View Speech Models Guide & Status",
				description: isZh
					? "查看 STT / TTS 详细说明与键盘快捷键配置"
					: "View speech model documentation and keybindings",
			},
			{
				label: isZh ? "← 返回设置菜单" : "← Back to Setup Menu",
				description: isZh ? "返回主设置菜单" : "Return to setup menu",
			},
		);

		const choice = await ctx.showHookSelector(title, menuItems);
		if (!choice || choice.includes("← Back") || choice.includes("← 返回")) {
			break;
		}

		if (choice.includes("查看语音模型说明") || choice.includes("View Speech Models Guide")) {
			const guideLines = [
				`# ${isZh ? "语音识别与合成模型指南" : "Speech STT & TTS Guide"}`,
				"",
				`- **${sttComp.name}**: ${sttReady ? "✅ " : "⚠️ "}${sttStatus}`,
				`- **${ttsComp.name}**: ${ttsReady ? "✅ " : "⚠️ "}${ttsStatus}`,
				"",
				`### ${isZh ? "快捷键与用法" : "Usage & Keybindings"}`,
				`- **STT (${isZh ? "语音输入" : "Speech-to-Text"})**: ${isZh ? "启用 `stt.enabled`，长按空格键可进行语音转文字。" : "Enable `stt.enabled`, then hold spacebar to dictate."}`,
				`- **TTS (${isZh ? "语音朗读" : "Text-to-Speech"})**: ${isZh ? "启用 `speech.enabled`，可在助手回复时朗读内容。" : "Enable `speech.enabled` to have assistant responses spoken aloud."}`,
			];
			if (typeof ctx.showCommandReport === "function") {
				ctx.showCommandReport({
					title: isZh ? "语音模型指南" : "Speech Models Guide",
					body: new Markdown(guideLines.join("\n"), 0, 0, getMarkdownTheme()),
				});
			}
			continue;
		}

		if (choice.includes("下载所有缺失") || choice.includes("Download All Missing")) {
			const confirmMsg = isZh
				? "是否确认下载所有缺失的语音模型？这可能需要从网络下载约几十至几百 MB 数据。"
				: "Download all missing speech models now? This may download tens to hundreds of MB.";
			const confirmed =
				typeof ctx.showHookConfirm === "function"
					? await ctx.showHookConfirm(isZh ? "确认下载" : "Confirm Download", confirmMsg)
					: true;
			if (!confirmed) continue;

			for (const comp of components) {
				if (!(await comp.isReady())) {
					ctx.showStatus?.(isZh ? `正在准备 ${comp.name}...` : `Preparing ${comp.name}...`);
					try {
						await comp.ensure(progress => {
							const pct = progress.percent !== undefined ? ` (${progress.percent}%)` : "";
							ctx.showStatus?.(`${progress.stage}${pct}`);
						});
						ctx.showStatus?.(isZh ? `✅ ${comp.name} 准备就绪` : `✅ ${comp.name} ready`);
					} catch (err) {
						ctx.showError?.(
							err instanceof Error
								? err.message
								: isZh
									? `下载 ${comp.name} 失败`
									: `Failed to download ${comp.name}`,
						);
					}
				}
			}
			continue;
		}

		if (choice.includes("[STT]")) {
			const sttSubmenu = [
				{
					label: isZh ? `⬇️ 下载 / 更新模型 (${sttStatus})` : `⬇️ Download / Cache Model (${sttStatus})`,
					description: isZh ? "下载当前配置的语音识别模型权重" : "Download weights for current STT model",
				},
				{
					label: isZh ? "🔄 切换 STT 模型" : "🔄 Switch STT Model",
					description: isZh ? "从候选 Whisper 模型中选择" : "Select from candidate Whisper models",
				},
				{
					label: isZh ? "← 返回" : "← Back",
					description: isZh ? "返回语音设置" : "Return to speech setup",
				},
			];
			const sttChoice = await ctx.showHookSelector(sttComp.name, sttSubmenu);
			if (sttChoice?.includes("下载") || sttChoice?.includes("Download")) {
				const confirmed =
					typeof ctx.showHookConfirm === "function"
						? await ctx.showHookConfirm(
								isZh ? "确认下载 STT 模型" : "Confirm STT Download",
								isZh ? `是否开始下载 ${sttComp.name}？` : `Download ${sttComp.name} now?`,
							)
						: true;
				if (confirmed) {
					try {
						await sttComp.ensure(p => {
							const pct = p.percent !== undefined ? ` (${p.percent}%)` : "";
							ctx.showStatus?.(`${p.stage}${pct}`);
						});
						ctx.showStatus?.(isZh ? `✅ ${sttComp.name} 下载完成` : `✅ ${sttComp.name} download complete`);
					} catch (err) {
						ctx.showError?.(err instanceof Error ? err.message : String(err));
					}
				}
			} else if (sttChoice?.includes("切换") || sttChoice?.includes("Switch")) {
				const picked = await ctx.showHookSelector(isZh ? "选择语音转文字模型" : "Select STT Model", [
					...STT_MODEL_OPTIONS.map(opt => ({
						label: opt.value,
						description: opt.label,
					})),
					{ label: isZh ? "← 返回" : "← Back", description: "" },
				]);
				if (picked && !picked.includes("← Back") && !picked.includes("← 返回")) {
					if (ctx.settings) {
						ctx.settings.setModelRole("dictation", `local/${picked}`);
						await ctx.settings.flush();
					}
					ctx.showStatus?.(isZh ? `已将 STT 模型切换为 ${picked}` : `Switched STT model to ${picked}`);
				}
			}
			continue;
		}

		if (choice.includes("[TTS]")) {
			const ttsSubmenu = [
				{
					label: isZh ? `⬇️ 下载 / 更新模型 (${ttsStatus})` : `⬇️ Download / Cache Model (${ttsStatus})`,
					description: isZh ? "下载当前配置的文字转语音模型权重" : "Download weights for current TTS model",
				},
				{
					label: isZh ? "🔄 切换 TTS 模型" : "🔄 Switch TTS Model",
					description: isZh ? "从候选文字转语音模型中选择" : "Select from candidate TTS models",
				},
				{
					label: isZh ? "← 返回" : "← Back",
					description: isZh ? "返回语音设置" : "Return to speech setup",
				},
			];
			const ttsChoice = await ctx.showHookSelector(ttsComp.name, ttsSubmenu);
			if (ttsChoice?.includes("下载") || ttsChoice?.includes("Download")) {
				const confirmed =
					typeof ctx.showHookConfirm === "function"
						? await ctx.showHookConfirm(
								isZh ? "确认下载 TTS 模型" : "Confirm TTS Download",
								isZh ? `是否开始下载 ${ttsComp.name}？` : `Download ${ttsComp.name} now?`,
							)
						: true;
				if (confirmed) {
					try {
						await ttsComp.ensure(p => {
							const pct = p.percent !== undefined ? ` (${p.percent}%)` : "";
							ctx.showStatus?.(`${p.stage}${pct}`);
						});
						ctx.showStatus?.(isZh ? `✅ ${ttsComp.name} 准备就绪` : `✅ ${ttsComp.name} ready`);
					} catch (err) {
						ctx.showError?.(err instanceof Error ? err.message : String(err));
					}
				}
			} else if (ttsChoice?.includes("切换") || ttsChoice?.includes("Switch")) {
				const picked = await ctx.showHookSelector(isZh ? "选择文字转语音模型" : "Select TTS Model", [
					...TTS_LOCAL_MODELS.map(opt => ({
						label: opt.key,
						description: `${opt.label} — ${opt.description}`,
					})),
					{ label: isZh ? "← 返回" : "← Back", description: "" },
				]);
				if (picked && !picked.includes("← Back") && !picked.includes("← 返回")) {
					if (ctx.settings) {
						ctx.settings.setModelRole("speech", `local/${picked}`);
						await ctx.settings.flush();
					}
					ctx.showStatus?.(isZh ? `已将 TTS 模型切换为 ${picked}` : `Switched TTS model to ${picked}`);
				}
			}
			continue;
		}
	}
}

export const BUILTIN_MODE_SLASH_COMMANDS: ReadonlyArray<SlashCommandSpec> = [
	{
		name: "security",
		icon: "shield",
		description: "Plan, run, inspect, import, and compare REVERSE-native security scans",
		allowArgs: true,
		acpInputHint: "<plan|scan|status|cancel|scans|show|import|export|validate|compare|disposition>",
		subcommands: [
			{ name: "plan", description: "Create an immutable security scan plan" },
			{ name: "scan", description: "Start a planned or newly planned native scan" },
			{ name: "status", description: "Show native scan operation status" },
			{ name: "cancel", description: "Cancel a running native scan" },
			{ name: "scans", description: "List stored project security scans" },
			{ name: "show", description: "Render a scan or security:// resource" },
			{ name: "import", description: "Import SARIF or a Codex Security bundle" },
			{ name: "export", description: "Export a canonical bundle, SARIF, or report" },
			{ name: "validate", description: "Validate one finding with REVERSE-native tools" },
			{ name: "compare", description: "Compare finding lineage across two scans" },
			{ name: "disposition", description: "Set a finding disposition with rationale" },
		],
		handle: handleSecurityCommand,
	},
	{
		name: "settings",
		icon: "settings",
		description: "Open settings menu",
		handleTui: (_command, runtime) => {
			runtime.ctx.showSettingsSelector();
			clearSubmittedText(runtime);
		},
	},
	{
		name: "setup",
		aliases: ["providers"],
		icon: "gear",
		description: "Open system and toolchain setup menu",
		allowArgs: true,
		subcommands: [
			{ name: "providers", description: "Configure sign-in, API keys, and web search providers" },
			{ name: "add", description: "Add a custom OpenAI/Anthropic-compatible provider with model discovery" },
			{ name: "reverse", description: "Inspect and install reverse engineering tools and MCP services" },
			{ name: "python", description: "Verify and configure Python 3 interpreter and execution environment" },
			{ name: "speech", description: "Configure and download STT and TTS local models" },
		],
		handleTui: async (command, runtime) => {
			if (command.name === "providers") {
				await runtime.ctx.showProviderSetup();
				clearSubmittedText(runtime);
				return;
			}
			const rawArgs = command.args.trim();
			const [subcommand, ...rest] = rawArgs.split(/\s+/);
			const sub = subcommand?.toLowerCase() ?? "";

			const installCallback =
				getInstallCallback(runtime) ??
				(typeof runtime.ctx.installReverseItem === "function"
					? runtime.ctx.installReverseItem.bind(runtime.ctx)
					: getInstallCallback(runtime.ctx));

			if (sub === "") {
				await runInteractiveSetupMenu(runtime.ctx, installCallback);
			} else if (sub === "providers") {
				await runtime.ctx.showProviderSetup();
			} else if (sub === "add" || sub === "add-provider") {
				await runtime.ctx.showCustomProviderWizard();
			} else if (sub === "reverse") {
				const targetTool = rest.join(" ").trim() || undefined;
				await runInteractiveReverseSetup(runtime.ctx, targetTool, installCallback);
			} else if (sub === "python") {
				await runInteractivePythonSetup(runtime.ctx);
			} else if (sub === "speech") {
				await runInteractiveSpeechSetup(runtime.ctx);
			} else {
				runtime.ctx.showWarning(`Usage: /${command.name} [providers|add|reverse|python|speech]`);
			}
			clearSubmittedText(runtime);
		},
	},
	{
		name: "provider",
		icon: "model",
		description: "Manage model providers (add custom provider, configure providers)",
		allowArgs: true,
		subcommands: [
			{ name: "add", description: "Add a custom OpenAI/Anthropic-compatible provider" },
			{ name: "setup", description: "Open provider setup" },
		],
		handleTui: async (command, runtime) => {
			const args = command.args.trim().toLowerCase();
			if (args === "add") {
				await runtime.ctx.showCustomProviderWizard();
			} else {
				await runtime.ctx.showProviderSetup();
			}
			clearSubmittedText(runtime);
		},
	},
	{
		name: "plan",
		icon: "plan",
		description: "Toggle plan mode (agent plans before executing)",
		inlineHint: "[prompt]",
		allowArgs: true,
		getTuiAutocompleteDescription: runtime => {
			if (!cfgPlanEnabled.get(runtime.ctx.settings)) return "Plan: disabled in settings";
			if (runtime.ctx.planModeEnabled) {
				const planFile = runtime.ctx.planModePlanFilePath;
				return `Plan: on${planFile ? ` (${path.basename(planFile)})` : ""}`;
			}
			if (runtime.ctx.goalModeEnabled) return "Plan: blocked by goal mode";
			return "Plan: off";
		},
		handleTui: async (command, runtime) => {
			await runWithDetachedDraft(command, runtime, () =>
				runtime.ctx.handlePlanModeCommand(command.args || undefined, runtime.input),
			);
		},
	},
	{
		name: "plan-review",
		icon: "plan",
		description: "Re-open the plan review for the latest plan (plan mode only)",
		getTuiAutocompleteDescription: runtime =>
			runtime.ctx.planModeEnabled ? "Plan review: available" : "Plan review: plan mode inactive",
		handleTui: async (_command, runtime) => {
			await runtime.ctx.openPlanReview();
			clearSubmittedText(runtime);
		},
	},
	{
		name: "vibe",
		icon: "wave",
		description: "Toggle vibe mode (direct persistent fast/good worker sessions; read-only toolset)",
		inlineHint: "[prompt]",
		allowArgs: true,
		getTuiAutocompleteDescription: runtime => {
			if (runtime.ctx.vibeModeEnabled) return "Vibe: on";
			if (runtime.ctx.planModeEnabled) return "Vibe: blocked by plan mode";
			if (runtime.ctx.goalModeEnabled) return "Vibe: blocked by goal mode";
			return "Vibe: off";
		},
		handleTui: async (command, runtime) => {
			await runWithDetachedDraft(command, runtime, () =>
				runtime.ctx.handleVibeModeCommand(command.args || undefined, runtime.input),
			);
		},
	},
	{
		name: "goal",
		icon: "goal",
		description: "Toggle goal mode (persistent autonomous objective for this session)",
		subcommands: [
			{ name: "set", description: "Set or replace the goal", usage: "<objective>" },
			{ name: "show", description: "Show current goal details" },
			{ name: "pause", description: "Pause the current goal" },
			{ name: "resume", description: "Resume a paused goal" },
			{ name: "drop", description: "Drop the current goal" },
			{ name: "budget", description: "Adjust the token budget", usage: "<N|off>" },
		],
		inlineHint: "[objective]",
		allowArgs: true,
		getTuiAutocompleteDescription: runtime => {
			if (!cfgGoalEnabled.get(runtime.ctx.settings)) return "Goal: disabled in settings";
			if (runtime.ctx.planModeEnabled) return "Goal: blocked by plan mode";
			const state = runtime.ctx.session.getGoalModeState();
			return state ? `Goal: ${state.goal.status} (${shortDetail(state.goal.objective)})` : "Goal: off";
		},
		handleTui: async (command, runtime) => {
			await runWithDetachedDraft(command, runtime, () =>
				runtime.ctx.handleGoalModeCommand(command.args || undefined, runtime.input),
			);
		},
	},
	{
		name: "guided-goal",
		icon: "compass",
		description: "Have the agent interview you in chat, then set up goal mode",
		inlineHint: "[rough objective]",
		allowArgs: true,
		handleTui: async (command, runtime) => {
			await runWithDetachedDraft(command, runtime, () =>
				runtime.ctx.handleGuidedGoalCommand(command.args || undefined, runtime.input),
			);
		},
	},
	{
		name: "loop",
		icon: "loop",
		get description() {
			return `Toggle loop mode. While enabled, the next prompt you send re-submits after every yield. Bound it with a count/duration, or gate it with \`--until '<cmd>'\` / \`--while '<cmd>'\` — the command's exit status decides whether the next iteration runs. ${formatKeyHint("escape")} suspends the ongoing loop; /loop again to disable.`;
		},
		inlineHint: "[count|duration] [--while|--until '<cmd>'] [prompt]",
		allowArgs: true,
		getTuiAutocompleteDescription: runtime => {
			if (!runtime.ctx.loopModeEnabled) return "Loop: off";
			if (runtime.ctx.loopModePaused) return "Loop: paused";
			const bounds = [
				runtime.ctx.loopLimit ? describeLoopLimitRuntime(runtime.ctx.loopLimit) : undefined,
				runtime.ctx.loopCondition ? describeLoopCondition(runtime.ctx.loopCondition) : undefined,
			].filter((part): part is string => part !== undefined);
			if (bounds.length > 0) return `Loop: on (${bounds.join(", ")})`;
			if (runtime.ctx.loopPrompt) return "Loop: on (repeating prompt)";
			return "Loop: on (waiting for next prompt)";
		},
		handleTui: async (command, runtime) => {
			const prompt = await runtime.ctx.handleLoopCommand(command.args);
			clearSubmittedText(runtime);
			// Surface any inline prompt so the dispatcher returns it and the normal
			// submit flow runs the first loop iteration (recording it as the loop prompt).
			if (prompt) return { prompt };
		},
	},
	{
		name: "queue",
		icon: "inbox",
		description: "Queue a message for after the agent yields",
		inlineHint: "<message>",
		allowArgs: true,
		handleTui: async (command, runtime) => {
			await runtime.ctx.handleQueueCommand(
				command.args,
				runtime.draftDetached ? { ...runtime.input, text: command.text } : undefined,
			);
		},
	},
	{
		name: "model",
		aliases: ["models"],
		icon: "model",
		description: "Switch model for this session",
		acpDescription: "Show current model selection",
		getTuiAutocompleteDescription: runtime => {
			const model = runtime.ctx.viewSession.model;
			return model ? `Model: ${model.provider}/${model.id}` : "Model: none selected";
		},
		handle: async (command, runtime) => {
			if (command.args) {
				const selector = command.args.trim();
				const resolved = resolveSessionModelSelector(selector, runtime.session, runtime.settings);
				const match = resolved.model;
				if (!match) {
					return usage(
						`Unknown model: ${selector}. Use ACP \`session/setModel\` for picker-driven selection or list available models with /model.`,
						runtime,
					);
				}
				try {
					await runtime.session.setModel(match);
					if (resolved.thinkingLevel !== undefined) runtime.session.setThinkingLevel(resolved.thinkingLevel);
					await runtime.output(`Model set to ${match.provider}/${match.id}.`);
					await runtime.notifyTitleChanged?.();
					await runtime.notifyConfigChanged?.();
					return commandConsumed();
				} catch (err) {
					return usage(`Failed to set model: ${errorMessage(err)}`, runtime);
				}
			}

			const model = runtime.session.model;
			await runtime.output(
				model ? `Current model: ${model.provider}/${model.id}` : "No model is currently selected.",
			);
			return commandConsumed();
		},
		handleTui: async (command, runtime) => {
			if (command.args.trim().toLowerCase() === "add") {
				await runtime.ctx.showCustomProviderWizard();
				clearSubmittedText(runtime);
				return;
			}
			runtime.ctx.showModelSelector();
			clearSubmittedText(runtime);
		},
	},
	{
		name: "switch",
		icon: "swap",
		get description() {
			return `Switch model for this session (same as ${formatKeyHint("alt+p")}); accepts fuzzy ids, provider/id, @role, :level`;
		},
		acpDescription: "Switch model for this session only",
		acpInputHint: "[model]",
		inlineHint: "[model]",
		allowArgs: true,
		getTuiAutocompleteDescription: runtime => {
			const model = runtime.ctx.viewSession.model;
			return model ? `Model: ${model.provider}/${model.id}` : "Model: none selected";
		},
		handle: async (command, runtime) => {
			const selector = command.args.trim();
			if (!selector) {
				const model = runtime.session.model;
				await runtime.output(
					model ? `Current model: ${model.provider}/${model.id}` : "No model is currently selected.",
				);
				return commandConsumed();
			}
			const resolved = resolveSessionModelSelector(selector, runtime.session, runtime.settings);
			if (!resolved.model) return usage(`Unknown model: ${selector}`, runtime);
			try {
				await runtime.session.setModelTemporary(resolved.model, resolved.thinkingLevel);
				await runtime.output(`Session-only model: ${formatModelString(resolved.model)}.`);
				await runtime.notifyTitleChanged?.();
				await runtime.notifyConfigChanged?.();
				return commandConsumed();
			} catch (err) {
				return usage(`Failed to switch model: ${errorMessage(err)}`, runtime);
			}
		},
		handleTui: async (command, runtime) => {
			clearSubmittedText(runtime);
			const selector = command.args.trim();
			if (!selector) {
				runtime.ctx.showModelSelector({ temporaryOnly: true });
				return;
			}
			const resolved = resolveSessionModelSelector(selector, runtime.ctx.session, runtime.ctx.settings);
			if (!resolved.model) {
				runtime.ctx.showError(`Unknown model: ${selector}`);
				return;
			}
			if (resolved.warning) runtime.ctx.showStatus(resolved.warning);
			await runtime.ctx.switchSessionModel(resolved.model, resolved.thinkingLevel);
		},
	},
	{
		name: "fast",
		icon: "fast",
		description:
			"Toggle fast service (OpenAI service_tier=priority or ultrafast, Anthropic speed=fast, Google priority)",
		acpDescription: "Toggle fast mode",
		acpInputHint: "[on|ultra|off|status]",
		subcommands: [
			{ name: "on", description: "Enable fast mode (priority tier)" },
			{ name: "ultra", description: "Enable Ultrafast (OpenAI API, or Codex models that offer it)" },
			{ name: "off", description: "Disable fast mode" },
			{ name: "status", description: "Show fast mode status" },
		],
		allowArgs: true,
		getTuiAutocompleteDescription: runtime => `Fast: ${formatFastModeStatus(runtime.ctx.session)}`,
		handle: async (command, runtime) => {
			const message = runFastCommand(command.args.trim().toLowerCase(), runtime.session);
			if (message === undefined) return usage(FAST_USAGE, runtime);
			await runtime.output(message);
			return commandConsumed();
		},
		handleTui: (command, runtime) => {
			const message = runFastCommand(command.args.trim().toLowerCase(), runtime.ctx.session);
			refreshStatusLine(runtime.ctx);
			runtime.ctx.showStatus(message ?? FAST_USAGE);
			clearSubmittedText(runtime);
		},
	},
	{
		name: "slow",
		icon: "fast",
		description:
			"Toggle slow mode: flex tier on OpenAI/Google; on Anthropic, continue at low priority after the Claude session limit",
		acpDescription: "Toggle slow mode",
		acpInputHint: "[on|off|status]",
		subcommands: [
			{ name: "on", description: "Flex tier, or Anthropic low priority at the session limit (auto)" },
			{ name: "off", description: "Standard service; stop Anthropic low priority" },
			{ name: "status", description: "Show slow mode status" },
		],
		allowArgs: true,
		getTuiAutocompleteDescription: runtime =>
			runtime.ctx.session.isSlowModeEnabled() ? "Slow mode: on" : "Slow mode: off",
		handle: async (command, runtime) => {
			const message = runSlowCommand(command.args.trim().toLowerCase(), runtime.session);
			if (message === undefined) return usage("Usage: /slow [on|off|status]", runtime);
			await runtime.output(message);
			return commandConsumed();
		},
		handleTui: (command, runtime) => {
			const message = runSlowCommand(command.args.trim().toLowerCase(), runtime.ctx.session);
			refreshStatusLine(runtime.ctx);
			runtime.ctx.showStatus(message ?? "Usage: /slow [on|off|status]");
			clearSubmittedText(runtime);
		},
	},
	{
		name: "skillful",
		icon: "compass",
		description: "Toggle listing available skills in the system prompt (session only)",
		acpDescription: "Toggle skill listing",
		acpInputHint: "[on|off|status]",
		subcommands: [
			{ name: "on", description: "List skills in the prompt for this session" },
			{ name: "off", description: "Omit the skills listing for this session" },
			{ name: "status", description: "Show skill listing status" },
		],
		allowArgs: true,
		getTuiAutocompleteDescription: runtime =>
			`Skill listing: ${cfgSkillful.get(runtime.ctx.session.settings) ? "on" : "off"}`,
		handle: async (command, runtime) => {
			const arg = command.args.trim().toLowerCase();
			if (arg === "status") {
				await runtime.output(
					`Skill listing: ${cfgSkillful.get(runtime.session.settings) ? "on" : "off"} (session override; default from the skillful setting).`,
				);
				return commandConsumed();
			}
			if (!arg || arg === "toggle" || arg === "on" || arg === "off") {
				const enabled =
					arg === "on"
						? await runtime.session.setSkillful(true)
						: arg === "off"
							? await runtime.session.setSkillful(false)
							: await runtime.session.toggleSkillful();
				await runtime.output(`Skill listing ${enabled ? "enabled" : "disabled"} for this session.`);
				return commandConsumed();
			}
			return usage("Usage: /skillful [on|off|status]", runtime);
		},
		handleTui: async (command, runtime) => {
			const arg = command.args.trim().toLowerCase();
			if (arg === "status") {
				runtime.ctx.showStatus(`Skill listing: ${cfgSkillful.get(runtime.ctx.session.settings) ? "on" : "off"}.`);
				clearSubmittedText(runtime);
				return;
			}
			if (!arg || arg === "toggle" || arg === "on" || arg === "off") {
				const enabled =
					arg === "on"
						? await runtime.ctx.session.setSkillful(true)
						: arg === "off"
							? await runtime.ctx.session.setSkillful(false)
							: await runtime.ctx.session.toggleSkillful();
				runtime.ctx.showStatus(`Skill listing ${enabled ? "enabled" : "disabled"} for this session.`);
				clearSubmittedText(runtime);
				return;
			}
			runtime.ctx.showStatus("Usage: /skillful [on|off|status]");
			clearSubmittedText(runtime);
		},
	},
	{
		name: "extended-context",
		icon: "expand",
		description: "Toggle extended context windows",
		acpDescription: "Toggle extended context",
		acpInputHint: "[on|off|status]",
		subcommands: [
			{ name: "on", description: "Enable larger context windows" },
			{ name: "off", description: "Use default or standard-pricing context windows" },
			{ name: "status", description: "Show extended context status" },
		],
		allowArgs: true,
		getTuiAutocompleteDescription: runtime =>
			`Extended context: ${formatExtendedContextStatus(runtime.ctx.settings)}`,
		handle: async (command, runtime) => {
			const output = applyExtendedContextCommand(runtime.settings, command.args);
			if (!output) return usage("Usage: /extended-context [on|off|status]", runtime);
			await runtime.output(output);
			return commandConsumed();
		},
		handleTui: (command, runtime) => {
			const output = applyExtendedContextCommand(runtime.ctx.settings, command.args);
			refreshStatusLine(runtime.ctx);
			runtime.ctx.showStatus(output ?? "Usage: /extended-context [on|off|status]");
			clearSubmittedText(runtime);
		},
	},
	{
		name: "computer",
		icon: "computer",
		description: "Toggle the native computer-use eval prelude for this session",
		acpDescription: "Toggle computer use",
		acpInputHint: "[on|off|status]",
		subcommands: [
			{ name: "on", description: "Enable computer use for this session" },
			{ name: "off", description: "Disable computer use for this session" },
			{ name: "status", description: "Show computer use status" },
		],
		allowArgs: true,
		getTuiAutocompleteDescription: runtime =>
			`Computer: ${cfgComputerEnabled.get(runtime.ctx.session.settings) ? "on" : "off"}`,
		handle: async (command, runtime) => {
			const arg = command.args.trim().toLowerCase();
			if (arg === "status") {
				await runtime.output(formatComputerUseStatus(runtime.session));
				return commandConsumed();
			}
			if (!arg || arg === "toggle" || arg === "on" || arg === "off") {
				const enable = arg === "off" ? false : arg === "on" || !cfgComputerEnabled.get(runtime.session.settings);
				await runtime.output(applyComputerUseToggle(runtime.session, enable));
				return commandConsumed();
			}
			return usage("Usage: /computer [on|off|status]", runtime);
		},
		handleTui: async (command, runtime) => {
			const arg = command.args.trim().toLowerCase();
			if (arg === "status") {
				runtime.ctx.showStatus(formatComputerUseStatus(runtime.ctx.session));
				clearSubmittedText(runtime);
				return;
			}
			if (!arg || arg === "toggle" || arg === "on" || arg === "off") {
				const enable =
					arg === "off" ? false : arg === "on" || !cfgComputerEnabled.get(runtime.ctx.session.settings);
				runtime.ctx.showStatus(applyComputerUseToggle(runtime.ctx.session, enable));
				clearSubmittedText(runtime);
				return;
			}
			runtime.ctx.showStatus("Usage: /computer [on|off|status]");
			clearSubmittedText(runtime);
		},
	},
	{
		name: "ratchet",
		icon: "loop",
		description: "Build (or reuse) an eval for an LLM flow, then hillclimb it unattended",
		inlineHint: "[flow and goal]",
		allowArgs: true,
		handle: (command, runtime) => {
			const armed = prepareRatchet(runtime.session, command.args);
			if ("error" in armed) return usage(armed.error, runtime);
			return { prompt: armed.kickoff };
		},
		handleTui: async (command, runtime) => {
			const { session } = runtime.ctx;
			const armed = prepareRatchet(session, command.args);
			clearSubmittedText(runtime);
			if ("error" in armed) {
				runtime.ctx.showWarning(armed.error);
				return;
			}
			// Same delivery as /guided-goal: the kickoff is a hidden developer message queued behind
			// any in-flight run; the agent's batched `ask` is the first thing the user sees.
			const images = runtime.input?.images?.length ? runtime.input.images : undefined;
			if (session.isStreaming) {
				await session.followUp(armed.kickoff, images, { synthetic: true });
				return;
			}
			try {
				await session.prompt(armed.kickoff, images ? { synthetic: true, images } : { synthetic: true });
			} catch (error) {
				if (!(error instanceof AgentBusyError)) throw error;
				await session.followUp(armed.kickoff, images, { synthetic: true });
			}
		},
	},
	{
		name: "prewalk",
		icon: "prewalk",
		description: "Arm, restart, or cancel a one-shot model handoff",
		allowArgs: true,
		acpDescription: "Arm, restart, or cancel prewalk",
		acpInputHint: "[into] | restart [from] [into] | off",
		subcommands: [
			{
				name: "restart",
				description: "Return to the planning model and re-arm the handoff (default prewalk.from → prewalk.into)",
				usage: "[from] [into]",
			},
			{ name: "off", description: "Cancel this session's handoff without changing the active model" },
		],
		handle: async (command, runtime) => {
			const [verb, ...rest] = command.args.trim().split(/\s+/).filter(Boolean);
			const keyword = verb?.toLowerCase();
			const restart = keyword === "restart";
			const args = restart || keyword === "off" ? rest : verb ? [verb, ...rest] : [];
			if (args.length > (restart ? 2 : keyword === "off" ? 0 : 1)) {
				return usage("Usage: /prewalk [into] | restart [from] [into] | off", runtime);
			}
			if (keyword === "off") {
				const armed = runtime.session.getPrewalkState() !== undefined;
				runtime.session.disarmPrewalk();
				await runtime.output(
					armed
						? "Prewalk off: canceled this session's pending handoff; keeping the active model."
						: "Prewalk already off for this session; keeping the active model.",
				);
				return commandConsumed();
			}
			const into = (restart ? args[1] : args[0]) ?? cfgPrewalkInto.get(runtime.settings);
			const target = resolveSessionModelSelector(into, runtime.session, runtime.settings);
			if (target.error || !target.model) {
				return usage(target.error ?? `Model "${into}" not found`, runtime);
			}
			if (!runtime.session.modelRegistry.hasConfiguredAuth(target.model)) {
				return usage(`No API key for ${target.model.provider}/${target.model.id}`, runtime);
			}
			const targetLabel = `${into} (${target.model.provider}/${target.model.id})`;
			if (restart) {
				const from = args[0] ?? cfgPrewalkFrom.get(runtime.settings);
				const source = resolveSessionModelSelector(from, runtime.session, runtime.settings);
				if (source.error || !source.model) {
					return usage(source.error ?? `Model "${from}" not found`, runtime);
				}
				if (!runtime.session.modelRegistry.hasConfiguredAuth(source.model)) {
					return usage(`No API key for ${source.model.provider}/${source.model.id}`, runtime);
				}
				const result = await runtime.session.restartPrewalk(
					source.model,
					source.thinkingLevel,
					target.model,
					target.thinkingLevel,
				);
				if (result === "rejected") return commandConsumed();
				const sourceLabel = `${from} (${source.model.provider}/${source.model.id})`;
				await runtime.output(
					result === "armed"
						? `Prewalk restarted: using ${sourceLabel} for planning, then switching to ${targetLabel} at the next edit/write (todo-gated).`
						: `Prewalk reset: using ${sourceLabel}; ${into} resolves to the same model and thinking level, so no handoff was armed.`,
				);
				return commandConsumed();
			}
			const armed = runtime.session.armPrewalk(target.model, target.thinkingLevel);
			if (armed) {
				await runtime.output(
					`Prewalk on: switching to ${target.model.provider}/${target.model.id} at the next edit/write (todo-gated).`,
				);
			}
			return commandConsumed();
		},
	},
	{
		name: "modelpreset",
		icon: "model",
		description: "Save and switch model presets (role models + thinking level)",
		acpDescription: "Manage model presets",
		acpInputHint: "[list|save|switch|delete] [name]",
		inlineHint: "[save|switch|delete|list] [name]",
		subcommands: [
			{ name: "list", description: "List saved presets" },
			{ name: "save", description: "Save the current role models and thinking level", usage: "<name>" },
			{ name: "switch", description: "Apply a saved preset", usage: "<name>" },
			{ name: "delete", description: "Delete a saved preset", usage: "<name>" },
		],
		allowArgs: true,
		getTuiAutocompleteDescription: runtime => {
			const count = getModelPresetNames(runtime.ctx.settings).length;
			return count > 0 ? `Presets: ${count} saved` : "Presets: none saved";
		},
		handle: async (command, runtime) => {
			const outcome = await runPresetsCommand(command.args, runtime.settings, runtime.session);
			if (outcome.usage) return usage(outcome.message, runtime);
			await runtime.output(outcome.message);
			if (outcome.switched) await runtime.notifyTitleChanged?.();
			if (outcome.changedConfig) await runtime.notifyConfigChanged?.();
			return commandConsumed();
		},
		handleTui: async (command, runtime) => {
			clearSubmittedText(runtime);
			const { ctx } = runtime;
			let args = command.args;
			if (!args.trim()) {
				const names = getModelPresetNames(ctx.settings);
				if (names.length === 0) {
					ctx.showStatus(NO_PRESETS_MESSAGE);
					return;
				}
				const picked = await ctx.showHookSelector("Switch to model preset", names);
				if (picked === undefined) return;
				args = `switch ${picked}`;
			}
			const outcome = await runPresetsCommand(args, ctx.settings, ctx.session);
			if (outcome.switched) {
				ctx.statusLine.invalidate();
				ctx.updateEditorBorderColor();
			}
			if (outcome.failed || outcome.usage) ctx.showWarning(outcome.message);
			else ctx.showStatus(outcome.message);
			ctx.ui.requestRender();
		},
	},
	{
		name: "effort",
		icon: "gauge",
		get description() {
			return `Set reasoning effort (thinking level, intelligence) for this session; ${formatKeyHint("shift+tab")} cycles levels`;
		},
		acpDescription: "Set or show reasoning effort (thinking level, intelligence)",
		acpInputHint: "[level]",
		inlineHint: "[level]",
		allowArgs: true,
		subcommands: CLI_THINKING_LEVELS.map(level => ({
			name: level,
			description: getConfiguredThinkingLevelMetadata(level).description,
		})),
		getTuiAutocompleteDescription: runtime =>
			`Thinking: ${runtime.ctx.viewSession.configuredThinkingLevel() ?? "model default"}`,
		handle: async (command, runtime) => {
			const session = runtime.session;
			if (!command.args.trim()) {
				await runtime.output(
					session.model?.reasoning
						? `Thinking: ${session.configuredThinkingLevel() ?? "model default"}\nAvailable: ${session.getAvailableEffortSelectors().join(", ")}`
						: noThinkingMessage(session),
				);
				return commandConsumed();
			}
			const resolved = resolveThinkingArgument(session, command.args);
			if ("error" in resolved) return usage(resolved.error, runtime);
			session.setThinkingLevel(resolved.level);
			await runtime.output(`Thinking set to ${resolved.level}.`);
			// `setThinkingLevel` emits `thinking_level_changed`, which hosts with a
			// session-lifetime subscription (ACP) already turn into a config push.
			await runtime.notifyConfigChanged?.({ handledBySessionEvent: true });
			return commandConsumed();
		},
		handleTui: (command, runtime) => {
			clearSubmittedText(runtime);
			const { ctx } = runtime;
			const session = ctx.viewSession;
			if (!command.args.trim()) {
				if (session.model?.reasoning) ctx.showThinkingSelector();
				else ctx.showStatus(noThinkingMessage(session));
				return;
			}
			const resolved = resolveThinkingArgument(session, command.args);
			if ("error" in resolved) {
				ctx.showError(resolved.error);
				return;
			}
			// thinking_level_changed refreshes the status line and editor border.
			session.setThinkingLevel(resolved.level);
			ctx.showStatus(`Thinking set to ${resolved.level}.`);
		},
	},
];

const PRESETS_USAGE = "Usage: /modelpreset [list | save <name> | switch <name> | delete <name>]";
const NO_PRESETS_MESSAGE = "No model presets saved. Use /modelpreset save <name> to create one.";

interface PresetsCommandOutcome {
	message: string;
	usage?: boolean;
	failed?: boolean;
	switched?: boolean;
	changedConfig?: boolean;
}

/** Shared by the ACP and TUI handlers of `/modelpreset`; `args` is everything after the command name. */
async function runPresetsCommand(
	args: string,
	settings: Settings,
	session: ModelPresetSession,
): Promise<PresetsCommandOutcome> {
	const [sub = "list", ...rest] = args.trim().split(/\s+/).filter(Boolean);
	const name = rest.join(" ");
	switch (sub) {
		case "list": {
			const names = getModelPresetNames(settings);
			return { message: names.length > 0 ? `Model presets: ${names.join(", ")}` : NO_PRESETS_MESSAGE };
		}
		case "save": {
			if (!name) return { message: "Usage: /modelpreset save <name>", usage: true };
			if (!isValidModelPresetName(name)) {
				return {
					message: `Invalid preset name "${name}": use a letter, then letters, digits, - or _`,
					usage: true,
				};
			}
			saveModelPreset(settings, name);
			return { message: modelPresetSavedMessage(settings, name), changedConfig: true };
		}
		case "switch": {
			if (!name) return { message: "Usage: /modelpreset switch <name>", usage: true };
			const result = await applyModelPreset(settings, session, name);
			const message = formatModelPresetSwitch(name, result);
			const wroteRoles = result.kind === "switched" || result.kind === "failed";
			return {
				message,
				failed: !isCleanModelPresetSwitch(result),
				switched: result.kind === "switched",
				changedConfig: wroteRoles,
			};
		}
		case "delete": {
			if (!name) return { message: "Usage: /modelpreset delete <name>", usage: true };
			const result = deleteModelPreset(settings, name);
			if (result === "deleted") return { message: `Deleted model preset "${name}"`, changedConfig: true };
			if (result === "project") {
				return {
					message: `Preset "${name}" is defined by a project or --config file; remove it there`,
					failed: true,
				};
			}
			return { message: `Preset not found: ${name}`, failed: true };
		}
		default:
			return { message: PRESETS_USAGE, usage: true };
	}
}
