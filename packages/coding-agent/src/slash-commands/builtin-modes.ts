import { clearSubmittedText, restoreDetachedDraft } from "./helpers/draft";
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
import { getEffectiveLocale } from "../config/persisted-locale";
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
import type { ParsedSlashCommand, SlashCommandSpec, TuiSlashCommandRuntime } from "./types";

import {
	cfgComputerDisplay,
	cfgComputerEnabled,
	cfgComputerMaxHeight,
	cfgComputerMaxWidth,
	cfgRatchetEnabled,
} from "../tools/settings";
import { cfgSkillful } from "../session/settings";
import { formatSlowModeResetClock } from "../session/anthropic-slow-mode";
import { cfgExtendedContext } from "../session/context-settings";
import { cfgGoalEnabled } from "../goals/settings";
import { cfgPlanEnabled } from "../plan-mode/settings";

export function refreshStatusLine(ctx: InteractiveModeContext): void {
	ctx.statusLine.invalidate();
	ctx.ui.requestRender();
}

/**
 * Resolve a `/model` / `/switch` selector the way `omp bench` and `--model`
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

async function runWithDetachedModeDraft(
	command: ParsedSlashCommand,
	runtime: TuiSlashCommandRuntime,
	run: () => Promise<boolean>,
): Promise<void> {
	const { editor } = runtime.ctx;
	if (!runtime.draftDetached) editor.clearDraft();
	try {
		const submitted = await run();
		const hasAttachments = (runtime.input?.images?.length ?? 0) > 0 || (runtime.input?.imageLinks?.length ?? 0) > 0;
		if (!submitted && hasAttachments) {
			if (runtime.draftDetached) {
				// Newer typing may already sit in the editor: merge the submission
				// back beside it so each draft's image markers keep their images.
				restoreDetachedDraft(editor, command.text, runtime.input?.images, runtime.input?.imageLinks);
				return;
			}
			editor.pendingImages = [...(runtime.input?.images ?? []), ...editor.pendingImages];
			editor.pendingImageLinks = [
				...(runtime.input?.imageLinks ?? runtime.input?.images?.map(() => undefined) ?? []),
				...editor.pendingImageLinks,
			];
			editor.imageLinks = editor.pendingImageLinks.length > 0 ? editor.pendingImageLinks : undefined;
		}
	} catch (error) {
		if (runtime.draftDetached) {
			// The caller already took this draft out of the editor before
			// dispatch (Ctrl+Enter's `handleFollowUp`, or `onSubmit` for these
			// mode commands); it owns restoring the submission and reporting
			// the error so a submission that failed after newer text was typed
			// merges with it once, instead of being silently dropped here.
			throw error;
		}
		if (!editor.getText() && editor.pendingImages.length === 0) {
			editor.setText(command.text);
			editor.pendingImages = runtime.input?.images ? [...runtime.input.images] : [];
			editor.pendingImageLinks = runtime.input?.imageLinks ? [...runtime.input.imageLinks] : [];
			editor.imageLinks = editor.pendingImageLinks.length > 0 ? editor.pendingImageLinks : undefined;
		}
		runtime.ctx.showError(error instanceof Error ? error.message : String(error));
	}
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
	};
	return [
		`Computer use: ${enabled ? "enabled" : "disabled"}`,
		`prelude: ${active ? "active" : "inactive"}`,
		`configured: display=${configured.display}, maxWidth=${configured.maxWidth}, maxHeight=${configured.maxHeight}`,
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
			? `> 提示：在终端中运行 \`${APP_NAME} setup reverse --execute\` 可交互式确认并安装工具。运行 \`/setup reverse <工具名>\` 查看具体工具说明。`
			: `> Tip: Run \`${APP_NAME} setup reverse --execute\` in terminal to install with interactive confirmation. Run \`/setup reverse <tool>\` to view a specific tool.`,
	);
	return lines.join("\n");
}

export type ReverseInstallCallback = (
	item: ReverseToolStatus | ReverseServiceStatus,
) => Promise<{ success: boolean; message?: string } | void>;

function getInstallCallback(source: unknown): ReverseInstallCallback | undefined {
	if (
		source &&
		typeof source === "object" &&
		"installReverseItem" in source &&
		typeof source.installReverseItem === "function"
	) {
		return source.installReverseItem as ReverseInstallCallback;
	}
	return undefined;
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

	let report = checkReverseTools();
	let currentFilter: "all" | "missing" | "services" = "all";

	if (targetTool) {
		const norm = targetTool.toLowerCase();
		const toolMatch = report.tools.find(t => t.id.toLowerCase() === norm || t.name.toLowerCase().includes(norm));
		const serviceMatch = toolMatch
			? undefined
			: report.services.find(
					s =>
						s.id.toLowerCase() === norm ||
						s.serverName.toLowerCase() === norm ||
						s.name.toLowerCase().includes(norm),
				);
		const targetItem = toolMatch ?? serviceMatch;
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
			);
			return;
		}
		ctx.showWarning?.(
			isZh ? `未在目录中找到工具或服务: "${targetTool}"` : `Tool/service "${targetTool}" not found in catalog.`,
		);
	}

	while (true) {
		report = checkReverseTools();
		const missingTools = report.tools.filter(t => t.status === "missing");
		const missingServices = report.services.filter(s => !s.ready);
		const totalMissing = missingTools.length + missingServices.length;

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

		const visibleTools =
			currentFilter === "services" ? [] : currentFilter === "missing" ? missingTools : report.tools;

		const visibleServices = currentFilter === "missing" ? missingServices : report.services;

		for (const tool of visibleTools) {
			const isOk = tool.status === "installed";
			const badge = isOk ? "✅" : "❌";
			items.push({
				label: `${badge} [CLI] ${tool.name} (${tool.id})`,
				description: `[${tool.category}] ${
					isOk
						? isZh
							? `已安装 (${tool.foundPath ?? "已就绪"})`
							: `Installed (${tool.foundPath ?? "ready"})`
						: tool.installCommand
							? `安装: ${tool.installCommand}`
							: isZh
								? "需手动下载安装"
								: "Manual install required"
				}`,
			});
		}

		if (currentFilter !== "all" || visibleServices.length > 0) {
			for (const service of visibleServices) {
				const badge = service.ready ? "✅" : "⚠️";
				const configState = service.configured
					? isZh
						? `已配置(${service.configuredScopes.join(", ")})`
						: `configured (${service.configuredScopes.join(", ")})`
					: isZh
						? "未配置"
						: "not configured";
				const connectionState = isZh ? "连接未验证" : "connection unverified";
				items.push({
					label: `${badge} [MCP] ${service.name} (${service.id})`,
					description: `[${service.category}] ${
						service.ready
							? isZh
								? "前置依赖已就绪"
								: "Prerequisites ready"
							: isZh
								? `缺少依赖: ${service.missingPrerequisites.join(", ")}`
								: `Missing: ${service.missingPrerequisites.join(", ")}`
					} • ${configState} • ${connectionState} • ${service.startCommand}`,
				});
			}
		}

		items.push({
			label: isZh ? "← 退出面板" : "← Exit",
			description: isZh ? "关闭逆向工程工具链面板" : "Close reverse engineering setup panel",
		});

		const title = isZh ? "逆向工程工具链" : "Reverse Engineering Toolchain";
		const selected = await ctx.showHookSelector(title, items);
		if (!selected || selected.includes("← Exit") || selected.includes("← 退出")) {
			break;
		}

		if (selected === filterLabelAll) {
			currentFilter = "all";
			continue;
		}
		if (selected === filterLabelMissing) {
			currentFilter = "missing";
			continue;
		}
		if (selected === filterLabelServices) {
			currentFilter = "services";
			continue;
		}

		const match = /\(([^)]+)\)$/.exec(selected.trim());
		const chosenId = match ? match[1] : undefined;
		if (!chosenId) continue;

		const chosenTool = report.tools.find(t => t.id === chosenId);
		const chosenService = chosenTool ? undefined : report.services.find(s => s.id === chosenId);
		const item = chosenTool ?? chosenService;
		if (!item) continue;

		await showItemDetails(
			ctx,
			item,
			() => {
				report = checkReverseTools();
				return report;
			},
			installCallback,
			isZh,
		);
	}
}

async function showItemDetails(
	ctx: InteractiveModeContext,
	initialItem: ReverseToolStatus | ReverseServiceStatus,
	refreshReport: () => ReverseCheckReport,
	installCallback:
		| ((item: ReverseToolStatus | ReverseServiceStatus) => Promise<{ success: boolean; message?: string } | void>)
		| undefined,
	isZh: boolean,
): Promise<void> {
	let currentItem = initialItem;

	while (true) {
		const isInstalled = currentItem.kind === "cli" ? currentItem.status === "installed" : currentItem.ready;
		const options: Array<{ label: string; description?: string }> = [];

		if (currentItem.kind === "cli") {
			if (currentItem.installCommand) {
				options.push({
					label: isInstalled
						? isZh
							? `重新安装: ${currentItem.installCommand}`
							: `Reinstall: ${currentItem.installCommand}`
						: isZh
							? `安装: ${currentItem.installCommand}`
							: `Install: ${currentItem.installCommand}`,
					description: currentItem.packageManager
						? `[${currentItem.packageManager}] ${currentItem.riskNote ?? ""}`
						: (currentItem.riskNote ?? undefined),
				});
			}
		} else {
			if (currentItem.installCommand) {
				options.push({
					label: isZh
						? `安装服务包: ${currentItem.installCommand}`
						: `Install Server Package: ${currentItem.installCommand}`,
					description: currentItem.packageManager
						? `[${currentItem.packageManager}] ${currentItem.riskNote}`
						: currentItem.riskNote,
				});
			}
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
			action.includes("安装服务包")
		) {
			const depsNote =
				currentItem.kind === "cli"
					? currentItem.secondaryMissing && currentItem.secondaryMissing.length > 0
						? isZh
							? `缺少依赖: ${currentItem.secondaryMissing.join(", ")}`
							: `Missing prerequisite: ${currentItem.secondaryMissing.join(", ")}`
						: isZh
							? "前置依赖已满足"
							: "Prerequisites satisfied"
					: currentItem.missingPrerequisites.length > 0
						? isZh
							? `缺少依赖: ${currentItem.missingPrerequisites.join(", ")}`
							: `Missing prerequisites: ${currentItem.missingPrerequisites.join(", ")}`
						: isZh
							? "前置依赖已满足"
							: "Prerequisites satisfied";

			const confirmTitle = isZh ? `确认执行安装: ${currentItem.name}` : `Confirm Installation: ${currentItem.name}`;

			const confirmLines = [
				`${isZh ? "目标" : "Target"}: ${currentItem.name} (${currentItem.id})`,
				`${isZh ? "执行命令" : "Command"}: ${currentItem.installCommand}`,
				`${isZh ? "包管理器" : "Package Manager"}: ${currentItem.packageManager ?? (isZh ? "无" : "none")}`,
				`${isZh ? "依赖要求" : "Dependencies"}: ${depsNote}`,
				`${isZh ? "风险提示" : "Risk / Notes"}: ${currentItem.riskNote ?? (isZh ? "无" : "none")}`,
			];
			if (currentItem.kind === "mcp") {
				confirmLines.push(`${isZh ? "目标配置路径" : "Config Path"}: ${currentItem.configPath}`);
			}
			confirmLines.push("");
			confirmLines.push(isZh ? "是否现在开始执行安装？" : "Do you want to run this installation command now?");

			const confirmed =
				typeof ctx.showHookConfirm === "function"
					? await ctx.showHookConfirm(confirmTitle, confirmLines.join("\n"))
					: true;

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
				const res = await callback(currentItem);
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
				const refreshedItem =
					currentItem.kind === "cli"
						? refreshedReport.tools.find(t => t.id === currentItem.id)
						: refreshedReport.services.find(s => s.id === currentItem.id);
				if (refreshedItem) currentItem = refreshedItem;
			} else {
				ctx.showWarning?.(
					isZh
						? `当前环境未配置安装执行器。请在终端中运行：\n${currentItem.installCommand}`
						: `No installer executor available. Please run in terminal:\n${currentItem.installCommand}`,
				);
			}
		}
	}
}

export const BUILTIN_MODE_SLASH_COMMANDS: ReadonlyArray<SlashCommandSpec> = [
	{
		name: "security",
		icon: "shield",
		description: "Plan, run, inspect, import, and compare OMP-native security scans",
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
			{ name: "validate", description: "Validate one finding with OMP-native tools" },
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
		description: "Open provider setup",
		allowArgs: true,
		subcommands: [
			{ name: "providers", description: "Configure sign-in and web search providers" },
			{ name: "add", description: "Add a custom OpenAI/Anthropic-compatible provider" },
			{ name: "reverse", description: "Inspect reverse engineering toolchain status and install guides" },
		],
		handleTui: async (command, runtime) => {
			const rawArgs = command.args.trim();
			const [subcommand, ...rest] = rawArgs.split(/\s+/);
			const sub = subcommand?.toLowerCase() ?? "";
			if (sub === "add" || sub === "add-provider") {
				await runtime.ctx.showCustomProviderWizard();
			} else if (sub === "reverse") {
				const targetTool = rest.join(" ").trim() || undefined;
				const installCallback =
					getInstallCallback(runtime) ??
					(typeof runtime.ctx.installReverseItem === "function"
						? runtime.ctx.installReverseItem.bind(runtime.ctx)
						: getInstallCallback(runtime.ctx));
				await runInteractiveReverseSetup(runtime.ctx, targetTool, installCallback);
			} else if (sub === "" || sub === "providers") {
				await runtime.ctx.showProviderSetup();
			} else {
				runtime.ctx.showWarning(`Usage: /${command.name} [providers|add|reverse]`);
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
			await runWithDetachedModeDraft(command, runtime, () =>
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
			await runWithDetachedModeDraft(command, runtime, () =>
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
			await runWithDetachedModeDraft(command, runtime, () =>
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
			await runWithDetachedModeDraft(command, runtime, () =>
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
			const model = runtime.ctx.session.model;
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
			const model = runtime.ctx.session.model;
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
		acpInputHint: "[restart|off]",
		subcommands: [
			{ name: "restart", description: "Return to @default and re-arm the handoff to @smol" },
			{ name: "off", description: "Cancel this session's handoff without changing the active model" },
		],
		handle: async (command, runtime) => {
			const arg = command.args.trim().toLowerCase();
			if (arg && arg !== "restart" && arg !== "off") return usage("Usage: /prewalk [restart|off]", runtime);
			if (arg === "off") {
				const armed = runtime.session.getPrewalkState() !== undefined;
				runtime.session.disarmPrewalk();
				await runtime.output(
					armed
						? "Prewalk off: canceled this session's pending handoff; keeping the active model."
						: "Prewalk already off for this session; keeping the active model.",
				);
				return commandConsumed();
			}
			const target = resolveSessionModelSelector("@smol", runtime.session, runtime.settings);
			if (target.error || !target.model) {
				return usage(target.error ?? 'Model "@smol" not found', runtime);
			}
			if (!runtime.session.modelRegistry.hasConfiguredAuth(target.model)) {
				return usage(`No API key for ${target.model.provider}/${target.model.id}`, runtime);
			}
			if (arg === "restart") {
				const source = resolveSessionModelSelector("@default", runtime.session, runtime.settings);
				if (source.error || !source.model) {
					return usage(source.error ?? 'Model "@default" not found', runtime);
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
				const restartSource = `${source.model.provider}/${source.model.id}`;
				await runtime.output(
					result === "armed"
						? `Prewalk restarted: using @default (${restartSource}) for planning, then switching to @smol (${target.model.provider}/${target.model.id}) at the next edit/write (todo-gated).`
						: `Prewalk reset: using @default (${restartSource}); @smol resolves to the same model and thinking level, so no handoff was armed.`,
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
			`Thinking: ${runtime.ctx.session.configuredThinkingLevel() ?? "model default"}`,
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
			if (!command.args.trim()) {
				if (ctx.session.model?.reasoning) ctx.showThinkingSelector();
				else ctx.showStatus(noThinkingMessage(ctx.session));
				return;
			}
			const resolved = resolveThinkingArgument(ctx.session, command.args);
			if ("error" in resolved) {
				ctx.showError(resolved.error);
				return;
			}
			// thinking_level_changed refreshes the status line and editor border.
			ctx.session.setThinkingLevel(resolved.level);
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
