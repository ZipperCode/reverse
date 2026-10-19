/**
 * Authoritative panel metadata for the unified 5-panel setup surface.
 * Shared between CLI (`reverse setup <panel>`) and TUI (`/setup [panel]`).
 */

import { getEffectiveLocale } from "../config/persisted-locale";
import { CLI_TRANSLATIONS_ZH_CN } from "../i18n/zh-CN/cli";

export type SetupPanelKey = "providers" | "add" | "reverse" | "python" | "speech";

export const SETUP_PANEL_KEYS: readonly SetupPanelKey[] = ["providers", "add", "reverse", "python", "speech"] as const;

export interface SetupPanelMeta {
	readonly key: SetupPanelKey;
	readonly icon: string;
	readonly name: string;
	readonly labelEn: string;
	readonly labelZh: string;
	readonly descriptionEn: string;
	readonly descriptionZh: string;
}

export const SETUP_PANELS: readonly SetupPanelMeta[] = [
	{
		key: "providers",
		icon: "🌐",
		name: "providers",
		labelEn: "Model Providers (providers)",
		labelZh: "模型服务商 (providers)",
		descriptionEn: "Configure sign-in, API keys, and web search providers",
		descriptionZh: "配置 OAuth 登录、API Key 及 Web 搜索服务",
	},
	{
		key: "add",
		icon: "➕",
		name: "add",
		labelEn: "Add Custom Provider (add)",
		labelZh: "添加自定义服务商 (add)",
		descriptionEn: "Add a custom OpenAI/Anthropic-compatible provider with model discovery",
		descriptionZh: "添加兼容 OpenAI / Anthropic 协议的自定义模型服务商并自动发现模型",
	},
	{
		key: "reverse",
		icon: "🛠️",
		name: "reverse",
		labelEn: "Reverse Engineering Toolchain (reverse)",
		labelZh: "逆向工程工具链 (reverse)",
		descriptionEn: "Inspect and install reverse tools (JADX, Frida, Radare2, ADB, etc.) and MCP services",
		descriptionZh: "检查并安装逆向工具 (JADX, Frida, Radare2, ADB 等) 及 MCP 辅助服务",
	},
	{
		key: "python",
		icon: "🐍",
		name: "python",
		labelEn: "Python Execution Environment (python)",
		labelZh: "Python 执行环境 (python)",
		descriptionEn: "Verify and configure Python 3 interpreter and code execution environment",
		descriptionZh: "检查并配置 Python 3 解释器与代码执行环境",
	},
	{
		key: "speech",
		icon: "🎙️",
		name: "speech",
		labelEn: "Speech Recognition & Synthesis (speech)",
		labelZh: "语音识别与合成 (speech)",
		descriptionEn: "Configure and download STT (whisper) and TTS local models",
		descriptionZh: "配置并下载语音转文字 (STT) 与文字转语音 (TTS) 本地模型",
	},
] as const;

export function isSetupPanelKey(value: string): value is SetupPanelKey {
	return (SETUP_PANEL_KEYS as readonly string[]).includes(value);
}

export interface LocalizedSetupPanel {
	readonly key: SetupPanelKey;
	readonly label: string;
	readonly description: string;
}

export function getLocalizedPanel(
	panel: SetupPanelMeta,
	isZh: boolean = getEffectiveLocale() === "zh-CN",
): LocalizedSetupPanel {
	const labelText = isZh
		? (CLI_TRANSLATIONS_ZH_CN[`cli.setup.panel.${panel.key}.label`] ?? panel.labelZh)
		: panel.labelEn;
	const descText = isZh
		? (CLI_TRANSLATIONS_ZH_CN[`cli.setup.panel.${panel.key}.desc`] ?? panel.descriptionZh)
		: panel.descriptionEn;

	return {
		key: panel.key,
		label: `${panel.icon} ${labelText}`,
		description: descText,
	};
}

export function getAllLocalizedPanels(isZh: boolean = getEffectiveLocale() === "zh-CN"): LocalizedSetupPanel[] {
	return SETUP_PANELS.map(panel => getLocalizedPanel(panel, isZh));
}
