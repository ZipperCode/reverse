import { APP_NAME } from "@reverse/utils/dirs";
import type { CommandMetadata } from "@reverse/utils/cli";
import type * as PersistedLocale from "../config/persisted-locale";

export const acpHelp = {
	get description() {
		return `Run ${APP_NAME} as an ACP (Agent Client Protocol) server over stdio`;
	},
} satisfies CommandMetadata;

export const agentsHelp = { description: "Manage bundled task agents" } satisfies CommandMetadata;

export const anonymizeHelp = {
	description:
		"Write a shareable copy of a session and its subagents: turn contents redacted, metadata kept, paths and literals replaced by consistent mock tokens",
} satisfies CommandMetadata;

export const authHelp = {
	description: "Export or import stored provider credentials (API keys and OAuth logins) as JSON",
} satisfies CommandMetadata;

export const authBrokerHelp = {
	get description() {
		return `Manage the ${APP_NAME} auth-broker (credential vault)`;
	},
} satisfies CommandMetadata;

export const authGatewayHelp = {
	description:
		"Run an auth-gateway: an HTTP forward proxy backed by the configured broker, or JSON lines on stdio with your own credentials",
} satisfies CommandMetadata;

export const benchHelp = {
	description:
		"Benchmark models: TTFT/prefill vs decode throughput with p50/p95, across chat, prefill, generation, and prompt-cache workloads, or single-user vs parallel load (--detailed)",
} satisfies CommandMetadata;

export const browserRelayHelp = {
	description: "Run the local CDP relay that lets the browser prelude drive your own Chrome tabs",
} satisfies CommandMetadata;

export const cleanseHelp = {
	description: "Detect and fix project diagnostics with weighted parallel subagents",
} satisfies CommandMetadata;

export const commitHelp = { description: "Generate a commit message and update changelogs" } satisfies CommandMetadata;

export const completionsHelp = {
	description: "Print a shell completion script (bash, zsh, or fish)",
} satisfies CommandMetadata;

export const completeHelp = { hidden: true } satisfies CommandMetadata;

export const compressHelp = {
	description: "Rewrite a text file into the dense prompt register, reporting what it drops",
} satisfies CommandMetadata;

export const configHelp = {
	get description() {
		// 静态导入会在 --profile 解析前加载默认 agent .env。
		const { getEffectiveLocale }: typeof PersistedLocale = require("../config/persisted-locale");
		return getEffectiveLocale() === "zh-CN" ? "管理配置设置" : "Manage configuration settings";
	},
} satisfies CommandMetadata;

export const dryBalanceHelp = {
	description: "Dry-run OAuth account balancing across random session ids",
} satisfies CommandMetadata;

export const galleryHelp = {
	description: "Preview tool, composer, and status-line renderers in a deterministic visual gallery",
} satisfies CommandMetadata;

export const gcHelp = { description: "Run storage garbage collection" } satisfies CommandMetadata;
export const ifBenchHelp = {
	description:
		"Benchmark instruction following and working memory: one cached thread of glyph array actions with a moving cat-sound directive",
} satisfies CommandMetadata;
export const gitHelp = {
	description: "Interactive fullscreen git UI: split diff viewer, staging sidebar, and commit composer",
} satisfies CommandMetadata;

export const findHelp = {
	description: "Semantic search: describe a behavior, get the files and line ranges that implement it",
} satisfies CommandMetadata;

export const grepHelp = { description: "Test grep tool" } satisfies CommandMetadata;

export const loginHelp = {
	description: "Log in to a model provider (terminal counterpart of /login)",
} satisfies CommandMetadata;

export const imagesHelp = {
	description: "Inspect, diagnose, probe, and purge image publication backends",
} satisfies CommandMetadata;

export const installHelp = {
	description: "Install or link an extension package (alias of `plugin install`/`plugin link`)",
} satisfies CommandMetadata;

export const modelsHelp = { description: "List, search, and refresh available models" } satisfies CommandMetadata;

export const pluginHelp = { description: "Manage plugins (install, uninstall, list, etc.)" } satisfies CommandMetadata;

export const playHelp = {
	description: "Replay a /record session recording in the terminal (space pauses, q quits)",
} satisfies CommandMetadata;

export const predictHelp = {
	description: "Type a prompt and compare every word-completion engine's ghost text live",
} satisfies CommandMetadata;

export const psHelp = {
	description: "List and control daemon-supervised background processes (logs, stop, kill, restart)",
} satisfies CommandMetadata;

export const readHelp = {
	description: "Show what the read tool will return for a path, URL, or internal URI",
} satisfies CommandMetadata;
export const renderHelp = {
	description: "Draw a session's entire thread through the production transcript pipeline (with repaint timing)",
} satisfies CommandMetadata;

export const sayHelp = {
	description: "Synthesize text with the local TTS engine and play it through the speakers",
} satisfies CommandMetadata;

export const searchHelp = { description: "Test web search providers" } satisfies CommandMetadata;

export const sessionHelp = {
	description: "Hand a session to another machine: pack it, unpack it, or mark the local copy moved",
} satisfies CommandMetadata;

export const setupHelp = {
	get description() {
		// 帮助元数据可被启动解析器导入；此时仍须延后读取配置。
		const { getEffectiveLocale }: typeof PersistedLocale = require("../config/persisted-locale");
		return getEffectiveLocale() === "zh-CN"
			? "运行入职设置或配置系统组件（providers、add、reverse、python、speech）"
			: "Run onboarding setup or configure system components (providers, add, reverse, python, speech)";
	},
} satisfies CommandMetadata;

export const shellHelp = { description: "Interactive shell console" } satisfies CommandMetadata;

export const skillHelp = {
	description:
		"List available skills and warnings, or check their external tool dependencies (skill list|check [dir] [--json])",
} satisfies CommandMetadata;

export const sshHelp = { description: "Manage SSH host configurations" } satisfies CommandMetadata;

export const statsHelp = { description: "View usage statistics" } satisfies CommandMetadata;

export const tinyModelsHelp = {
	description: "Download tiny local models (session titles, memory, word completion)",
} satisfies CommandMetadata;

export const tokenHelp = { description: "Get the API key or OAuth token for a provider" } satisfies CommandMetadata;

export const toksHelp = {
	description: "Count a file or text with every embedded offline tokenizer (OpenAI, Claude, Qwen, …)",
} satisfies CommandMetadata;

export const ttsrHelp = {
	description: "Inspect and test Time-Traveling Stream Rules (TTSR)",
} satisfies CommandMetadata;

export const usageHelp = {
	description: "Show provider usage limits for every authenticated account",
} satisfies CommandMetadata;

export const worktreeHelp = {
	description: "Add, list, or clear git worktrees (clone-first when enabled)",
} satisfies CommandMetadata;
