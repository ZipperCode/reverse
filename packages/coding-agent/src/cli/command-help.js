import { getEffectiveLocale } from "../config/persisted-locale";
export const acpHelp = {
    description: "Run rea as an ACP (Agent Client Protocol) server over stdio",
};
export const agentsHelp = { description: "Manage bundled task agents" };
export const anonymizeHelp = {
    description: "Write a shareable copy of a session and its subagents: turn contents redacted, metadata kept, paths and literals replaced by consistent mock tokens",
};
export const authHelp = {
    description: "Export or import stored provider credentials (API keys and OAuth logins) as JSON",
};
export const authBrokerHelp = {
    description: "Manage the rea auth-broker (credential vault)",
};
export const authGatewayHelp = {
    description: "Run an auth-gateway: an HTTP forward proxy backed by the configured broker, or JSON lines on stdio with your own credentials",
};
export const benchHelp = {
    description: "Benchmark models: TTFT/prefill vs decode throughput with p50/p95, across chat, prefill, generation, and prompt-cache workloads, or single-user vs parallel load (--detailed)",
};
export const browserRelayHelp = {
    description: "Run the local CDP relay that lets the browser prelude drive your own Chrome tabs",
};
export const cleanseHelp = {
    description: "Detect and fix project diagnostics with weighted parallel subagents",
};
export const commitHelp = { description: "Generate a commit message and update changelogs" };
export const completionsHelp = {
    description: "Print a shell completion script (bash, zsh, or fish)",
};
export const completeHelp = { hidden: true };
export const compressHelp = {
    description: "Rewrite a text file into the dense prompt register, reporting what it drops",
};
export const configHelp = {
    get description() {
        return getEffectiveLocale() === "zh-CN" ? "管理配置设置" : "Manage configuration settings";
    },
};
export const dryBalanceHelp = {
    description: "Dry-run OAuth account balancing across random session ids",
};
export const galleryHelp = {
    description: "Preview tool, composer, and status-line renderers in a deterministic visual gallery",
};
export const gcHelp = { description: "Run storage garbage collection" };
export const ifBenchHelp = {
    description: "Benchmark instruction following and working memory: one cached thread of glyph array actions with a moving cat-sound directive",
};
export const gitHelp = {
    description: "Interactive fullscreen git UI: split diff viewer, staging sidebar, and commit composer",
};
export const findHelp = {
    description: "Semantic search: describe a behavior, get the files and line ranges that implement it",
};
export const grepHelp = { description: "Test grep tool" };
export const loginHelp = {
    description: "Log in to a model provider (terminal counterpart of /login)",
};
export const imagesHelp = {
    description: "Inspect, diagnose, probe, and purge image publication backends",
};
export const installHelp = {
    description: "Install or link an extension package (alias of `plugin install`/`plugin link`)",
};
export const modelsHelp = { description: "List, search, and refresh available models" };
export const pluginHelp = { description: "Manage plugins (install, uninstall, list, etc.)" };
export const playHelp = {
    description: "Replay a /record session recording in the terminal (space pauses, q quits)",
};
export const predictHelp = {
    description: "Type a prompt and compare every word-completion engine's ghost text live",
};
export const psHelp = {
    description: "List and control daemon-supervised background processes (logs, stop, kill, restart)",
};
export const readHelp = {
    description: "Show what the read tool will return for a path, URL, or internal URI",
};
export const renderHelp = {
    description: "Draw a session's entire thread through the production transcript pipeline (with repaint timing)",
};
export const sayHelp = {
    description: "Synthesize text with the local TTS engine and play it through the speakers",
};
export const searchHelp = { description: "Test web search providers" };
export const sessionHelp = {
    description: "Hand a session to another machine: pack it, unpack it, or mark the local copy moved",
};
export const setupHelp = {
    get description() {
        return getEffectiveLocale() === "zh-CN"
            ? "运行入职设置或安装可选功能的依赖（reverse、python、speech）"
            : "Run onboarding setup or install dependencies for optional features (reverse, python, speech)";
    },
};
export const shellHelp = { description: "Interactive shell console" };
export const skillHelp = {
    description: "List available skills and warnings, or check their external tool dependencies (skill list|check [dir] [--json])",
};
export const sshHelp = { description: "Manage SSH host configurations" };
export const statsHelp = { description: "View usage statistics" };
export const tinyModelsHelp = {
    description: "Download tiny local models (session titles, memory, word completion)",
};
export const tokenHelp = { description: "Get the API key or OAuth token for a provider" };
export const toksHelp = {
    description: "Count a file or text with every embedded offline tokenizer (OpenAI, Claude, Qwen, …)",
};
export const ttsrHelp = {
    description: "Inspect and test Time-Traveling Stream Rules (TTSR)",
};
export const usageHelp = {
    description: "Show provider usage limits for every authenticated account",
};
export const worktreeHelp = {
    description: "Add, list, or clear git worktrees (clone-first when enabled)",
};
