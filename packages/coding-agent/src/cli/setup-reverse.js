/**
 * Universal reverse engineering toolchain setup and inspection panel.
 *
 * Provides a trusted, cross-platform CLI and TUI interface for checking and
 * manually installing external reverse tools (JADX, Apktool, ADB, Frida,
 * Radare2, IDA, UPX, etc.).
 *
 * Design principles:
 * - Explicit user trigger: Never run or prompted automatically by skill loading.
 * - Trusted catalog: Commands come strictly from {@link SKILL_TOOL_CATALOG};
 *   no untrusted strings from skills or network are ever executed.
 * - Interactive confirmation: Every single installation command requires explicit
 *   review and manual confirmation [y/N] before execution; no bypass flags allowed.
 * - Authorized setup path: Subprocess execution is only reachable through this
 *   explicit user confirmation boundary; non-interactive modes (--check, --json)
 *   are strictly read-only probes that never execute subprocesses.
 * - Package manager agnostic: Detects brew/apt/choco/winget/pipx/npm/cargo
 *   and falls back to clear manual download instructions when none is available.
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import * as readline from "node:readline";
import { $which, APP_NAME, getMCPConfigPath, getProjectDir, WhichCachePolicy } from "@rva/utils";
import chalk from "@rva/utils/chalk";
import { theme } from "@rva/tui/theme";
import { getEffectiveLocale } from "../config/persisted-locale";
import { SKILL_TOOL_CATALOG, } from "../extensibility/skill-tool-catalog";
import { getMcpServices, mcpServerSnippet } from "../extensibility/mcp-service-catalog";
import { checkToolRequirements, } from "../extensibility/skill-requirements";
import { CLI_TRANSLATIONS_ZH_CN } from "../i18n/zh-CN/cli";
/** Read an MCP config file without writing or starting anything. */
function readMcpConfigFileSync(filePath) {
    try {
        const parsed = JSON.parse(readFileSync(filePath, "utf8"));
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
            return null;
        return parsed;
    }
    catch {
        return null;
    }
}
function t(key, fallback, vars) {
    const locale = getEffectiveLocale();
    let text = locale === "zh-CN" ? (CLI_TRANSLATIONS_ZH_CN[key] ?? fallback) : fallback;
    if (vars) {
        for (const [k, v] of Object.entries(vars)) {
            text = text.replaceAll(`{${k}}`, v);
        }
    }
    return text;
}
/** Detect installed package managers on the host system. */
export function detectPackageManagers(platform, which) {
    const candidates = {
        darwin: ["brew", "pipx", "pip", "python3", "npm", "cargo", "r2pm"],
        linux: ["apt", "apt-get", "pacman", "dnf", "brew", "pipx", "pip", "python3", "npm", "cargo", "r2pm"],
        win32: ["winget", "choco", "scoop", "pipx", "pip", "py", "npm", "cargo", "r2pm"],
    };
    const options = { cache: WhichCachePolicy.Bypass, requireAbsolutePaths: true };
    const found = [];
    for (const candidate of candidates[platform] ?? []) {
        if (which(candidate, options) !== null) {
            found.push(candidate);
        }
    }
    return found;
}
function isManagerAvailable(manager, availableManagers) {
    if (availableManagers.includes(manager))
        return true;
    if (manager === "apt" && availableManagers.includes("apt-get"))
        return true;
    if (manager === "pip" && (availableManagers.includes("python3") || availableManagers.includes("py")))
        return true;
    return false;
}
function selectInstallCommand(descriptor, platform, availableManagers) {
    const commands = descriptor.installCommands?.[platform] ?? [];
    for (const cmd of commands) {
        if (isManagerAvailable(cmd.manager, availableManagers)) {
            return cmd;
        }
    }
    return undefined;
}
/**
 * Check all reverse engineering tools in the catalog and resolve their
 * availability and installation paths for the current machine.
 */
export function checkReverseTools(deps = {}) {
    const requestedPlatform = deps.platform ?? process.platform;
    const platform = requestedPlatform === "darwin" || requestedPlatform === "win32" ? requestedPlatform : "linux";
    const which = deps.which ?? $which;
    const detectedPackageManagers = detectPackageManagers(platform, which);
    const descriptors = Object.values(SKILL_TOOL_CATALOG);
    const toolRequirements = descriptors.map(desc => ({ id: desc.id, optional: desc.optional ?? true }));
    const statuses = checkToolRequirements(toolRequirements, {
        platform: requestedPlatform,
        which,
        env: deps.env,
    });
    const statusById = Object.fromEntries(statuses.map(s => [s.id, s]));
    const tools = [];
    const missingRequired = [];
    const missingOptional = [];
    for (const desc of descriptors) {
        const reqStatus = statusById[desc.id];
        const foundPath = reqStatus?.foundPath ?? null;
        const secondaryMissing = reqStatus?.secondaryMissing;
        const isInstalled = foundPath !== null && (!secondaryMissing || secondaryMissing.length === 0);
        const isOptional = desc.optional ?? true;
        if (!isInstalled) {
            if (isOptional)
                missingOptional.push(desc.id);
            else
                missingRequired.push(desc.id);
        }
        const chosenCmd = isInstalled ? undefined : selectInstallCommand(desc, platform, detectedPackageManagers);
        const manualGuide = desc.manualInstructions?.[platform] ??
            (desc.manualUrl ? `See official instructions at ${desc.manualUrl}` : "Manual setup required.");
        tools.push({
            kind: "cli",
            id: desc.id,
            name: desc.name ?? desc.id,
            category: desc.category ?? "general",
            description: desc.description ?? "",
            optional: isOptional,
            systemTool: desc.systemTool ?? false,
            status: isInstalled ? "installed" : "missing",
            foundPath,
            ...(secondaryMissing && secondaryMissing.length > 0 && { secondaryMissing }),
            packageManager: chosenCmd?.manager ?? null,
            installCommand: chosenCmd?.command ?? null,
            installArgv: chosenCmd?.argv && chosenCmd.argv.length > 0 ? chosenCmd.argv : null,
            riskNote: chosenCmd?.riskNote ?? null,
            manualUrl: desc.manualUrl ?? "",
            manualInstructions: manualGuide,
            hint: desc.installHints?.[platform]?.join(" or "),
        });
    }
    // Service prerequisites are catalogued CLI tools, but keep the fallback for
    // future entries whose ids are not yet in the CLI catalog: an unknown id is
    // probed on PATH and never claims to be an installed service.
    const serviceDescriptors = getMcpServices().filter(desc => !desc.platforms || desc.platforms.includes(platform));
    const uncoveredRequirementIds = [
        ...new Set(serviceDescriptors.flatMap(desc => desc.requires).filter(id => !statusById[id])),
    ];
    const uncoveredStatuses = uncoveredRequirementIds.length > 0
        ? checkToolRequirements(uncoveredRequirementIds.map(id => ({ id, optional: true })), { platform: requestedPlatform, which, env: deps.env })
        : [];
    for (const status of uncoveredStatuses)
        statusById[status.id] = status;
    // Resolve the real config candidates from the running installation instead of
    // repeating the catalog's display hint. Reading is probe-only: no file is
    // written and no server is launched.
    const cwd = deps.cwd ?? getProjectDir();
    const configPaths = {
        project: getMCPConfigPath("project", cwd),
        user: getMCPConfigPath("user", cwd),
    };
    const readConfig = deps.readMcpConfig ?? readMcpConfigFileSync;
    const configFiles = {
        project: readConfig(configPaths.project),
        user: readConfig(configPaths.user),
    };
    const services = serviceDescriptors.map(desc => {
        const prerequisites = desc.requires
            .map(id => statusById[id])
            .filter((status) => status !== undefined);
        const missingPrerequisites = prerequisites
            .filter(status => status.foundPath === null || (status.secondaryMissing?.length ?? 0) > 0)
            .map(status => status.id);
        const ready = missingPrerequisites.length === 0;
        // Config presence is checked per scope. `enabled` stays null when the
        // service is unconfigured: connection state cannot be observed without
        // starting the server, which inspection never does.
        const configuredScopes = [];
        let enabled = null;
        for (const scope of ["project", "user"]) {
            const file = configFiles[scope];
            const entry = file?.mcpServers?.[desc.serverName];
            if (!entry || typeof entry !== "object")
                continue;
            configuredScopes.push(scope);
            const scopeEnabled = !file?.disabledServers?.includes(desc.serverName) &&
                (entry.enabled !== false || (file?.enabledServers?.includes(desc.serverName) ?? false));
            enabled = enabled === null ? scopeEnabled : enabled || scopeEnabled;
        }
        const configured = configuredScopes.length > 0;
        // Readiness means the prerequisite CLI tools exist, not that the server
        // package is installed. Offer the catalog install command in both states;
        // execution still requires the explicit interactive confirmation below.
        const chosenCmd = selectInstallCommand(desc, platform, detectedPackageManagers);
        const manualGuide = desc.manualInstructions[platform] ?? `See official instructions at ${desc.manualUrl}`;
        return {
            kind: "mcp",
            id: desc.id,
            name: desc.name,
            category: desc.category,
            description: desc.description,
            optional: true,
            license: desc.license,
            serverName: desc.serverName,
            transport: desc.server.type ?? "stdio",
            startCommand: desc.startCommand,
            configPath: desc.configPath,
            configPaths,
            configSnippet: { ...mcpServerSnippet(desc) },
            prerequisites,
            missingPrerequisites,
            prerequisitesReady: ready,
            ready,
            configured,
            configuredScopes,
            enabled,
            connection: "unknown",
            status: ready ? "ready" : "missing",
            packageManager: chosenCmd?.manager ?? null,
            installCommand: chosenCmd?.command ?? null,
            installArgv: chosenCmd?.argv && chosenCmd.argv.length > 0 ? chosenCmd.argv : null,
            riskNote: chosenCmd?.riskNote ?? desc.riskNote,
            manualUrl: desc.manualUrl,
            manualInstructions: manualGuide,
            hint: desc.installHints?.[platform]?.join(" or "),
            usage: desc.usage,
        };
    });
    return {
        ok: missingRequired.length === 0,
        platform,
        detectedPackageManagers,
        tools,
        services,
        missingRequired,
        missingOptional,
    };
}
/** Verify that an item's installArgv strictly originates from the trusted catalog. */
export function isTrustedCatalogArgv(item) {
    if (!item.installArgv || item.installArgv.length === 0) {
        return false;
    }
    if (item.kind === "cli") {
        const desc = SKILL_TOOL_CATALOG[item.id];
        if (!desc || !desc.installCommands)
            return false;
        for (const cmds of Object.values(desc.installCommands)) {
            if (!cmds)
                continue;
            for (const cmd of cmds) {
                if (cmd.argv &&
                    cmd.argv.length === item.installArgv.length &&
                    cmd.argv.every((val, idx) => val === item.installArgv[idx])) {
                    return true;
                }
            }
        }
        return false;
    }
    if (item.kind === "mcp") {
        const services = getMcpServices();
        const service = services.find(s => s.id === item.id);
        if (!service || !service.installCommands)
            return false;
        for (const cmds of Object.values(service.installCommands)) {
            if (!cmds)
                continue;
            for (const cmd of cmds) {
                if (cmd.argv &&
                    cmd.argv.length === item.installArgv.length &&
                    cmd.argv.every((val, idx) => val === item.installArgv[idx])) {
                    return true;
                }
            }
        }
        return false;
    }
    return false;
}
/**
 * Safely execute a catalog installation command for TUI.
 * - Refuses non-TTY execution unless allowNonTTY is explicitly provided.
 * - Subprocess stdin is ignored (never blocks or hijacks TUI keyboard).
 * - Enforces catalog argv validation (rejects untrusted/tampered argv).
 */
export async function executeSafeCatalogCommand(item, options) {
    if (!isTrustedCatalogArgv(item)) {
        return {
            exitCode: 1,
            stdout: "",
            stderr: `Untrusted installation command for ${item.name}: argv does not match catalog definition.`,
        };
    }
    const isTTY = options?.isTTY ?? (options?.allowNonTTY ? true : Boolean(process.stdin.isTTY && process.stdout.isTTY));
    if (!isTTY) {
        return {
            exitCode: 1,
            stdout: "",
            stderr: "TUI installation executor requires an interactive TTY.",
        };
    }
    const argv = item.installArgv;
    const timeout = options?.timeoutMs ?? 180000;
    if (typeof Bun !== "undefined" && typeof Bun.spawn === "function") {
        const proc = Bun.spawn(argv, {
            stdin: "ignore",
            stdout: "pipe",
            stderr: "pipe",
        });
        let stdout = "";
        let stderr = "";
        const readStream = async (stream, isErr) => {
            const reader = stream.getReader();
            const decoder = new TextDecoder();
            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done)
                        break;
                    const text = decoder.decode(value, { stream: true });
                    if (isErr)
                        stderr += text;
                    else
                        stdout += text;
                    options?.onChunk?.(text);
                }
            }
            finally {
                reader.releaseLock();
            }
        };
        let timer;
        const timeoutPromise = new Promise(resolve => {
            timer = setTimeout(() => resolve({ timeout: true }), timeout);
        });
        const runPromise = Promise.all([
            readStream(proc.stdout, false),
            readStream(proc.stderr, true),
        ]).then(async () => {
            const exitCode = await proc.exited;
            return { exitCode, stdout, stderr };
        });
        try {
            const res = await Promise.race([runPromise, timeoutPromise]);
            if ("timeout" in res) {
                proc.kill();
                return { exitCode: 124, stdout, stderr: `${stderr}\nExecution timed out after ${timeout}ms.` };
            }
            return res;
        }
        finally {
            if (timer)
                clearTimeout(timer);
        }
    }
    const { spawn } = await import("node:child_process");
    const { promise, resolve } = Promise.withResolvers();
    let stdout = "";
    let stderr = "";
    let settled = false;
    const child = spawn(argv[0], argv.slice(1), { stdio: ["ignore", "pipe", "pipe"] });
    const timer = setTimeout(() => {
        if (!settled) {
            settled = true;
            child.kill("SIGKILL");
            resolve({ exitCode: 124, stdout, stderr: `${stderr}\nExecution timed out after ${timeout}ms.` });
        }
    }, timeout);
    child.stdout?.on("data", chunk => {
        const text = String(chunk);
        stdout += text;
        options?.onChunk?.(text);
    });
    child.stderr?.on("data", chunk => {
        const text = String(chunk);
        stderr += text;
        options?.onChunk?.(text);
    });
    child.on("close", code => {
        if (!settled) {
            settled = true;
            clearTimeout(timer);
            resolve({ exitCode: code ?? 1, stdout, stderr });
        }
    });
    child.on("error", err => {
        if (!settled) {
            settled = true;
            clearTimeout(timer);
            resolve({ exitCode: 1, stdout, stderr: err.message });
        }
    });
    return promise;
}
async function runDefaultExecutor(argv, options) {
    if (argv.length === 0) {
        return { exitCode: 1, stdout: "", stderr: "Empty command arguments." };
    }
    if (typeof Bun !== "undefined" && typeof Bun.spawn === "function") {
        const proc = Bun.spawn(argv, {
            stdin: "inherit",
            stdout: "pipe",
            stderr: "pipe",
        });
        let stdout = "";
        let stderr = "";
        const readStream = async (stream, isErr) => {
            const reader = stream.getReader();
            const decoder = new TextDecoder();
            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done)
                        break;
                    const text = decoder.decode(value, { stream: true });
                    if (isErr)
                        stderr += text;
                    else
                        stdout += text;
                    options?.onChunk?.(text);
                }
            }
            finally {
                reader.releaseLock();
            }
        };
        await Promise.all([
            readStream(proc.stdout, false),
            readStream(proc.stderr, true),
        ]);
        const exitCode = await proc.exited;
        return { exitCode, stdout, stderr };
    }
    const { promise, resolve } = Promise.withResolvers();
    const child = spawn(argv[0], argv.slice(1), { stdio: ["inherit", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", chunk => {
        const text = String(chunk);
        stdout += text;
        options?.onChunk?.(text);
    });
    child.stderr?.on("data", chunk => {
        const text = String(chunk);
        stderr += text;
        options?.onChunk?.(text);
    });
    child.on("close", code => resolve({ exitCode: code ?? 1, stdout, stderr }));
    child.on("error", err => resolve({ exitCode: 1, stdout, stderr: err.message }));
    return promise;
}
function runDefaultPrompt(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const { promise, resolve } = Promise.withResolvers();
    rl.question(question, answer => {
        rl.close();
        resolve(answer.trim());
    });
    return promise;
}
async function runDefaultConfirm(question) {
    const answer = (await runDefaultPrompt(question)).toLowerCase();
    return answer === "y" || answer === "yes";
}
function renderToolTable(report, write) {
    const colIndex = " #".padEnd(4);
    const colStatus = "Status".padEnd(11);
    const colTool = "Tool".padEnd(16);
    const colCategory = "Category".padEnd(12);
    const colType = "Type".padEnd(10);
    const colDetail = "Details / Install Method";
    write(`\n${chalk.dim("--------------------------------------------------------------------------------")}\n`);
    write(`${chalk.bold(colIndex + colStatus + colTool + colCategory + colType + colDetail)}\n`);
    write(`${chalk.dim("--------------------------------------------------------------------------------")}\n`);
    report.tools.forEach((tool, index) => {
        const idxStr = ` ${index + 1}`.padEnd(4);
        const isOk = tool.status === "installed";
        const statusBadge = isOk
            ? chalk.green("[OK]".padEnd(11))
            : tool.optional
                ? chalk.yellow("[MISSING]".padEnd(11))
                : chalk.red("[MISSING]".padEnd(11));
        const toolStr = chalk.bold(tool.id.padEnd(16));
        const catStr = chalk.cyan(tool.category.padEnd(12));
        const typeStr = tool.optional ? chalk.dim("optional".padEnd(10)) : chalk.magenta("required".padEnd(10));
        let detailStr = "";
        if (isOk) {
            const secondaryNote = tool.secondaryMissing && tool.secondaryMissing.length > 0
                ? chalk.yellow(` [Missing prerequisite: ${tool.secondaryMissing.join(", ")}]`)
                : "";
            detailStr = `${chalk.dim(tool.foundPath ?? "found")}${secondaryNote}`;
        }
        else if (tool.installCommand) {
            detailStr = `${chalk.blue(`[${tool.packageManager}]`)} ${tool.installCommand}`;
        }
        else {
            detailStr = chalk.gray(`Manual (${tool.manualUrl ? "see download URL" : tool.manualInstructions})`);
        }
        write(`${idxStr}${statusBadge}${toolStr}${catStr}${typeStr}${detailStr}\n`);
    });
    write(`${chalk.dim("--------------------------------------------------------------------------------")}\n\n`);
}
function renderServiceTable(report, write) {
    if (report.services.length === 0)
        return;
    write(`\n${chalk.bold("Optional MCP helper services")}\n`);
    write(`${chalk.dim("These are MCP servers, not PATH binaries. Prerequisites and mcp.json entries are probed read-only; connection is never verified.")}\n`);
    write(`${chalk.dim("--------------------------------------------------------------------------------")}\n`);
    write(`${chalk.bold(" #".padEnd(4) + "Prereqs".padEnd(11) + "Service".padEnd(20) + "Category".padEnd(12) + "Transport".padEnd(11) + "Prerequisites / Config / Setup")}\n`);
    write(`${chalk.dim("--------------------------------------------------------------------------------")}\n`);
    report.services.forEach((service, index) => {
        const idxStr = ` ${index + 1}`.padEnd(4);
        const statusBadge = service.ready ? chalk.green("[READY]".padEnd(11)) : chalk.yellow("[MISSING]".padEnd(11));
        const serviceStr = chalk.bold(service.id.padEnd(20));
        const catStr = chalk.cyan(service.category.padEnd(12));
        const transportStr = chalk.dim(service.transport.padEnd(11));
        const configStr = service.configured
            ? `configured (${service.configuredScopes.join(", ")})${service.enabled === false ? ", disabled" : ""}`
            : "not configured";
        let detailStr;
        if (service.ready) {
            detailStr = `${chalk.dim(`prerequisites ok: ${service.prerequisites.map(p => p.id).join(", ") || "none"}; ${configStr}`)}`;
        }
        else if (service.installCommand) {
            detailStr = `${chalk.blue(`[${service.packageManager}]`)} ${service.installCommand} ${chalk.dim(`(${configStr})`)}`;
        }
        else {
            detailStr = `${chalk.gray(`Manual (${service.manualUrl})`)} ${chalk.dim(`(${configStr})`)}`;
        }
        write(`${idxStr}${statusBadge}${serviceStr}${catStr}${transportStr}${detailStr}\n`);
    });
    write(`${chalk.dim("--------------------------------------------------------------------------------")}\n\n`);
}
/**
 * Handle reverse tools setup: report `--json` / `--check` or render
 * interactive panel with manual tool selection, pre-install confirmation,
 * safe catalog execution, and status refresh.
 */
export async function handleReverseSetup(flags, targetTool, deps = {}) {
    const write = deps.writeStdout ?? (text => process.stdout.write(text));
    const writeErr = deps.writeStderr ?? (text => process.stderr.write(text));
    const promptLine = deps.promptLine ?? runDefaultPrompt;
    const confirm = deps.confirm ?? runDefaultConfirm;
    const executor = deps.executor ?? runDefaultExecutor;
    let report = checkReverseTools(deps);
    if (flags.json) {
        write(`${JSON.stringify(report, null, 2)}\n`);
        if (flags.check && !report.ok) {
            return 1;
        }
        return 0;
    }
    if (flags.check) {
        write(`${chalk.bold(t("cli.setup.reverse.checkSummary", "Reverse engineering toolchain catalog overview:"))}\n`);
        for (const tool of report.tools) {
            const isOk = tool.status === "installed";
            const mark = isOk ? chalk.green("[ok]") : tool.optional ? chalk.yellow("[missing]") : chalk.red("[missing]");
            const typeBadge = tool.optional ? chalk.dim("(optional)") : chalk.bold("(required)");
            const secondaryNote = tool.secondaryMissing && tool.secondaryMissing.length > 0
                ? ` (missing prerequisite: ${tool.secondaryMissing.join(", ")})`
                : "";
            const details = isOk
                ? `${tool.foundPath}${secondaryNote}`
                : tool.installCommand
                    ? `not found - command: ${tool.installCommand}`
                    : `not found - manual: ${tool.manualUrl || tool.manualInstructions}`;
            write(`  ${mark} ${chalk.bold(tool.id)}: ${details} ${typeBadge}\n`);
        }
        for (const service of report.services) {
            const mark = service.ready ? chalk.green("[ready]") : chalk.yellow("[missing]");
            const config = service.configured
                ? `configured in ${service.configuredScopes.join(", ")}${service.enabled === false ? " (disabled)" : ""}`
                : "not configured";
            const details = service.ready
                ? `prerequisites ok (${service.prerequisites.map(p => p.id).join(", ") || "none"}); ${config}; connection unverified; start: ${service.startCommand}${service.installCommand ? `; install: ${service.installCommand}` : ""}`
                : service.installCommand
                    ? `prerequisites missing (${service.missingPrerequisites.join(", ")}); ${config} - install: ${service.installCommand}`
                    : `prerequisites missing (${service.missingPrerequisites.join(", ")}); ${config} - manual: ${service.manualUrl}`;
            write(`  ${mark} ${chalk.bold(service.id)} (mcp): ${details} ${chalk.dim("(optional)")}\n`);
        }
        if (!report.ok) {
            const missingNames = report.missingRequired.join(", ");
            const errIcon = theme?.status?.error ?? "✗";
            writeErr(`\n${chalk.red(errIcon)} ${t("cli.setup.reverse.missingRequiredNotice", `Missing required system tools: ${missingNames}`, { tools: missingNames })}\n`);
            return 1;
        }
        const successIcon = theme?.status?.success ?? "✓";
        const optionalInstalledCount = report.tools.filter(t => t.optional && t.status === "installed").length;
        const optionalMissingCount = report.missingOptional.length;
        write(`\n${chalk.green(successIcon)} ${t("cli.setup.reverse.allReady", `Core system tools are present (strings, file). ${optionalInstalledCount} installed, ${optionalMissingCount} optional tools available in catalog.`, { installed: String(optionalInstalledCount), missing: String(optionalMissingCount) })}\n`);
        return 0;
    }
    // Interactive terminal panel
    const executeMode = flags.execute ?? false;
    const isTTY = deps.isTTY ?? Boolean(process.stdin.isTTY && process.stdout.isTTY);
    if (executeMode && !isTTY) {
        const ttyError = t("cli.setup.reverse.executeRequiresTTY", `${APP_NAME} setup reverse --execute requires an interactive TTY. Use --check or --json for non-interactive inspections.`, { app: APP_NAME });
        writeErr(`${chalk.red(theme?.status?.error ?? "✗")} ${ttyError}\n`);
        return 1;
    }
    write(`\n${chalk.bold.cyan("================================================================================")}\n`);
    write(`  ${chalk.bold(t("cli.setup.reverse.title", `${APP_NAME} Reverse Engineering Toolchain Manual Setup Panel`))}\n`);
    write(`  ${chalk.dim(t("cli.setup.reverse.description", "Inspect tool status, manual installation guides, and copy-pastable commands"))}\n`);
    write(`${chalk.bold.cyan("================================================================================")}\n`);
    const installedCount = report.tools.filter(t => t.status === "installed").length;
    const missingCount = report.tools.filter(t => t.status === "missing").length;
    const pmList = report.detectedPackageManagers.length > 0
        ? report.detectedPackageManagers.join(", ")
        : t("cli.setup.reverse.noPackageManagers", "none (manual only)");
    write(`${chalk.dim(`Catalog overview: ${report.tools.length} CLI tools (${installedCount} installed, ${missingCount} missing), ${report.services.length} MCP services | Platform: ${report.platform}`)}\n`);
    write(`${chalk.dim(t("cli.setup.reverse.packageManagers", `Package Managers: ${pmList}`, { managers: pmList }))}\n`);
    renderToolTable(report, write);
    renderServiceTable(report, write);
    const selectedTools = [];
    const selectedServices = [];
    if (targetTool) {
        const normalizedTarget = targetTool.trim().toLowerCase();
        const match = report.tools.find(tool => tool.id.toLowerCase() === normalizedTarget || tool.name.toLowerCase().includes(normalizedTarget));
        const serviceMatch = match
            ? undefined
            : report.services.find(service => service.id.toLowerCase() === normalizedTarget ||
                service.serverName.toLowerCase() === normalizedTarget ||
                service.name.toLowerCase().includes(normalizedTarget));
        if (match) {
            selectedTools.push(match);
        }
        else if (serviceMatch) {
            selectedServices.push(serviceMatch);
        }
        else {
            const errIcon = theme?.status?.error ?? "✗";
            writeErr(`${chalk.red(errIcon)} Unknown tool or MCP service: ${targetTool}\n`);
            return 1;
        }
    }
    else {
        const promptText = t("cli.setup.reverse.promptSelect", "Enter tool/service number(s) or ID(s) to install (e.g. 1, 3, jadx, r2mcp, 'all-missing', or 'q' to quit): ");
        const selection = await promptLine(promptText);
        if (!selection || selection.toLowerCase() === "q" || selection.toLowerCase() === "quit") {
            write(chalk.dim("Setup panel closed.\n"));
            return 0;
        }
        if (selection.toLowerCase() === "all-missing") {
            selectedTools.push(...report.tools.filter(t => t.status === "missing"));
            selectedServices.push(...report.services.filter(service => !service.ready && service.installArgv));
        }
        else {
            const tokens = selection.split(/[\s,]+/);
            for (const token of tokens) {
                const trimmed = token.trim();
                if (!trimmed)
                    continue;
                const serviceNumber = /^s(\d+)$/i.exec(trimmed);
                const num = serviceNumber ? Number.NaN : Number.parseInt(trimmed, 10);
                if (!Number.isNaN(num) && num >= 1 && num <= report.tools.length) {
                    selectedTools.push(report.tools[num - 1]);
                }
                else if (serviceNumber) {
                    const index = Number.parseInt(serviceNumber[1], 10);
                    if (index >= 1 && index <= report.services.length)
                        selectedServices.push(report.services[index - 1]);
                    else
                        write(chalk.yellow(`Warning: Unrecognized MCP service selection "${trimmed}". Skipped.\n`));
                }
                else {
                    const match = report.tools.find(t => t.id.toLowerCase() === trimmed.toLowerCase());
                    const serviceMatch = match
                        ? undefined
                        : report.services.find(service => service.id.toLowerCase() === trimmed.toLowerCase() ||
                            service.serverName.toLowerCase() === trimmed.toLowerCase());
                    if (match)
                        selectedTools.push(match);
                    else if (serviceMatch)
                        selectedServices.push(serviceMatch);
                    else
                        write(chalk.yellow(`Warning: Unrecognized tool/service selection "${trimmed}". Skipped.\n`));
                }
            }
        }
    }
    if (selectedTools.length === 0 && selectedServices.length === 0) {
        write(chalk.dim("No valid tools or services selected.\n"));
        return 0;
    }
    let hasFailures = false;
    for (const tool of selectedTools) {
        write(`\n${chalk.cyan("--------------------------------------------------------------------------------")}\n`);
        write(`${chalk.bold(t("cli.setup.reverse.detailTool", `Tool: ${tool.name} (${tool.id})`, { name: tool.name, id: tool.id }))}\n`);
        write(`${chalk.dim(t("cli.setup.reverse.detailCategory", `Category: ${tool.category}`, { category: tool.category }))} | ${chalk.dim(t("cli.setup.reverse.detailType", `Type: ${tool.optional ? "optional" : "required"}`, { type: tool.optional ? "optional" : "required" }))}\n`);
        write(`${chalk.dim(`Status: ${tool.status === "installed" ? "Installed" : "Not installed"}`)}${tool.foundPath ? ` (${tool.foundPath})` : ""}\n`);
        if (tool.secondaryMissing && tool.secondaryMissing.length > 0) {
            write(`${chalk.yellow(`Prerequisite missing: ${tool.secondaryMissing.join(", ")} (requires Java runtime)`)}\n`);
        }
        if (tool.installCommand) {
            write(`\n${chalk.bold("Recommended installation command:")}\n`);
            write(`  ${chalk.green(tool.installCommand)}\n`);
            if (tool.riskNote) {
                write(`  ${chalk.dim(`Notes: ${tool.riskNote}`)}\n`);
            }
        }
        else {
            write(chalk.yellow(`\n${t("cli.setup.reverse.noManagerFound", "No compatible package manager (e.g. brew/apt/choco) detected for automated install.")}\n`));
        }
        write(`\n${chalk.bold("Manual setup:")}\n`);
        if (tool.manualUrl) {
            write(`  ${t("cli.setup.reverse.manualUrl", `Official URL: ${tool.manualUrl}`, { url: tool.manualUrl })}\n`);
        }
        write(`  ${t("cli.setup.reverse.manualGuide", `Guide: ${tool.manualInstructions}`, { guide: tool.manualInstructions })}\n`);
        if (!executeMode) {
            continue;
        }
        if (tool.status === "installed") {
            const alreadyPrompt = t("cli.setup.reverse.alreadyInstalled", `Tool ${tool.name} is already installed at ${tool.foundPath}. Reinstall? [y/N]: `, { name: tool.name, path: tool.foundPath ?? "PATH" });
            const shouldReinstall = await confirm(alreadyPrompt);
            if (!shouldReinstall) {
                write(chalk.dim(t("cli.setup.reverse.cancelled", `Skipped ${tool.name}.`, { name: tool.name })) + "\n");
                continue;
            }
        }
        if (!tool.installArgv || tool.installArgv.length === 0) {
            write(chalk.yellow(`\n${t("cli.setup.reverse.noManagerFound", "No compatible package manager (e.g. brew/apt/choco) detected for automated install.")}\n`));
            continue;
        }
        write(`${t("cli.setup.reverse.detailManager", `Package manager: ${tool.packageManager}`, { manager: tool.packageManager ?? "unknown" })}\n`);
        write(`${chalk.bold(t("cli.setup.reverse.detailCommand", `Command: ${tool.installCommand}`, { command: tool.installCommand ?? "" }))}\n`);
        if (tool.riskNote) {
            write(`${chalk.yellow(t("cli.setup.reverse.detailRisk", `Risk / Note: ${tool.riskNote}`, { risk: tool.riskNote }))}\n`);
        }
        const proceedPrompt = t("cli.setup.reverse.confirmPrompt", `Do you want to run this installation command now? [y/N]: `);
        const proceed = await confirm(proceedPrompt);
        if (!proceed) {
            write(chalk.dim(t("cli.setup.reverse.cancelled", `Installation cancelled for ${tool.name}.`, {
                name: tool.name,
            })) + "\n");
            continue;
        }
        write(chalk.cyan(`\n${t("cli.setup.reverse.executing", `Executing: ${tool.installCommand}...`, { command: tool.installCommand ?? "" })}\n`));
        const result = await executor(tool.installArgv, {
            onChunk: chunk => write(chalk.dim(chunk)),
        });
        if (result.exitCode === 0) {
            const successIcon = theme?.status?.success ?? "✓";
            write(chalk.green(`\n${successIcon} ${t("cli.setup.reverse.execSuccess", "Installation command finished successfully.")}\n`));
            const refreshedStatuses = checkToolRequirements([{ id: tool.id }], {
                platform: deps.platform,
                which: deps.which,
                env: deps.env,
            });
            const refreshed = refreshedStatuses[0];
            if (refreshed?.foundPath) {
                write(chalk.green(`${successIcon} ${t("cli.setup.reverse.verifiedFound", `Verified: ${tool.name} is now available at ${refreshed.foundPath}!`, { name: tool.name, path: refreshed.foundPath })}\n`));
            }
            else {
                write(chalk.yellow(`${t("cli.setup.reverse.verifiedNotFound", `Note: Command completed, but ${tool.id} was not yet discovered on PATH. You may need to reopen your terminal or reload environment variables.`, { name: tool.name })}\n`));
            }
        }
        else {
            hasFailures = true;
            const errIcon = theme?.status?.error ?? "✗";
            writeErr(chalk.red(`\n${errIcon} ${t("cli.setup.reverse.execFailed", `Installation command failed with exit code ${result.exitCode}.`, { code: String(result.exitCode) })}\n`));
            if (result.stderr) {
                writeErr(`${chalk.dim(result.stderr)}\n`);
            }
            if (tool.manualUrl) {
                write(`  ${t("cli.setup.reverse.manualUrl", `Official URL: ${tool.manualUrl}`, { url: tool.manualUrl })}\n`);
            }
        }
    }
    for (const service of selectedServices) {
        write(`\n${chalk.cyan("--------------------------------------------------------------------------------")}\n`);
        write(`${chalk.bold(`MCP service: ${service.name} (${service.id})`)}\n`);
        write(`${chalk.dim(`Category: ${service.category}`)} | ${chalk.dim(`Transport: ${service.transport}`)} | ${chalk.dim(`License: ${service.license}`)}\n`);
        write(`${chalk.dim(service.description)}\n`);
        write(`${chalk.dim(`Prerequisites: ${service.ready ? "ready" : "missing"}`)}${service.missingPrerequisites.length > 0 ? ` (${service.missingPrerequisites.join(", ")})` : ""} | ${chalk.dim(`Configured: ${service.configured ? service.configuredScopes.join(", ") + (service.enabled === false ? " (disabled)" : "") : "no"}`)} | ${chalk.dim("Connection: unverified")}\n`);
        write(`\n${chalk.bold("Prerequisites:")}\n`);
        for (const prerequisite of service.prerequisites) {
            const found = prerequisite.foundPath !== null && (prerequisite.secondaryMissing?.length ?? 0) === 0;
            write(`  ${found ? chalk.green("[ok]") : chalk.yellow("[missing]")} ${prerequisite.id}${prerequisite.foundPath ? `: ${prerequisite.foundPath}` : ""}\n`);
        }
        write(`\n${chalk.bold("Start command:")}\n  ${chalk.green(service.startCommand)}\n`);
        write(`\n${chalk.bold("MCP config paths (resolved):")}\n`);
        write(`  project: ${service.configPaths.project}${service.configuredScopes.includes("project") ? chalk.green(" [entry found]") : ""}\n`);
        write(`  user: ${service.configPaths.user}${service.configuredScopes.includes("user") ? chalk.green(" [entry found]") : ""}\n`);
        write(`  ${chalk.dim("Inspection is read-only: it never writes mcp.json, starts the server, or verifies a connection.")}\n`);
        write(`\n${chalk.bold("Config snippet:")}\n`);
        for (const line of JSON.stringify(service.configSnippet, null, 2).split("\n")) {
            write(`  ${chalk.dim(line)}\n`);
        }
        if (service.installCommand) {
            write(`\n${chalk.bold("Recommended install command:")}\n`);
            write(`  ${chalk.green(service.installCommand)}\n`);
            if (service.riskNote) {
                write(`  ${chalk.dim(`Notes: ${service.riskNote}`)}\n`);
            }
        }
        else {
            write(chalk.yellow(`\nNo automated install for this service. Configure the snippet above; uvx/npx resolve the server package on first launch.\n`));
        }
        write(`\n${chalk.bold("Manual setup:")}\n`);
        write(`  Official URL: ${service.manualUrl}\n`);
        write(`  Guide: ${service.manualInstructions}\n`);
        if (!executeMode || !service.installArgv || service.installArgv.length === 0) {
            continue;
        }
        const proceedPrompt = `Do you want to run this installation command for ${service.name} now? [y/N]: `;
        const proceed = await confirm(proceedPrompt);
        if (!proceed) {
            write(chalk.dim(`Installation cancelled for ${service.name}.\n`));
            continue;
        }
        write(chalk.cyan(`\nExecuting: ${service.installCommand}...\n`));
        const result = await executor(service.installArgv, {
            onChunk: chunk => write(chalk.dim(chunk)),
        });
        if (result.exitCode === 0) {
            const successIcon = theme?.status?.success ?? "✓";
            write(chalk.green(`\n${successIcon} Installation command finished successfully.\n`));
            write(chalk.dim(`The server package was installed, but MCP services are not PATH binaries. Add the snippet above to ${service.configPath}, then start the client and verify with: ${service.startCommand}\n`));
        }
        else {
            hasFailures = true;
            const errIcon = theme?.status?.error ?? "✗";
            writeErr(chalk.red(`\n${errIcon} Installation command failed with exit code ${result.exitCode}.\n`));
            if (result.stderr)
                writeErr(`${chalk.dim(result.stderr)}\n`);
            write(`  Official URL: ${service.manualUrl}\n`);
        }
    }
    if (!executeMode) {
        write(`\n${chalk.dim(t("cli.setup.reverse.manualModeNotice", `[Manual mode] Run the commands above in your terminal, or run '${APP_NAME} setup reverse --execute' to execute interactively with confirmation.`))}\n`);
        return 0;
    }
    // Refreshed status table after execute mode
    write(`\n${chalk.bold("Refreshed reverse toolchain status:")}\n`);
    report = checkReverseTools(deps);
    renderToolTable(report, write);
    return hasFailures ? 1 : 0;
}
