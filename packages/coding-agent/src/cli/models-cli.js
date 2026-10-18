import { sendsImageInputOnWire } from "@rva/ai/providers/vision-guard";
import { getEffectiveTokenCost, getModelPricingStatus } from "@rva/catalog/models";
import { getSupportedEfforts } from "@rva/catalog/model-thinking";
import { modelKind } from "@rva/catalog/types";
import { formatNumber, getProjectDir } from "@rva/utils";
import chalk from "@rva/utils/chalk";
import { ModelRegistry } from "../config/model-registry";
import { Settings } from "../config/settings";
import { discoverAndLoadExtensions, ExtensionRunner, emitSessionShutdownEvent } from "../extensibility/extensions";
import { discoverAuthStorage } from "../sdk";
import { SessionManager } from "../session/session-manager";
import { EventBus } from "../utils/event-bus";
import { cfgDisabledExtensions, cfgExtensions } from "../extensibility/settings";
/**
 * Known action keywords. Any other first token (e.g. `openai-codex`) is treated
 * as a provider/substring filter for the default `ls` view, so every provider
 * name doubles as an `omp models <provider>` shortcut.
 */
const KNOWN_ACTIONS = {
    ls: "ls",
    list: "ls",
    find: "find",
    refresh: "refresh",
};
/** Resolve the two positional args into an action + filter (provider names fall through to `ls`). */
export function resolveModelsArgs(first, second) {
    const known = first === undefined ? undefined : KNOWN_ACTIONS[first];
    if (known) {
        return { action: known, pattern: second };
    }
    return { action: "ls", pattern: first };
}
function writeLine(line = "") {
    process.stdout.write(`${line}\n`);
}
function writeModelsConfigError(error) {
    writeLine(chalk.yellow("Warning: models.yml validation failed — custom providers disabled"));
    for (const line of error.message.split("\n")) {
        writeLine(`  ${line}`);
    }
    writeLine();
}
function formatLimit(n) {
    return n === null ? "-" : formatNumber(n);
}
function byProviderThenId(left, right) {
    const providerCmp = left.provider.localeCompare(right.provider);
    if (providerCmp !== 0)
        return providerCmp;
    return left.id.localeCompare(right.id);
}
function toModelJson(model) {
    // Scalar legs report the card in force now, not the one current when the row was built.
    const { input, output, cacheRead, cacheWrite } = getEffectiveTokenCost(model.cost);
    return {
        provider: model.provider,
        kind: modelKind(model),
        id: model.id,
        selector: `${model.provider}/${model.id}`,
        name: model.name,
        contextWindow: model.contextWindow,
        maxTokens: model.maxTokens,
        reasoning: model.reasoning,
        thinking: model.thinking ? getSupportedEfforts(model) : null,
        input: model.input,
        cost: { ...model.cost, input, output, cacheRead, cacheWrite },
        pricingStatus: getModelPricingStatus(model),
    };
}
/** Right- or left-pad a plain (ANSI-free) cell to `width` display columns. */
function padCell(text, width, align = "left") {
    const space = width - Bun.stringWidth(text);
    if (space <= 0)
        return text;
    const fill = " ".repeat(space);
    return align === "right" ? fill + text : text + fill;
}
/**
 * Render `rows` as a box-drawing table. Cells must be plain text (no ANSI); the
 * header row is bolded and the borders dimmed (both no-ops on non-TTY output).
 */
function boxTable(columns, rows) {
    const widths = columns.map((column, index) => Math.max(Bun.stringWidth(column.header), ...rows.map(row => Bun.stringWidth(row[index] ?? ""))));
    const bar = chalk.dim("│");
    const segments = widths.map(width => "─".repeat(width + 2));
    const renderRow = (cells, bold) => {
        const padded = columns.map((column, index) => {
            const cell = padCell(cells[index] ?? "", widths[index], column.align);
            return bold ? chalk.bold(cell) : cell;
        });
        return `${bar} ${padded.join(` ${bar} `)} ${bar}`;
    };
    const lines = [chalk.dim(`┌${segments.join("┬")}┐`)];
    lines.push(renderRow(columns.map(column => column.header), true));
    lines.push(chalk.dim(`├${segments.join("┼")}┤`));
    for (const row of rows) {
        lines.push(renderRow(row, false));
    }
    lines.push(chalk.dim(`└${segments.join("┴")}┘`));
    return lines;
}
/**
 * Render `omp models ls`/`find` as one box table per provider, selecting chat
 * models by default or the caller-requested catalog kind.
 */
export function renderProviderModels(source, action, pattern, json, kind = "chat") {
    const available = source.getAvailable(kind);
    const needle = pattern?.toLowerCase();
    let filtered = available;
    if (needle) {
        let exactFound = false;
        if (action !== "find") {
            const exact = available.filter(m => m.provider.toLowerCase() === needle);
            if (exact.length > 0) {
                filtered = exact;
                exactFound = true;
            }
        }
        if (!exactFound) {
            filtered = available.filter(model => model.id.toLowerCase().includes(needle) ||
                model.provider.toLowerCase().includes(needle) ||
                `${model.provider}/${model.id}`.toLowerCase().includes(needle) ||
                model.name.toLowerCase().includes(needle));
        }
    }
    const configError = source.getError();
    if (json) {
        if (configError) {
            process.stderr.write(`Warning: models.yml validation failed — custom providers disabled\n${configError.message}\n`);
        }
        const output = { models: filtered.slice().sort(byProviderThenId).map(toModelJson) };
        writeLine(JSON.stringify(output));
        return;
    }
    if (configError) {
        writeModelsConfigError(configError);
    }
    if (available.length === 0) {
        writeLine("No models available. Set API keys in environment variables.");
        return;
    }
    if (filtered.length === 0) {
        writeLine(`No models matching "${pattern}"`);
        return;
    }
    // One section per provider: bold heading + a box table of that provider's models.
    const byProvider = new Map();
    for (const model of filtered.slice().sort(byProviderThenId)) {
        let group = byProvider.get(model.provider);
        if (!group) {
            group = [];
            byProvider.set(model.provider, group);
        }
        group.push(model);
    }
    let firstProvider = true;
    for (const [provider, models] of byProvider) {
        if (!firstProvider)
            writeLine();
        firstProvider = false;
        writeLine(`${chalk.bold.cyan(provider)} ${chalk.dim(`(${models.length})`)}`);
        const rows = models.map(model => [
            model.id,
            formatLimit(model.contextWindow),
            formatLimit(model.maxTokens),
            model.thinking ? getSupportedEfforts(model).join(",") : model.reasoning ? "yes" : "-",
            // Wire truth, not the declared `input`: the transport drops image parts for
            // models the catalog marks text-only (`compat.stripImageInput`, #9697).
            sendsImageInputOnWire(model) ? "yes" : "no",
        ]);
        for (const line of boxTable([
            { header: "model" },
            { header: "context", align: "right" },
            { header: "max-out", align: "right" },
            { header: "thinking" },
            { header: "images" },
        ], rows)) {
            writeLine(line);
        }
    }
}
export async function runModelsListing(options) {
    const { modelRegistry, cwd, action = "ls", pattern, json = false, kind = "chat", additionalExtensionPaths = [], settingsExtensions = [], disabledExtensionIds = [], disableExtensionDiscovery = false, } = options;
    const eventBus = new EventBus();
    const configuredPaths = disableExtensionDiscovery
        ? additionalExtensionPaths
        : [...additionalExtensionPaths, ...settingsExtensions];
    const extensionsResult = await discoverAndLoadExtensions(configuredPaths, cwd, eventBus, disableExtensionDiscovery ? undefined : disabledExtensionIds, { ambient: !disableExtensionDiscovery, includeAmbientHooks: false });
    const extensionRunner = extensionsResult.extensions.length > 0
        ? new ExtensionRunner(extensionsResult.extensions, extensionsResult.runtime, cwd, SessionManager.inMemory(cwd), modelRegistry)
        : undefined;
    try {
        for (const { path: extPath, error } of extensionsResult.errors) {
            process.stderr.write(`Failed to load extension: ${extPath}: ${error}\n`);
        }
        // Mirror sdk.ts: drain pending provider registrations into the registry.
        const activeSources = extensionsResult.extensions.map(extension => extension.path);
        modelRegistry.syncExtensionSources(activeSources);
        for (const sourceId of new Set(activeSources)) {
            modelRegistry.clearSourceRegistrations(sourceId);
        }
        for (const { name, config, sourceId } of extensionsResult.runtime.pendingProviderRegistrations) {
            modelRegistry.registerProvider(name, config, sourceId);
        }
        extensionsResult.runtime.pendingProviderRegistrations = [];
        // Discover runtime (extension) provider catalogs now that they are registered.
        await modelRegistry.refreshRuntimeProviders(action === "refresh" ? "online" : "online-if-uncached");
        for (const warning of modelRegistry.drainConfigWarnings()) {
            process.stderr.write(`${chalk.yellow(`Warning: ${warning}`)}\n`);
        }
        renderProviderModels(modelRegistry, action, pattern, json, kind);
    }
    finally {
        await emitSessionShutdownEvent(extensionRunner);
    }
}
/**
 * Entry point for the standalone `omp models` command: bootstraps auth storage,
 * settings, and the model registry, force/cache-refreshes built-in providers per
 * the chosen action, then delegates to {@link runModelsListing}.
 */
export async function runModelsCommand(command) {
    const { action, pattern } = command;
    const json = command.flags.json ?? false;
    const kind = command.flags.kind ?? "chat";
    if (action === "find" && (!pattern || pattern.trim().length === 0)) {
        process.stderr.write("`omp models find` requires a search substring, e.g. `omp models find minimax`\n");
        process.exitCode = 1;
        return;
    }
    const cwd = getProjectDir();
    const settings = await Settings.init({ cwd, configFiles: command.flags.config });
    const authStorage = await discoverAuthStorage(undefined, { settings });
    try {
        const modelRegistry = new ModelRegistry(authStorage);
        if (action === "refresh" && !json && process.stderr.isTTY) {
            process.stderr.write("Refreshing models from all providers…\n");
        }
        await modelRegistry.refresh(action === "refresh" ? "online" : "online-if-uncached", action === "refresh" ? { refreshCommandCredentials: true } : undefined);
        const cliExtensionPaths = command.flags.extensions ?? [];
        await runModelsListing({
            modelRegistry,
            cwd,
            action,
            pattern,
            json,
            kind,
            additionalExtensionPaths: cliExtensionPaths,
            settingsExtensions: cfgExtensions.get(settings),
            disabledExtensionIds: cfgDisabledExtensions.get(settings),
            disableExtensionDiscovery: Boolean(command.flags.noExtensions),
        });
    }
    finally {
        authStorage.close();
    }
}
