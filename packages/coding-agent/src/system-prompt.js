/**
 * System prompt construction and project context loading
 */
import * as os from "node:os";
import * as path from "node:path";
import { renderToolInventory } from "@rva/ai/dialect";
import { $env, getAgentDir, getProjectDir, hasFsCode, isEnoent, logger, prompt } from "@rva/utils";
import { contextFileCapability } from "./capability/context-file";
import { systemPromptCapability } from "./capability/system-prompt";
import { findConfigFile } from "./config";
import { loadCapability } from "./discovery";
import { expandAtImports } from "./discovery/at-imports";
import { SkillDescriptionCatalog } from "./extensibility/skill-descriptions";
import { loadSkills } from "./extensibility/skills";
import { InternalUrlRouter } from "./internal-urls/router";
import activeRepoContextTemplate from "./prompts/system/active-repo-context.md" with { type: "text" };
import customSystemPromptTemplate from "./prompts/system/custom-system-prompt.md" with { type: "text" };
import defaultPersonality from "./prompts/system/personalities/default.md" with { type: "text" };
import friendlyPersonality from "./prompts/system/personalities/friendly.md" with { type: "text" };
import pragmaticPersonality from "./prompts/system/personalities/pragmatic.md" with { type: "text" };
import projectPromptTemplate from "./prompts/system/project-prompt.md" with { type: "text" };
import systemPromptTemplate from "./prompts/system/system-prompt.md" with { type: "text" };
import userAppendPromptTemplate from "./prompts/system/user-append.md" with { type: "text" };
import { normalizeConcurrencyLimit } from "./task/parallel";
import { XD_URL_PREFIX } from "@rva/tui/tools/xd-url";
import { resolveActiveRepoContext } from "./utils/active-repo-context";
import { normalizePromptPath } from "./utils/prompt-path";
import { AGENTS_MD_LIMIT, buildWorkspaceTree } from "./workspace-tree";
import { combine } from "./config/registry";
import { cfgBashAutoBackgroundEnabled } from "./exec/settings";
import { cfgEvalAutoBackgroundEnabled } from "./eval/settings";
import { cfgTtsrBuiltinRules, cfgTtsrDisabledRules, cfgTtsrEnabled } from "./export/ttsr-settings";
import { cfgTuiAutoGraph, cfgTuiReactions, cfgTuiRenderMermaid, cfgTuiRenderSvg } from "./modes/settings";
import { cfgSecretsEnabled } from "./secrets/settings";
import { cfgToolsFormat } from "./session/context-settings";
import { cfgIncludeModelInPrompt, cfgIncludeWorkspaceTree, cfgInlineToolDescriptors, cfgPersonality, } from "./session/settings";
import { cfgTaskBatch, cfgTaskEager } from "./task/settings";
import { cfgAsyncEnabled, cfgToolsIntentTracing, cfgToolsXdevDocs, cfgToolsXdevInlineDevices, cfgVaultEnabled, } from "./tools/settings";
/**
 * Settings the system prompt renders from (`secrets.enabled` via the obfuscator state it
 * reports). A session rebuilds its prompt once per coalesced change of this value, so a bulk
 * settings change rebuilds once. Settings that change the tool set, skills, memory, or workspace
 * roots rebuild through their own reconcile instead.
 */
export const cfgSystemPromptInputs = combine({
    personality: cfgPersonality,
    includeModelInPrompt: cfgIncludeModelInPrompt,
    includeWorkspaceTree: cfgIncludeWorkspaceTree,
    inlineToolDescriptors: cfgInlineToolDescriptors,
    toolsFormat: cfgToolsFormat,
    intentTracing: cfgToolsIntentTracing,
    xdevDocs: cfgToolsXdevDocs,
    xdevInlineDevices: cfgToolsXdevInlineDevices,
    vaultEnabled: cfgVaultEnabled,
    renderMermaid: cfgTuiRenderMermaid,
    renderSvg: cfgTuiRenderSvg,
    autoGraph: cfgTuiAutoGraph,
    reactions: cfgTuiReactions,
    // Rendered into the bash/eval/task tool descriptions (inline catalog) or read by
    // the prompt builder (eager/batch delegation).
    asyncEnabled: cfgAsyncEnabled,
    bashAutoBackground: cfgBashAutoBackgroundEnabled,
    evalAutoBackground: cfgEvalAutoBackgroundEnabled,
    taskEager: cfgTaskEager,
    taskBatch: cfgTaskBatch,
    // Rule bucketing (TTSR registrations, rulebook, always-apply) runs at rebuild time.
    ttsrEnabled: cfgTtsrEnabled,
    ttsrBuiltinRules: cfgTtsrBuiltinRules,
    ttsrDisabledRules: cfgTtsrDisabledRules,
    secretsEnabled: cfgSecretsEnabled,
});
/** Bundled personality specs, keyed by the `personality` setting value. */
const PERSONALITY_SPECS = {
    default: defaultPersonality,
    friendly: friendlyPersonality,
    pragmatic: pragmaticPersonality,
};
/**
 * Load the user-level PERSONALITY.md override for the system prompt's
 * personality block from `<agentDir>/PERSONALITY.md` (`~/.omp/agent` by
 * default; profile, XDG, and `PI_CODING_AGENT_DIR` aware). Returns null when
 * the file is absent, empty, or unreadable; callers then render the configured
 * preset. Read failures other than a missing file warn instead of failing the
 * build.
 */
async function loadPersonalityOverride() {
    const filePath = path.join(getAgentDir(), "PERSONALITY.md");
    try {
        const content = (await Bun.file(filePath).text()).trim();
        if (content)
            return content;
        logger.warn("PERSONALITY.md is empty; using the configured personality preset", { path: filePath });
    }
    catch (error) {
        if (!isEnoent(error)) {
            logger.warn("Failed to read PERSONALITY.md; using the configured personality preset", {
                path: filePath,
                error: String(error),
            });
        }
    }
    return null;
}
function normalizePromptBlock(content) {
    return prompt.format(content, { renderPhase: "post-render" }).trim();
}
function splitComparablePromptBlocks(content) {
    const normalized = firstNonEmpty(content);
    if (!normalized)
        return [];
    const rendered = normalizePromptBlock(normalized);
    // Split on blank-line paragraph boundaries, but not inside fenced code
    // blocks. A rule that appears only inside a fenced example in another file
    // is an example, not an instruction, so it must not count as containment.
    const blocks = [];
    let current = [];
    let inFence = false;
    for (const line of rendered.split("\n")) {
        if (/^\s*(```|~~~)/.test(line)) {
            inFence = !inFence;
            current.push(line);
            continue;
        }
        if (!inFence && line.trim() === "" && current.length > 0 && current[current.length - 1].trim() !== "") {
            const block = current.join("\n").trim();
            if (block.length > 0)
                blocks.push(block);
            current = [];
            continue;
        }
        current.push(line);
    }
    const tail = current.join("\n").trim();
    if (tail.length > 0)
        blocks.push(tail);
    return blocks;
}
/**
 * Check whether `ruleBlocks` appears as a contiguous subsequence of
 * `sourceBlocks`. Both inputs must already be normalized and split via
 * {@link splitComparablePromptBlocks}.
 */
function promptBlocksContain(sourceBlocks, ruleBlocks) {
    if (sourceBlocks.length === 0 || ruleBlocks.length === 0 || ruleBlocks.length > sourceBlocks.length) {
        return false;
    }
    for (let start = 0; start <= sourceBlocks.length - ruleBlocks.length; start += 1) {
        if (ruleBlocks.every((block, offset) => sourceBlocks[start + offset] === block))
            return true;
    }
    return false;
}
function promptSourceContainsRule(source, ruleContent) {
    return promptBlocksContain(splitComparablePromptBlocks(source), splitComparablePromptBlocks(ruleContent));
}
function dedupeAlwaysApplyRules(alwaysApplyRules, promptSources) {
    if (!alwaysApplyRules || alwaysApplyRules.length === 0)
        return [];
    return alwaysApplyRules.filter(rule => !promptSources.some(source => promptSourceContainsRule(source, rule.content)));
}
function dedupePromptSource(source, otherSources) {
    const resolvedSource = firstNonEmpty(source);
    if (!resolvedSource)
        return "";
    return otherSources.some(otherSource => promptSourceContainsRule(otherSource, resolvedSource)) ? "" : resolvedSource;
}
function firstNonEmpty(...values) {
    for (const value of values) {
        const trimmed = value?.trim();
        if (trimmed)
            return trimmed;
    }
    return null;
}
function renderActiveRepoContextPrompt(activeRepoContext) {
    if (!activeRepoContext)
        return "";
    return prompt
        .render(activeRepoContextTemplate, {
        relativeRepoRoot: normalizePromptPath(activeRepoContext.relativeRepoRoot),
    })
        .trim();
}
const SYSTEM_PROMPT_PREP_TIMEOUT_MS = 5000;
/** Workstation facts the model needs to pick commands and paths: platform/release and CPU architecture. */
function getEnvironmentInfo() {
    return [
        { label: "OS", value: `${os.platform()} ${os.release()}` },
        { label: "Arch", value: os.arch() },
    ];
}
/** Discover TITLE_SYSTEM.md file for automatic session-title prompt overrides */
export function discoverTitleSystemPromptFile(cwd) {
    const projectPath = findConfigFile("TITLE_SYSTEM.md", { user: false, cwd });
    if (projectPath) {
        return projectPath;
    }
    const globalPath = findConfigFile("TITLE_SYSTEM.md", { user: true, cwd });
    if (globalPath) {
        return globalPath;
    }
    return undefined;
}
/**
 * Unified discovery for literal and template overrides. Project scope beats
 * user scope; within each scope a literal beats a template: SYSTEM.md is the
 * long-established override, so an existing literal keeps working until its
 * author deliberately removes it in favor of a template. Ancestor walk-up
 * and `.agent/.agents` coverage come from the capability providers, so a
 * repo-root file wins from a nested cwd.
 */
export async function discoverSystemPromptOverride(cwd) {
    const result = await loadCapability(systemPromptCapability.id, {
        cwd: cwd ?? getProjectDir(),
    });
    for (const level of ["project", "user"]) {
        const text = result.items.find(item => item.level === level && (item.kind ?? "text") === "text");
        if (text)
            return { kind: "text", path: text.path, content: text.content };
        const template = result.items.find(item => item.level === level && (item.kind ?? "text") === "template");
        if (template) {
            if (!template.content.trim()) {
                logger.warn("Ignoring empty system prompt template", { path: template.path });
                continue;
            }
            return { kind: "template", path: template.path, content: template.content };
        }
    }
    return undefined;
}
/** Unlike literal prompt inputs, explicit template paths never fall back to inline text. */
export async function loadSystemPromptTemplateFile(filePath) {
    const text = await Bun.file(filePath).text();
    if (!text.trim()) {
        throw new Error(`System prompt template must not be empty: ${filePath}`);
    }
    return text;
}
/** Resolve input as file path or literal string */
export async function resolvePromptInput(input, description) {
    if (!input) {
        return input;
    }
    else if (input.includes("\n")) {
        return input;
    }
    try {
        return await Bun.file(input).text();
    }
    catch (error) {
        if (!hasFsCode(error, "ENAMETOOLONG") && !isEnoent(error)) {
            logger.warn(`Could not read ${description} file`, { path: input, error: String(error) });
        }
        return input;
    }
}
/**
 * Deduplicate context files by paragraph containment.
 *
 * Files are sorted by depth descending (farther from cwd first) so that a
 * file is omitted only when a more-authoritative (closer-to-cwd) file
 * contains its entire normalized paragraph sequence as a contiguous run.
 * This makes the function self-contained — it does not rely on callers
 * pre-sorting the array, which matters because some callers concatenate
 * independently sorted workspace roots where array position does not reflect
 * authority. Files whose paragraphs are merely paraphrased or interleaved are
 * kept — containment is exact after normalization, not fuzzy.
 *
 * @internal Exported for testing.
 */
export function dedupeContainedContextFiles(contextFiles) {
    // Sort by depth descending: higher depth (farther from cwd, less
    // authoritative) first, lower depth (closer to cwd, more authoritative)
    // last. Stable sort preserves caller order among equal-depth files.
    const sorted = [...contextFiles].sort((a, b) => {
        const depthA = a.depth ?? Number.POSITIVE_INFINITY;
        const depthB = b.depth ?? Number.POSITIVE_INFINITY;
        return depthB - depthA;
    });
    const blocks = sorted.map(file => splitComparablePromptBlocks(file.content));
    return sorted.filter((_file, index) => !blocks.some((candidateBlocks, candidateIndex) => candidateIndex > index && promptBlocksContain(candidateBlocks, blocks[index])));
}
/**
 * Load all project context files using the capability API.
 * Returns {path, content, depth} entries for all discovered context files.
 * Files are sorted by depth (descending) so files closer to cwd appear last/more prominent.
 */
export async function loadProjectContextFiles(options = {}) {
    const resolvedCwd = options.cwd ?? getProjectDir();
    const result = await loadCapability(contextFileCapability.id, {
        cwd: resolvedCwd,
        disabledExtensions: options.disabledExtensions,
    });
    // Materialize ContextFile items, expanding any `@path/to/file` includes
    // in their content. The expansion uses the file's own directory as the
    // resolution base so relative imports work the same way Claude Code,
    // Goose, and other tools document.
    const files = await Promise.all(result.items.map(async (item) => {
        const contextFile = item;
        return {
            path: contextFile.path,
            content: await expandAtImports(contextFile.content, contextFile.path),
            depth: contextFile.depth,
        };
    }));
    // Sort by depth (descending): higher depth (farther from cwd) comes first,
    // so files closer to cwd appear later and are more prominent
    files.sort((a, b) => {
        const depthA = a.depth ?? -1;
        const depthB = b.depth ?? -1;
        return depthB - depthA;
    });
    return dedupeContainedContextFiles(files);
}
/**
 * Load the effective system prompt customization from SYSTEM.md.
 * Project-level SYSTEM.md overrides user-level SYSTEM.md.
 */
export async function loadSystemPromptFiles(options = {}) {
    const resolvedCwd = options.cwd ?? getProjectDir();
    const result = await loadCapability(systemPromptCapability.id, { cwd: resolvedCwd });
    if (result.items.length === 0)
        return null;
    const projectLevel = result.items.find(item => item.level === "project");
    if (projectLevel) {
        return projectLevel.content;
    }
    const userLevel = result.items.find(item => item.level === "user");
    return userLevel?.content ?? null;
}
export const DEFAULT_SYSTEM_PROMPT_TOOL_NAMES = ["read", "bash", "edit", "write"];
export function buildSystemPromptToolMetadata(tools, overrides = {}) {
    return projectSystemPromptToolMetadata(tools, { mode: "full", overrides });
}
/** Whether a tool can read `skill://` instruction content.
 *
 * Shared by initial prompt construction and mid-session skill notices so both
 * consult declared capability instead of the tool name. Accepts live tools
 * (`AgentTool` declares the `readsSkillUris` capability) and projected
 * metadata (`SystemPromptToolMetadata`). Accepts `undefined`/`null` (missing
 * registry/metadata entries) and returns `false` for them. */
export function toolReadsSkillUris(tool) {
    return tool != null && tool.readsSkillUris === true;
}
/** Builds a mode-specific metadata snapshot for internal prompt assembly. */
export function projectSystemPromptToolMetadata(tools, projection) {
    const metadata = new Map();
    const addTool = (name, tool) => {
        const override = projection.overrides?.[name];
        const labelValue = override?.label ?? tool.label;
        const wireNameValue = override?.wireName ?? tool.customWireName;
        const metadataEntry = {
            label: typeof labelValue === "string" ? labelValue : "",
            description: "",
            wireName: typeof wireNameValue === "string" ? wireNameValue : undefined,
        };
        if (projection.mode === "full") {
            const descriptionValue = override?.description ?? tool.description;
            metadataEntry.description = typeof descriptionValue === "string" ? descriptionValue : "";
            metadataEntry.parameters = tool.parameters;
            metadataEntry.examples = tool.examples;
        }
        if ((override?.readsSkillUris ?? toolReadsSkillUris(tool)) === true)
            metadataEntry.readsSkillUris = true;
        metadata.set(name, metadataEntry);
    };
    if (projection.mode === "compact") {
        for (const name of projection.toolNames) {
            const tool = tools.get(name);
            if (tool)
                addTool(name, tool);
        }
    }
    else {
        for (const [name, tool] of tools)
            addTool(name, tool);
    }
    return metadata;
}
/** Static wrapper; compiled (not rendered) so user-authored Markdown passes through byte-for-byte. */
const renderUserAppend = prompt.compile(userAppendPromptTemplate.trimEnd());
/**
 * Join generated append blocks (memory, auto-learn, `xd://` routes, MCP server
 * instructions) with the user's append prompt. Keep the user text in its own
 * section so it is not misclassified as MCP server-controlled instructions.
 */
export function composeAppendPrompt(appendParts, appendSystemPrompt) {
    const generated = appendParts.length > 0 ? appendParts.join("\n\n") : undefined;
    if (!appendSystemPrompt || appendSystemPrompt.trim().length === 0) {
        return generated;
    }
    if (!generated) {
        return appendSystemPrompt;
    }
    return renderUserAppend({ generatedAppend: generated, userAppend: appendSystemPrompt });
}
/** Build the system prompt with tools, guidelines, and context */
export async function buildSystemPrompt(options = {}) {
    if ($env.NULL_PROMPT === "true") {
        return { systemPrompt: [] };
    }
    const { customPrompt, resolvedCustomPrompt: providedResolvedCustomPrompt, tools, appendSystemPrompt, inlineToolDescriptors: providedInlineToolDescriptors, resolvedAppendSystemPrompt: providedResolvedAppendPrompt, nativeTools = true, skillsSettings, toolNames: providedToolNames, cwd, additionalWorkspaceRoots = [], contextFiles: providedContextFiles, skills: providedSkills, rules, alwaysApplyRules, intentField, eagerTasks = false, eagerTasksAlways = false, taskBatch = true, taskMaxConcurrency = 0, taskIrcEnabled = false, secretsEnabled = false, workspaceTree: providedWorkspaceTree, scoutAvailable = true, delegationBias = "eager", memoryBackend, securityEnabled = false, settingsApproval = false, evalPreludes = [], model, includeModelInPrompt = true, personality = "default", includeWorkspaceTree = false, renderMermaid = true, renderSvg = false, autoGraph = false, reactions = false, xdevTools = [], xdevDocs = "", writeTransportOnly = false, subagent = false, activeRepoContext: providedActiveRepoContext, } = options;
    const inlineToolDescriptors = providedInlineToolDescriptors ?? false;
    const resolvedCwd = cwd ?? getProjectDir();
    let resolvedSystemPromptTemplate = options.systemPromptTemplate;
    let resolvedCustomPromptInput = providedResolvedCustomPrompt;
    const hasExplicitCustomPrompt = customPrompt !== undefined || providedResolvedCustomPrompt !== undefined;
    if (resolvedSystemPromptTemplate !== undefined && hasExplicitCustomPrompt) {
        throw new Error("systemPromptTemplate cannot be combined with a literal custom system prompt");
    }
    if (resolvedSystemPromptTemplate === undefined && !hasExplicitCustomPrompt) {
        const override = await discoverSystemPromptOverride(resolvedCwd);
        if (override?.kind === "template" && override.content !== undefined) {
            resolvedSystemPromptTemplate = override.content;
        }
        else if (override?.content !== undefined) {
            resolvedCustomPromptInput = override.content;
        }
    }
    const hasDiscoveredTemplate = resolvedSystemPromptTemplate !== undefined && options.systemPromptTemplate === undefined;
    if (resolvedSystemPromptTemplate !== undefined && !resolvedSystemPromptTemplate.trim()) {
        if (hasDiscoveredTemplate) {
            logger.warn("Ignoring empty discovered system prompt template; using the bundled prompt");
            resolvedSystemPromptTemplate = undefined;
        }
        else {
            throw new Error("System prompt template must not be empty");
        }
    }
    const prepDefaults = {
        resolvedCustomPrompt: undefined,
        resolvedAppendPrompt: undefined,
        systemPromptCustomization: null,
        contextFiles: dedupeContainedContextFiles(providedContextFiles ?? []),
        skills: providedSkills ?? [],
        workspaceTree: {
            rootPath: resolvedCwd,
            rendered: "",
            truncated: false,
            totalLines: 0,
            agentsMdFiles: [],
        },
        activeRepoContext: null,
    };
    const { promise: deadline, resolve: fireDeadline } = Promise.withResolvers();
    const deadlineTimer = setTimeout(() => fireDeadline("__timeout__"), SYSTEM_PROMPT_PREP_TIMEOUT_MS);
    // Unref so a fast prep does not hold a one-shot CLI alive waiting for this timer.
    deadlineTimer.unref();
    const timedOut = [];
    const failed = [];
    async function withDeadline(name, work, fallback) {
        const tagged = work
            .then(value => ({ kind: "ok", value }))
            .catch(error => ({ kind: "err", error }));
        const result = await Promise.race([tagged, deadline]);
        if (result === "__timeout__") {
            timedOut.push(name);
            // Let the work continue in the background so its caches still warm; just log on completion.
            void tagged.then(r => {
                if (r.kind === "err") {
                    logger.warn("Background system prompt preparation step failed", { name, error: String(r.error) });
                }
                else {
                    logger.debug("Background system prompt preparation step completed after timeout", { name });
                }
            });
            return fallback;
        }
        if (result.kind === "err") {
            failed.push({ name, error: result.error });
            return fallback;
        }
        return result.value;
    }
    // An explicit literal prompt or selected template owns block 0; the secondary
    // capability-path SYSTEM.md walk-up must not silently augment either.
    const callerControlsCustomPrompt = hasExplicitCustomPrompt || resolvedSystemPromptTemplate !== undefined || resolvedCustomPromptInput !== undefined;
    const systemPromptCustomizationPromise = callerControlsCustomPrompt
        ? Promise.resolve(null)
        : logger.time("loadSystemPromptFiles", loadSystemPromptFiles, { cwd: resolvedCwd });
    const contextFilesPromise = (async () => {
        const primary = providedContextFiles
            ? providedContextFiles
            : await logger.time("loadProjectContextFiles", loadProjectContextFiles, { cwd: resolvedCwd });
        // Also discover context files (AGENTS.md, rules, etc.) for each additional workspace root.
        const additionalRoots = additionalWorkspaceRoots.filter(d => path.resolve(d) !== path.resolve(resolvedCwd));
        if (additionalRoots.length === 0)
            return primary;
        const extra = await Promise.all(additionalRoots.map(root => loadProjectContextFiles({ cwd: root }).catch(() => [])));
        return dedupeContainedContextFiles([...primary, ...extra.flat()]);
    })();
    const additionalRootsForTree = additionalWorkspaceRoots.filter(d => path.resolve(d) !== path.resolve(resolvedCwd));
    const workspaceTreePromise = (async () => {
        const primary = providedWorkspaceTree !== undefined
            ? await Promise.resolve(providedWorkspaceTree)
            : includeWorkspaceTree
                ? await logger.time("buildWorkspaceTree", () => buildWorkspaceTree(resolvedCwd, { timeoutMs: SYSTEM_PROMPT_PREP_TIMEOUT_MS }))
                : { rootPath: resolvedCwd, rendered: "", truncated: false, totalLines: 0, agentsMdFiles: [] };
        if (additionalRootsForTree.length === 0 || !includeWorkspaceTree)
            return primary;
        const extraTrees = await Promise.all(additionalRootsForTree.map(root => buildWorkspaceTree(root, { timeoutMs: SYSTEM_PROMPT_PREP_TIMEOUT_MS }).catch(() => ({
            rootPath: root,
            rendered: "",
            truncated: false,
            totalLines: 0,
            agentsMdFiles: [],
        }))));
        return { ...primary, agentsMdFiles: [...primary.agentsMdFiles, ...extraTrees.flatMap(t => t.agentsMdFiles)] };
    })();
    const skillsPromise = providedSkills !== undefined
        ? Promise.resolve(providedSkills)
        : skillsSettings?.enabled !== false
            ? loadSkills({ ...skillsSettings, cwd: resolvedCwd }).then(result => result.skills)
            : Promise.resolve([]);
    const activeRepoContextPromise = providedActiveRepoContext !== undefined
        ? Promise.resolve(providedActiveRepoContext)
        : logger.time("resolveActiveRepoContext", () => resolveActiveRepoContext(resolvedCwd));
    // "none" (explicit off — and every subagent) omits the block and skips the file lookup.
    const bundledPersonality = personality === "none" ? "" : PERSONALITY_SPECS[personality].trim();
    const personalityPromise = personality === "none"
        ? Promise.resolve("")
        : logger
            .time("loadPersonalityOverride", loadPersonalityOverride)
            .then(override => override ?? bundledPersonality);
    const [resolvedCustomPrompt, resolvedAppendPrompt, systemPromptCustomization, contextFiles, skills, workspaceTree, activeRepoContext, personalityBlock,] = await Promise.all([
        withDeadline("customPrompt", resolvedCustomPromptInput !== undefined
            ? Promise.resolve(resolvedCustomPromptInput)
            : resolvePromptInput(customPrompt, "system prompt"), prepDefaults.resolvedCustomPrompt),
        withDeadline("appendSystemPrompt", providedResolvedAppendPrompt !== undefined
            ? Promise.resolve(providedResolvedAppendPrompt)
            : resolvePromptInput(appendSystemPrompt, "append system prompt"), prepDefaults.resolvedAppendPrompt),
        withDeadline("loadSystemPromptFiles", systemPromptCustomizationPromise, prepDefaults.systemPromptCustomization),
        withDeadline("loadProjectContextFiles", contextFilesPromise, prepDefaults.contextFiles).then(dedupeContainedContextFiles),
        withDeadline("loadSkills", skillsPromise, prepDefaults.skills),
        withDeadline("buildWorkspaceTree", workspaceTreePromise, prepDefaults.workspaceTree),
        withDeadline("resolveActiveRepoContext", activeRepoContextPromise, prepDefaults.activeRepoContext),
        withDeadline("loadPersonalityOverride", personalityPromise, bundledPersonality),
    ]);
    clearTimeout(deadlineTimer);
    const agentsMdFiles = Array.from(new Set(workspaceTree.agentsMdFiles)).sort().slice(0, AGENTS_MD_LIMIT);
    if (timedOut.length > 0) {
        logger.warn("System prompt preparation steps timed out; using minimal fallback for those steps", {
            cwd: resolvedCwd,
            timeoutMs: SYSTEM_PROMPT_PREP_TIMEOUT_MS,
            steps: timedOut,
        });
        process.stderr.write(`Warning: system prompt preparation steps timed out after ${SYSTEM_PROMPT_PREP_TIMEOUT_MS}ms (${timedOut.join(", ")}); using minimal fallback for those steps.\n`);
    }
    if (failed.length > 0) {
        for (const { name, error } of failed) {
            logger.warn("System prompt preparation step failed; using minimal fallback", {
                cwd: resolvedCwd,
                step: name,
                error: String(error),
            });
        }
    }
    const promptCwd = normalizePromptPath(resolvedCwd);
    const activeRepoContextPrompt = renderActiveRepoContextPrompt(activeRepoContext);
    // Build tool metadata for system prompt rendering.
    // Priority: explicit list > tools map > conservative SDK fallback.
    let toolNames = providedToolNames;
    if (!toolNames) {
        toolNames = tools ? Array.from(tools.keys()) : [...DEFAULT_SYSTEM_PROMPT_TOOL_NAMES];
    }
    // List mode shows a compact tool-name list; it only applies when descriptors
    // stay in provider-native tool schemas AND native tool calling is active.
    // Otherwise render the full functions-namespace catalog in the system prompt.
    const toolListMode = !inlineToolDescriptors && nativeTools;
    // Build tool descriptions for system prompt rendering.
    const toolPromptNames = new Map(toolNames.map(name => [name, tools?.get(name)?.wireName ?? name]));
    // xd://-mounted tools count as present for prompt gates ({{#has tools "lsp"}})
    // and resolve to their `xd://<name>` URL, the only way to reach them. The
    // Tool Inventory list stays limited to real defs.
    for (const mounted of xdevTools) {
        if (!toolPromptNames.has(mounted.name))
            toolPromptNames.set(mounted.name, `${XD_URL_PREFIX}${mounted.name}`);
    }
    const toolRefs = Object.fromEntries(toolPromptNames.entries());
    const xdevToolNames = new Set(xdevTools.map(mounted => mounted.name));
    // A direct custom tool can share a name with a retained built-in device.
    // Presence in both toolNames and tools proves it still has a top-level definition.
    const inventoryToolNames = xdevToolNames.size === 0 ? toolNames : toolNames.filter(name => tools?.has(name) || !xdevToolNames.has(name));
    const toolInfo = inventoryToolNames.map(name => ({
        name: toolPromptNames.get(name) ?? name,
        internalName: name,
        label: tools?.get(name)?.label ?? "",
    }));
    const toolInventory = toolListMode
        ? ""
        : renderToolInventory(inventoryToolNames.map(name => {
            const meta = tools?.get(name);
            return {
                name: toolPromptNames.get(name) ?? name,
                description: meta?.description ?? "",
                parameters: meta?.parameters ?? { type: "object" },
                examples: meta?.examples,
            };
        }));
    // Filter skills for the rendered system prompt:
    // - require an active tool that declares `skill://` read capability (any tool
    //   name, not just `read`, so custom resolvers count once projected; mounted
    //   xd:// tools count too when their metadata is projected);
    // - drop skills with frontmatter `hide: true` (still loadable via skill:// and /skill:<name>).
    const hasSkillReader = tools === undefined
        ? toolNames.includes("read")
        : toolNames.some(name => toolReadsSkillUris(tools.get(name))) ||
            xdevTools.some(entry => toolReadsSkillUris(tools.get(entry.name)));
    const hasSkillUriAccess = hasSkillReader && skills.length > 0;
    const schemeHost = {
        skillUriAccess: hasSkillUriAccess,
        ruleCount: rules?.length ?? 0,
        memoryBackend,
        securityEnabled,
        settingsApproval,
    };
    const filteredSkills = (options.skillDescriptions ?? new SkillDescriptionCatalog()).render(hasSkillReader ? skills.filter(skill => skill.hide !== true) : []);
    const effectiveSystemPromptCustomization = dedupePromptSource(systemPromptCustomization, [
        resolvedCustomPrompt,
        resolvedAppendPrompt,
    ]);
    const contextPromptSources = contextFiles.map(file => file.content);
    const promptSources = [
        effectiveSystemPromptCustomization,
        resolvedCustomPrompt,
        resolvedAppendPrompt,
        ...contextPromptSources,
    ];
    const injectedAlwaysApplyRules = dedupeAlwaysApplyRules(alwaysApplyRules, promptSources);
    const environment = getEnvironmentInfo();
    const data = {
        systemPromptCustomization: effectiveSystemPromptCustomization,
        customPrompt: resolvedCustomPrompt,
        appendPrompt: resolvedAppendPrompt ?? "",
        tools: [...new Set([...toolNames, ...xdevTools.map(mounted => mounted.name)])],
        toolInfo,
        toolInventory,
        inlineToolDescriptors,
        toolListMode,
        toolRefs,
        environment,
        contextFiles,
        agentsMdSearch: { files: agentsMdFiles },
        workspaceTree,
        hasSkillUriAccess,
        internalUrls: InternalUrlRouter.instance().describe(schemeHost),
        skills: filteredSkills,
        rules: rules ?? [],
        alwaysApplyRules: injectedAlwaysApplyRules,
        cwd: promptCwd,
        additionalWorkspaceRoots: additionalWorkspaceRoots.filter(d => path.resolve(d) !== path.resolve(resolvedCwd)),
        model: includeModelInPrompt ? (model ?? "") : "",
        delegationBias,
        personality: personalityBlock,
        intentTracing: !!intentField,
        intentField: intentField ?? "",
        eagerTasks,
        eagerTasksAlways,
        // Restrained bias yields to an explicit eager-tasks mode.
        inlineFirstDelegation: delegationBias === "restrained" && !eagerTasks,
        taskBatch,
        MAX_CONCURRENCY: normalizeConcurrencyLimit(taskMaxConcurrency),
        scoutAvailable,
        taskIrcEnabled,
        secretsEnabled,
        browserEnabled: evalPreludes.some(prelude => prelude.name === "browser"),
        computerEnabled: evalPreludes.some(prelude => prelude.name === "computer"),
        includeWorkspaceTree,
        renderMermaid,
        renderSvg,
        autoGraph,
        reactions,
        xdevTools,
        hasDynamicXdevTools: xdevTools.some(mounted => mounted.dynamic === true),
        xdevDocs,
        writeTransportOnly,
        subagent,
    };
    const selectedTemplate = resolvedCustomPrompt
        ? customSystemPromptTemplate
        : (resolvedSystemPromptTemplate ?? systemPromptTemplate);
    let rendered;
    try {
        rendered = prompt.render(selectedTemplate, data);
    }
    catch (error) {
        if (resolvedSystemPromptTemplate === undefined)
            throw error;
        if (!hasDiscoveredTemplate) {
            throw new Error(`Invalid system prompt template: ${String(error)}`, { cause: error });
        }
        logger.warn("Ignoring invalid discovered system prompt template; using the bundled prompt", {
            error: String(error),
        });
        resolvedSystemPromptTemplate = undefined;
        rendered = prompt.render(systemPromptTemplate, data);
    }
    const systemPrompt = [rendered];
    for (const prelude of evalPreludes) {
        const guidance = prelude.guidance?.trim();
        if (guidance)
            systemPrompt.push(guidance);
    }
    // Working-directory content (context files with their paths, workspace
    // tree/roots, active repo) and session append text form one trailing
    // `<project-context>` block after every static block, so sessions in
    // different directories share the static prefix and the Anthropic head
    // cache breakpoint lands right before this block.
    const projectPrompt = prompt
        .render(projectPromptTemplate, { ...data, activeRepoContext: activeRepoContextPrompt })
        .trim();
    if (projectPrompt) {
        systemPrompt.push(projectPrompt);
    }
    // Claim delivery only when the rendered block 0 actually carries the xd://
    // section, so a template that references {{xdevDocs}} keeps mount-notice
    // dedupe while one that omits it stays honest.
    const xdevCatalogNames = !resolvedCustomPrompt && xdevTools.length > 0 && rendered.includes("xd://")
        ? xdevTools.map(mounted => mounted.name)
        : undefined;
    return { systemPrompt, xdevCatalogNames };
}
