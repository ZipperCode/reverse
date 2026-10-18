import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { FileType, glob } from "@rva/natives";
import { CONFIG_DIR_NAME, getAgentDir, getConfigDirName, getPluginsDir, getProjectDir, logger, normalizePathForComparison, parseFrontmatter, tryParseJson, } from "@rva/utils";
import { isUserSourceEnabled } from "../capability";
import { invalidate as invalidateFsCache, readDirEntries, readFile } from "../capability/fs";
import { MAIN_AGENT_RULE_NAME, parseRuleAgents, parseRuleConditionAndScope, SUB_AGENT_RULE_NAME, } from "../capability/rule";
import { resolveClaudePaths } from "../config/claude-paths";
import { parseConfiguredThinkingLevel } from "@rva/tui/thinking";
import { normalizeToolNames } from "../tools/builtin-names";
import { realpathIfExists, resolveContainedPath } from "./contained-path";
import { buildPluginDirRoot } from "./plugin-dir-roots";
/**
 * Standard paths for each config source.
 */
export const SOURCE_PATHS = {
    native: {
        get userBase() {
            return getConfigDirName();
        },
        get userAgent() {
            return `${getConfigDirName()}/agent`;
        },
        projectDir: CONFIG_DIR_NAME,
    },
    claude: {
        userBase: ".claude",
        userAgent: ".claude",
        projectDir: ".claude",
    },
    codex: {
        userBase: ".codex",
        userAgent: ".codex",
        projectDir: ".codex",
    },
    gemini: {
        userBase: ".gemini",
        userAgent: ".gemini",
        projectDir: ".gemini",
    },
    opencode: {
        userBase: ".config/opencode",
        userAgent: ".config/opencode",
        projectDir: ".opencode",
    },
    cursor: {
        userBase: ".cursor",
        userAgent: ".cursor",
        projectDir: ".cursor",
    },
    windsurf: {
        userBase: ".codeium/windsurf",
        userAgent: ".codeium/windsurf",
        projectDir: ".windsurf",
    },
    cline: {
        userBase: ".cline",
        userAgent: ".cline",
        projectDir: null, // Cline uses root-level .clinerules
    },
    github: {
        userBase: null,
        userAgent: null,
        projectDir: ".github",
    },
    vscode: {
        userBase: ".vscode",
        userAgent: ".vscode",
        projectDir: ".vscode",
    },
};
/**
 * Resolve a user-level path for a source without the `~/` opt-in gate.
 * Only for callers that hold their own explicit opt-in (a per-capability
 * `skills.enable*User` / `commands.enable*User` toggle); everything else
 * goes through {@link getUserPath}.
 */
export function resolveUserPath(ctx, source, subpath) {
    // Native user config is profile-scoped via getAgentDir() (the active profile's
    // agent dir), matching builtin.ts and getMCPConfigPath("user").
    if (source === "native")
        return path.join(getAgentDir(), subpath);
    if (source === "claude")
        return path.join(resolveClaudePaths(ctx.home).configDir, subpath);
    const paths = SOURCE_PATHS[source];
    if (!paths.userAgent)
        return null;
    return path.join(ctx.home, paths.userAgent, subpath);
}
/**
 * Get user-level path for a source, or null when its `~/` config is not
 * opted in (see {@link isUserSourceEnabled}).
 */
export function getUserPath(ctx, source, subpath) {
    if (!isUserSourceEnabled(source, ctx))
        return null;
    return resolveUserPath(ctx, source, subpath);
}
/**
 * Get project-level path for a source (cwd only).
 */
export function getProjectPath(ctx, source, subpath) {
    const paths = SOURCE_PATHS[source];
    if (!paths.projectDir)
        return null;
    return path.join(ctx.cwd, paths.projectDir, subpath);
}
/**
 * Resolve GitHub Copilot CLI's user-global config root. Copilot stores per-user
 * instructions/prompts/agents/MCP under `~/.copilot`, relocatable via the
 * `COPILOT_HOME` env var (mirrors Copilot CLI's `--config-dir`). Falls back to
 * `<home>/.copilot` when the override is unset.
 */
export function resolveCopilotHome(home) {
    const override = process.env.COPILOT_HOME?.trim();
    return override ? override : path.join(home, ".copilot");
}
/**
 * Create source metadata for an item.
 */
export function createSourceMeta(provider, filePath, level, origin, pluginName) {
    return {
        provider,
        providerName: "", // Filled in by registry
        path: path.resolve(filePath),
        level,
        ...(origin !== undefined && { origin }),
        ...(pluginName !== undefined && { pluginName }),
    };
}
export function parseBoolean(value) {
    if (typeof value === "boolean")
        return value;
    if (typeof value === "string") {
        const normalized = value.trim().toLowerCase();
        if (normalized === "true")
            return true;
        if (normalized === "false")
            return false;
    }
    return undefined;
}
/**
 * Parse an MCP `requestIdFormat` value. Unrecognized values are dropped so a typo
 * degrades to the default integer ids rather than reaching a transport.
 */
export function parseRequestIdFormat(value) {
    if (value === "string" || value === "number")
        return value;
    return undefined;
}
/**
 * Parse a comma-separated string into an array of trimmed, non-empty strings.
 */
export function parseCSV(value) {
    return value
        .split(",")
        .map(s => s.trim())
        .filter(Boolean);
}
/**
 * Parse a value that may be an array of strings or a comma-separated string.
 * Returns undefined if the result would be empty.
 */
export function parseArrayOrCSV(value) {
    if (Array.isArray(value)) {
        const filtered = value.filter((item) => typeof item === "string");
        return filtered.length > 0 ? filtered : undefined;
    }
    if (typeof value === "string") {
        const parsed = parseCSV(value);
        return parsed.length > 0 ? parsed : undefined;
    }
    return undefined;
}
function buildRule(name, body, frontmatter, filePath, source, options) {
    const { condition, astCondition, question, scope } = parseRuleConditionAndScope(frontmatter);
    let globs;
    if (Array.isArray(frontmatter.globs)) {
        globs = frontmatter.globs.filter((item) => typeof item === "string");
    }
    else if (typeof frontmatter.globs === "string") {
        globs = [frontmatter.globs];
    }
    const resolvedName = options?.ruleName ?? name.replace(options?.stripNamePattern ?? /\.(md|mdc)$/, "");
    const rawMode = frontmatter.interruptMode;
    const interruptMode = rawMode === "never" || rawMode === "prose-only" || rawMode === "tool-only" || rawMode === "always"
        ? rawMode
        : undefined;
    return {
        name: resolvedName,
        path: filePath,
        content: body,
        globs,
        alwaysApply: frontmatter.alwaysApply === true,
        description: typeof frontmatter.description === "string" ? frontmatter.description : undefined,
        condition,
        astCondition,
        question,
        scope,
        agents: parseRuleAgents(frontmatter.agents),
        interruptMode,
        _source: source,
    };
}
/** Build a canonical rule from Markdown, including explicitly loaded disabled files. */
export function buildRuleFromMarkdown(name, content, filePath, source, options) {
    const { frontmatter, body } = parseFrontmatter(content, { source: filePath });
    return buildRule(name, body, frontmatter, filePath, source, options);
}
/** Build a discovered rule from Markdown, returning null when its frontmatter disables it. */
export function discoverRuleFromMarkdown(name, content, filePath, source, options) {
    const { frontmatter, body } = parseFrontmatter(content, { source: filePath });
    if (frontmatter.enabled === false)
        return null;
    return buildRule(name, body, frontmatter, filePath, source, options);
}
/**
 * Parse model field into a prioritized list.
 */
export function parseModelList(value) {
    const parsed = parseArrayOrCSV(value);
    if (!parsed)
        return undefined;
    const normalized = parsed.map(entry => entry.trim()).filter(Boolean);
    return normalized.length > 0 ? normalized : undefined;
}
/**
 * Parse agent fields from frontmatter.
 * Returns null if required fields (name, description) are missing.
 */
export function parseAgentFields(frontmatter) {
    const name = typeof frontmatter.name === "string" ? frontmatter.name : undefined;
    const description = typeof frontmatter.description === "string" ? frontmatter.description : undefined;
    if (!name || !description) {
        return null;
    }
    // "main" is the sentinel `agentName` for the top-level session (see
    // MAIN_AGENT_RULE_NAME); "sub" is the fallback `agentName` for a subagent
    // session with no explicit name (see SUB_AGENT_RULE_NAME / sdk.ts). A
    // custom agent definition sharing either name would resolve to the same
    // sentinel value, letting it load rules scoped `agents: [main]` or
    // `agents: [sub]` that are documented to target only that session kind.
    const normalizedName = name.trim().toLowerCase();
    if (normalizedName === MAIN_AGENT_RULE_NAME || normalizedName === SUB_AGENT_RULE_NAME) {
        return null;
    }
    // Only absent or null tools select defaults; malformed restrictions must not widen access.
    const rawTools = frontmatter.tools;
    let tools = rawTools == null ? undefined : (parseArrayOrCSV(rawTools) ?? []);
    if (tools?.length === 0 && !(Array.isArray(rawTools) && rawTools.length === 0)) {
        const valueType = Array.isArray(rawTools) ? "array" : typeof rawTools;
        logger.warn("Agent tools declaration names no tools; using an empty built-in allowlist", {
            agent: name,
            valueType,
        });
    }
    if (tools)
        tools = normalizeToolNames(tools);
    // Parse spawns field (array, "*", or CSV)
    let spawns;
    if (frontmatter.spawns === "*") {
        spawns = "*";
    }
    else if (typeof frontmatter.spawns === "string") {
        const trimmed = frontmatter.spawns.trim();
        if (trimmed === "*") {
            spawns = "*";
        }
        else {
            spawns = parseArrayOrCSV(trimmed);
        }
    }
    else {
        spawns = parseArrayOrCSV(frontmatter.spawns);
    }
    // Backward compat: infer spawns: "*" when tools includes "task"
    if (spawns === undefined && tools?.includes("task")) {
        spawns = "*";
    }
    const output = frontmatter.output !== undefined ? frontmatter.output : undefined;
    const rawThinkingLevel = typeof frontmatter.thinkingLevel === "string"
        ? frontmatter.thinkingLevel
        : typeof frontmatter.thinking === "string"
            ? frontmatter.thinking
            : undefined;
    const thinkingLevel = parseConfiguredThinkingLevel(rawThinkingLevel);
    const model = parseModelList(frontmatter.model);
    const blocking = parseBoolean(frontmatter.blocking);
    const structured = parseBoolean(frontmatter.structured);
    const readSummarize = parseBoolean(frontmatter.readSummarize);
    // prewalk: true → hand off to the default prewalk target; "<pattern>" → custom target.
    let prewalk = parseBoolean(frontmatter.prewalk);
    if (prewalk === undefined && typeof frontmatter.prewalk === "string") {
        const trimmed = frontmatter.prewalk.trim();
        if (trimmed)
            prewalk = trimmed;
    }
    // advisor: true → advise with the default advisor-role model; "<pattern>" → custom advisor model.
    let advisor = parseBoolean(frontmatter.advisor);
    if (advisor === undefined && typeof frontmatter.advisor === "string") {
        const trimmed = frontmatter.advisor.trim();
        if (trimmed)
            advisor = trimmed;
    }
    const autoloadSkills = parseArrayOrCSV(frontmatter.autoloadSkills)
        ?.map(s => s.trim())
        .filter(Boolean);
    return {
        name,
        description,
        tools,
        spawns,
        model,
        output,
        thinkingLevel,
        blocking,
        structured,
        autoloadSkills,
        readSummarize,
        prewalk,
        advisor,
    };
}
async function globIf(dir, pattern, fileType, recursive = true) {
    try {
        const result = await glob({ pattern, path: dir, gitignore: true, hidden: false, fileType, recursive });
        return result.matches;
    }
    catch {
        return [];
    }
}
// Stable ordering used for skill lists in prompts: name (case-insensitive), then name, then path.
export function compareSkillOrder(aName, aPath, bName, bPath) {
    const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
    const lowerCompare = cmp(aName.toLowerCase(), bName.toLowerCase());
    if (lowerCompare !== 0)
        return lowerCompare;
    const nameCompare = cmp(aName, bName);
    if (nameCompare !== 0)
        return nameCompare;
    return cmp(aPath, bPath);
}
export async function scanSkillsFromDir(_ctx, options) {
    const items = [];
    const warnings = [];
    const { dir, level, providerId, requireDescription = false } = options;
    let entries;
    try {
        entries = await fs.promises.readdir(dir, { withFileTypes: true });
    }
    catch (error) {
        if (error.code !== "ENOENT") {
            warnings.push(`Failed to read skills directory: ${dir} (${String(error)})`);
        }
        return { items, warnings };
    }
    const loadSkill = async (skillPath) => {
        try {
            const content = await readFile(skillPath);
            if (!content)
                return;
            const { frontmatter, body } = parseFrontmatter(content, { source: skillPath });
            if (frontmatter.enabled === false) {
                return;
            }
            if (requireDescription && !frontmatter.description) {
                return;
            }
            const skillDirName = path.basename(path.dirname(skillPath));
            const rawName = frontmatter.name;
            const name = typeof rawName === "string" ? rawName.trim() || skillDirName : skillDirName;
            // `/` is reserved for collision namespaces (`<namespace>/<name>`) and
            // path resolution in skill:// URLs; a raw name must never claim one.
            if (/[\\/]/.test(name)) {
                warnings.push(`Skill name "${name}" contains a path separator, skipping: ${skillPath}`);
                return;
            }
            items.push({
                name,
                path: skillPath,
                content: body,
                frontmatter: frontmatter,
                level,
                _source: createSourceMeta(providerId, skillPath, level, options.origin, options.pluginName),
            });
        }
        catch {
            warnings.push(`Failed to read skill file: ${skillPath}`);
        }
    };
    const work = [];
    if (options.includeSelf) {
        const selfSkillPath = path.join(dir, "SKILL.md");
        if (fs.existsSync(selfSkillPath)) {
            work.push(loadSkill(selfSkillPath));
        }
    }
    for (const entry of entries) {
        if (entry.name.startsWith("."))
            continue;
        if (!entry.isDirectory() && !entry.isSymbolicLink())
            continue;
        const skillPath = path.join(dir, entry.name, "SKILL.md");
        if (fs.existsSync(skillPath)) {
            work.push(loadSkill(skillPath));
        }
    }
    await Promise.all(work);
    // Deterministic ordering: async file reads complete nondeterministically, so sort after loading.
    items.sort((a, b) => compareSkillOrder(a.name, a.path, b.name, b.path));
    return { items, warnings };
}
/**
 * Resolve a placeholder name against `extraEnv`, then the ambient environment.
 *
 * Inherited members of either map (`__proto__`, `constructor`, `toString`, …)
 * are never substitutable: `extraEnv` is consulted by own property only, and
 * `Bun.env`'s getter falls through to `Object.prototype`, so `${constructor}`
 * would otherwise stringify into the value as `function Object() { [native
 * code] }`. Every real variable is a string, so a non-string ambient hit means
 * the name resolved to a prototype member and counts as unset.
 */
function lookupEnvValue(varName, extraEnv) {
    if (extraEnv !== undefined && Object.hasOwn(extraEnv, varName))
        return extraEnv[varName];
    const ambient = Bun.env[varName];
    return typeof ambient === "string" ? ambient : undefined;
}
/**
 * Expand environment variables in a string.
 * Supports ${VAR} and ${VAR:-default} syntax.
 */
function expandEnvVars(value, extraEnv) {
    return value.replace(/\$\{([^}:]+)(?::-([^}]*))?\}/g, (_, varName, defaultValue) => {
        const envValue = lookupEnvValue(varName, extraEnv);
        // `${VAR:-default}` follows POSIX `:-`: the default applies when the
        // variable is unset OR empty. Plain `${VAR}` keeps the value verbatim
        // (even an empty one) and stays literal when unset.
        if (envValue !== undefined && (defaultValue === undefined || envValue !== ""))
            return envValue;
        if (defaultValue !== undefined)
            return defaultValue;
        return `\${${varName}}`;
    });
}
/**
 * Recursively expand environment variables in an object.
 */
export function expandEnvVarsDeep(obj, extraEnv) {
    if (typeof obj === "string") {
        return expandEnvVars(obj, extraEnv);
    }
    if (Array.isArray(obj)) {
        return obj.map(item => expandEnvVarsDeep(item, extraEnv));
    }
    if (obj !== null && typeof obj === "object") {
        const result = {};
        for (const [key, value] of Object.entries(obj)) {
            result[key] = expandEnvVarsDeep(value, extraEnv);
        }
        return result;
    }
    return obj;
}
/**
 * Load files from a directory matching extensions.
 * Uses native glob for fast filesystem scanning with gitignore support.
 */
export async function loadFilesFromDir(_ctx, dir, provider, level, options) {
    const items = [];
    const warnings = [];
    // Build glob pattern based on extensions and recursion
    const { extensions, recursive = false } = options;
    let pattern;
    if (extensions && extensions.length > 0) {
        const extPattern = extensions.length === 1 ? extensions[0] : `{${extensions.join(",")}}`;
        pattern = recursive ? `**/*.${extPattern}` : `*.${extPattern}`;
    }
    else {
        pattern = recursive ? "**/*" : "*";
    }
    // Use native glob for fast scanning with gitignore support
    let matches;
    try {
        const result = await glob({
            pattern,
            path: dir,
            gitignore: true,
            hidden: false,
            fileType: FileType.File,
            // Thread the caller's non-recursive intent explicitly: the native glob
            // defaults `recursive` to true and rewrites `*.{ts,js}` -> `**/*.{ts,js}`,
            // which would walk the entire subtree (e.g. a venv's site-packages under
            // ~/.codex/tools) and import arbitrary frontend assets as tools (#8552).
            recursive,
        });
        matches = result.matches;
    }
    catch {
        // Directory doesn't exist or isn't readable
        return { items, warnings };
    }
    // Read all matching files in parallel
    const fileResults = await Promise.all(matches.map(async (match) => {
        const filePath = path.join(dir, match.path);
        const content = await readFile(filePath);
        return { filePath, content };
    }));
    for (const { filePath, content } of fileResults) {
        if (content === null) {
            warnings.push(`Failed to read file: ${filePath}`);
            continue;
        }
        const name = path.basename(filePath);
        const source = createSourceMeta(provider, filePath, level, options.origin);
        try {
            const item = options.transform(name, content, filePath, source);
            if (item !== null) {
                items.push(item);
            }
        }
        catch (err) {
            warnings.push(`Failed to parse ${filePath}: ${err}`);
        }
    }
    return { items, warnings };
}
/**
 * Calculate depth of target directory relative to current working directory.
 * Depth is the number of directory levels from cwd to target.
 * - Positive depth: target is above cwd (parent/ancestor)
 * - Zero depth: target is cwd
 * - This uses path splitting to count directory levels
 */
export function calculateDepth(cwd, targetDir, separator) {
    return cwd.split(separator).length - targetDir.split(separator).length;
}
// =============================================================================
// Standalone context-file walker (AGENTS.md, CLAUDE.md, …)
// =============================================================================
/**
 * Compare paths while tolerating Windows drive casing.
 */
function samePath(left, right) {
    const normalizedLeft = path.resolve(left);
    const normalizedRight = path.resolve(right);
    return process.platform === "win32"
        ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
        : normalizedLeft === normalizedRight;
}
/**
 * Return whether `child` is at or below `parent`.
 */
function isWithin(parent, child) {
    const normalizedParent = path.resolve(parent);
    const normalizedChild = path.resolve(child);
    const relative = path.relative(process.platform === "win32" ? normalizedParent.toLowerCase() : normalizedParent, process.platform === "win32" ? normalizedChild.toLowerCase() : normalizedChild);
    return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}
/**
 * Load standalone context files (e.g. AGENTS.md, CLAUDE.md) by walking up from
 * cwd. Shared across providers whose files live in project root rather than
 * config directories (which their own providers handle).
 *
 * When a repository is nested below the user's home directory, continue past
 * the Git root to discover workspace-level files, but stop before loading the
 * home directory's own copy as project context. A repository rooted at the
 * home directory itself is not "nested below" it, so the home-level file
 * remains project context.
 */
export async function loadStandaloneContextFiles(ctx, providerId, fileName) {
    const items = [];
    const warnings = [];
    const home = path.resolve(ctx.home);
    const cwd = path.resolve(ctx.cwd);
    const repoRoot = ctx.repoRoot ? path.resolve(ctx.repoRoot) : null;
    const filesystemRoot = path.parse(cwd).root;
    const cwdIsUnderHome = isWithin(home, cwd);
    const repoIsHome = repoRoot !== null && samePath(home, repoRoot);
    const repoIsUnderHome = repoRoot !== null && isWithin(home, repoRoot) && !repoIsHome;
    const scanToHome = repoRoot !== null && cwdIsUnderHome && repoIsUnderHome;
    const boundary = scanToHome ? home : (repoRoot ?? (cwdIsUnderHome ? home : filesystemRoot));
    const includeBoundary = repoRoot === null ? cwdIsUnderHome : !samePath(boundary, home) || repoIsHome;
    const excludeHome = scanToHome;
    let current = cwd;
    while (true) {
        const atBoundary = samePath(current, boundary);
        const atHome = excludeHome && samePath(current, home);
        if (!(atHome || (atBoundary && !includeBoundary))) {
            const candidate = path.join(current, fileName);
            const content = await readFile(candidate);
            // Empty files contribute nothing and must not claim the depth scope:
            // at a priority tie, an empty first-registered file would shadow a
            // non-empty sibling (e.g. an empty AGENTS.md shadowing CLAUDE.md).
            if (content !== null && content !== "") {
                const parent = path.dirname(candidate);
                const baseName = parent.split(path.sep).pop() ?? "";
                if (!baseName.startsWith(".")) {
                    const fileDir = path.dirname(candidate);
                    const calculatedDepth = calculateDepth(cwd, fileDir, path.sep);
                    items.push({
                        path: candidate,
                        content,
                        level: "project",
                        depth: calculatedDepth,
                        _source: createSourceMeta(providerId, candidate, "project"),
                    });
                }
            }
        }
        if (atBoundary)
            break;
        const parent = path.dirname(current);
        if (parent === current)
            break;
        current = parent;
    }
    return { items, warnings };
}
async function discoverLinkedExtensionModuleFiles(dir) {
    const entries = await readDirEntries(dir);
    const indexFiles = [];
    const packageJsonFiles = [];
    await Promise.all(entries.map(async (entry) => {
        if (entry.name.startsWith(".") || entry.isDirectory())
            return;
        const entryPath = path.join(dir, entry.name);
        const stat = await fs.promises.stat(entryPath).catch(() => null);
        if (!stat?.isDirectory())
            return;
        const [packageJsonContent, indexTsContent, indexJsContent] = await Promise.all([
            readFile(path.join(entryPath, "package.json")),
            readFile(path.join(entryPath, "index.ts")),
            readFile(path.join(entryPath, "index.js")),
        ]);
        if (packageJsonContent !== null) {
            packageJsonFiles.push({ path: `${entry.name}/package.json` });
        }
        if (indexTsContent !== null) {
            indexFiles.push({ path: `${entry.name}/index.ts` });
        }
        else if (indexJsContent !== null) {
            indexFiles.push({ path: `${entry.name}/index.js` });
        }
    }));
    return { indexFiles, packageJsonFiles };
}
async function readExtensionModuleManifest(_ctx, packageJsonPath) {
    const content = await readFile(packageJsonPath);
    if (!content)
        return null;
    const pkg = tryParseJson(content);
    const manifest = pkg?.omp ?? pkg?.pi;
    if (manifest && typeof manifest === "object") {
        return manifest;
    }
    return null;
}
/**
 * Discover extension module entry points in a directory.
 *
 * Discovery rules:
 * 1. Direct files: `extensions/*.ts` or `*.js` → load
 * 2. Subdirectory with index: `extensions/<ext>/index.ts` or `index.js` → load
 * 3. Subdirectory with package.json: `extensions/<ext>/package.json` with "omp"/"pi" field → load declared paths
 *
 * No recursion beyond one level. Complex packages must use package.json manifest.
 * Uses native glob for fast filesystem scanning with gitignore support.
 */
export async function discoverExtensionModulePaths(_ctx, dir) {
    const discovered = new Set();
    // Find all candidate files in parallel using glob
    const [directFiles, globIndexFiles, globPackageJsonFiles, linkedFiles] = await Promise.all([
        // 1. Direct *.ts or *.js files
        globIf(dir, "*.{ts,js}", FileType.File, false),
        // 2. Subdirectory index files
        globIf(dir, "*/index.{ts,js}", FileType.File, false),
        // 3. Subdirectory package.json files
        globIf(dir, "*/package.json", FileType.File, false),
        // Native glob does not follow linked extension directories.
        discoverLinkedExtensionModuleFiles(dir),
    ]);
    const indexFiles = [...globIndexFiles, ...linkedFiles.indexFiles];
    const packageJsonFiles = [...globPackageJsonFiles, ...linkedFiles.packageJsonFiles];
    // The native glob walker runs with follow_links=false, so a symlinked extension
    // directory is yielded as a Symlink entry but never descended into: its inner
    // index.{ts,js}/package.json are invisible to the `*/...` patterns above.
    // Detect top-level symlinked directories and synthesize the equivalent subdir
    // matches so the resolution below treats them like real directories. Symlinked
    // *files* already match, because the native file-type filter resolves a
    // symlink's target type for File filters.
    const topLevelEntries = await readDirEntries(dir);
    for (const entry of topLevelEntries) {
        if (!entry.isSymbolicLink())
            continue;
        // readDirEntries follows the symlink: a link to a file/dangling link yields [].
        const subEntries = await readDirEntries(path.join(dir, entry.name));
        const hasEntry = (name) => subEntries.some(e => e.name === name && (e.isFile() || e.isSymbolicLink()));
        if (hasEntry("package.json"))
            packageJsonFiles.push({ path: `${entry.name}/package.json` });
        if (hasEntry("index.ts"))
            indexFiles.push({ path: `${entry.name}/index.ts` });
        else if (hasEntry("index.js"))
            indexFiles.push({ path: `${entry.name}/index.js` });
    }
    // Process direct files
    for (const match of directFiles) {
        if (match.path.includes("/"))
            continue;
        discovered.add(path.join(dir, match.path));
    }
    // Track which subdirectories have package.json manifests with declared extensions
    const subdirsWithDeclaredExtensions = new Set();
    for (const match of packageJsonFiles) {
        const subdir = path.dirname(match.path); // e.g., "my-extension"
        const packageJsonPath = path.join(dir, match.path);
        const manifest = await readExtensionModuleManifest(_ctx, packageJsonPath);
        const declaredExtensions = manifest?.extensions?.filter((extPath) => typeof extPath === "string") ?? [];
        if (declaredExtensions.length === 0)
            continue;
        subdirsWithDeclaredExtensions.add(subdir);
        const subdirPath = path.join(dir, subdir);
        for (const extPath of declaredExtensions) {
            let resolvedExtPath = path.resolve(subdirPath, extPath);
            const entries = await readDirEntries(resolvedExtPath);
            if (entries.length !== 0) {
                const pluginFilePath = entries.find(e => e.isFile() && (e.name === "index.ts" || e.name === "index.js"))?.name;
                resolvedExtPath = pluginFilePath ? path.join(resolvedExtPath, pluginFilePath) : resolvedExtPath;
            }
            const content = await readFile(resolvedExtPath);
            if (content !== null) {
                discovered.add(resolvedExtPath);
            }
        }
    }
    const preferredIndexBySubdir = new Map();
    for (const match of indexFiles) {
        if (match.path.split("/").length !== 2)
            continue;
        const subdir = path.dirname(match.path);
        if (subdirsWithDeclaredExtensions.has(subdir))
            continue;
        const existing = preferredIndexBySubdir.get(subdir);
        if (!existing || (existing.endsWith("index.js") && match.path.endsWith("index.ts"))) {
            preferredIndexBySubdir.set(subdir, match.path);
        }
    }
    for (const preferredPath of preferredIndexBySubdir.values()) {
        discovered.add(path.join(dir, preferredPath));
    }
    return [...discovered];
}
/**
 * Derive a stable extension name from a path.
 */
export function getExtensionNameFromPath(extensionPath) {
    const base = extensionPath.replace(/\\/g, "/").split("/").pop() ?? extensionPath;
    if (base === "index.ts" || base === "index.js") {
        const parts = extensionPath.replace(/\\/g, "/").split("/");
        const parent = parts[parts.length - 2];
        return parent ?? base;
    }
    const dot = base.lastIndexOf(".");
    if (dot > 0) {
        return base.slice(0, dot);
    }
    return base;
}
/**
 * Build ExtensionModule items from discovered user/project paths.
 * Shared across providers that expose extension modules via user + project dirs.
 */
export function buildExtensionModuleItems(providerId, userPaths, projectPaths) {
    return [
        ...userPaths.map(extPath => ({
            name: getExtensionNameFromPath(extPath),
            path: extPath,
            level: "user",
            _source: createSourceMeta(providerId, extPath, "user"),
        })),
        ...projectPaths.map(extPath => ({
            name: getExtensionNameFromPath(extPath),
            path: extPath,
            level: "project",
            _source: createSourceMeta(providerId, extPath, "project"),
        })),
    ];
}
/**
 * Parse Claude Code installed_plugins.json content.
 */
export function parseClaudePluginsRegistry(content) {
    const data = tryParseJson(content);
    if (!data || typeof data !== "object")
        return null;
    if (typeof data.version !== "number" ||
        !data.plugins ||
        typeof data.plugins !== "object" ||
        Array.isArray(data.plugins))
        return null;
    return data;
}
/** Project discovery never examines home or shared temporary roots, or their ancestors. */
export function getProjectDiscoveryCeilings() {
    const ceilings = new Set();
    ceilings.add(normalizePathForComparison(os.homedir()));
    ceilings.add(normalizePathForComparison(os.tmpdir()));
    if (process.platform !== "win32") {
        ceilings.add(normalizePathForComparison("/tmp"));
        ceilings.add(normalizePathForComparison("/var/tmp"));
    }
    return ceilings;
}
/** The current user's config roots are never project anchors. */
export function isUserConfigRoot(root) {
    const configDir = normalizePathForComparison(path.join(root, getConfigDirName()));
    return (configDir === normalizePathForComparison(path.join(os.homedir(), getConfigDirName())) ||
        configDir === normalizePathForComparison(path.dirname(getPluginsDir())));
}
/**
 * An inactive default user layout (`<configDirName>/agent/`) is not a project anchor above a git
 * root or without a repo. `configDirName` is the project config dir the caller would load from.
 */
export async function isForeignUserConfigRoot(root, configDirName) {
    try {
        const agentDir = path.join(root, configDirName, "agent");
        const stat = await fs.promises.stat(agentDir);
        return stat.isDirectory() && normalizePathForComparison(agentDir) !== normalizePathForComparison(getAgentDir());
    }
    catch {
        return false;
    }
}
/**
 * Resolve the active project registry path by walking up from `cwd`.
 *
 * Walk order:
 * 1. Walk up from `cwd` looking for the nearest directory containing `.omp/`.
 *    The first match returns `<dir>/.omp/plugins/installed_plugins.json`.
 * 2. If no `.omp/` is found, rescan from `cwd` upward looking for `.git`.
 *    The git root is used as an anchor: `<gitRoot>/.omp/plugins/installed_plugins.json`.
 * 3. Stop before home or a temporary root in either pass. If neither anchor is
 *    found below that ceiling, return `null` — no project context is active.
 * Inactive `.omp/agent/` layouts are skipped only above the nearest git root,
 * or throughout an unanchored walk, so repo-local agent directories stay project scope.
 *
 * This is the single source of truth for "active project root" used by install,
 * uninstall, list, upgrade, discovery, and doctor. Deterministic for a given `cwd`.
 */
export async function resolveActiveProjectRegistryPath(cwd) {
    return resolveProjectRegistryPath(cwd, getProjectDiscoveryCeilings());
}
async function resolveProjectRegistryPath(cwd, ceilings) {
    // Find the nearest git root once, retaining the existing user-root exclusion for fallback.
    let nearestGitRoot = null;
    let gitAnchor = null;
    let dir = path.resolve(cwd);
    while (!ceilings.has(normalizePathForComparison(dir))) {
        try {
            await fs.promises.stat(path.join(dir, ".git"));
            nearestGitRoot ??= dir;
            if (!isUserConfigRoot(dir)) {
                gitAnchor = dir;
                break;
            }
        }
        catch {
            // not found at this level — continue up
        }
        const parent = path.dirname(dir);
        if (parent === dir)
            break; // filesystem root
        dir = parent;
    }
    // Existing .omp/ directories still win, even above the git root, except foreign user roots.
    const configDirName = getConfigDirName();
    let aboveGitRoot = nearestGitRoot === null;
    dir = path.resolve(cwd);
    while (!ceilings.has(normalizePathForComparison(dir))) {
        try {
            const stat = await fs.promises.stat(path.join(dir, configDirName));
            if (stat.isDirectory() &&
                !isUserConfigRoot(dir) &&
                (!aboveGitRoot || !(await isForeignUserConfigRoot(dir, configDirName)))) {
                return path.join(dir, configDirName, "plugins", "installed_plugins.json");
            }
        }
        catch {
            // not found at this level — continue up
        }
        if (dir === nearestGitRoot)
            aboveGitRoot = true;
        const parent = path.dirname(dir);
        if (parent === dir)
            break; // filesystem root
        dir = parent;
    }
    return gitAnchor ? path.join(gitAnchor, getConfigDirName(), "plugins", "installed_plugins.json") : null;
}
/**
 * Like resolveActiveProjectRegistryPath, but falls back to `<cwd>/.omp/plugins/installed_plugins.json`
 * when no project anchor (.omp/ or .git/) is found.
 *
 * Use this when the caller accepts an explicit --scope project so that installing into a freshly
 * bootstrapped directory (no .omp/ or .git/ yet) works: writeInstalledPluginsRegistry auto-creates
 * the directory tree on first write.
 *
 * Returns undefined when cwd is a discovery ceiling or user config root, so the
 * fallback never creates a shared temporary registry or aliases the user registry.
 */
export async function resolveOrDefaultProjectRegistryPath(cwd) {
    const ceilings = getProjectDiscoveryCeilings();
    const resolved = await resolveProjectRegistryPath(cwd, ceilings);
    if (resolved)
        return resolved;
    // A cwd containing .omp/ at or below a git root already resolved above.
    if (ceilings.has(normalizePathForComparison(cwd)) ||
        isUserConfigRoot(cwd) ||
        (await isForeignUserConfigRoot(cwd, getConfigDirName())))
        return undefined;
    return path.join(cwd, getConfigDirName(), "plugins", "installed_plugins.json");
}
async function canonicalClaudeProjectPath(projectPath) {
    try {
        return await fs.promises.realpath(path.resolve(projectPath));
    }
    catch {
        return null;
    }
}
/**
 * Claude Code `enabledPlugins` overrides, merged across the same settings
 * layers Claude Code itself consults: `<claude-config>/settings.json`, then
 * `<dir>/.claude/settings.json` and `<dir>/.claude/settings.local.json` for
 * each project directory (later layers win, `.local` wins within a layer).
 *
 * Returns `pluginId -> boolean` for the ids the user toggled explicitly, and
 * the list of settings files that contributed (for cache keying).
 */
async function readClaudeEnabledPlugins(claudeConfigDir, projectDirs) {
    const enabled = new Map();
    const sources = [];
    const candidates = [path.join(claudeConfigDir, "settings.json")];
    for (const dir of projectDirs) {
        candidates.push(path.join(dir, ".claude", "settings.json"), path.join(dir, ".claude", "settings.local.json"));
    }
    for (const file of candidates) {
        const content = await readFile(file);
        if (!content)
            continue;
        const data = tryParseJson(content);
        if (!data || typeof data !== "object")
            continue;
        const map = data.enabledPlugins;
        if (!map || typeof map !== "object" || Array.isArray(map))
            continue;
        sources.push(file);
        for (const [pluginId, value] of Object.entries(map)) {
            if (typeof value === "boolean")
                enabled.set(pluginId, value);
        }
    }
    return { enabled, sources };
}
const pluginRootsCache = new Map();
const pluginCacheInvalidators = new Set();
/** Register a process-global plugin cache invalidator called whenever plugin roots are cleared. */
export function registerPluginCacheInvalidator(invalidator) {
    pluginCacheInvalidators.add(invalidator);
}
/**
 * List all installed Claude Code plugin roots from its active plugin cache and
 * ~/.omp/plugins/installed_plugins.json, plus the nearest project registry when present.
 *
 * Results are cached per Claude and OMP config directories, project registry, and canonical active project.
 */
export async function listClaudePluginRoots(home, cwd) {
    const claudeConfigDir = resolveClaudePaths(home).configDir;
    const ompRegistryPath = path.join(getPluginsDir(home), "installed_plugins.json");
    const projectPath = cwd ? await resolveActiveProjectRegistryPath(cwd) : null;
    const resolvedProjectPath = projectPath && normalizePathForComparison(projectPath) !== normalizePathForComparison(ompRegistryPath)
        ? projectPath
        : null;
    const projectRoot = resolvedProjectPath ? path.dirname(path.dirname(path.dirname(resolvedProjectPath))) : cwd;
    const activeClaudeProjectPath = projectRoot ? await canonicalClaudeProjectPath(projectRoot) : null;
    const canonicalCwd = cwd ? await canonicalClaudeProjectPath(cwd) : null;
    const settingsDirs = [...new Set([activeClaudeProjectPath, canonicalCwd].filter((d) => !!d))];
    const enabledOverrides = await readClaudeEnabledPlugins(claudeConfigDir, settingsDirs);
    const cacheKey = `${claudeConfigDir}:${ompRegistryPath}:${resolvedProjectPath ?? ""}:${activeClaudeProjectPath ?? ""}:${canonicalCwd ?? ""}:${enabledOverrides.sources.join("|")}`;
    const cached = pluginRootsCache.get(cacheKey);
    if (cached)
        return cached;
    // Cache the in-flight promise so concurrent callers share one computation.
    const pending = loadClaudePluginRoots({
        claudeConfigDir,
        ompRegistryPath,
        resolvedProjectPath,
        activeClaudeProjectPath,
        enabledOverrides,
    });
    pluginRootsCache.set(cacheKey, pending);
    try {
        return await pending;
    }
    catch (error) {
        if (pluginRootsCache.get(cacheKey) === pending)
            pluginRootsCache.delete(cacheKey);
        throw error;
    }
}
async function loadClaudePluginRoots({ claudeConfigDir, ompRegistryPath, resolvedProjectPath, activeClaudeProjectPath, enabledOverrides, }) {
    const roots = [];
    const warnings = [];
    const projectRoots = [];
    const canonicalClaudeProjectPaths = new Map();
    // ── Claude Code registry ──────────────────────────────────────────────────
    const registryPath = path.join(claudeConfigDir, "plugins", "installed_plugins.json");
    const content = await readFile(registryPath);
    if (content) {
        const registry = parseClaudePluginsRegistry(content);
        if (!registry) {
            warnings.push(`Failed to parse Claude Code plugin registry: ${registryPath}`);
        }
        else {
            for (const [pluginId, entries] of Object.entries(registry.plugins)) {
                if (!Array.isArray(entries) || entries.length === 0)
                    continue;
                // Parse plugin ID format: "plugin-name@marketplace"
                const atIndex = pluginId.lastIndexOf("@");
                if (atIndex === -1) {
                    warnings.push(`Invalid plugin ID format (missing @marketplace): ${pluginId}`);
                    continue;
                }
                const pluginName = pluginId.slice(0, atIndex);
                const marketplace = pluginId.slice(atIndex + 1);
                // Process all valid entries, not just the first one.
                // This handles plugins with multiple installs (different scopes/versions).
                for (const entry of entries) {
                    if (!entry.installPath || typeof entry.installPath !== "string") {
                        warnings.push(`Plugin ${pluginId} entry has no installPath`);
                        continue;
                    }
                    if (entry.enabled === false)
                        continue;
                    // Claude Code's own on/off switch: `enabledPlugins` in settings.json /
                    // settings.local.json. `false` hides the plugin here even though it is
                    // installed; `true` opts a project-bound install into this project even
                    // when its recorded projectPath is a different directory.
                    const override = enabledOverrides.enabled.get(pluginId);
                    if (override === false)
                        continue;
                    if ((entry.scope === "local" || entry.scope === "project") && override !== true) {
                        if (!entry.projectPath || !activeClaudeProjectPath)
                            continue;
                        let entryProjectPath = canonicalClaudeProjectPaths.get(entry.projectPath);
                        if (entryProjectPath === undefined) {
                            entryProjectPath = await canonicalClaudeProjectPath(entry.projectPath);
                            canonicalClaudeProjectPaths.set(entry.projectPath, entryProjectPath);
                        }
                        if (entryProjectPath !== activeClaudeProjectPath)
                            continue;
                    }
                    roots.push({
                        id: pluginId,
                        marketplace,
                        plugin: pluginName,
                        version: entry.version || "unknown",
                        path: entry.installPath,
                        scope: entry.scope === "local" ? "project" : entry.scope || "user",
                        origin: "claude",
                    });
                }
            }
        }
    }
    // ── OMP installed plugins registry ───────────────────────────────────────
    // OMP registry is authoritative: its entries replace Claude's entries for the same plugin ID.
    // In production `home` is `os.homedir()`, so `getPluginsDir(home)` resolves to the
    // same XDG-aware path the marketplace writer uses (reads and writes always agree).
    // Tests pass a temp dir, which short-circuits the resolver for deterministic isolation.
    // Computed before the cache lookup because isolated SDK homes select distinct OMP registries.
    const ompContent = await readFile(ompRegistryPath);
    if (ompContent) {
        const ompRegistry = parseClaudePluginsRegistry(ompContent);
        if (ompRegistry) {
            for (const [pluginId, entries] of Object.entries(ompRegistry.plugins)) {
                if (!Array.isArray(entries) || entries.length === 0)
                    continue;
                const atIndex = pluginId.lastIndexOf("@");
                if (atIndex === -1) {
                    warnings.push(`Invalid plugin ID format (missing @marketplace): ${pluginId}`);
                    continue;
                }
                const pluginName = pluginId.slice(0, atIndex);
                const marketplace = pluginId.slice(atIndex + 1);
                // OMP is authoritative: drop all Claude-sourced entries for this plugin ID
                const filtered = roots.filter(r => r.id !== pluginId);
                roots.length = 0;
                roots.push(...filtered);
                for (const entry of entries) {
                    if (!entry.installPath || typeof entry.installPath !== "string") {
                        warnings.push(`Plugin ${pluginId} entry has no installPath`);
                        continue;
                    }
                    if (entry.enabled === false)
                        continue;
                    // Deduplicate by installPath within same ID
                    if (roots.some(r => r.id === pluginId && r.path === entry.installPath))
                        continue;
                    roots.push({
                        id: pluginId,
                        marketplace,
                        plugin: pluginName,
                        version: entry.version || "unknown",
                        path: entry.installPath,
                        scope: entry.scope === "local" ? "project" : entry.scope || "user",
                        origin: "omp",
                    });
                }
            }
        }
        else {
            warnings.push(`Failed to parse OMP plugin registry: ${ompRegistryPath}`);
        }
    }
    // ── Project-scoped OMP registry ────────────────────────────────────────
    // Loaded from the nearest .omp/plugins/installed_plugins.json relative to cwd.
    // Project entries take precedence over user entries for the same plugin ID.
    if (resolvedProjectPath) {
        const projectContent = await readFile(resolvedProjectPath);
        if (projectContent) {
            const projectRegistry = parseClaudePluginsRegistry(projectContent);
            if (projectRegistry) {
                for (const [pluginId, entries] of Object.entries(projectRegistry.plugins)) {
                    if (!Array.isArray(entries) || entries.length === 0)
                        continue;
                    const atIndex = pluginId.lastIndexOf("@");
                    if (atIndex === -1) {
                        warnings.push(`Invalid plugin ID format (missing @marketplace): ${pluginId}`);
                        continue;
                    }
                    const pluginName = pluginId.slice(0, atIndex);
                    const marketplace = pluginId.slice(atIndex + 1);
                    for (const entry of entries) {
                        if (!entry.installPath || typeof entry.installPath !== "string") {
                            warnings.push(`Plugin ${pluginId} entry has no installPath`);
                            continue;
                        }
                        if (entry.enabled === false)
                            continue;
                        projectRoots.push({
                            id: pluginId,
                            marketplace,
                            plugin: pluginName,
                            version: entry.version || "unknown",
                            path: entry.installPath,
                            scope: "project",
                            origin: "omp",
                        });
                    }
                }
            }
            else {
                warnings.push(`Failed to parse project plugin registry: ${resolvedProjectPath}`);
            }
        }
    }
    // Project entries shadow user entries for the same plugin ID.
    if (projectRoots.length > 0) {
        const projectIds = new Set(projectRoots.map(r => r.id));
        const deduped = roots.filter(r => !projectIds.has(r.id));
        roots.length = 0;
        roots.push(...projectRoots, ...deduped);
    }
    // Merge --plugin-dir roots (highest precedence) on every fresh load
    if (injectedPluginDirRoots.length > 0) {
        const injectedIds = new Set(injectedPluginDirRoots.map(r => r.id));
        const filtered = roots.filter(r => !injectedIds.has(r.id));
        roots.length = 0;
        roots.push(...injectedPluginDirRoots, ...filtered);
    }
    // Runs once per cached promise, so each warning is logged once per computation.
    for (const warning of warnings)
        logger.warn(warning);
    return { roots, warnings };
}
/**
 * Clear the plugin roots cache (useful for testing or when plugins change).
 */
export function clearClaudePluginRootsCache() {
    pluginRootsCache.clear();
    for (const invalidate of pluginCacheInvalidators)
        invalidate();
    preloadedPluginRoots = [...injectedPluginDirRoots];
    // Re-warm preloaded roots asynchronously so sync LSP config reads stay valid
    if (lastPreloadHome) {
        void preloadPluginRoots(lastPreloadHome, getProjectDir());
    }
}
/**
 * Invalidate fs caches for installed-plugin registry files and reset the
 * in-memory plugin roots cache. Used by MarketplaceManager clients after
 * installing/uninstalling/enabling/disabling plugins.
 */
export function clearPluginRootsAndCaches(extraPaths) {
    invalidateFsCache(path.join(resolveClaudePaths().configDir, "plugins", "installed_plugins.json"));
    invalidateFsCache(path.join(getPluginsDir(), "installed_plugins.json"));
    for (const p of extraPaths ?? [])
        invalidateFsCache(p);
    clearClaudePluginRootsCache();
}
// ── Preloaded plugin roots (for sync consumers like LSP config) ─────────────
// Populated at startup by preloadPluginRoots(). Read synchronously by
// getPreloadedPluginRoots(). Safe degradation: empty array if not warmed.
let preloadedPluginRoots = [];
let injectedPluginDirRoots = [];
let lastPreloadHome;
/**
 * Populate the module-level plugin roots cache for sync consumers.
 * Call during session initialization, after dir resolution completes
 * but before any LSP config is read.
 */
export async function preloadPluginRoots(home, cwd) {
    lastPreloadHome = home;
    const { roots } = await listClaudePluginRoots(home, cwd);
    preloadedPluginRoots = roots;
}
/**
 * Get pre-loaded plugin roots synchronously.
 * Returns empty array if preloadPluginRoots() hasn't been called.
 */
export function getPreloadedPluginRoots() {
    return preloadedPluginRoots;
}
// ── --plugin-dir injection ──────────────────────────────────────────────────
/**
 * Inject synthetic plugin roots from --plugin-dir paths.
 * These are prepended to the cache with highest precedence (before OMP/Claude entries).
 * Must be called before any listClaudePluginRoots() access.
 */
export async function injectPluginDirRoots(home, dirs, cwd) {
    const injected = [];
    for (const dir of dirs) {
        const resolved = path.resolve(dir);
        // Read plugin name from manifest: Claude marketplace layout first, then
        // the Agent Plugins standard root manifest (agent-plugins.org). Each
        // manifest is resolved and proven inside the plugin directory BEFORE the
        // read (Agent Plugins §4.1) — an escaping symlink falls back to the
        // directory basename without consuming outside content.
        let pluginName = path.basename(resolved);
        const realRoot = await realpathIfExists(resolved);
        if (realRoot !== null) {
            for (const manifestPath of [
                path.join(realRoot, ".claude-plugin", "plugin.json"),
                path.join(realRoot, "plugin.json"),
            ]) {
                const contained = await resolveContainedPath(realRoot, manifestPath);
                if (contained.status !== "ok")
                    continue;
                try {
                    const manifest = await Bun.file(contained.realPath).json();
                    if (typeof manifest?.name === "string" && manifest.name) {
                        pluginName = manifest.name;
                        break;
                    }
                }
                catch {
                    // Invalid manifest — try next, fall back to directory name
                }
            }
        }
        injected.push(buildPluginDirRoot(resolved, pluginName));
    }
    // Set injected roots BEFORE populating cache so listClaudePluginRoots merges them.
    injectedPluginDirRoots = injected;
    lastPreloadHome = home; // ensure cache-clear re-warm fires even when injectPluginDirRoots was the startup path
    // Clear any stale cache entries (populated before injected roots were set).
    pluginRootsCache.clear();
    // Rebuild — cache miss triggers fresh load that includes both user+project registries
    // and prepends injectedPluginDirRoots at highest precedence.
    const { roots } = await listClaudePluginRoots(home, cwd);
    preloadedPluginRoots = roots;
}
