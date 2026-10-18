import * as path from "node:path";
/**
 * Recursively substitute ${CLAUDE_PLUGIN_ROOT} and ${RVA_PLUGIN_ROOT}
 * with the actual plugin root path in strings, arrays, and plain objects.
 */
// Use concatenation to avoid noTemplateCurlyInString lint rule on literal placeholder names
const CLAUDE_VAR = "$" + "{CLAUDE_PLUGIN_ROOT}";
const RVA_VAR = "$" + "{RVA_PLUGIN_ROOT}";
export function substitutePluginRoot(value, rootPath) {
    if (typeof value === "string") {
        return value
            .replaceAll(CLAUDE_VAR, rootPath)
            .replaceAll(RVA_VAR, rootPath);
    }
    if (Array.isArray(value)) {
        return value.map(v => substitutePluginRoot(v, rootPath));
    }
    if (value && typeof value === "object") {
        const result = Object.create(null);
        for (const [k, v] of Object.entries(value)) {
            Object.defineProperty(result, k, {
                value: substitutePluginRoot(v, rootPath),
                enumerable: true,
                writable: true,
                configurable: true,
            });
        }
        return result;
    }
    return value;
}
/**
 * Rebase relative filesystem values in a discovered stdio server config against
 * the directory of the config file (`.mcp.json`/`config.toml`) that declared them.
 *
 * External configs (bundled ChatGPT/Codex plugins, Claude marketplace plugins)
 * express `command`/`cwd` relative to their own config file, but MCP stdio
 * spawning roots relative values at the session cwd — so a server shipping
 * `command: "./bin/server"`, `cwd: "."` launches from the wrong directory and
 * fails with ENOENT. This resolves those against `configDir` instead:
 *
 * - relative `cwd` → resolved against `configDir`;
 * - path-like `command` (`./`, `../`, or the Windows `.\`/`..\` forms) →
 *   resolved against the base selected by `commandBase` (see {@link StdioCommandBase});
 * - bare executables (`npx`, `uvx`, …) and absolute paths are left untouched.
 */
export function resolvePluginStdioPaths(config, configDir, commandBase = "config-dir") {
    const resolved = {};
    if (typeof config.cwd === "string") {
        resolved.cwd = path.isAbsolute(config.cwd) ? config.cwd : path.resolve(configDir, config.cwd);
    }
    if (config.command !== undefined) {
        const isPathLike = /^\.\.?[/\\]/.test(config.command);
        const base = commandBase === "cwd" ? (resolved.cwd ?? configDir) : configDir;
        resolved.command = isPathLike ? path.resolve(base, config.command) : config.command;
    }
    return resolved;
}
