import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getConfigDirPaths } from "../config";
import { getPreloadedPluginRoots } from "../discovery/helpers";
/**
 * Read one JSON/YAML config file through `adapt`. Reading, parsing and rejecting
 * all happen inside one guard so an unreadable, malformed, or irrelevant file is
 * skipped instead of thrown. `adapt` receives the raw content because the YAML/JSON
 * split lives with the config files that consume this walk, not here.
 */
export function readConfigFile(filePath, adapt) {
    try {
        const content = fs.readFileSync(filePath, "utf-8");
        return adapt(content, filePath);
    }
    catch {
        return null;
    }
}
/**
 * Config sources for base name `base` — `"lsp"` covers `lsp.json`/`.lsp.json`/`lsp.yaml`/`.lsp.yaml`/
 * `lsp.yml`/`.lsp.yml` — in priority order: cwd files, project config dirs, user config dirs,
 * plugin roots (plus {@link ConfigFileSourcesOptions.pluginRootSource} per root), then home-directory
 * files. Lowest priority comes last, so callers merge over a reversed list.
 */
export function configFileSources(base, cwd, adapt, options = {}) {
    const filenames = [`${base}.json`, `.${base}.json`, `${base}.yaml`, `.${base}.yaml`, `${base}.yml`, `.${base}.yml`];
    const sources = [];
    const addDir = (dir) => {
        for (const filename of filenames) {
            sources.push({ read: () => readConfigFile(path.join(dir, filename), adapt) });
        }
    };
    addDir(cwd);
    for (const dir of getConfigDirPaths("", { user: false, project: true, cwd }))
        addDir(dir);
    for (const dir of getConfigDirPaths("", { user: true, project: false }))
        addDir(dir);
    for (const root of getPreloadedPluginRoots()) {
        addDir(root.path);
        const extra = options.pluginRootSource?.(root);
        if (extra)
            sources.push(extra);
    }
    addDir(os.homedir());
    return sources;
}
