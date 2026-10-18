import * as os from "node:os";
import * as path from "node:path";
/** Resolves Claude Code's user paths, honoring `CLAUDE_CONFIG_DIR`. */
export function resolveClaudePaths(home = os.homedir()) {
    const override = process.env.CLAUDE_CONFIG_DIR?.trim();
    if (override) {
        const configDir = path.resolve(override);
        return { configDir, configFile: path.join(configDir, ".claude.json") };
    }
    return { configDir: path.join(home, ".claude"), configFile: path.join(home, ".claude.json") };
}
