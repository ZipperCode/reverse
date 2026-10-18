/**
 * AGENTS.md Provider
 *
 * Discovers standalone AGENTS.md files by walking up from cwd.
 * This handles AGENTS.md files that live in project root (not in config directories
 * like .codex/ or .gemini/, which are handled by their respective providers).
 */
import { registerProvider } from "../capability";
import { contextFileCapability } from "../capability/context-file";
import { loadStandaloneContextFiles } from "./helpers";
const PROVIDER_ID = "agents-md";
const DISPLAY_NAME = "AGENTS.md";
/**
 * Load standalone AGENTS.md files by walking up from cwd
 * (see {@link loadStandaloneContextFiles}).
 */
export async function loadAgentsMd(ctx) {
    return loadStandaloneContextFiles(ctx, PROVIDER_ID, "AGENTS.md");
}
registerProvider(contextFileCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Standalone AGENTS.md files (Codex/Gemini style)",
    priority: 10,
    load: loadAgentsMd,
});
