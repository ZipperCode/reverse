/**
 * Bundled Reverse-Engineering Skills Provider
 *
 * The six reverse skills (`reverse-lab`, `reverse-tool-guide`,
 * `android-reverse`, `windows-reverse`, `web-protocol-reverse`,
 * `native-binary-reverse`) also live in
 * the package source tree as `./builtin-skills/<name>/`. The repository-root
 * `.agents/skills/` copies remain for project discovery (and other agent
 * tools), so a fresh clone keeps the existing local behavior.
 *
 * Every skill file is imported with `{ type: "file" }` so Bun embeds it in the
 * compiled binary as well as shipping it through the npm `src` file set. The
 * provider runs at the lowest priority: an authored project/user skill with
 * the same name wins, and identical copies collapse during collision
 * resolution.
 *
 * @see ../extensibility/skills.ts
 */
import { parseFrontmatter } from "@rva/utils";
import { registerProvider } from "../capability";
import { readFile } from "../capability/fs";
import { type Skill, skillCapability } from "../capability/skill";
import type { LoadContext, LoadResult } from "../capability/types";
import { createSourceMeta } from "./helpers";

// SKILL.md entrypoints. Imported as files (not text) so skill:// subpath reads
// resolve against a real directory in both source and compiled installs.
import androidReversePath from "./builtin-skills/android-reverse/SKILL.md" with { type: "file" };
import nativeBinaryReversePath from "./builtin-skills/native-binary-reverse/SKILL.md" with { type: "file" };
import reverseLabPath from "./builtin-skills/reverse-lab/SKILL.md" with { type: "file" };
import reverseToolGuidePath from "./builtin-skills/reverse-tool-guide/SKILL.md" with { type: "file" };
import webProtocolReversePath from "./builtin-skills/web-protocol-reverse/SKILL.md" with { type: "file" };
import windowsReversePath from "./builtin-skills/windows-reverse/SKILL.md" with { type: "file" };

// Reference assets are imported so they are embedded alongside their skill and
// remain readable through `skill://<name>/references/...`.
import androidRef from "./builtin-skills/reverse-lab/references/android.md" with { type: "file" };
import evidenceRef from "./builtin-skills/reverse-lab/references/evidence.md" with { type: "file" };
import targetRoutingRef from "./builtin-skills/reverse-lab/references/target-routing.md" with { type: "file" };
import toolFallbackRef from "./builtin-skills/reverse-lab/references/tool-fallback.md" with { type: "file" };
import webProtocolRef from "./builtin-skills/reverse-lab/references/web-protocol.md" with { type: "file" };
import windowsRef from "./builtin-skills/reverse-lab/references/windows.md" with { type: "file" };
import cliToolsRef from "./builtin-skills/reverse-tool-guide/references/cli-tools.md" with { type: "file" };
import mcpServicesRef from "./builtin-skills/reverse-tool-guide/references/mcp-services.md" with { type: "file" };

const PROVIDER_ID = "builtin-skills";
const DISPLAY_NAME = "Bundled Reverse Skills";
const DESCRIPTION = "Reverse-engineering skills shipped with the agent";
// Below every authored/user provider so project and user skills win collisions.
const PRIORITY = 1;

/** Instruction files for every bundled skill, in stable name order. */
export const BUILTIN_SKILL_SOURCES: readonly { name: string; path: string }[] = [
	{ name: "android-reverse", path: androidReversePath },
	{ name: "native-binary-reverse", path: nativeBinaryReversePath },
	{ name: "reverse-lab", path: reverseLabPath },
	{ name: "reverse-tool-guide", path: reverseToolGuidePath },
	{ name: "web-protocol-reverse", path: webProtocolReversePath },
	{ name: "windows-reverse", path: windowsReversePath },
];

/** Reference assets embedded with the bundled skills (exposed for packaging tests). */
export const BUILTIN_SKILL_REFERENCES: readonly string[] = [
	androidRef,
	evidenceRef,
	targetRoutingRef,
	toolFallbackRef,
	webProtocolRef,
	windowsRef,
	cliToolsRef,
	mcpServicesRef,
];

async function loadSkills(_ctx: LoadContext): Promise<LoadResult<Skill>> {
	const items: Skill[] = [];
	const warnings: string[] = [];

	for (const source of BUILTIN_SKILL_SOURCES) {
		const content = await readFile(source.path);
		if (!content) {
			warnings.push(`Bundled skill file is unreadable: ${source.path}`);
			continue;
		}
		const { frontmatter, body } = parseFrontmatter(content, { source: source.path });
		if (frontmatter.enabled === false) continue;
		const name =
			typeof frontmatter.name === "string" && frontmatter.name.trim() ? frontmatter.name.trim() : source.name;
		items.push({
			name,
			path: source.path,
			content: body,
			frontmatter: frontmatter as Skill["frontmatter"],
			level: "user",
			_source: createSourceMeta(PROVIDER_ID, source.path, "user"),
		});
	}

	return { items, warnings };
}

registerProvider<Skill>(skillCapability.id, {
	id: PROVIDER_ID,
	displayName: DISPLAY_NAME,
	description: DESCRIPTION,
	priority: PRIORITY,
	load: loadSkills,
});

export { PROVIDER_ID as BUILTIN_SKILLS_PROVIDER_ID };
