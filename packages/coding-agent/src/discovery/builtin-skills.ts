/**
 * Bundled Reverse-Engineering Skills Provider
 *
 * The seven reverse skills (`reverse-lab`, `reverse-tool-guide`,
 * `android-reverse`, `windows-reverse`, `web-protocol-reverse`,
 * `native-binary-reverse`, `vmp-reverse`) also live in
 * the package source tree as `./builtin-skills/<name>/`. The repository-root
 * `.agents/skills/` entries are directory symlinks to these canonical directories,
 * ensuring a single source of truth for both project discovery and bundled
 * distribution while compiled binaries embed the canonical assets.
 * Every skill file is imported with `{ type: "file" }` so Bun embeds it in the
 * compiled binary as well as shipping it through the npm `src` file set. The
 * provider runs at the lowest priority: an authored project/user skill with
 * the same name wins, and identical copies collapse during collision
 * resolution.
 *
 * @see ../extensibility/skills.ts
 */
import * as path from "node:path";
import { parseFrontmatter } from "@reverse/utils";
import { registerProvider } from "../capability";
import { readFile } from "../capability/fs";
import { type Skill, skillCapability } from "../capability/skill";
import type { LoadContext, LoadResult } from "../capability/types";
import { createSourceMeta } from "./helpers";

// Raw SKILL.md and reference entrypoints.
import androidReversePathRaw from "./builtin-skills/android-reverse/SKILL.md" with { type: "file" };
import nativeBinaryReversePathRaw from "./builtin-skills/native-binary-reverse/SKILL.md" with { type: "file" };
import reverseLabPathRaw from "./builtin-skills/reverse-lab/SKILL.md" with { type: "file" };
import reverseToolGuidePathRaw from "./builtin-skills/reverse-tool-guide/SKILL.md" with { type: "file" };
import webProtocolReversePathRaw from "./builtin-skills/web-protocol-reverse/SKILL.md" with { type: "file" };
import windowsReversePathRaw from "./builtin-skills/windows-reverse/SKILL.md" with { type: "file" };
import vmpReversePathRaw from "./builtin-skills/vmp-reverse/SKILL.md" with { type: "file" };

import androidRefRaw from "./builtin-skills/reverse-lab/references/android.md" with { type: "file" };
import evidenceRefRaw from "./builtin-skills/reverse-lab/references/evidence.md" with { type: "file" };
import targetRoutingRefRaw from "./builtin-skills/reverse-lab/references/target-routing.md" with { type: "file" };
import toolFallbackRefRaw from "./builtin-skills/reverse-lab/references/tool-fallback.md" with { type: "file" };
import webProtocolRefRaw from "./builtin-skills/reverse-lab/references/web-protocol.md" with { type: "file" };
import windowsRefRaw from "./builtin-skills/reverse-lab/references/windows.md" with { type: "file" };
import cliToolsRefRaw from "./builtin-skills/reverse-tool-guide/references/cli-tools.md" with { type: "file" };
import mcpServicesRefRaw from "./builtin-skills/reverse-tool-guide/references/mcp-services.md" with { type: "file" };
import vmpDevirtBackendsRefRaw from "./builtin-skills/vmp-reverse/references/devirt-backends.md" with { type: "file" };
import vmpTraceFormatRefRaw from "./builtin-skills/vmp-reverse/references/vmp-trace-format.md" with { type: "file" };
import vmpDiffVerificationRefRaw from "./builtin-skills/vmp-reverse/references/differential-verification.md" with { type: "file" };

function normalizeAssetPath(assetPath: string, moduleDir: string = import.meta.dir): string {
	if (path.isAbsolute(assetPath) || path.win32.isAbsolute(assetPath)) return assetPath;
	return path.resolve(moduleDir, assetPath);
}

const androidReversePath = normalizeAssetPath(androidReversePathRaw);
const nativeBinaryReversePath = normalizeAssetPath(nativeBinaryReversePathRaw);
const reverseLabPath = normalizeAssetPath(reverseLabPathRaw);
const reverseToolGuidePath = normalizeAssetPath(reverseToolGuidePathRaw);
const webProtocolReversePath = normalizeAssetPath(webProtocolReversePathRaw);
const windowsReversePath = normalizeAssetPath(windowsReversePathRaw);
const vmpReversePath = normalizeAssetPath(vmpReversePathRaw);

const androidRef = normalizeAssetPath(androidRefRaw);
const evidenceRef = normalizeAssetPath(evidenceRefRaw);
const targetRoutingRef = normalizeAssetPath(targetRoutingRefRaw);
const toolFallbackRef = normalizeAssetPath(toolFallbackRefRaw);
const webProtocolRef = normalizeAssetPath(webProtocolRefRaw);
const windowsRef = normalizeAssetPath(windowsRefRaw);
const cliToolsRef = normalizeAssetPath(cliToolsRefRaw);
const mcpServicesRef = normalizeAssetPath(mcpServicesRefRaw);
const vmpDevirtBackendsRef = normalizeAssetPath(vmpDevirtBackendsRefRaw);
const vmpTraceFormatRef = normalizeAssetPath(vmpTraceFormatRefRaw);
const vmpDiffVerificationRef = normalizeAssetPath(vmpDiffVerificationRefRaw);
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
	{ name: "vmp-reverse", path: vmpReversePath },
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
	vmpDevirtBackendsRef,
	vmpTraceFormatRef,
	vmpDiffVerificationRef,
];

/** Logical reference map mapping each skill and subpath to its concrete embedded/file path. */
export const BUILTIN_SKILL_LOGICAL_FILES: Record<string, Record<string, string>> = {
	"android-reverse": {
		"SKILL.md": androidReversePath,
	},
	"native-binary-reverse": {
		"SKILL.md": nativeBinaryReversePath,
	},
	"reverse-lab": {
		"SKILL.md": reverseLabPath,
		"references/android.md": androidRef,
		"references/evidence.md": evidenceRef,
		"references/target-routing.md": targetRoutingRef,
		"references/tool-fallback.md": toolFallbackRef,
		"references/web-protocol.md": webProtocolRef,
		"references/windows.md": windowsRef,
	},
	"reverse-tool-guide": {
		"SKILL.md": reverseToolGuidePath,
		"references/cli-tools.md": cliToolsRef,
		"references/mcp-services.md": mcpServicesRef,
	},
	"web-protocol-reverse": {
		"SKILL.md": webProtocolReversePath,
	},
	"windows-reverse": {
		"SKILL.md": windowsReversePath,
	},
	"vmp-reverse": {
		"SKILL.md": vmpReversePath,
		"references/devirt-backends.md": vmpDevirtBackendsRef,
		"references/vmp-trace-format.md": vmpTraceFormatRef,
		"references/differential-verification.md": vmpDiffVerificationRef,
	},
};

export function isBuiltinSkill(skill: { name: string; source?: string; _source?: { provider?: string } }): boolean {
	return (
		skill._source?.provider === PROVIDER_ID ||
		Boolean(skill.source && (skill.source === PROVIDER_ID || skill.source.startsWith(`${PROVIDER_ID}:`)))
	);
}

export function canonicalBuiltinSkillName(skill: {
	name: string;
	source?: string;
	_source?: { provider?: string };
}): string | undefined {
	if (!isBuiltinSkill(skill)) return undefined;
	const raw = skill.name.includes("/") ? skill.name.slice(skill.name.lastIndexOf("/") + 1) : skill.name;
	const base = raw.replace(/~\d+$/, "");
	return Object.hasOwn(BUILTIN_SKILL_LOGICAL_FILES, base) ? base : undefined;
}

export function resolveBuiltinSkillTarget(
	skill: { name: string; source?: string; _source?: { provider?: string } },
	subpath: string,
): string | undefined {
	const canonical = canonicalBuiltinSkillName(skill);
	if (!canonical) return undefined;
	const files = BUILTIN_SKILL_LOGICAL_FILES[canonical];
	if (!files) return undefined;
	const normalized = subpath.replace(/\\/g, "/").replace(/^\/+/, "");
	const key = normalized === "" ? "SKILL.md" : normalized;
	return Object.hasOwn(files, key) ? files[key] : undefined;
}

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
