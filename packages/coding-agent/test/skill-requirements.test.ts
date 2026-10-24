import { describe, expect, it } from "bun:test";
import { WhichCachePolicy, type WhichOptions } from "@reverse/utils";
import { validateAgentSkillFrontmatter } from "@reverse/coding-agent/discovery/agent-plugin-format";
import {
	checkToolRequirements,
	missingRequirementNotice,
	readSkillRequirements,
	type SkillRequirementWhich,
} from "@reverse/coding-agent/extensibility/skill-requirements";
import { SKILL_TOOL_CATALOG } from "@reverse/coding-agent/extensibility/skill-tool-catalog";

function whichFrom(found: Readonly<Record<string, string | null>>): SkillRequirementWhich {
	return command => found[command] ?? null;
}

describe("readSkillRequirements", () => {
	it("reads portable metadata.requires and metadata.requiresOptional", () => {
		const requirements = readSkillRequirements({
			metadata: { requires: "jadx, apktool", requiresOptional: ["frida"] },
		});
		expect(requirements).toEqual([{ id: "jadx" }, { id: "apktool" }, { id: "frida", optional: true }]);
	});

	it("accepts top-level keys for rev-local skills and dedupes case-insensitively", () => {
		const requirements = readSkillRequirements({
			requires: "jadx Jadx ../escape",
			requiresOptional: "jadx, frida",
		});
		expect(requirements).toEqual([{ id: "jadx" }, { id: "frida", optional: true }]);
	});

	it("drops malformed ids instead of turning them into lookups", () => {
		expect(readSkillRequirements({ metadata: { requires: "bad/id, ok.tool-1, ../escape, -nope" } })).toEqual([
			{ id: "ok.tool-1" },
		]);
	});

	it("keeps Agent Plugins frontmatter valid and still reads its metadata", () => {
		const frontmatter = {
			name: "reverse-lab",
			description: "Orchestrator.",
			metadata: { requires: "jadx, adb", requiresOptional: "frida" },
		};
		// The Agent Skills schema is closed; using `metadata` keeps the skill valid.
		expect(validateAgentSkillFrontmatter(frontmatter, "reverse-lab")).toBeNull();
		expect(readSkillRequirements(frontmatter)).toEqual([
			{ id: "jadx" },
			{ id: "adb" },
			{ id: "frida", optional: true },
		]);
	});

	it("returns no requirements for missing or non-object metadata", () => {
		expect(readSkillRequirements(undefined)).toEqual([]);
		expect(readSkillRequirements({ metadata: "jadx" })).toEqual([]);
	});
});

describe("checkToolRequirements", () => {
	it("is silent when every required tool and secondary binary is present", () => {
		const statuses = checkToolRequirements([{ id: "jadx" }], {
			platform: "linux",
			which: whichFrom({ jadx: "/usr/bin/jadx", java: "/usr/bin/java" }),
		});
		expect(statuses[0]).toMatchObject({ id: "jadx", foundPath: "/usr/bin/jadx" });
		expect(missingRequirementNotice(statuses)).toBeUndefined();
	});

	it("defaults to the host platform when no platform is injected", () => {
		const statuses = checkToolRequirements([{ id: "jadx" }], { which: whichFrom({}) });
		const expected =
			process.platform === "darwin"
				? "brew install jadx"
				: process.platform === "win32"
					? "choco install jadx"
					: "apt install jadx";
		expect(statuses[0].hint).toBe(expected);
	});

	it("reports a missing required tool with its catalog install hint", () => {
		const statuses = checkToolRequirements([{ id: "jadx" }], {
			platform: "darwin",
			which: whichFrom({ java: "/usr/bin/java" }),
		});
		expect(statuses[0].foundPath).toBeNull();
		expect(statuses[0].hint).toContain("brew install jadx");
		const notice = missingRequirementNotice(statuses);
		expect(notice).toContain("jadx");
		expect(notice).toContain("brew install jadx");
	});

	it("stays silent when only optional tools are missing", () => {
		const statuses = checkToolRequirements([{ id: "frida", optional: true }], {
			platform: "linux",
			which: whichFrom({}),
		});
		expect(statuses[0]).toMatchObject({ id: "frida", optional: true, foundPath: null });
		expect(missingRequirementNotice(statuses)).toBeUndefined();
	});

	it("probes unknown ids without inventing an install hint", () => {
		const statuses = checkToolRequirements([{ id: "reverse-unknown-fixture" }], {
			platform: "linux",
			which: whichFrom({}),
		});
		expect(statuses[0]).toMatchObject({ unknown: true });
		expect(statuses[0].hint).toBeUndefined();
		const notice = missingRequirementNotice(statuses);
		expect(notice).toContain("reverse-unknown-fixture");
		expect(notice).not.toContain("brew");
		expect(notice).not.toContain("apt");
		expect(notice).not.toContain("choco");
	});

	it("never probes or renders malformed ids passed directly", () => {
		let probes = 0;
		const statuses = checkToolRequirements([{ id: "../escape" }], {
			which: () => {
				probes++;
				return "/tmp/escape";
			},
		});
		expect(probes).toBe(0);
		expect(statuses[0]).toMatchObject({ invalid: true, unknown: true, foundPath: null });
		expect(missingRequirementNotice(statuses)).toBeUndefined();
	});

	it("reports a missing catalog secondary binary", () => {
		const statuses = checkToolRequirements([{ id: "jadx" }], {
			platform: "linux",
			which: whichFrom({ jadx: "/usr/bin/jadx" }),
		});
		expect(statuses[0].secondaryMissing).toEqual(["java"]);
		const notice = missingRequirementNotice(statuses);
		expect(notice).toContain("java");
	});

	it("treats droidasc as a catalogued tool with trusted installation hints", () => {
		const missing = checkToolRequirements([{ id: "droidasc" }], {
			platform: "linux",
			which: whichFrom({}),
		});
		expect(missing[0]).toMatchObject({ id: "droidasc", foundPath: null });
		expect(missing[0].unknown).toBeUndefined();
		expect(missing[0].hint).toContain("pipx install droidasc");
		expect(missing[0].hint).toContain("python -m pip install droidasc");
		const notice = missingRequirementNotice(missing);
		expect(notice).toContain("droidasc");
		expect(notice).toContain("pipx install droidasc");

		const found = checkToolRequirements([{ id: "droidasc" }], {
			platform: "linux",
			which: whichFrom({ droidasc: "/usr/local/bin/droidasc" }),
		});
		expect(found[0]).toMatchObject({ foundPath: "/usr/local/bin/droidasc" });
		expect(found[0].hint).toBeUndefined();
		expect(missingRequirementNotice(found)).toBeUndefined();
	});

	it("delegates IDA detection to the install probe", () => {
		expect(typeof SKILL_TOOL_CATALOG.ida?.probe).toBe("function");
	});

	it("adds catalog-owned platform directories and still requires absolute lookups", () => {
		let seen: WhichOptions | undefined;
		const which: SkillRequirementWhich = (command, options) => {
			seen = options;
			return command === "adb" ? "C:\\sdk\\platform-tools\\adb.exe" : null;
		};
		checkToolRequirements([{ id: "adb" }], {
			platform: "win32",
			env: {
				PATH: "C:\\Windows",
				LOCALAPPDATA: "C:\\Users\\fixture\\AppData\\Local",
				ProgramFiles: "C:\\Program Files",
			},
			which,
		});
		expect(seen?.cache).toBe(WhichCachePolicy.Bypass);
		expect(seen?.requireAbsolutePaths).toBe(true);
		expect(seen?.PATH).toContain("C:\\Windows");
		expect(seen?.PATH).toContain("C:\\Users\\fixture\\AppData\\Local");
		expect(seen?.PATH).toContain("platform-tools");
	});

	it("does not report cargo_auditable, tshark, readelf, or vbindiff when only fallback programs exist on PATH", () => {
		const which = whichFrom({
			rustc: "/usr/bin/rustc",
			tcpdump: "/usr/sbin/tcpdump",
			objdump: "/usr/bin/objdump",
			radiff2: "/usr/bin/radiff2",
		});
		const statuses = checkToolRequirements(
			[{ id: "cargo_auditable" }, { id: "tshark" }, { id: "readelf" }, { id: "vbindiff" }],
			{ which, platform: "linux" },
		);
		expect(statuses.map(s => s.foundPath)).toEqual([null, null, null, null]);

		// Legitimate alternatives still work
		const readelfGnu = checkToolRequirements([{ id: "readelf" }], {
			which: whichFrom({ greadelf: "/opt/homebrew/bin/greadelf" }),
			platform: "darwin",
		});
		expect(readelfGnu[0].foundPath).toBe("/opt/homebrew/bin/greadelf");

		const readelfLlvm = checkToolRequirements([{ id: "readelf" }], {
			which: whichFrom({ "llvm-readelf": "/usr/bin/llvm-readelf" }),
			platform: "linux",
		});
		expect(readelfLlvm[0].foundPath).toBe("/usr/bin/llvm-readelf");

		const tsharkValid = checkToolRequirements([{ id: "tshark" }], {
			which: whichFrom({ tshark: "/usr/bin/tshark" }),
			platform: "linux",
		});
		expect(tsharkValid[0].foundPath).toBe("/usr/bin/tshark");

		const cargoAuditableValid = checkToolRequirements([{ id: "cargo_auditable" }], {
			which: whichFrom({ "cargo-auditable": "/home/user/.cargo/bin/cargo-auditable" }),
			platform: "linux",
		});
		expect(cargoAuditableValid[0].foundPath).toBe("/home/user/.cargo/bin/cargo-auditable");

		const vbindiffValid = checkToolRequirements([{ id: "vbindiff" }], {
			which: whichFrom({ vbindiff: "/usr/bin/vbindiff" }),
			platform: "linux",
		});
		expect(vbindiffValid[0].foundPath).toBe("/usr/bin/vbindiff");
	});
});
