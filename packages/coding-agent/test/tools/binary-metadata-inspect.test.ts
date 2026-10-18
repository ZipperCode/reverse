import { describe, expect, it } from "bun:test";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import * as zlib from "node:zlib";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	BinaryMetadataInspectTool,
	inspectGoBuildInfo,
	inspectRustAuditInfo,
	type BinaryMetadataInspectDetails,
	type ToolSession,
} from "@rva/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@rva/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@rva/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

/** Builds synthetic Go binary buffer with buildinfo header and module table. */
function createSyntheticGoBinary(options: {
	runtimeVersion?: string;
	modulePath?: string;
	cgoEnabled?: string;
	vcsRevision?: string;
	dependencies?: Array<{ path: string; version: string; sum: string }>;
} = {}): Buffer {
	const chunks: Buffer[] = [];

	// Minimal ELF header (x86_64, little endian)
	const elfHeader = Buffer.alloc(64, 0);
	elfHeader[0] = 0x7f;
	elfHeader[1] = 0x45;
	elfHeader[2] = 0x4c;
	elfHeader[3] = 0x46;
	elfHeader[4] = 2; // 64-bit
	elfHeader[5] = 1; // little-endian
	elfHeader[6] = 1; // version
	elfHeader.writeUInt16LE(2, 16); // ET_EXEC
	elfHeader.writeUInt16LE(62, 18); // x86_64
	chunks.push(elfHeader);

	// Pclntab magic (Go 1.20+)
	chunks.push(Buffer.from([0xf2, 0xff, 0xff, 0xff]));

	// Go buildinfo header: \xff Go buildinf:\x08\x00
	const goBuildinfMagic = Buffer.from("\xff Go buildinf:\x08\x00");
	chunks.push(goBuildinfMagic);

	// Version string
	const versionStr = options.runtimeVersion ?? "go1.22.4";
	chunks.push(Buffer.from(`\x00${versionStr}\x00`));

	// Module table
	const modLines: string[] = [];
	modLines.push(`path\t${options.modulePath ?? "github.com/example/sampleapp"}`);
	modLines.push(`mod\t${options.modulePath ?? "github.com/example/sampleapp"}\tv0.1.0\th1:abc`);
	if (options.dependencies) {
		for (const dep of options.dependencies) {
			modLines.push(`dep\t${dep.path}\t${dep.version}\t${dep.sum}`);
		}
	} else {
		modLines.push("dep\tgithub.com/stretchr/testify\tv1.9.0\th1:testifysum123");
		modLines.push("dep\tgolang.org/x/crypto\tv0.21.0\th1:cryptosum456");
	}
	modLines.push(`build\tCGO_ENABLED=${options.cgoEnabled ?? "0"}`);
	modLines.push("build\tGOARCH=amd64");
	modLines.push("build\tGOOS=linux");
	modLines.push(`build\tvcs.revision=${options.vcsRevision ?? "abcdef0123456789"}`);
	modLines.push("build\t-compiler=gc");

	chunks.push(Buffer.from(`\n${modLines.join("\n")}\n\x00`));

	// Runtime symbol markers
	chunks.push(Buffer.from("runtime.main\x00runtime.goexit\x00"));

	return Buffer.concat(chunks);
}

/** Builds synthetic Rust ELF binary with .dep-v0 section and rustc strings. */
function createSyntheticRustBinary(options: {
	rustcVersion?: string;
	rustcCommit?: string;
	packages?: Array<{ name: string; version: string; source?: string }>;
} = {}): Buffer {
	const chunks: Buffer[] = [];

	// Minimal ELF header with 1 section header entry pointing to .dep-v0
	const elfHeader = Buffer.alloc(64, 0);
	elfHeader[0] = 0x7f;
	elfHeader[1] = 0x45;
	elfHeader[2] = 0x4c;
	elfHeader[3] = 0x46;
	elfHeader[4] = 2; // 64-bit
	elfHeader[5] = 1; // little-endian
	elfHeader.writeUInt16LE(2, 16); // ET_EXEC
	elfHeader.writeUInt16LE(62, 18); // x86_64
	chunks.push(elfHeader);

	// Rust strings & commit hash
	const commit = options.rustcCommit ?? "129f3b9964af4d4a709d1383930dea12a7c08291";
	const version = options.rustcVersion ?? "1.77.2";
	chunks.push(Buffer.from(`/rustc/${commit}/library/std/src/panicking.rs\x00`));
	chunks.push(Buffer.from(`rustc ${version} (commit ${commit.slice(0, 9)})\x00`));
	chunks.push(Buffer.from("rust_eh_personality\x00panic_unwind\x00tokio::runtime\x00serde::de\x00"));

	// Prepare cargo-auditable .dep-v0 payload:
	// 0x01 followed by zlib-compressed JSON
	const pkgList = options.packages ?? [
		{ name: "sample-rust-cli", version: "0.2.0", source: "root" },
		{ name: "serde", version: "1.0.197", source: "registry+https://github.com/rust-lang/crates.io-index" },
		{ name: "tokio", version: "1.37.0", source: "registry+https://github.com/rust-lang/crates.io-index" },
	];
	const auditableJson = JSON.stringify({ packages: pkgList });
	const compressed = zlib.deflateSync(Buffer.from(auditableJson, "utf8"));
	const depPayload = Buffer.concat([Buffer.from([0x01]), compressed]);

	chunks.push(depPayload);

	return Buffer.concat(chunks);
}

// ============================================================================
// Registration and Discovery
// ============================================================================

describe("binary_metadata_inspect registration and discovery", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes aliases", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("binary_metadata_inspect");
		expect(normalizeToolName("binary_metadata_inspect")).toBe("binary_metadata_inspect");
		expect(normalizeToolName("binary_metadata")).toBe("binary_metadata_inspect");
		expect(normalizeToolName("go_metadata")).toBe("binary_metadata_inspect");
		expect(normalizeToolName("rust_metadata")).toBe("binary_metadata_inspect");
		expect(normalizeToolName("metadata_inspect")).toBe("binary_metadata_inspect");
	});

	it("creates tool instance with discoverable loadMode and read approval", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "bin-meta-disc-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["binary_metadata_inspect"]);
			const tool = tools.find(t => t.name === "binary_metadata_inspect") as
				| BinaryMetadataInspectTool
				| undefined;
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("binary_metadata_inspect");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
			expect(tool?.label).toBe("Binary Metadata Inspect (Go/Rust)");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Path Validation and Error Handling
// ============================================================================

describe("binary_metadata_inspect path validation", () => {
	it("rejects non-existent file with descriptive error", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "bin-meta-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryMetadataInspectTool(session);
			await expect(
				tool.execute({ action: "info", path: "nonexistent_binary.exe" }),
			).rejects.toThrow("File not found");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "bin-meta-dir-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryMetadataInspectTool(session);
			await expect(tool.execute({ action: "info", path: "." })).rejects.toThrow(
				"Path is a directory",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Go Metadata Inspection
// ============================================================================

describe("binary_metadata_inspect Go metadata inspection", () => {
	it("extracts Go build info, runtime version, and dependencies", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "bin-meta-go-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryMetadataInspectTool(session);

			const goBuf = createSyntheticGoBinary({
				runtimeVersion: "go1.22.4",
				modulePath: "github.com/example/orderservice",
				cgoEnabled: "0",
				vcsRevision: "1a2b3c4d5e6f",
			});
			const samplePath = path.join(tempDir, "orderservice");
			await fs.writeFile(samplePath, goBuf);

			// 1. Info action
			const infoResult = await tool.execute({ action: "info", path: "orderservice" });
			expect(infoResult.details.language).toBe("go");
			expect(infoResult.details.isGo).toBe(true);
			expect(infoResult.details.go?.runtimeVersion).toBe("go1.22.4");
			expect(infoResult.details.go?.modulePath).toBe("github.com/example/orderservice");
			expect(infoResult.details.go?.buildSettings["CGO_ENABLED"]).toBe("0");
			expect(infoResult.details.go?.buildSettings["vcs.revision"]).toBe("1a2b3c4d5e6f");
			expect(infoResult.details.go?.totalDependencies).toBeGreaterThanOrEqual(2);

			const infoText = textOf(infoResult);
			expect(infoText).toContain("orderservice");
			expect(infoText).toContain("go1.22.4");
			expect(infoText).toContain("github.com/example/orderservice");

			// 2. Go action
			const goResult = await tool.execute({ action: "go", path: "orderservice" });
			expect(goResult.details.action).toBe("go");
			expect(goResult.details.isGo).toBe(true);
			expect(goResult.details.go?.dependencies.length).toBeGreaterThanOrEqual(2);

			const goText = textOf(goResult);
			expect(goText).toContain("github.com/stretchr/testify");
			expect(goText).toContain("golang.org/x/crypto");
			expect(goText).toContain("CGO_ENABLED");

			// 3. Filter test
			const filterResult = await tool.execute({
				action: "go",
				path: "orderservice",
				filter: "crypto",
			});
			expect(filterResult.details.go?.dependencies.length).toBe(1);
			expect(filterResult.details.go?.dependencies[0].path).toBe("golang.org/x/crypto");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("handles pagination for Go dependencies", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "bin-meta-gopage-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryMetadataInspectTool(session);

			const deps = [
				{ path: "example.com/dep1", version: "v1.0.0", sum: "h1:1" },
				{ path: "example.com/dep2", version: "v1.0.0", sum: "h1:2" },
				{ path: "example.com/dep3", version: "v1.0.0", sum: "h1:3" },
				{ path: "example.com/dep4", version: "v1.0.0", sum: "h1:4" },
			];
			const goBuf = createSyntheticGoBinary({ dependencies: deps });
			await fs.writeFile(path.join(tempDir, "app"), goBuf);

			const pagedResult = await tool.execute({
				action: "go",
				path: "app",
				limit: 2,
				offset: 2,
			});
			expect(pagedResult.details.go?.dependencies.length).toBe(2);
			expect(pagedResult.details.go?.dependencies[0].path).toBe("example.com/dep3");
			expect(pagedResult.details.go?.dependencies[1].path).toBe("example.com/dep4");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Rust Metadata Inspection
// ============================================================================

describe("binary_metadata_inspect Rust metadata inspection", () => {
	it("extracts cargo-auditable dependency packages and rustc version", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "bin-meta-rust-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryMetadataInspectTool(session);

			const rustBuf = createSyntheticRustBinary({
				rustcVersion: "1.77.2",
				rustcCommit: "129f3b9964af4d4a709d1383930dea12a7c08291",
			});
			const samplePath = path.join(tempDir, "cli_rust");
			await fs.writeFile(samplePath, rustBuf);

			// 1. Info action
			const infoResult = await tool.execute({ action: "info", path: "cli_rust" });
			expect(infoResult.details.language).toBe("rust");
			expect(infoResult.details.isRust).toBe(true);
			expect(infoResult.details.rust?.cargoAuditable).toBe(true);
			expect(infoResult.details.rust?.rustcVersion).toBe("1.77.2");
			expect(infoResult.details.rust?.rustcCommit).toBe("129f3b9964af4d4a709d1383930dea12a7c08291");
			expect(infoResult.details.rust?.panicStrategy).toBe("unwind");
			expect(infoResult.details.rust?.totalPackages).toBe(3);

			const infoText = textOf(infoResult);
			expect(infoText).toContain("1.77.2");
			expect(infoText).toContain("Cargo Auditable (.dep-v0)");

			// 2. Rust action
			const rustResult = await tool.execute({ action: "rust", path: "cli_rust" });
			expect(rustResult.details.action).toBe("rust");
			expect(rustResult.details.isRust).toBe(true);
			expect(rustResult.details.rust?.packages.length).toBe(3);

			const rustText = textOf(rustResult);
			expect(rustText).toContain("sample-rust-cli");
			expect(rustText).toContain("serde");
			expect(rustText).toContain("tokio");

			// 3. Filter test
			const filterResult = await tool.execute({
				action: "rust",
				path: "cli_rust",
				filter: "tokio",
			});
			expect(filterResult.details.rust?.packages.length).toBe(1);
			expect(filterResult.details.rust?.packages[0].name).toBe("tokio");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("cleanly reports unknown language when non-Go/non-Rust binary is inspected", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "bin-meta-c-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryMetadataInspectTool(session);

			// Plain ELF binary without Go or Rust markers
			const plainElf = Buffer.alloc(128, 0);
			plainElf[0] = 0x7f;
			plainElf[1] = 0x45;
			plainElf[2] = 0x4c;
			plainElf[3] = 0x46;
			plainElf[4] = 2;
			plainElf[5] = 1;
			await fs.writeFile(path.join(tempDir, "plain_c_app"), plainElf);

			const result = await tool.execute({ action: "info", path: "plain_c_app" });
			expect(result.details.format).toBe("elf");
			expect(result.details.language).toBe("unknown");
			expect(result.details.isGo).toBe(false);
			expect(result.details.isRust).toBe(false);

			const text = textOf(result);
			expect(text).toContain("No Go or Rust build metadata detected");

			// Asking for go action on non-Go binary returns clean unsupported message
			const goResult = await tool.execute({ action: "go", path: "plain_c_app" });
			expect(goResult.details.isGo).toBe(false);
			expect(textOf(goResult)).toContain("No Go build metadata or runtime markers were detected");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
