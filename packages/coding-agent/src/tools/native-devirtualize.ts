/**
 * Native VMProtect devirtualization and symbolic lifting tool (Mergen / NoVmp).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import nativeDevirtualizeDescription from "../prompts/tools/native-devirtualize.md" with { type: "text" };
import {
	getVmpToolUnsupportedReason,
	isVmpToolSupportedOnPlatform,
	resolveVmpTool,
} from "../extensibility/vmp-toolchain";
import type { ToolSession } from "./index";
import { throwIfAborted } from "./tool-errors";
import {
	formatHexAddress,
	getFileMetadata,
	parseAddress,
	parseAndValidatePe64,
	runSafeSubprocess,
	safePublishArtifact,
	validateLlvmIr,
	validateMergenStartVa,
	validateNoVmpRva,
	type ArtifactMetadata,
} from "./vmp-common";

// ============================================================================
// Parameter Schema
// ============================================================================

const nativeDevirtualizeSchema = type({
	action: type
		.enumerated("status", "lift")
		.describe(
			"Action to perform: 'status' to probe Mergen and NoVmp backend availability and platform support; 'lift' to run static devirtualization / lifting",
		),
	"backend?": type
		.enumerated("mergen", "novmp")
		.describe(
			"Devirtualization engine: 'mergen' (x64 PE to LLVM IR function lifter) or 'novmp' (VMProtect 3.0-3.5 bytecode to VTIL lifter). Required for 'lift'",
		),
	"path?": type("string").describe(
		"Path to target 64-bit Windows PE executable (.exe, .dll, .sys) on disk. Required for 'lift'",
	),
	// Mergen Parameters
	"start_address?": type("string | number").describe(
		"Mergen: starting Virtual Address (VA) of the function to lift (e.g. '0x140001000'). Must be >= ImageBase. Required for Mergen 'lift'",
	),
	"outline_addresses?": type("string[]").describe(
		"Mergen: array of function Virtual Addresses to outline as external call targets rather than inlining",
	),
	"enable_debug?": type("boolean").describe("Mergen: enable verbose debug output (--enable-debug)"),
	// NoVmp Parameters
	"vms?": type("string[]").describe(
		"NoVmp: array of VM entry Relative Virtual Addresses in hex (e.g. ['0x1000', '0x2500']). Must be RVAs (< SizeOfImage)",
	),
	"sections?": type("string[]").describe(
		"NoVmp: array of section name prefixes to scan for VM entry stubs (e.g. ['.vmp0', '.vmp1'])",
	),
	"image_base?": type("string | number").describe("NoVmp: optional ImageBase override in hex passed to -base"),
	"no_opt?": type("boolean").describe("NoVmp: disable VTIL optimization passes (-noopt)"),
	"strip_constant_obfuscation?": type("boolean").describe("NoVmp: strip constant obfuscation (-opt:constant)"),
	"experimental_recompile?": type("boolean").describe(
		"NoVmp: attempt experimental recompilation of lifted VTIL routines into a .devirt.<ext> PE file (-experimental:recompile)",
	),
	// General output controls
	"output_dir?": type("string").describe(
		"Optional destination directory to copy generated artifacts (.ll, .vtil, .json, .devirt.exe)",
	),
	"timeout?": type("number").describe("Execution timeout in seconds (default 120, max 600)"),
});

export type NativeDevirtualizeParams = typeof nativeDevirtualizeSchema.infer;

export interface DevirtualizeArtifactInfo extends ArtifactMetadata {
	kind: "llvm_ir_opt" | "llvm_ir_unopt" | "diagnostics" | "vtil_premature" | "vtil_opt" | "recompiled_pe" | "other";
}

export interface NativeDevirtualizeStatusDetails {
	action: "status";
	platform: NodeJS.Platform;
	mergen: {
		available: boolean;
		supported: boolean;
		binaryPath: string | null;
		setupCommand: string;
		unsupportedReason: string | null;
	};
	novmp: {
		available: boolean;
		supported: boolean;
		binaryPath: string | null;
		setupCommand: string;
		unsupportedReason: string | null;
	};
}

export interface NativeDevirtualizeLiftDetails {
	action: "lift";
	success: boolean;
	backend: "mergen" | "novmp";
	inputPath: string;
	imageBase: string;
	sizeOfImage: string;
	stagingDir: string;
	artifacts: DevirtualizeArtifactInfo[];
	publishedArtifacts?: DevirtualizeArtifactInfo[];
	scopeLimitations: string[];
	durationMs: number;
	exitCode: number | null;
}

export type NativeDevirtualizeDetails = NativeDevirtualizeStatusDetails | NativeDevirtualizeLiftDetails;

// ============================================================================
// Tool Implementation
// ============================================================================

export class NativeDevirtualizeTool implements AgentTool<typeof nativeDevirtualizeSchema, NativeDevirtualizeDetails> {
	readonly name = "native_devirtualize";
	readonly label = "Native Devirtualize";
	readonly description: string;
	readonly parameters = nativeDevirtualizeSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = (args as { action?: unknown }).action;
			if (action === "lift") {
				return "exec";
			}
		}
		return "read";
	};

	private readonly sessionAbort = new AbortController();

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(nativeDevirtualizeDescription);
		session.registerDisposeCallback?.(() => {
			this.sessionAbort.abort();
		});
	}

	async execute(
		callId: string,
		params: NativeDevirtualizeParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<NativeDevirtualizeDetails>> {
		if (this.sessionAbort.signal.aborted) {
			throw new ToolError("Session is already disposed.");
		}

		const effectiveSignal = signal ? AbortSignal.any([signal, this.sessionAbort.signal]) : this.sessionAbort.signal;
		throwIfAborted(effectiveSignal);

		const cwd = this.session.cwd ?? process.cwd();

		// ------------------------------------------------------------------------
		// Action: status
		// ------------------------------------------------------------------------
		if (params.action === "status") {
			const mergenBin = resolveVmpTool("mergen");
			const mergenPlatform = isVmpToolSupportedOnPlatform("mergen", process.platform);
			const mergenAvailable = mergenBin !== null;
			const mergenSupported = mergenPlatform || mergenAvailable;
			const mergenReason = mergenSupported ? null : getVmpToolUnsupportedReason("mergen", process.platform);

			const novmpBin = resolveVmpTool("novmp");
			const novmpPlatform = isVmpToolSupportedOnPlatform("novmp", process.platform);
			const novmpAvailable = novmpBin !== null;
			const novmpSupported = novmpPlatform || novmpAvailable;
			const novmpReason = novmpSupported ? null : getVmpToolUnsupportedReason("novmp", process.platform);

			const lines = [
				"### Native Devirtualization Backend Status",
				`- Platform: ${process.platform}`,
				"",
				"#### 1. Mergen (Function-level x64 PE to LLVM IR Symbolic Lifter)",
				`- Supported: ${mergenSupported ? (mergenAvailable && !mergenPlatform ? "true (via custom native build)" : "true (Windows x64)") : `false (${mergenReason ?? "Non-Windows platform"})`}`,
				`- Binary Status: ${mergenAvailable ? `ready (\`${mergenBin}\`)` : "missing"}`,
				`- Setup Command: \`reverse setup reverse mergen --execute\``,
				"",
				"#### 2. NoVmp (VMProtect 3.0-3.5 Bytecode to VTIL Deobfuscator)",
				`- Supported: ${novmpSupported ? (novmpAvailable && !novmpPlatform ? "true (via custom native build)" : "true (Windows x64)") : `false (${novmpReason ?? "Non-Windows platform"})`}`,
				`- Binary Status: ${novmpAvailable ? `ready (\`${novmpBin}\`)` : "missing"}`,
				`- Setup Command: \`reverse setup reverse novmp --execute\``,
			];

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "status",
					platform: process.platform,
					mergen: {
						available: mergenAvailable,
						supported: mergenSupported,
						binaryPath: mergenBin,
						setupCommand: "reverse setup reverse mergen --execute",
						unsupportedReason: mergenReason,
					},
					novmp: {
						available: novmpAvailable,
						supported: novmpSupported,
						binaryPath: novmpBin,
						setupCommand: "reverse setup reverse novmp --execute",
						unsupportedReason: novmpReason,
					},
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: lift (Static Devirtualization)
		// ------------------------------------------------------------------------
		if (this.session.getPlanModeState?.()?.enabled) {
			throw new ToolError(
				"Plan mode is read-only. Static devirtualization produces artifacts and files; exit plan mode first.",
			);
		}

		if (!params.backend) {
			throw new ToolError("Action 'lift' requires backend ('mergen' or 'novmp')");
		}

		if (!params.path) {
			throw new ToolError("Action 'lift' requires target PE file path (path)");
		}

		const resolvedInputPath = path.isAbsolute(params.path) ? params.path : path.resolve(cwd, params.path);

		// Validate input is valid 64-bit Windows PE
		const peInfo = await parseAndValidatePe64(resolvedInputPath);
		const origLstat = await fs.promises.lstat(resolvedInputPath);
		const forbiddenInodes = new Set<string>([`${origLstat.dev}:${origLstat.ino}`]);

		// Upfront parameter validation before backend binary resolution
		let mergenStartVa: bigint | undefined;
		const mergenOutlineAddrs: string[] = [];
		const novmpVmsRvas: bigint[] = [];
		const novmpCleanSections: string[] = [];
		let novmpBaseOverride: bigint | undefined;

		if (params.backend === "mergen") {
			if (params.start_address === undefined || params.start_address === null) {
				throw new ToolError(
					"Mergen requires function start Virtual Address start_address (VA >= ImageBase, e.g. '0x140001000')",
				);
			}
			mergenStartVa = validateMergenStartVa(params.start_address, peInfo);

			if (params.outline_addresses && params.outline_addresses.length > 0) {
				for (const a of params.outline_addresses) {
					const v = parseAddress(a, "outline_addresses");
					if (v < peInfo.imageBase) {
						throw new ToolError(
							`Outline address ${formatHexAddress(v)} must be a Virtual Address (VA >= ImageBase)`,
						);
					}
					mergenOutlineAddrs.push(formatHexAddress(v));
				}
			}
		} else if (params.backend === "novmp") {
			if (params.sections && params.sections.length > 0) {
				for (const sec of params.sections) {
					if (typeof sec !== "string" || !sec.trim()) {
						throw new ToolError("Section prefix cannot be empty");
					}
					const trimmed = sec.trim();
					if (trimmed.startsWith("-")) {
						throw new ToolError(
							`Invalid section name '${sec}': section names cannot start with '-' (option injection prevented).`,
						);
					}
					if (trimmed.length > 8 || /[\s\x00-\x1f]/.test(trimmed)) {
						throw new ToolError(
							`Invalid section name '${sec}': PE section names must be <= 8 bytes without control or whitespace characters.`,
						);
					}
					novmpCleanSections.push(trimmed);
				}
			}

			if (params.vms && params.vms.length > 0) {
				for (const v of params.vms) {
					const rva = validateNoVmpRva(v, peInfo, "vms");
					novmpVmsRvas.push(rva);
				}
			}

			if (params.image_base !== undefined && params.image_base !== null) {
				novmpBaseOverride = parseAddress(params.image_base, "image_base");
			}
		}

		const binaryPath = resolveVmpTool(params.backend);
		if (!binaryPath) {
			const reason = getVmpToolUnsupportedReason(params.backend, process.platform);
			throw new ToolError(
				reason
					? `Backend '${params.backend}' is not supported on this platform: ${reason}`
					: `Binary for '${params.backend}' not found. Run 'reverse setup reverse ${params.backend} --execute' to install.`,
			);
		}

		// Unique isolated scratch staging directory
		const stagingDir = path.join(
			cwd,
			".reverse-tmp",
			`devirt-${params.backend}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
		);
		await fs.promises.mkdir(stagingDir, { recursive: true });

		const stagedInputPath = path.join(stagingDir, path.basename(resolvedInputPath));
		await fs.promises.copyFile(resolvedInputPath, stagedInputPath, fs.constants.COPYFILE_EXCL);

		const timeoutSeconds = Math.min(600, Math.max(10, params.timeout ?? 120));
		const artifacts: DevirtualizeArtifactInfo[] = [];
		const scopeLimitations: string[] = [];

		let runExitCode: number | null = null;
		let runDurationMs = 0;

		try {
			// ====================================================================
			// Backend: Mergen
			// ====================================================================
			if (params.backend === "mergen") {
				const args: string[] = [];
				if (mergenOutlineAddrs.length > 0) {
					args.push("--outline", mergenOutlineAddrs.join(","));
				}
				if (params.enable_debug) {
					args.push("--enable-debug");
				}
				args.push(stagedInputPath, formatHexAddress(mergenStartVa!));

				const runResult = await runSafeSubprocess({
					binary: binaryPath,
					args,
					cwd: stagingDir,
					timeoutMs: timeoutSeconds * 1000,
					signal: effectiveSignal,
				});

				runExitCode = runResult.exitCode;
				runDurationMs = runResult.durationMs;

				const optLlPath = path.join(stagingDir, "output.ll");
				const unoptLlPath = path.join(stagingDir, "output_no_opts.ll");
				const diagPath = path.join(stagingDir, "output_diagnostics.json");

				if (runExitCode !== 0) {
					throw new ToolError(
						`Mergen lifting failed with exit code ${runExitCode}.\nSTDOUT:\n${runResult.stdout}\nSTDERR:\n${runResult.stderr}`,
					);
				}

				const optStat = await fs.promises.stat(optLlPath).catch(() => null);
				if (!optStat || optStat.size === 0) {
					throw new ToolError(
						`Mergen completed without errors but failed to generate output.ll.\nSTDOUT:\n${runResult.stdout}\nSTDERR:\n${runResult.stderr}`,
					);
				}

				// Validate LLVM IR syntax
				await validateLlvmIr(optLlPath);
				const optMeta = await getFileMetadata(optLlPath);
				if (!optMeta) {
					throw new ToolError(`Failed to read metadata for generated output.ll artifact: ${optLlPath}`);
				}
				artifacts.push({ ...optMeta, kind: "llvm_ir_opt" });

				const unoptStat = await fs.promises.stat(unoptLlPath).catch(() => null);
				if (unoptStat && unoptStat.size > 0) {
					await validateLlvmIr(unoptLlPath);
					const unoptMeta = await getFileMetadata(unoptLlPath);
					if (unoptMeta) artifacts.push({ ...unoptMeta, kind: "llvm_ir_unopt" });
				}

				const diagMeta = await getFileMetadata(diagPath);
				if (diagMeta) {
					try {
						const diagText = await fs.promises.readFile(diagPath, "utf-8");
						const diagJson = JSON.parse(diagText);
						if (
							diagJson &&
							typeof diagJson === "object" &&
							Array.isArray(diagJson.errors) &&
							diagJson.errors.length > 0
						) {
							throw new ToolError(`Mergen completed with diagnostics errors: ${diagJson.errors.join("; ")}`);
						}
					} catch (e) {
						if (e instanceof ToolError) throw e;
					}
					artifacts.push({ ...diagMeta, kind: "diagnostics" });
				}

				scopeLimitations.push(
					"Mergen uses a function-level symbolic lifting architecture; it lifts only the single function beginning at start_address and does not claim full binary deprotection or whole-program semantic equivalence.",
					"Self-modifying code is unsupported by Mergen.",
					"Complex control-flow or unrolled loops may require explicit function boundaries via --outline to prevent unintended inlining expansion.",
				);
			}

			// ====================================================================
			// Backend: NoVmp
			// ====================================================================
			else if (params.backend === "novmp") {
				const args: string[] = [stagedInputPath];

				if (novmpBaseOverride !== undefined) {
					args.push("-base", formatHexAddress(novmpBaseOverride));
				}

				if (novmpVmsRvas.length > 0) {
					args.push("-vms", ...novmpVmsRvas.map(r => r.toString(16)));
				}

				if (novmpCleanSections.length > 0) {
					args.push("-sections", ...novmpCleanSections);
				}

				if (params.no_opt) {
					args.push("-noopt");
				}

				if (params.strip_constant_obfuscation) {
					args.push("-opt:constant");
				}

				if (params.experimental_recompile) {
					args.push("-experimental:recompile");
				}

				const runResult = await runSafeSubprocess({
					binary: binaryPath,
					args,
					cwd: stagingDir,
					timeoutMs: timeoutSeconds * 1000,
					signal: effectiveSignal,
				});

				runExitCode = runResult.exitCode;
				runDurationMs = runResult.durationMs;

				if (runExitCode !== 0) {
					throw new ToolError(
						`NoVmp failed with exit code ${runExitCode}.\nSTDOUT:\n${runResult.stdout}\nSTDERR:\n${runResult.stderr}`,
					);
				}

				const vmsDir = path.join(stagingDir, "vms");
				const vmsExists = await fs.promises.stat(vmsDir).catch(() => null);

				const prematureRvas = new Set<string>();
				const optimizedRvas = new Set<string>();

				if (vmsExists && vmsExists.isDirectory()) {
					const entries = await fs.promises.readdir(vmsDir);
					for (const entry of entries) {
						const match = entry.match(/^(?:0x)?([0-9a-fA-F]+)\.(optimized|premature)\.vtil$/);
						if (!match) continue;

						const hexStr = match[1]!;
						const kindStr = match[2]!;
						const rvaBigInt = BigInt(`0x${hexStr}`);
						const rvaKey = rvaBigInt.toString(16);

						const entryPath = path.join(vmsDir, entry);
						const meta = await getFileMetadata(entryPath);
						if (meta && meta.bytes > 16) {
							if (kindStr === "optimized") {
								optimizedRvas.add(rvaKey);
								artifacts.push({ ...meta, kind: "vtil_opt" });
							} else {
								prematureRvas.add(rvaKey);
								artifacts.push({ ...meta, kind: "vtil_premature" });
							}
						}
					}
				}

				// Per-RVA terminal artifact validation
				if (novmpVmsRvas.length > 0) {
					for (const reqRva of novmpVmsRvas) {
						const reqKey = reqRva.toString(16);
						if (!optimizedRvas.has(reqKey) && !prematureRvas.has(reqKey)) {
							throw new ToolError(
								`NoVmp devirtualization failed for requested VM entry 0x${reqKey}: routine was not discovered or lifted.`,
							);
						}
						if (!params.no_opt && !optimizedRvas.has(reqKey)) {
							throw new ToolError(
								`NoVmp optimization failed for requested VM entry 0x${reqKey}: routine produced only premature VTIL without optimized counterpart.`,
							);
						}
					}
				} else if (!params.no_opt) {
					// Default (all discovered): every premature routine must have an optimized counterpart
					for (const premKey of prematureRvas) {
						if (!optimizedRvas.has(premKey)) {
							throw new ToolError(
								`NoVmp optimization incomplete: routine at 0x${premKey} produced premature VTIL but failed optimization.`,
							);
						}
					}
					if (optimizedRvas.size === 0 && artifacts.length > 0) {
						throw new ToolError("NoVmp optimization phase failed: no optimized VTIL outputs were produced.");
					}
				}

				// Check recompiled PE output if requested
				if (params.experimental_recompile) {
					const ext = path.extname(stagedInputPath);
					const base = path.basename(stagedInputPath, ext);
					const devirtPath = path.join(stagingDir, `${base}.devirt${ext}`);
					const devirtMeta = await getFileMetadata(devirtPath);
					if (!devirtMeta) {
						throw new ToolError(
							`NoVmp experimental recompilation requested (-experimental:recompile), but .devirt PE output was not generated at: ${devirtPath}`,
						);
					}
					await parseAndValidatePe64(devirtPath);
					artifacts.push({ ...devirtMeta, kind: "recompiled_pe" });
				}

				if (artifacts.length === 0) {
					throw new ToolError(
						`NoVmp completed with exit code ${runExitCode}, but no valid .vtil routines were produced.\nSTDOUT:\n${runResult.stdout}\nSTDERR:\n${runResult.stderr}`,
					);
				}

				scopeLimitations.push(
					"NoVmp targets legacy VMProtect 3.0-3.5 x64 routines for VTIL lifting; it does not claim whole-binary unpacking or full functional equivalence.",
					"PE files with stripped relocations have limited compatibility.",
					"Experimental recompilation appends a .novmp section but does not guarantee runtime stability.",
				);
			}
		} finally {
			// Clean up staged input copy
			await fs.promises.unlink(stagedInputPath).catch(() => null);
		}

		// ------------------------------------------------------------------------
		// Publish artifacts (if output_dir specified)
		// ------------------------------------------------------------------------
		let publishedArtifacts: DevirtualizeArtifactInfo[] | undefined;
		if (params.output_dir) {
			const resolvedOutputDir = path.isAbsolute(params.output_dir)
				? params.output_dir
				: path.resolve(cwd, params.output_dir);

			publishedArtifacts = [];
			for (const art of artifacts) {
				const destPath = path.join(resolvedOutputDir, path.basename(art.path));
				const publishedMeta = await safePublishArtifact(art.path, destPath, forbiddenInodes);
				publishedArtifacts.push({
					...publishedMeta,
					kind: art.kind,
				});
			}
		}

		const summaryLines = [
			`### Native Devirtualization Completed (${params.backend.toUpperCase()})`,
			`- Input Image: \`${resolvedInputPath}\``,
			`- ImageBase: ${formatHexAddress(peInfo.imageBase)} (Size: ${formatHexAddress(peInfo.sizeOfImage)})`,
			`- Staging Directory: \`${stagingDir}\``,
			`- Generated Artifacts: ${artifacts.length}`,
			...artifacts.map(
				a => `  - [${a.kind}] \`${a.path}\` (${a.bytes} bytes, SHA-256: ${a.sha256.slice(0, 16)}...)`,
			),
			publishedArtifacts ? `- Published Directory: \`${params.output_dir}\`` : "",
			`- Duration: ${runDurationMs}ms`,
			"",
			"#### Scope Limitations:",
			...scopeLimitations.map(s => `- ${s}`),
		];

		return {
			content: [{ type: "text", text: summaryLines.filter(Boolean).join("\n") }],
			details: {
				action: "lift",
				success: true,
				backend: params.backend,
				inputPath: resolvedInputPath,
				imageBase: formatHexAddress(peInfo.imageBase),
				sizeOfImage: formatHexAddress(peInfo.sizeOfImage),
				stagingDir,
				artifacts,
				publishedArtifacts,
				scopeLimitations,
				durationMs: runDurationMs,
				exitCode: runExitCode,
			},
		};
	}
}
