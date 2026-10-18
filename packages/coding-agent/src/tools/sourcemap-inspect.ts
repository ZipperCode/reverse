import * as fs from "node:fs/promises";
import type { Stats } from "node:fs";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@rva/agent";
import { type } from "@rva/omptype";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { formatBytes, prompt } from "@rva/utils";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import sourcemapInspectDescription from "../prompts/tools/sourcemap-inspect.md" with { type: "text" };

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;
const HARD_MAX_BYTES = 50 * 1024 * 1024;

const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_LOOKUP = new Int8Array(128).fill(-1);
for (let i = 0; i < BASE64_CHARS.length; i++) {
	B64_LOOKUP[BASE64_CHARS.charCodeAt(i)] = i;
}

const sourcemapInspectSchema = type({
	action: type.enumerated("info", "lookup", "extract"),
	path: type("string").describe("Path to target .map file or compiled .js/.ts file containing sourceMappingURL"),
	"line?": type("number.integer >= 1").describe("1-based line number in generated file for lookup"),
	"column?": type("number.integer >= 0").describe("Column number in generated file for lookup (default 0-based)"),
	"column_zero_based?": type("boolean").describe("Whether the provided column is 0-based (default true)"),
	"source_index?": type("number.integer >= 0").describe("Source index to extract (0-based)"),
	"source_path?": type("string").describe("Substring or extension filter for extracting source files"),
	"destination_dir?": type("string").describe("Directory to save extracted original files (optional)"),
	"limit?": type("number.integer >= 1").describe("Maximum items to list or files to extract (default 50, max 500)"),
	"skip?": type("number.integer >= 0").describe("Pagination offset for sources or names list"),
	"max_bytes?": type("number.integer >= 1").describe(
		"Maximum file bytes to read or extract (default 5MB, hard limit 50MB)",
	),
});

export type SourcemapInspectParams = typeof sourcemapInspectSchema.infer;

export interface RawSourceMapV3 {
	version: number;
	file?: string;
	sourceRoot?: string;
	sources?: string[];
	sourcesContent?: Array<string | null>;
	names?: string[];
	mappings?: string;
	sections?: Array<{
		offset: { line: number; column: number };
		map: RawSourceMapV3;
	}>;
}

export interface MappingSegment {
	generatedColumn: number;
	sourceIndex?: number;
	originalLine?: number; // 0-based
	originalColumn?: number; // 0-based
	nameIndex?: number;
}

export interface MappingState {
	sourceIndex: number;
	originalLine: number;
	originalColumn: number;
	nameIndex: number;
}

export interface ExtractedSourceFile {
	source: string;
	index: number;
	size: number;
	content: string;
	savedPath?: string;
}

export interface SourcemapInspectDetails {
	action: "info" | "lookup" | "extract";
	targetPath: string;
	resolvedMapPath?: string;
	detectedFrom: "direct_map" | "inline_base64" | "inline_uri" | "relative_file" | "adjacent_map";
	version: number;
	file?: string;
	sourceRoot?: string;
	sourcesCount: number;
	sources?: string[];
	namesCount: number;
	names?: string[];
	hasSourcesContent: boolean;
	sourcesWithContentCount: number;
	mappingsLength: number;
	totalLinesMapped: number;
	lookup?: {
		generatedLine: number;
		generatedColumn: number;
		originalSource?: string;
		originalSourceIndex?: number;
		originalLine?: number;
		originalColumn?: number;
		originalName?: string;
		sourceSnippet?: string;
	};
	extracted?: {
		totalExtracted: number;
		destinationDir?: string;
		files: ExtractedSourceFile[];
	};
}

export function decodeVLQ(str: string, startIndex: number): [value: number, nextIndex: number] {
	let result = 0;
	let shift = 0;
	let continuation = true;
	let index = startIndex;

	while (continuation) {
		if (index >= str.length) {
			throw new Error("Unexpected end of VLQ sequence");
		}
		const charCode = str.charCodeAt(index++);
		if (charCode >= 128) {
			throw new Error(`Invalid character in VLQ sequence: code ${charCode}`);
		}
		const digit = B64_LOOKUP[charCode];
		if (digit === -1) {
			throw new Error(`Invalid base64 character in VLQ sequence: ${str[index - 1]}`);
		}
		continuation = (digit & 32) !== 0;
		const value = digit & 31;
		result += value * (1 << shift);
		shift += 5;
	}

	const isNegative = (result & 1) === 1;
	const decoded = Math.floor(result / 2);
	return [isNegative ? -decoded : decoded, index];
}

function decodeLineDeltas(lineStr: string, state: MappingState): void {
	if (!lineStr) return;
	const segments = lineStr.split(",");
	for (const seg of segments) {
		if (!seg) continue;
		let idx = 0;
		// Field 0: generatedColumn delta (ignored when advancing state across earlier lines)
		const [, afterCol] = decodeVLQ(seg, idx);
		idx = afterCol;
		if (idx >= seg.length) continue;

		// Field 1: sourceIndex delta
		const [srcDelta, afterSrc] = decodeVLQ(seg, idx);
		state.sourceIndex += srcDelta;
		idx = afterSrc;
		if (idx >= seg.length) continue;

		// Field 2: originalLine delta
		const [lineDelta, afterLine] = decodeVLQ(seg, idx);
		state.originalLine += lineDelta;
		idx = afterLine;
		if (idx >= seg.length) continue;

		// Field 3: originalColumn delta
		const [colDelta, afterOrigCol] = decodeVLQ(seg, idx);
		state.originalColumn += colDelta;
		idx = afterOrigCol;
		if (idx >= seg.length) continue;

		// Field 4: nameIndex delta (optional)
		const [nameDelta] = decodeVLQ(seg, idx);
		state.nameIndex += nameDelta;
	}
}

function decodeLineSegments(lineStr: string, state: MappingState): MappingSegment[] {
	if (!lineStr) return [];
	const rawSegments = lineStr.split(",");
	const segments: MappingSegment[] = [];
	let generatedColumn = 0;

	for (const seg of rawSegments) {
		if (!seg) continue;
		let idx = 0;
		const [colDelta, afterCol] = decodeVLQ(seg, idx);
		generatedColumn += colDelta;
		idx = afterCol;

		if (idx >= seg.length) {
			segments.push({ generatedColumn });
			continue;
		}

		const [srcDelta, afterSrc] = decodeVLQ(seg, idx);
		state.sourceIndex += srcDelta;
		idx = afterSrc;

		if (idx >= seg.length) {
			segments.push({
				generatedColumn,
				sourceIndex: state.sourceIndex,
			});
			continue;
		}

		const [lineDelta, afterLine] = decodeVLQ(seg, idx);
		state.originalLine += lineDelta;
		idx = afterLine;

		if (idx >= seg.length) {
			segments.push({
				generatedColumn,
				sourceIndex: state.sourceIndex,
				originalLine: state.originalLine,
			});
			continue;
		}

		const [origColDelta, afterOrigCol] = decodeVLQ(seg, idx);
		state.originalColumn += origColDelta;
		idx = afterOrigCol;

		let nameIndex: number | undefined;
		if (idx < seg.length) {
			const [nameDelta] = decodeVLQ(seg, idx);
			state.nameIndex += nameDelta;
			nameIndex = state.nameIndex;
		}

		segments.push({
			generatedColumn,
			sourceIndex: state.sourceIndex,
			originalLine: state.originalLine,
			originalColumn: state.originalColumn,
			nameIndex,
		});
	}

	return segments;
}

export function sanitizeExtractionPath(sourcePath: string): string {
	let clean = sourcePath.replace(/\?.*$/, "");
	clean = clean.replace(/^(?:webpack|vite|file):\/{2,3}/i, "");
	clean = clean.replace(/^[a-zA-Z]:[\\\/]/, "").replace(/^[\\\/]+/, "");
	clean = path.normalize(clean).replace(/^(\.\.[\/\\])+/, "");
	return clean || "recovered-source.js";
}

export class SourcemapInspectTool
	implements AgentTool<typeof sourcemapInspectSchema, SourcemapInspectDetails>
{
	readonly name = "sourcemap_inspect";
	readonly approval: ToolTier = "read";
	readonly label = "SourceMap Inspect";
	readonly summary =
		"Static inspection, VLQ mapping lookup, and source code recovery from SourceMap files and inline directives";
	readonly description: string;
	readonly parameters = sourcemapInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(sourcemapInspectDescription);
	}

	async execute(
		_toolCallId: string,
		params: SourcemapInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<SourcemapInspectDetails>> {
		throwIfAborted(signal);

		const requestedPath = params.path?.trim();
		if (!requestedPath) {
			throw new ToolError("path parameter is required");
		}

		if (/^https?:\/\//i.test(requestedPath)) {
			throw new ToolError(
				`Remote URL targets are not permitted: ${requestedPath}. Provide a local .map or .js file path.`,
			);
		}

		const maxBytes = Math.min(HARD_MAX_BYTES, Math.max(1024, params.max_bytes ?? DEFAULT_MAX_BYTES));
		const absolutePath = resolveReadPath(requestedPath, this.session.cwd);

		let fileStat: Stats;
		try {
			fileStat = await fs.stat(absolutePath);
		} catch {
			throw new ToolError(`Target file not found: ${requestedPath}`);
		}

		if (!fileStat.isFile()) {
			throw new ToolError(`Target is not a regular file: ${requestedPath}`);
		}

		if (fileStat.size > maxBytes) {
			throw new ToolError(
				`Target file size (${formatBytes(fileStat.size)}) exceeds allowed max_bytes (${formatBytes(maxBytes)})`,
			);
		}

		const fileBuffer = await fs.readFile(absolutePath);
		throwIfAborted(signal);

		let mapJson: RawSourceMapV3;
		let detectedFrom: SourcemapInspectDetails["detectedFrom"] = "direct_map";
		let resolvedMapPath = absolutePath;

		const isDirectMap = requestedPath.endsWith(".map") || requestedPath.endsWith(".json");
		const fileText = fileBuffer.toString("utf-8");

		if (isDirectMap) {
			try {
				mapJson = JSON.parse(fileText) as RawSourceMapV3;
			} catch (err) {
				throw new ToolError(`Failed to parse sourcemap JSON in ${requestedPath}: ${String(err)}`);
			}
		} else {
			// Check if raw file is JSON sourcemap despite extension
			let parsedDirectly = false;
			if (fileText.trimStart().startsWith("{")) {
				try {
					const candidate = JSON.parse(fileText);
					if (candidate && candidate.version === 3 && (candidate.sources || candidate.mappings)) {
						mapJson = candidate as RawSourceMapV3;
						parsedDirectly = true;
					}
				} catch {}
			}

			if (!parsedDirectly) {
				// Search for sourceMappingURL directive
				const directiveRegex = /(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL=([^\s*]+)/g;
				let match: RegExpExecArray | null = null;
				let lastMatch: RegExpExecArray | null = null;
				while ((match = directiveRegex.exec(fileText)) !== null) {
					lastMatch = match;
				}

				if (lastMatch && lastMatch[1]) {
					const url = lastMatch[1].trim();
					if (url.startsWith("data:application/json")) {
						if (url.includes(";base64,")) {
							const b64 = url.substring(url.indexOf(";base64,") + 8);
							try {
								const decoded = Buffer.from(b64, "base64").toString("utf-8");
								mapJson = JSON.parse(decoded) as RawSourceMapV3;
								detectedFrom = "inline_base64";
							} catch (err) {
								throw new ToolError(`Failed to decode inline base64 sourcemap: ${String(err)}`);
							}
						} else {
							const commaIndex = url.indexOf(",");
							if (commaIndex === -1) {
								throw new ToolError("Invalid data URI sourcemap format");
							}
							try {
								const decoded = decodeURIComponent(url.substring(commaIndex + 1));
								mapJson = JSON.parse(decoded) as RawSourceMapV3;
								detectedFrom = "inline_uri";
							} catch (err) {
								throw new ToolError(`Failed to decode inline URI sourcemap: ${String(err)}`);
							}
						}
					} else if (/^https?:\/\//i.test(url)) {
						throw new ToolError(
							`Remote sourceMappingURL detected: "${url}". Remote network fetching is not allowed. Please download the .map file locally and inspect it.`,
						);
					} else {
						// Relative map file path
						const targetDir = path.dirname(absolutePath);
						const mapCandidate = path.resolve(targetDir, url);
						try {
							const mapContent = await fs.readFile(mapCandidate, "utf-8");
							mapJson = JSON.parse(mapContent) as RawSourceMapV3;
							detectedFrom = "relative_file";
							resolvedMapPath = mapCandidate;
						} catch (err) {
							throw new ToolError(
								`Found sourceMappingURL "${url}", but could not load file at "${mapCandidate}": ${String(err)}`,
							);
						}
					}
				} else {
					// Fallback: check adjacent ${path}.map
					const adjacentMap = `${absolutePath}.map`;
					try {
						const mapContent = await fs.readFile(adjacentMap, "utf-8");
						mapJson = JSON.parse(mapContent) as RawSourceMapV3;
						detectedFrom = "adjacent_map";
						resolvedMapPath = adjacentMap;
					} catch {
						throw new ToolError(
							`No sourceMappingURL directive or adjacent .map file found for "${requestedPath}". Provide a .map file directly or an asset with valid sourceMappingURL.`,
						);
					}
				}
			}
		}

		if (!mapJson! || typeof mapJson.version !== "number") {
			throw new ToolError(`Invalid or missing SourceMap version in "${requestedPath}"`);
		}

		const sources = mapJson.sources || [];
		const names = mapJson.names || [];
		const sourcesContent = mapJson.sourcesContent || [];
		const mappings = mapJson.mappings || "";

		let semiCount = 0;
		for (let i = 0; i < mappings.length; i++) {
			if (mappings.charCodeAt(i) === 59) semiCount++;
		}
		const totalLinesMapped = mappings.length > 0 ? semiCount + 1 : 0;

		const sourcesWithContentCount = sourcesContent.filter(c => typeof c === "string").length;
		const hasSourcesContent = sourcesWithContentCount > 0;

		const action = params.action;
		const limit = Math.min(MAX_LIMIT, Math.max(1, params.limit ?? DEFAULT_LIMIT));
		const skip = Math.max(0, params.skip ?? 0);

		if (action === "info") {
			const slicedSources = sources.slice(skip, skip + limit);
			const slicedNames = names.slice(skip, skip + limit);

			const lines = [
				`# SourceMap Info: ${path.basename(resolvedMapPath)}`,
				`- **Format**: SourceMap v${mapJson.version} (${detectedFrom})`,
				mapJson.file ? `- **Generated File**: \`${mapJson.file}\`` : null,
				mapJson.sourceRoot ? `- **Source Root**: \`${mapJson.sourceRoot}\`` : null,
				`- **Sources Count**: ${sources.length}`,
				`- **Names Count**: ${names.length}`,
				`- **Embedded SourcesContent**: ${hasSourcesContent ? `Yes (${sourcesWithContentCount}/${sources.length} files)` : "No"}`,
				`- **Mappings Length**: ${mappings.length} chars (~${totalLinesMapped} mapped lines)`,
				`- **Map File Path**: \`${resolvedMapPath}\``,
				"",
				`### Sources (${skip + 1}-${Math.min(skip + slicedSources.length, sources.length)} of ${sources.length}):`,
				slicedSources.length > 0
					? slicedSources.map((s, idx) => `  ${skip + idx + 1}. \`${s}\``).join("\n")
					: "  [none]",
				"",
				`### Names Sample (${skip + 1}-${Math.min(skip + slicedNames.length, names.length)} of ${names.length}):`,
				slicedNames.length > 0
					? slicedNames.map((n, idx) => `  ${skip + idx + 1}. \`${n}\``).join("\n")
					: "  [none]",
			].filter(Boolean) as string[];

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "info",
					targetPath: requestedPath,
					resolvedMapPath,
					detectedFrom,
					version: mapJson.version,
					file: mapJson.file,
					sourceRoot: mapJson.sourceRoot,
					sourcesCount: sources.length,
					sources: slicedSources,
					namesCount: names.length,
					names: slicedNames,
					hasSourcesContent,
					sourcesWithContentCount,
					mappingsLength: mappings.length,
					totalLinesMapped,
				},
			};
		}

		if (action === "lookup") {
			const targetLine = params.line;
			if (typeof targetLine !== "number" || targetLine < 1) {
				throw new ToolError("line parameter (1-based integer >= 1) is required for 'lookup' action");
			}

			const targetCol = params.column ?? 0;
			const targetLineIndex = targetLine - 1;

			if (targetLineIndex >= totalLinesMapped) {
				throw new ToolError(
					`Line ${targetLine} exceeds total lines mapped in sourcemap (${totalLinesMapped} lines).`,
				);
			}

			const state: MappingState = {
				sourceIndex: 0,
				originalLine: 0,
				originalColumn: 0,
				nameIndex: 0,
			};

			let currentLine = 0;
			let lineStart = 0;
			while (currentLine < targetLineIndex) {
				const nextSemi = mappings.indexOf(";", lineStart);
				if (nextSemi === -1) {
					throw new ToolError(`Unexpected end of mappings while navigating to line ${targetLine}`);
				}
				const lineStr = mappings.slice(lineStart, nextSemi);
				decodeLineDeltas(lineStr, state);
				lineStart = nextSemi + 1;
				currentLine++;
			}

			const nextSemi = mappings.indexOf(";", lineStart);
			const lineEnd = nextSemi === -1 ? mappings.length : nextSemi;
			const targetLineStr = mappings.slice(lineStart, lineEnd);
			const segments = decodeLineSegments(targetLineStr, state);

			if (segments.length === 0) {
				throw new ToolError(`No mapping segments found for line ${targetLine}`);
			}

			let matched: MappingSegment = segments[0];
			for (const seg of segments) {
				if (seg.generatedColumn <= targetCol) {
					matched = seg;
				} else {
					break;
				}
			}

			const originalSource =
				matched.sourceIndex !== undefined && matched.sourceIndex < sources.length
					? sources[matched.sourceIndex]
					: undefined;
			const originalLineNum = matched.originalLine !== undefined ? matched.originalLine + 1 : undefined;
			const originalColumnNum = matched.originalColumn;
			const originalName =
				matched.nameIndex !== undefined && matched.nameIndex < names.length
					? names[matched.nameIndex]
					: undefined;

			let sourceSnippet: string | undefined;
			if (matched.sourceIndex !== undefined && sourcesContent[matched.sourceIndex]) {
				const rawContent = sourcesContent[matched.sourceIndex];
				if (typeof rawContent === "string" && originalLineNum !== undefined) {
					const codeLines = rawContent.split(/\r?\n/);
					const startLn = Math.max(1, originalLineNum - 3);
					const endLn = Math.min(codeLines.length, originalLineNum + 3);
					const snippetRows: string[] = [];
					for (let ln = startLn; ln <= endLn; ln++) {
						const isTarget = ln === originalLineNum;
						const marker = isTarget ? ">" : " ";
						const pad = String(ln).padStart(String(endLn).length, " ");
						snippetRows.push(`${marker} ${pad} | ${codeLines[ln - 1]}`);
					}
					sourceSnippet = snippetRows.join("\n");
				}
			}

			const lines = [
				`# SourceMap Lookup: Line ${targetLine}, Column ${targetCol}`,
				`- **Generated Position**: ${targetLine}:${targetCol}`,
				`- **Original Source**: \`${originalSource || "[unmapped]"}\``,
				`- **Original Line & Col**: ${originalLineNum !== undefined ? `${originalLineNum}:${originalColumnNum}` : "[unmapped]"}`,
				originalName ? `- **Original Symbol Name**: \`${originalName}\`` : null,
				sourceSnippet
					? [
							"",
							"### Original Source Snippet:",
							"```typescript",
							sourceSnippet,
							"```",
						].join("\n")
					: null,
			].filter(Boolean) as string[];

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "lookup",
					targetPath: requestedPath,
					resolvedMapPath,
					detectedFrom,
					version: mapJson.version,
					file: mapJson.file,
					sourceRoot: mapJson.sourceRoot,
					sourcesCount: sources.length,
					namesCount: names.length,
					hasSourcesContent,
					sourcesWithContentCount,
					mappingsLength: mappings.length,
					totalLinesMapped,
					lookup: {
						generatedLine: targetLine,
						generatedColumn: targetCol,
						originalSource,
						originalSourceIndex: matched.sourceIndex,
						originalLine: originalLineNum,
						originalColumn: originalColumnNum,
						originalName,
						sourceSnippet,
					},
				},
			};
		}

		// Action: extract
		if (!hasSourcesContent) {
			throw new ToolError(
				`SourceMap in "${resolvedMapPath}" does not contain embedded 'sourcesContent' to extract. Original sources cannot be reconstructed from VLQ coordinates alone.`,
			);
		}

		const filterIndex = params.source_index;
		const filterPath = params.source_path?.toLowerCase();
		const destinationDir = params.destination_dir?.trim();

		let resolvedDestDir: string | undefined;
		if (destinationDir) {
			resolvedDestDir = path.resolve(this.session.cwd, destinationDir);
			await fs.mkdir(resolvedDestDir, { recursive: true });
		}

		const extractedFiles: ExtractedSourceFile[] = [];

		for (let i = 0; i < sources.length; i++) {
			throwIfAborted(signal);
			if (extractedFiles.length >= limit) break;

			if (typeof filterIndex === "number" && filterIndex !== i) continue;

			const sourceName = sources[i];
			if (filterPath && !sourceName.toLowerCase().includes(filterPath)) continue;

			const content = sourcesContent[i];
			if (typeof content !== "string") continue;

			let savedPath: string | undefined;
			if (resolvedDestDir) {
				const relativeClean = sanitizeExtractionPath(sourceName);
				const targetOut = path.resolve(resolvedDestDir, relativeClean);
				if (!targetOut.startsWith(resolvedDestDir)) {
					throw new ToolError(
						`Path traversal detected for source "${sourceName}". Target path escapes destination directory.`,
					);
				}
				await fs.mkdir(path.dirname(targetOut), { recursive: true });
				await fs.writeFile(targetOut, content, "utf-8");
				savedPath = targetOut;
			}

			extractedFiles.push({
				source: sourceName,
				index: i,
				size: Buffer.byteLength(content, "utf-8"),
				content,
				savedPath,
			});
		}

		if (extractedFiles.length === 0) {
			throw new ToolError("No matching embedded source files found matching the extraction filter.");
		}

		const summaryLines = [
			`# Extracted Original Sources (${extractedFiles.length} file${extractedFiles.length > 1 ? "s" : ""})`,
			`- **SourceMap**: \`${path.basename(resolvedMapPath)}\``,
			resolvedDestDir ? `- **Saved To**: \`${resolvedDestDir}\`` : "- **Mode**: Inline text recovery",
			"",
			...extractedFiles.map(f => {
				const header = `- [Index ${f.index}] \`${f.source}\` (${formatBytes(f.size)})${f.savedPath ? ` -> \`${f.savedPath}\`` : ""}`;
				if (!resolvedDestDir) {
					const preview = f.content.length > 500 ? `${f.content.slice(0, 500)}...\n[truncated ${f.content.length - 500} chars]` : f.content;
					return `${header}\n\`\`\`typescript\n${preview}\n\`\`\``;
				}
				return header;
			}),
		];

		return {
			content: [{ type: "text", text: summaryLines.join("\n") }],
			details: {
				action: "extract",
				targetPath: requestedPath,
				resolvedMapPath,
				detectedFrom,
				version: mapJson.version,
				file: mapJson.file,
				sourceRoot: mapJson.sourceRoot,
				sourcesCount: sources.length,
				namesCount: names.length,
				hasSourcesContent,
				sourcesWithContentCount,
				mappingsLength: mappings.length,
				totalLinesMapped,
				extracted: {
					totalExtracted: extractedFiles.length,
					destinationDir: resolvedDestDir,
					files: extractedFiles,
				},
			},
		};
	}
}
