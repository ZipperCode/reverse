/**
 * Biome CLI-based linter client.
 * Uses Biome's CLI with JSON output instead of LSP (which has stale diagnostics issues).
 */
import * as path from "node:path";
import { logger } from "@rva/utils";
// =============================================================================
// Helpers
// =============================================================================
/**
 * Parse Biome severity to LSP DiagnosticSeverity.
 */
function parseSeverity(severity) {
    switch (severity) {
        case "error":
            return 1;
        case "warning":
            return 2;
        case "info":
            return 3;
        case "hint":
            return 4;
        default:
            return 2;
    }
}
/**
 * Run a Biome CLI command.
 */
async function runBiome(args, cwd, resolvedCommand, signal) {
    const command = resolvedCommand ?? "biome";
    try {
        const proc = Bun.spawn([command, ...args], {
            cwd,
            stdout: "pipe",
            stderr: "pipe",
            windowsHide: true,
            signal,
        });
        const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
        const exitCode = await proc.exited;
        signal?.throwIfAborted();
        return { stdout, stderr, success: exitCode === 0 };
    }
    catch (err) {
        if (signal?.aborted)
            throw err;
        return { stdout: "", stderr: String(err), success: false };
    }
}
// Surface broken-binary / CLI failures once instead of silently reporting
// "no diagnostics" forever (and instead of spamming every writethrough).
const reportedBiomeFailures = new Set();
function warnBiomeOnce(key, message, meta) {
    if (reportedBiomeFailures.has(key))
        return;
    reportedBiomeFailures.add(key);
    logger.warn(message, meta);
}
// =============================================================================
// Biome Client
// =============================================================================
/**
 * Biome CLI-based linter client.
 * Parses Biome's --reporter=json output into LSP Diagnostic format.
 */
export class BiomeClient {
    config;
    cwd;
    /** Factory method for creating BiomeClient instances */
    static create(config, cwd) {
        return new BiomeClient(config, cwd);
    }
    constructor(config, cwd) {
        this.config = config;
        this.cwd = cwd;
    }
    async format(filePath, content) {
        // Keep the standalone LinterClient contract: callers supply the content to
        // format, regardless of what is currently on disk.
        await Bun.write(filePath, content);
        const result = await runBiome(["format", "--write", filePath], this.cwd, this.config.resolvedCommand);
        if (result.success) {
            return await Bun.file(filePath).text();
        }
        // Format failed, return original
        return content;
    }
    async lint(filePath, signal) {
        // Run biome lint with JSON reporter
        const result = await runBiome(["lint", "--reporter=json", filePath], this.cwd, this.config.resolvedCommand, signal);
        // Biome exits non-zero when diagnostics are found, so only an empty
        // stdout signals an actual run failure (missing binary, CLI error).
        if (!result.success && result.stdout.trim().length === 0) {
            warnBiomeOnce(`run:${this.cwd}`, "Biome lint failed; reporting no diagnostics", {
                cwd: this.cwd,
                stderr: result.stderr.slice(0, 500),
            });
            return [];
        }
        return this.#parseJsonOutput(result.stdout, filePath);
    }
    /**
     * Parse Biome's JSON output into LSP Diagnostics.
     */
    #parseJsonOutput(jsonOutput, targetFile) {
        let parsed;
        try {
            parsed = JSON.parse(jsonOutput);
        }
        catch {
            warnBiomeOnce(`parse:${this.cwd}`, "Failed to parse Biome JSON output; reporting no diagnostics", {
                cwd: this.cwd,
                file: targetFile,
            });
            return [];
        }
        const emitted = parsed.diagnostics ?? [];
        const target = path.resolve(targetFile);
        const diagnostics = [];
        // Biome's JSON reporter is experimental and may reshape its output in
        // patch releases. Track whether any diagnostic carried a usable location
        // so a schema drift surfaces as a warning instead of a silent empty list.
        let sawUsableLocation = false;
        for (const diag of emitted) {
            const location = diag.location;
            const filePath = location?.path;
            if (!filePath)
                continue;
            sawUsableLocation = true;
            // Biome reports paths relative to its cwd.
            const diagFile = path.isAbsolute(filePath) ? filePath : path.join(this.cwd, filePath);
            // Only include diagnostics for the target file.
            if (path.resolve(diagFile) !== target)
                continue;
            // Biome positions are 1-indexed; LSP ranges are 0-indexed.
            const start = location.start;
            const end = location.end ?? start;
            const startLine = start?.line ?? 1;
            const startColumn = start?.column ?? 1;
            const endLine = end?.line ?? startLine;
            const endColumn = end?.column ?? startColumn;
            diagnostics.push({
                range: {
                    start: { line: startLine - 1, character: startColumn - 1 },
                    end: { line: endLine - 1, character: endColumn - 1 },
                },
                severity: parseSeverity(diag.severity),
                message: diag.message,
                source: "biome",
                code: diag.category,
            });
        }
        // Non-empty output whose diagnostics all lacked a recognizable location
        // means the reporter schema changed out from under us — warn loudly
        // instead of masking the regression as "no lint issues".
        if (emitted.length > 0 && !sawUsableLocation) {
            warnBiomeOnce(`schema:${this.cwd}`, "Biome diagnostics had no recognizable location; reporter schema may have changed", { cwd: this.cwd, file: targetFile, count: emitted.length });
        }
        return diagnostics;
    }
    dispose() {
        // Nothing to dispose for CLI client
    }
}
