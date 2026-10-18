function parseSeverity(severity) {
    switch (severity) {
        case "Error":
            return 1;
        case "Warning":
            return 2;
        default:
            return 2;
    }
}
async function runSwiftLint(args, cwd, resolvedCommand, signal) {
    const command = resolvedCommand ?? "swiftlint";
    try {
        const proc = Bun.spawn([command, ...args], {
            cwd,
            stdout: "pipe",
            stderr: "pipe",
            windowsHide: true,
            signal,
        });
        const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
        await proc.exited;
        signal?.throwIfAborted();
        // swiftlint exits non-zero when violations found — that's not a failure
        return { stdout, stderr, success: stdout.length > 0 };
    }
    catch (err) {
        if (signal?.aborted)
            throw err;
        return { stdout: "", stderr: String(err), success: false };
    }
}
/**
 * SwiftLint CLI-based linter client.
 * Runs `swiftlint lint --reporter json` and converts violations to LSP diagnostics.
 */
export class SwiftLintClient {
    config;
    cwd;
    /** Factory method for creating SwiftLintClient instances */
    static create(config, cwd) {
        return new SwiftLintClient(config, cwd);
    }
    constructor(config, cwd) {
        this.config = config;
        this.cwd = cwd;
    }
    async format(_filePath, content) {
        // SwiftLint doesn't support formatting
        return content;
    }
    async lint(filePath, signal) {
        const result = await runSwiftLint(["lint", "--quiet", "--reporter", "json", filePath], this.cwd, this.config.resolvedCommand, signal);
        if (!result.success) {
            return [];
        }
        return this.#parseJsonOutput(result.stdout);
    }
    #parseJsonOutput(jsonOutput) {
        const diagnostics = [];
        try {
            const violations = JSON.parse(jsonOutput);
            for (const v of violations) {
                // SwiftLint lines/characters are 1-based; LSP is 0-based
                const line = Math.max(0, v.line - 1);
                const character = Math.max(0, v.character - 1);
                diagnostics.push({
                    range: {
                        start: { line, character },
                        end: { line, character },
                    },
                    severity: parseSeverity(v.severity),
                    message: v.reason,
                    source: "swiftlint",
                    code: v.rule_id,
                });
            }
        }
        catch {
            // JSON parse failed, return empty
        }
        return diagnostics;
    }
    dispose() {
        // Nothing to dispose for CLI client
    }
}
