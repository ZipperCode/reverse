/**
 * `/export` argument parsing, split from `./index.ts` so slash-command
 * registries can parse arguments without eagerly loading the export module's
 * embedded template/tool-view text.
 */
/** Parse `/export [--themes] [path]`; paths containing spaces were never supported. */
export function parseExportArgs(args) {
    const parts = args.trim().split(/\s+/).filter(Boolean);
    const useUserThemes = parts.includes("--themes");
    const paths = parts.filter(part => part !== "--themes");
    if (paths.length > 1)
        throw new Error("Usage: /export [--themes] [path]");
    return { outputPath: paths[0], useUserThemes };
}
