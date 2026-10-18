/**
 * Public shape of the `shake` operation, kept in a dependency-free leaf module
 * so slash-command registries and controllers can import `formatShakeSummary`
 * without pulling in the heavy `agent-session` module graph (which would form
 * an import cycle through the slash-command registry).
 */
/** One-line operator summary of a {@link ShakeResult} (shared by TUI + ACP). */
export function formatShakeSummary(result) {
    if (result.mode === "images") {
        const n = result.imagesDropped ?? 0;
        return n === 0
            ? "No images found in this session."
            : `Dropped ${n} image${n === 1 ? "" : "s"} from this session.`;
    }
    if (result.mode === "thinking") {
        const n = result.thinkingBlocksDropped ?? 0;
        return n === 0
            ? "No thinking blocks found in this session."
            : `Dropped ${n} thinking block${n === 1 ? "" : "s"} from this session${result.tokensFreed > 0 ? ` (~${result.tokensFreed} tokens freed)` : ""}.`;
    }
    const parts = [];
    if (result.toolResultsDropped > 0) {
        parts.push(`${result.toolResultsDropped} tool result${result.toolResultsDropped === 1 ? "" : "s"}`);
    }
    if (result.blocksDropped > 0) {
        parts.push(`${result.blocksDropped} block${result.blocksDropped === 1 ? "" : "s"}`);
    }
    if (parts.length === 0)
        return "Nothing to shake.";
    return `Shook ${parts.join(" + ")} (~${result.tokensFreed} tokens freed).`;
}
