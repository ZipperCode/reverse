/** Split like Rust `str::lines`: `\n`-separated, trailing `\r` stripped, no phantom last line after a final newline. */
export function lines(text) {
    if (text.length === 0)
        return [];
    const out = text.split("\n");
    if (out[out.length - 1] === "")
        out.pop();
    for (let i = 0; i < out.length; i++) {
        const line = out[i];
        if (line.endsWith("\r"))
            out[i] = line.slice(0, -1);
    }
    return out;
}
/** Longest prefix of `text` that fits in `bytes` UTF-8 bytes without splitting a code point. */
export function clipBytes(text, bytes) {
    if (Buffer.byteLength(text) <= bytes)
        return text;
    let used = 0;
    let end = 0;
    for (const char of text) {
        const width = Buffer.byteLength(char);
        if (used + width > bytes)
            break;
        used += width;
        end += char.length;
    }
    return text.slice(0, end);
}
/** First `count` code points of `text`. */
export function takeChars(text, count) {
    let end = 0;
    let taken = 0;
    for (const char of text) {
        if (taken === count)
            break;
        end += char.length;
        taken++;
    }
    return text.slice(0, end);
}
/** Non-overlapping occurrences of `needle` in `haystack`; 0 for an empty needle. */
export function countOccurrences(haystack, needle) {
    if (needle.length === 0)
        return 0;
    let count = 0;
    let from = 0;
    for (;;) {
        const at = haystack.indexOf(needle, from);
        if (at === -1)
            return count;
        count++;
        from = at + needle.length;
    }
}
export class ReadTextError extends Error {
    kind;
    constructor(kind, message) {
        super(message);
        this.kind = kind;
        this.name = "ReadTextError";
    }
}
const BINARY_PROBE_BYTES = 8192;
/**
 * Read up to `maxBytes` of a text file (host path or internal URL) through
 * `filesystem`. Rejects binaries (NUL in the first 8 KB) and blank files;
 * trims a truncated read back to the last full line.
 * @throws {ReadTextError} `binary`, `empty`, or `io`.
 */
export async function readText(filesystem, path, maxBytes) {
    let buf;
    try {
        buf = await filesystem.readPrefix(path, maxBytes + 1);
    }
    catch (error) {
        throw new ReadTextError("io", error instanceof Error ? error.message : String(error));
    }
    const probe = buf.subarray(0, Math.min(buf.length, BINARY_PROBE_BYTES));
    if (probe.includes(0))
        throw new ReadTextError("binary", "binary");
    const truncated = buf.length > maxBytes;
    if (truncated) {
        buf = buf.subarray(0, maxBytes);
        const newline = buf.lastIndexOf(0x0a);
        if (newline !== -1)
            buf = buf.subarray(0, newline + 1);
    }
    const text = new TextDecoder().decode(buf);
    if (lines(text).every(line => line.trim().length === 0))
        throw new ReadTextError("empty", "empty");
    return { text, bytes: buf.length, truncated };
}
