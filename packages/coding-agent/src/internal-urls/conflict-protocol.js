import { readConflictUri, writeConflictUri } from "../tools/conflict-uri";
function callerSession(context) {
    const session = context?.session;
    if (!session)
        throw new Error("conflict:// requires a calling session.");
    return session;
}
/** Session-scoped merge-conflict blocks registered by `read`; writable to resolve them. */
export class ConflictProtocolHandler {
    scheme = "conflict";
    spec = {
        backing: "virtual",
        selectors: "none",
        immutable: false,
        // Verbatim: `conflict://*` per-id directives must be parsed before hashline
        // stripping, so the handler strips copied prefixes itself.
        write: { via: "handler", payload: "verbatim", scope: "workspace", tier: () => "write" },
    };
    async resolve(url, context) {
        const region = readConflictUri(callerSession(context), url.rawHref ?? url.href);
        return {
            url: url.href,
            content: region.text,
            contentType: "text/plain",
            size: Buffer.byteLength(region.text, "utf-8"),
            sourcePath: region.absolutePath,
            shape: "value",
            details: { display: { text: region.rawText, startLine: region.startLine } },
        };
    }
    async write(url, content, context) {
        return writeConflictUri(callerSession(context), url.rawHref ?? url.href, content, context?.signal);
    }
}
