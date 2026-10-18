/**
 * Protocol handler for `attachment://<N>` URLs: image attachments of the
 * calling session, backed by their content-addressed source files.
 */
import { ToolError } from "@rva/tui/tools/tool-errors";
/** Canonical `attachment://<N>` form (no query/hash) as listed by `getImageAttachments`. */
function attachmentUri(url) {
    return `attachment://${url.rawHost}${url.rawPathname ?? ""}`;
}
/** Session image attachments (`attachment://1`), located at their original image files. */
export class AttachmentProtocolHandler {
    scheme = "attachment";
    spec = {
        backing: "file",
        selectors: "none",
        immutable: true,
        imageQuestion: true,
    };
    async resolve(url, context) {
        const uri = attachmentUri(url);
        const attachments = context?.session?.getImageAttachments?.() ?? [];
        const attachment = attachments.find(entry => entry.uri === uri);
        if (!attachment) {
            const availableUris = attachments.map(entry => entry.uri).join(", ") || "none";
            throw new ToolError(`Could not resolve image attachment '${uri}'. Available attachment URIs: ${availableUris}. Use one of the listed attachment URIs, or attach an image first when none are available.`);
        }
        const content = `${attachment.label}: ${attachment.image.mimeType} image attachment stored at ${attachment.sourcePath}`;
        return {
            url: uri,
            content,
            contentType: "text/plain",
            size: Buffer.byteLength(content, "utf-8"),
            sourcePath: attachment.sourcePath,
        };
    }
    async locate(url, context) {
        const uri = attachmentUri(url);
        const attachments = context?.session?.getImageAttachments?.() ?? [];
        return attachments.find(entry => entry.uri === uri)?.sourcePath ?? null;
    }
}
