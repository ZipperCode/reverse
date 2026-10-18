import { isRecord } from "@rva/utils";
import { htmlToBasicMarkdown } from "../../web/scrapers/types";
import { evalImageMetadata } from "../types";
function normalizeDisplayText(text) {
    return text.endsWith("\n") ? text : `${text}\n`;
}
/** Render a MIME bundle into text + structured outputs. */
export async function renderKernelDisplay(content) {
    // Accept both raw bundles ({"text/plain": ...}) and Jupyter-style
    // content envelopes ({ data: {...} }) so callers don't need to unwrap.
    const data = isRecord(content.data) ? content.data : content;
    const outputs = [];
    // Status events bypass the text path entirely — they exist only for TUI hooks.
    if (data["application/x-omp-status"] !== undefined) {
        const statusData = data["application/x-omp-status"];
        if (statusData && typeof statusData === "object" && "op" in statusData) {
            outputs.push({ type: "status", event: statusData });
        }
        return { text: "", outputs };
    }
    const image = data["application/x-omp-image"];
    if (isRecord(image) && typeof image.data === "string" && typeof image.mimeType === "string") {
        outputs.push({
            type: "image",
            data: image.data,
            mimeType: image.mimeType,
            ...evalImageMetadata(image),
        });
    }
    if (typeof data["image/png"] === "string") {
        outputs.push({ type: "image", data: data["image/png"], mimeType: "image/png" });
    }
    if (typeof data["image/jpeg"] === "string") {
        outputs.push({ type: "image", data: data["image/jpeg"], mimeType: "image/jpeg" });
    }
    if (data["application/json"] !== undefined) {
        outputs.push({ type: "json", data: data["application/json"] });
    }
    // text/markdown takes precedence over text/plain (Markdown objects expose both
    // where text/plain is just the repr).
    if (typeof data["text/markdown"] === "string") {
        outputs.push({ type: "markdown" });
        return { text: normalizeDisplayText(String(data["text/markdown"])), outputs };
    }
    if (typeof data["text/plain"] === "string") {
        return { text: normalizeDisplayText(String(data["text/plain"])), outputs };
    }
    if (data["text/html"] !== undefined) {
        const markdown = (await htmlToBasicMarkdown(String(data["text/html"]))) || "";
        return { text: markdown ? normalizeDisplayText(markdown) : "", outputs };
    }
    return { text: "", outputs };
}
