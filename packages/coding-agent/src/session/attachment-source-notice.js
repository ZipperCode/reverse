import { imageAttachmentSource } from "@rva/tui/prompt/image-source";
import { prompt } from "@rva/utils";
import imageAttachmentPrompt from "../prompts/system/image-attachment.md" with { type: "text" };
import videoAttachmentPrompt from "../prompts/system/video-attachment.md" with { type: "text" };
import { IMAGE_ATTACHMENT_TYPE, VIDEO_ATTACHMENT_TYPE } from "./queued-messages";
/**
 * Render the notice for attachment `[Image #index]` / `[Video #index]` so the model can `read`,
 * copy, or upload its file. Undefined when no file backs the attachment.
 */
export function renderAttachmentSourceNotice(image, index, options) {
    const source = imageAttachmentSource(image);
    if (!source)
        return undefined;
    const isVideo = source.kind === "video";
    return {
        customType: isVideo ? VIDEO_ATTACHMENT_TYPE : IMAGE_ATTACHMENT_TYPE,
        content: prompt.render(isVideo ? videoAttachmentPrompt : imageAttachmentPrompt, {
            index: String(index),
            path: source.path,
            askAnswer: options?.askAnswer,
        }),
        details: { index, path: source.path },
    };
}
