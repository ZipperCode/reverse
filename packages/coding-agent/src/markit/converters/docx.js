// Adapted from markit-ai (MIT). See ../NOTICE.
import * as path from "node:path";
import mammoth from "@rva/utils/docx";
import { createTurndown, normalizeTablesHtml } from "../../utils/turndown";
const EXTENSIONS = [".docx"];
const MIMETYPES = ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"];
export class DocxConverter {
    name = "docx";
    accepts(streamInfo) {
        if (streamInfo.extension && EXTENSIONS.includes(streamInfo.extension)) {
            return true;
        }
        if (streamInfo.mimetype && MIMETYPES.some(m => streamInfo.mimetype?.startsWith(m))) {
            return true;
        }
        return false;
    }
    async convert(input, streamInfo) {
        const imageDir = streamInfo.imageDir;
        let imageCount = 0;
        const convertImage = imageDir
            ? mammoth.images.imgElement(image => {
                imageCount++;
                const ext = (image.contentType?.split("/")[1] || "png").replace("jpeg", "jpg");
                const filename = `image_${imageCount}.${ext}`;
                const filepath = path.join(imageDir, filename);
                return image.readBytes().then(async (bytes) => {
                    await Bun.write(filepath, bytes);
                    return { src: filepath, alt: `image_${imageCount}` };
                });
            })
            : mammoth.images.imgElement(image => {
                imageCount++;
                // The data URI is replaced by a placeholder below, so the payload is never read.
                return { src: `data:${image.contentType || "image/png"};base64,`, alt: `image_${imageCount}` };
            });
        const { value: html } = await mammoth.convertToHtml({ buffer: input }, { convertImage });
        const turndown = createTurndown();
        let markdown = turndown.turndown(normalizeTablesHtml(html));
        // Replace data URI images with comment placeholders when no imageDir
        if (!imageDir) {
            markdown = markdown.replace(/!\[([^\]]*)\]\(data:[^)]*\)/g, "<!-- image: $1 -->");
        }
        return { markdown: markdown.trim() };
    }
}
