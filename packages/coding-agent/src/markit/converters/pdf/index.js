import { pdfToMarkdown } from "@rva/natives";
const EXTENSIONS = [".pdf"];
const MIMETYPES = ["application/pdf", "application/x-pdf"];
/** Converts PDF buffers to Markdown through the native `pdf-inspector` bridge. */
export class PdfConverter {
    name = "pdf";
    accepts(streamInfo) {
        if (streamInfo.extension && EXTENSIONS.includes(streamInfo.extension)) {
            return true;
        }
        if (streamInfo.mimetype && MIMETYPES.some(m => streamInfo.mimetype?.startsWith(m))) {
            return true;
        }
        return false;
    }
    async convert(input, _streamInfo) {
        const result = await pdfToMarkdown(input);
        const notice = result.pagesNeedingOcr.length > 0
            ? `Text extraction is incomplete for PDF pages ${result.pagesNeedingOcr.join(", ")}. Use the browser prelude to render those pages or OCR them.`
            : undefined;
        const conversion = {
            markdown: notice ? [result.markdown, notice].filter(Boolean).join("\n\n") : result.markdown,
        };
        if (result.title !== undefined)
            conversion.title = result.title;
        return conversion;
    }
}
