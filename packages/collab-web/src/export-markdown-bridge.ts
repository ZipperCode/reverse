import { Marked } from "@reverse/utils/marked";

globalThis.reverseMarkdown = { Marked };

declare global {
	var reverseMarkdown: { Marked: typeof Marked } | undefined;
}

export { Marked };
