/**
 * Protocol handler for rva:// URLs (compatibility alias for reverse://).
 *
 * Serves statically embedded documentation files bundled at build time.
 */
import rvaDoc from "../prompts/internal-urls/rva.md" with { type: "text" };
import { ReverseProtocolHandler } from "./reverse-protocol";

/**
 * Handler for legacy rva:// URLs.
 *
 * Resolves documentation file names to their content, or lists available docs,
 * preserving rva:// formatted URLs and links for backward compatibility.
 */
export class RvaProtocolHandler extends ReverseProtocolHandler {
	constructor() {
		super("rva");
	}

	override promptDoc(): string {
		return rvaDoc.trim();
	}
}
