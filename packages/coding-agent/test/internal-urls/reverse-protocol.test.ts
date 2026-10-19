import { describe, expect, it } from "bun:test";
import {
	InternalUrlRouter,
	ReverseProtocolHandler,
	reverseDocFilename,
	reverseDocRel,
	parseInternalUrl,
} from "@rva/coding-agent/internal-urls";

describe("ReverseProtocolHandler", () => {
	it("registers reverse on InternalUrlRouter and rejects legacy rva", () => {
		const router = InternalUrlRouter.instance();
		expect(router.isBuiltin("reverse")).toBe(true);
		expect(router.isBuiltin("rva")).toBe(false);
		expect(router.getHandler("reverse")).toBeInstanceOf(ReverseProtocolHandler);
		expect(router.getHandler("rva")).toBeUndefined();
	});

	it("resolves documentation files via canonical reverse://", async () => {
		const router = InternalUrlRouter.instance();
		const resource = await router.resolve("reverse://tools/read.md");
		expect(resource.content).toBeDefined();
		expect(resource.contentType).toBe("text/markdown");
		expect(resource.url).toContain("reverse://tools/read.md");
	});

	it("lists documentation with reverse:// URLs for reverse:// root", async () => {
		const router = InternalUrlRouter.instance();
		const resource = await router.resolve("reverse://");
		expect(resource.content).toContain("# Documentation");
		expect(resource.content).toContain("- [tools/read.md](reverse://tools/read.md)");
	});

	it("enumerates canonical reverse:// URLs", async () => {
		const handler = new ReverseProtocolHandler();
		const entries = await handler.enumerate(parseInternalUrl("reverse://"));
		expect(entries.length).toBeGreaterThan(0);
		expect(entries[0].url.startsWith("reverse://")).toBe(true);
	});

	it("parses doc paths and rejects path traversal for reverse://", () => {
		expect(reverseDocRel(parseInternalUrl("reverse://tools/read.md"))).toBe("tools/read.md");
		expect(reverseDocRel(parseInternalUrl("reverse://docs/tools/read.md"))).toBe("tools/read.md");
		expect(reverseDocRel(parseInternalUrl("reverse://"))).toBe("");
		expect(reverseDocRel(parseInternalUrl("reverse://docs"))).toBe("");

		expect(() => reverseDocRel(parseInternalUrl("reverse://../etc/passwd"))).toThrow(
			"Path traversal (..) is not allowed in reverse:// URLs",
		);
	});

	it("provides promptDoc for reverse://", () => {
		const reverseHandler = new ReverseProtocolHandler();
		expect(reverseHandler.promptDoc()).toContain("reverse://");
	});
});
