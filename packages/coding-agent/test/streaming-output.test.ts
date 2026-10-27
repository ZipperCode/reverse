import { afterEach, describe, expect, test, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@reverse/agent";
import { Settings } from "@reverse/coding-agent/config/settings";
import { ArtifactManager } from "@reverse/coding-agent/session/artifacts";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import {
	ARTIFACT_DEFAULT_HEAD_BYTES,
	ARTIFACT_DEFAULT_MAX_BYTES,
	capArtifactText,
	enforceInlineByteCap,
	formatHeadTruncationNotice,
	formatMiddleElisionMarker,
	formatTailTruncationNotice,
	OutputSink,
	TailBuffer,
	truncateHead,
	truncateHeadBytes,
	truncateLine,
	truncateMiddle,
	truncateTail,
	truncateTailBytes,
} from "@reverse/tui/tools/streaming-output";
import { formatOutputNotice, stripOutputNotice } from "@reverse/tui/tools/output-meta";
import { outputMeta, postProcessToolResult } from "@reverse/coding-agent/tools/output-meta";
import { formatBytes, removeWithRetries } from "@reverse/utils";

const createdTempDirs: string[] = [];
const originalForceProtocol = Bun.env.PI_FORCE_IMAGE_PROTOCOL;
const originalAllowPassthrough = Bun.env.PI_ALLOW_SIXEL_PASSTHROUGH;

async function createTempDir(): Promise<string> {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), "streaming-output-test-"));
	createdTempDirs.push(dir);
	return dir;
}

function byteLength(text: string): number {
	return Buffer.byteLength(text, "utf-8");
}

afterEach(async () => {
	vi.useRealTimers();
	for (const dir of createdTempDirs.splice(0)) {
		await removeWithRetries(dir);
	}
	if (originalForceProtocol === undefined) delete Bun.env.PI_FORCE_IMAGE_PROTOCOL;
	else Bun.env.PI_FORCE_IMAGE_PROTOCOL = originalForceProtocol;
	if (originalAllowPassthrough === undefined) delete Bun.env.PI_ALLOW_SIXEL_PASSTHROUGH;
	else Bun.env.PI_ALLOW_SIXEL_PASSTHROUGH = originalAllowPassthrough;
});

describe("truncateTailBytes", () => {
	test("returns source when already under limit", () => {
		const text = "hello";
		expect(truncateTailBytes(text, 10)).toEqual({ text: "hello", bytes: 5 });
	});

	test("truncates from end without breaking UTF-8 boundaries", () => {
		const text = "a😀b";
		const result = truncateTailBytes(text, 4);
		expect(result).toEqual({ text: "b", bytes: 1 });
		expect(result.text).not.toContain("\uFFFD");
	});

	test("accepts Uint8Array input", () => {
		const bytes = new TextEncoder().encode("abc😀");
		const result = truncateTailBytes(bytes, 4);
		expect(result.text).toBe("😀");
		expect(result.bytes).toBe(4);
	});
});

describe("truncateHeadBytes", () => {
	test("returns source when already under limit", () => {
		const text = "hello";
		expect(truncateHeadBytes(text, 10)).toEqual({ text: "hello", bytes: 5 });
	});

	test("truncates from start without breaking UTF-8 boundaries", () => {
		const text = "a😀b";
		const result = truncateHeadBytes(text, 2);
		expect(result).toEqual({ text: "a", bytes: 1 });
		expect(result.text).not.toContain("\uFFFD");
	});

	test("returns empty when maxBytes is zero", () => {
		const result = truncateHeadBytes("abc", 0);
		expect(result).toEqual({ text: "", bytes: 0 });
	});
});

describe("truncateHead", () => {
	test("returns unmodified content when within limits", () => {
		const content = "a\nb";
		const result = truncateHead(content, { maxLines: 10, maxBytes: 20 });
		expect(result.truncated).toBeUndefined();
		expect(result.content).toBe(content);
		expect(result.truncatedBy).toBeUndefined();
	});

	test("handles first line exceeding byte limit", () => {
		const result = truncateHead("abcdef\nnext", { maxBytes: 3, maxLines: 10 });
		expect(result.content).toBe("");
		expect(result.truncated).toBe(true);
		expect(result.truncatedBy).toBe("bytes");
		expect(result.firstLineExceedsLimit).toBe(true);
	});

	test("includes first line when text fits exact byte budget", () => {
		const result = truncateHead("abc\nx", { maxBytes: 3, maxLines: 10 });
		expect(result.content).toBe("abc");
		expect(result.truncated).toBe(true);
		expect(result.truncatedBy).toBe("bytes");
		expect(result.firstLineExceedsLimit).toBe(false);
		expect(result.outputBytes).toBe(byteLength("abc"));
	});
	test("truncates by line count", () => {
		const result = truncateHead("l1\nl2\nl3", { maxLines: 2, maxBytes: 100 });
		expect(result.content).toBe("l1\nl2");
		expect(result.truncatedBy).toBe("lines");
		expect(result.outputLines).toBe(2);
	});

	test("truncates by byte budget using complete lines", () => {
		const result = truncateHead("12345\nabc\nz", { maxLines: 10, maxBytes: 7 });
		expect(result.content).toBe("12345");
		expect(result.truncatedBy).toBe("bytes");
		expect(result.lastLinePartial).toBe(false);
		expect(result.outputBytes).toBe(byteLength("12345"));
	});
});

describe("truncateTail", () => {
	test("returns unmodified content when within limits", () => {
		const content = "a\nb";
		const result = truncateTail(content, { maxLines: 10, maxBytes: 20 });
		expect(result.truncated).toBeUndefined();
		expect(result.content).toBe(content);
		expect(result.truncatedBy).toBeUndefined();
	});

	test("truncates by line count", () => {
		const result = truncateTail("l1\nl2\nl3", { maxLines: 2, maxBytes: 100 });
		expect(result.content).toBe("l2\nl3");
		expect(result.truncatedBy).toBe("lines");
		expect(result.outputLines).toBe(2);
	});

	test("truncates by byte budget while preserving line boundaries", () => {
		const result = truncateTail("aaa\nbbbb\ncc", { maxLines: 10, maxBytes: 6 });
		expect(result.content).toBe("cc");
		expect(result.truncatedBy).toBe("bytes");
		expect(result.lastLinePartial).toBe(false);
	});

	test("returns partial single line when last line exceeds byte limit", () => {
		const result = truncateTail("abcdefghij", { maxLines: 10, maxBytes: 4 });
		expect(result.content).toBe("ghij");
		expect(result.truncatedBy).toBe("bytes");
		expect(result.lastLinePartial).toBe(true);
	});

	test("fills the remaining byte budget from a giant line before smaller trailing lines", () => {
		const result = truncateTail("abcdefghijk\n}\n```", { maxLines: 10, maxBytes: 10 });

		expect(result.content).toBe("hijk\n}\n```");
		expect(result.truncatedBy).toBe("bytes");
		expect(result.outputLines).toBe(3);
		expect(result.outputBytes).toBe(10);
		expect(result.partialByteWindows).toBe(true);
		expect(result.lastLinePartial).toBe(false);
	});
});

describe("truncateLine", () => {
	test("does not truncate short lines", () => {
		expect(truncateLine("hello", 10)).toEqual({ text: "hello", wasTruncated: false });
	});

	test("truncates long lines with ellipsis", () => {
		expect(truncateLine("abcdefgh", 5)).toEqual({ text: "abcde…", wasTruncated: true });
	});
});

describe("TailBuffer", () => {
	test("keeps trailing bytes under budget", () => {
		const tail = new TailBuffer(5);
		tail.append("abc");
		tail.append("def");
		expect(tail.text()).toBe("bcdef");
		expect(tail.bytes()).toBe(5);
	});

	test("handles multibyte data and empty appends", () => {
		const tail = new TailBuffer(4);
		tail.append("");
		tail.append("😀");
		tail.append("x");
		expect(tail.text()).toBe("x");
		expect(tail.bytes()).toBe(1);
	});

	test("streams the same window as tail-truncating the whole output", () => {
		const series = [
			["abc", "de\n", "fghij", "k"],
			["ab", "é中", "😀x", "line\n", "✓ ok", "yy😀", "z"],
		];
		for (const chunks of series) {
			for (const max of [3, 4, 5, 7, 9, 12, 20]) {
				const tail = new TailBuffer(max);
				let all = "";
				for (let round = 0; round < 3; round++) {
					for (const chunk of chunks) {
						tail.append(chunk);
						all += chunk;
						const expected = truncateTailBytes(all, max);
						expect(tail.text()).toBe(expected.text);
						expect(tail.bytes()).toBe(expected.bytes);
					}
				}
			}
		}
	});

	test("joins a surrogate pair split across appends before trimming", () => {
		const tail = new TailBuffer(6);
		tail.append("ab\uD83D");
		expect(tail.text()).toBe("ab\uD83D");
		tail.append("\uDE00cd");
		expect(tail.text()).toBe("😀cd");
		expect(tail.bytes()).toBe(6);
	});

	test("keeps the character after a lone surrogate when trimming a budget-sized chunk", () => {
		const tail = new TailBuffer(6);
		tail.append("ab\uD800x");
		tail.append("yzw");
		expect(tail.text()).toBe("xyzw");
		expect(tail.bytes()).toBe(4);
	});
});

describe("OutputSink", () => {
	test("tracks totals and adds notice in dump", async () => {
		const sink = new OutputSink();
		await sink.push("hello\nworld");
		const dumped = await sink.dump("notice");

		expect(dumped.output).toBe("[notice]\nhello\nworld");
		expect(dumped.truncated).toBe(false);
		expect(dumped.totalLines).toBe(2);
		expect(dumped.totalBytes).toBe(byteLength("hello\nworld"));
		expect(dumped.outputLines).toBe(2);
		expect(dumped.outputBytes).toBe(byteLength("hello\nworld"));
	});

	test("counts lines correctly when chunks contain no newlines", async () => {
		const sink = new OutputSink();
		await sink.push("abc");
		await sink.push("def");
		const dumped = await sink.dump();

		expect(dumped.totalLines).toBe(1);
		expect(dumped.outputLines).toBe(1);
	});

	test("counts all newline boundaries across chunk splits", async () => {
		const sink = new OutputSink();
		await sink.push("a\n");
		await sink.push("b\n\n");
		await sink.push("c");
		const dumped = await sink.dump();

		expect(dumped.output).toBe("a\nb\n\nc");
		expect(dumped.totalLines).toBe(4);
		expect(dumped.outputLines).toBe(4);
	});
	test("normalizes carriage-return progress frames across chunk boundaries", async () => {
		const chunks: string[] = [];
		const sink = new OutputSink({ onChunk: chunk => chunks.push(chunk) });

		sink.push("start\r");
		sink.push("one\r");
		sink.push("two\r");
		sink.push("\n");
		const dumped = await sink.dump();

		expect(chunks.join("")).toBe("start\none\ntwo\n");
		expect(dumped.output).toBe("start\none\ntwo\n");
	});

	test("preserves SIXEL chunks when passthrough gates are enabled", async () => {
		const sixel = "\x1bPqabc\x1b\\";
		Bun.env.PI_FORCE_IMAGE_PROTOCOL = "sixel";
		Bun.env.PI_ALLOW_SIXEL_PASSTHROUGH = "1";
		const chunks: string[] = [];
		const sink = new OutputSink({ onChunk: chunk => chunks.push(chunk) });
		await sink.push(`before\n${sixel}\nafter`);
		const dumped = await sink.dump();
		expect(chunks).toHaveLength(1);
		expect(chunks[0]).toContain(sixel);
		expect(dumped.output).toContain(sixel);
	});

	test("strips SIXEL chunks when passthrough gates are disabled", async () => {
		const sixel = "\x1bPqabc\x1b\\";
		delete Bun.env.PI_FORCE_IMAGE_PROTOCOL;
		delete Bun.env.PI_ALLOW_SIXEL_PASSTHROUGH;
		const sink = new OutputSink();
		await sink.push(sixel);
		const dumped = await sink.dump();
		expect(dumped.output).not.toContain("\x1bPq");
		expect(dumped.output).toBe("");
	});

	test("truncates in-memory output when spill threshold is exceeded", async () => {
		const sink = new OutputSink({ spillThreshold: 5 });
		await sink.push("abc");
		await sink.push("def");

		const dumped = await sink.dump();
		expect(dumped.truncated).toBe(true);
		expect(dumped.output).toBe("bcdef");
		expect(dumped.totalBytes).toBe(6);
		expect(dumped.outputBytes).toBe(5);
	});

	test("spills full output to artifact file when artifact path is provided", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "output.log");
		const sink = new OutputSink({
			artifactPath,
			artifactId: "artifact-1",
			spillThreshold: 5,
		});

		await sink.push("abc");
		await sink.push("def");
		const dumped = await sink.dump();
		const artifactText = await Bun.file(artifactPath).text();

		expect(dumped.truncated).toBe(true);
		expect(dumped.artifactId).toBe("artifact-1");
		expect(artifactText).toBe("abcdef");
		expect(dumped.output).toBe("bcdef");
	});

	test("artifact file includes head-retained bytes when head retention is enabled", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "output.log");
		const sink = new OutputSink({
			artifactPath,
			artifactId: "artifact-2",
			spillThreshold: 5,
			headBytes: 4,
		});

		// First chunk lands fully in the head window; later chunks overflow the
		// tail budget and trigger the artifact spill.
		sink.push("head");
		sink.push("abc");
		sink.push("defgh");
		const dumped = await sink.dump();
		const artifactText = await Bun.file(artifactPath).text();

		expect(dumped.truncated).toBe(true);
		expect(artifactText).toBe("headabcdefgh");
	});

	test("throttled onChunk coalesces held-back chunks instead of dropping them", async () => {
		const chunks: string[] = [];
		const sink = new OutputSink({ onChunk: chunk => chunks.push(chunk), chunkThrottleMs: 60_000 });
		sink.push("a");
		// Inside the throttle window: buffered, not dropped.
		sink.push("b");
		sink.push("c");
		const dumped = await sink.dump();

		// First push fires immediately; dump flushes the coalesced remainder.
		expect(chunks).toEqual(["a", "bc"]);
		expect(dumped.output).toBe("abc");
	});

	test("throttled onChunk emits a quiet tail at the throttle boundary", () => {
		vi.useFakeTimers();
		const chunks: string[] = [];
		const sink = new OutputSink({ onChunk: chunk => chunks.push(chunk), chunkThrottleMs: 20 });

		sink.push("a");
		sink.push("b");
		expect(chunks).toEqual(["a"]);

		vi.advanceTimersByTime(20);

		expect(chunks).toEqual(["a", "b"]);
	});

	test("dump flushes a throttled tail once and cancels its timer", async () => {
		vi.useFakeTimers();
		const chunks: string[] = [];
		const sink = new OutputSink({ onChunk: chunk => chunks.push(chunk), chunkThrottleMs: 20 });

		sink.push("a");
		sink.push("b");
		expect((await sink.dump()).output).toBe("ab");
		expect(chunks).toEqual(["a", "b"]);

		vi.advanceTimersByTime(20);

		expect(chunks).toEqual(["a", "b"]);
	});

	test("replace cancels a throttled tail and discards its pending preview", () => {
		vi.useFakeTimers();
		const chunks: string[] = [];
		const sink = new OutputSink({ onChunk: chunk => chunks.push(chunk), chunkThrottleMs: 20 });

		sink.push("a");
		sink.push("superseded");
		sink.replace("replacement");
		vi.advanceTimersByTime(20);

		expect(chunks).toEqual(["a"]);
	});

	test("caps artifact-on-disk size: head + notice + tail stays <= artifactMaxBytes", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "capped.log");
		const sink = new OutputSink({
			artifactPath,
			artifactId: "art-cap",
			spillThreshold: 16,
			artifactMaxBytes: 256,
			artifactHeadBytes: 64,
		});

		const headBlock = "HEAD0123456789AB".repeat(4); // 64 bytes
		const middleBlock = "M".repeat(384);
		const tailBlock = "0123456789ABCDEF".repeat(4); // 64 bytes
		const payload = `${headBlock}${middleBlock}${tailBlock}`; // 512 bytes
		sink.push(payload);
		const summary = await sink.dump();
		const artifactText = await Bun.file(artifactPath).text();
		const diskBytes = byteLength(artifactText);

		expect(diskBytes).toBeLessThanOrEqual(256);
		expect(summary.artifactBytes).toBe(diskBytes);
		expect(summary.artifactMaxBytes).toBe(256);
		expect(artifactText.startsWith(headBlock)).toBe(true);
		expect(artifactText.endsWith("89ABCDEF")).toBe(true);
		expect(artifactText).toContain("[ARTIFACT TRUNCATED:");
		expect(artifactText).toContain("elided from the middle");
		const stripped = artifactText.replace(/\n?\[ARTIFACT TRUNCATED:[^\]]+\]\n?/g, "");
		expect(summary.artifactElidedBytes).toBe(byteLength(payload) - byteLength(stripped));
	});

	test("artifact cap stays a no-op when total stream fits inside the cap", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "small.log");
		const sink = new OutputSink({
			artifactPath,
			artifactId: "art-small",
			spillThreshold: 4,
			artifactMaxBytes: 64,
			artifactHeadBytes: 32,
		});

		// Forces spill (in-memory tail) but file should stay verbatim.
		sink.push("abcde");
		sink.push("fghij");
		const summary = await sink.dump();
		const artifactText = await Bun.file(artifactPath).text();

		expect(artifactText).toBe("abcdefghij");
		expect(summary.artifactBytes).toBe(10);
		expect(summary.artifactElidedBytes).toBeUndefined();
		expect(artifactText).not.toContain("[ARTIFACT TRUNCATED:");
	});

	test("artifact stays verbatim when spillover exceeds head budget but still fits inside the cap", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "spilled.log");
		const sink = new OutputSink({
			artifactPath,
			artifactId: "art-spilled",
			spillThreshold: 8,
			artifactMaxBytes: 32,
			artifactHeadBytes: 16,
		});

		// 24 bytes total: head takes 16, tail ring receives 8 (fits, no eviction).
		const payload = "0123456789ABCDEFghijklmn";
		sink.push(payload);
		const summary = await sink.dump();
		const artifactText = await Bun.file(artifactPath).text();

		expect(artifactText).toBe(payload);
		expect(summary.artifactBytes).toBe(24);
		expect(summary.artifactElidedBytes).toBeUndefined();
		expect(artifactText).not.toContain("[ARTIFACT TRUNCATED:");
	});

	test("artifact cap stays bounded across many small streaming chunks (including notice)", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "stream.log");
		const sink = new OutputSink({
			artifactPath,
			artifactId: "art-stream",
			spillThreshold: 16,
			artifactMaxBytes: 256,
			artifactHeadBytes: 64,
		});

		// 200 chunks * 4 bytes = 800 bytes streamed; total on-disk bytes <= 256.
		for (let i = 0; i < 200; i++) {
			sink.push(String(i % 10).repeat(4));
		}
		const summary = await sink.dump();
		const artifactText = await Bun.file(artifactPath).text();
		const diskBytes = byteLength(artifactText);

		expect(diskBytes).toBeLessThanOrEqual(256);
		expect(summary.artifactBytes).toBe(diskBytes);
		expect(artifactText).toContain("[ARTIFACT TRUNCATED:");
	});

	test("head-retained bytes count against the artifact cap", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "head-capped.log");
		const sink = new OutputSink({
			artifactPath,
			artifactId: "art-head-cap",
			spillThreshold: 16,
			headBytes: 16,
			artifactMaxBytes: 180,
			artifactHeadBytes: 32,
		});

		for (let i = 0; i < 80; i++) {
			sink.push("abcd");
		}
		const summary = await sink.dump();
		const artifactText = await Bun.file(artifactPath).text();
		const diskBytes = byteLength(artifactText);

		expect(diskBytes).toBeLessThanOrEqual(180);
		expect(summary.artifactBytes).toBe(diskBytes);
		expect(artifactText.startsWith("abcd".repeat(8))).toBe(true);
		expect(artifactText).toContain("[ARTIFACT TRUNCATED:");
	});

	test("tiny caps and split UTF-8 multibyte chunks never exceed artifactMaxBytes or corrupt UTF-8", async () => {
		const dir = await createTempDir();
		for (const [cap, head] of [
			[16, 8],
			[32, 16],
			[64, 32],
			[180, 45],
		] as const) {
			const artifactPath = path.join(dir, `tiny-${cap}.log`);
			const sink = new OutputSink({
				artifactPath,
				artifactId: `tiny-${cap}`,
				spillThreshold: 8,
				artifactMaxBytes: cap,
				artifactHeadBytes: head,
			});
			const chunks = ["αβγ", "😀🎉🚀", "中文逆向测试", "é€😀".repeat(25)];
			for (const chunk of chunks) sink.push(chunk);
			const summary = await sink.dump();
			const rawBytes = await Bun.file(artifactPath).bytes();
			const decoded = new TextDecoder("utf-8", { fatal: true }).decode(rawBytes);

			expect(rawBytes.byteLength).toBeLessThanOrEqual(cap);
			expect(summary.artifactBytes).toBe(rawBytes.byteLength);
			expect(summary.artifactElidedBytes).toBeGreaterThan(0);
			expect(decoded.includes("\uFFFD")).toBe(false);
		}
	});

	test("artifactMaxBytes=0 restores unbounded artifact streaming", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "uncapped.log");
		const sink = new OutputSink({
			artifactPath,
			artifactId: "art-uncapped",
			spillThreshold: 16,
			artifactMaxBytes: 0,
		});

		const payload = "X".repeat(1024);
		await sink.push(payload);
		await sink.dump();
		const artifactText = await Bun.file(artifactPath).text();

		expect(artifactText).toBe(payload);
		expect(artifactText).not.toContain("[ARTIFACT TRUNCATED:");
	});

	test("default sink caps an oversized artifact at 4 MiB (including truncation notice) between head and tail", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "oversized.log");
		const sink = new OutputSink({ artifactPath, artifactId: "art-oversized" });

		expect(ARTIFACT_DEFAULT_MAX_BYTES).toBe(4 * 1024 * 1024);
		expect(ARTIFACT_DEFAULT_HEAD_BYTES).toBe(1 * 1024 * 1024);

		const line = `${"x".repeat(1023)}\n`;
		const block = line.repeat(64); // 64 KiB, a typical pipe read
		sink.push("HEAD-START\n");
		for (let i = 0; i < 96; i++) sink.push(block); // 6 MiB (> 4 MiB default cap)
		sink.push("TAIL-END\n");
		const summary = await sink.dump();
		const artifactText = await Bun.file(artifactPath).text();
		const diskBytes = byteLength(artifactText);

		expect(summary.artifactId).toBe("art-oversized");
		expect(diskBytes).toBeLessThanOrEqual(ARTIFACT_DEFAULT_MAX_BYTES);
		expect(diskBytes).toBeGreaterThan(ARTIFACT_DEFAULT_MAX_BYTES - 512);
		expect(summary.artifactBytes).toBe(diskBytes);
		expect(summary.artifactElidedBytes).toBeGreaterThan(2 * 1024 * 1024);
		expect(artifactText.startsWith("HEAD-START\n")).toBe(true);
		expect(artifactText.endsWith(`${line}TAIL-END\n`)).toBe(true);
		const notices = artifactText.match(/\[ARTIFACT TRUNCATED:[^\]]+\]/g) ?? [];
		expect(notices).toHaveLength(1);
		expect(notices[0]).toContain("elided from the middle");
		expect(artifactText.indexOf("[ARTIFACT TRUNCATED:")).toBe(ARTIFACT_DEFAULT_HEAD_BYTES + 1);
	});

	test("default sink keeps a spilled artifact below the cap lossless", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "spilled-small.log");
		const sink = new OutputSink({ artifactPath, artifactId: "art-small-default" });

		const payload = Array.from({ length: 4096 }, (_, i) => `line ${i} ${"y".repeat(40)}`).join("\n");
		sink.push(payload);
		const summary = await sink.dump();

		expect(summary.truncated).toBe(true);
		expect(summary.artifactId).toBe("art-small-default");
		expect(summary.artifactElidedBytes).toBeUndefined();
		expect(await Bun.file(artifactPath).text()).toBe(payload);
		const notice = formatOutputNotice(outputMeta().truncationFromSummary(summary, { direction: "tail" }).get());
		expect(notice).toContain("Read artifact://art-small-default for full output");
	});

	test("a small cap without an explicit head budget still keeps the most recent output within cap", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "small-cap.log");
		const sink = new OutputSink({
			artifactPath,
			artifactId: "art-small-cap",
			spillThreshold: 8,
			artifactMaxBytes: 256,
		});

		const payload = Array.from({ length: 120 }, (_, i) => String(i).padStart(4, "0")).join(""); // 480 bytes
		sink.push(payload);
		const summary = await sink.dump();
		const artifactText = await Bun.file(artifactPath).text();
		const diskBytes = byteLength(artifactText);

		expect(diskBytes).toBeLessThanOrEqual(256);
		expect(summary.artifactBytes).toBe(diskBytes);
		expect(artifactText.startsWith(payload.slice(0, 128))).toBe(true);
		expect(artifactText.endsWith("01180119")).toBe(true);
	});

	test("a capped artifact is advertised as a head/tail sample, not as full output", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "sampled.log");
		const sink = new OutputSink({
			artifactPath,
			artifactId: "art-sampled",
			spillThreshold: 16,
			maxColumns: 8,
			artifactMaxBytes: 200,
			artifactHeadBytes: 32,
		});

		// 340 bytes of 17-byte lines: over the 200-byte artifact cap and the 8-byte column cap.
		sink.push("0123456789ABCDEF\n".repeat(20));
		const summary = await sink.dump();
		const diskBytes = byteLength(await Bun.file(artifactPath).text());
		expect(diskBytes).toBeLessThanOrEqual(200);
		expect(summary.artifactId).toBe("art-sampled");
		expect(summary.artifactBytes).toBe(diskBytes);
		expect(summary.artifactElidedBytes).toBeGreaterThan(140);

		const elided = summary.artifactElidedBytes!;
		const formattedElided = formatBytes(elided);
		const meta = outputMeta().truncationFromSummary(summary, { direction: "tail" }).get();
		expect(meta?.truncation?.artifactElidedBytes).toBe(elided);
		expect(meta?.truncation?.artifactBytes).toBe(diskBytes);
		expect(meta?.truncation?.artifactMaxBytes).toBe(200);
		expect(meta?.limits?.columnTruncated?.artifactElidedBytes).toBe(elided);
		const notice = formatOutputNotice(meta);
		// Both the truncation and the column-cap notices carry the partial sample reference.
		const expectedRef = `Read artifact://art-sampled for a head/tail sample of the output; ${formattedElided} from its middle was not saved`;
		expect(notice.split(expectedRef).length - 1).toBe(2);
		expect(notice).not.toContain("for full output");
	});
	test("createInput decodes streamed UTF-8 chunks correctly", async () => {
		const sink = new OutputSink();
		const writer = sink.createInput().getWriter();
		const bytes = new TextEncoder().encode("😀X");

		await writer.write(bytes.subarray(0, 2));
		await writer.write(bytes.subarray(2));
		await writer.close();

		const dumped = await sink.dump();
		expect(dumped.output).toBe("😀X");
		expect(dumped.totalBytes).toBe(byteLength("😀X"));
	});
});

describe("truncation notice formatting", () => {
	test("formatTailTruncationNotice returns empty string for non-truncated results", () => {
		const truncation = truncateTail("a\nb", { maxLines: 10, maxBytes: 50 });
		expect(formatTailTruncationNotice(truncation)).toBe("");
	});

	test("formatTailTruncationNotice distinguishes partial leading and final lines", () => {
		const partialLineTruncation = truncateTail("abcdefghij", { maxLines: 10, maxBytes: 4 });
		const partialLineNotice = formatTailTruncationNotice(partialLineTruncation, {
			fullOutputPath: "/tmp/full.log",
			originalContent: "abcdefghij",
			suffix: " [suffix]",
		});
		expect(partialLineNotice).toBe(
			"\n\n[Showing last 4B of line 1 (line is 10B). Full output: /tmp/full.log [suffix]]",
		);

		const lineTruncation = truncateTail("l1\nl2\nl3", { maxLines: 2, maxBytes: 100 });
		expect(formatTailTruncationNotice(lineTruncation)).toBe("\n\n[Showing lines 2-3 of 3]");

		const byteTruncation = truncateTail("aaa\nbbbb\ncc", { maxLines: 10, maxBytes: 6 });
		expect(formatTailTruncationNotice(byteTruncation)).toBe("\n\n[Showing lines 3-3 of 3]");

		const leadingPartialTruncation = truncateTail("abcdefghijk\n}\n```", { maxLines: 10, maxBytes: 10 });
		expect(formatTailTruncationNotice(leadingPartialTruncation)).toBe(
			"\n\n[Showing last 10B across lines 1-3 of 3; line 1 is partial]",
		);
	});

	test("formatHeadTruncationNotice returns empty string for non-truncated results", () => {
		const truncation = truncateHead("a\nb", { maxLines: 10, maxBytes: 50 });
		expect(formatHeadTruncationNotice(truncation)).toBe("");
	});

	test("formatHeadTruncationNotice formats head truncation range", () => {
		const lineTruncation = truncateHead("l1\nl2\nl3", { maxLines: 2, maxBytes: 100 });
		expect(formatHeadTruncationNotice(lineTruncation)).toBe("\n\n[Showing lines 1-2 of 3. Use :3 to continue]");

		const byteTruncation = truncateHead("12345\nabc\nz", { maxLines: 10, maxBytes: 7 });
		expect(
			formatHeadTruncationNotice(byteTruncation, {
				startLine: 100,
				totalFileLines: 500,
			}),
		).toBe("\n\n[Showing lines 100-100 of 500. Use :101 to continue]");
	});
});

describe("truncateMiddle", () => {
	test("returns content unchanged when within budget", () => {
		const result = truncateMiddle("a\nb\nc", { maxBytes: 100, maxLines: 10 });
		expect(result.truncated).toBeFalsy();
		expect(result.content).toBe("a\nb\nc");
	});

	test("keeps head and tail with marker for byte-overflow content", () => {
		const lines = Array.from({ length: 12 }, (_, i) => `line-${i + 1}`).join("\n");
		const result = truncateMiddle(lines, {
			maxBytes: 24, // 12 bytes head + 12 bytes tail
			maxLines: 12,
			maxHeadBytes: 12,
			maxHeadLines: 3,
		});
		expect(result.truncated).toBe(true);
		expect(result.truncatedBy).toBe("middle");
		// Must contain first line and last line, plus the elision marker.
		expect(result.content.startsWith("line-1\n")).toBe(true);
		expect(result.content.endsWith("line-12")).toBe(true);
		expect(result.content).toContain("elided");
		expect(result.content).not.toContain("line-7"); // a middle line
		expect(result.elidedLines).toBeGreaterThan(0);
		expect(result.elidedBytes).toBeGreaterThan(0);
	});

	test("uses non-overlapping byte windows when the first line exceeds the head budget", () => {
		const giantFirstLine = `${"x".repeat(200)}\nshort-2\nshort-3`;
		const result = truncateMiddle(giantFirstLine, {
			maxBytes: 40,
			maxLines: 10,
			maxHeadBytes: 8,
			maxHeadLines: 1,
		});
		expect(result.truncated).toBe(true);
		expect(result.truncatedBy).toBe("middle");
		expect(result.content.startsWith("xxxxxxxx")).toBe(true);
		expect(result.content.endsWith("short-3")).toBe(true);
		expect(result.content).toContain("elided");
		expect(result.elidedBytes).toBeGreaterThan(0);
		expect(result.headLines).toBe(1);
		expect(result.tailLines).toBe(3);
		expect(result.partialByteWindows).toBe(true);
		expect(result.lastLinePartial).toBe(false);
	});

	test("does not duplicate overlapping fallback windows", () => {
		const content = `${"x".repeat(5000)}\n${Array.from({ length: 100 }, (_, i) => `line-${i}`).join("\n")}`;
		const result = truncateMiddle(content, { maxBytes: 8192, maxLines: 80 });

		expect(result.truncatedBy).toBe("middle");
		expect(result.elidedBytes).toBeGreaterThan(0);
		expect(result.content).not.toContain("[…0B elided…]");
		expect(result.headLines).toBe(1);
		expect(result.tailLines).toBeLessThanOrEqual(40);
		expect(result.outputBytes).toBeLessThanOrEqual(8192 + 64);
	});

	test("marks multi-line partial byte windows so exact ranges are omitted", () => {
		const content = `${"x".repeat(20_000)}\n${"y".repeat(20_000)}`;
		const result = truncateMiddle(content, { maxBytes: 8192, maxLines: 80 });

		expect(result.truncatedBy).toBe("middle");
		expect(result.partialByteWindows).toBe(true);
		expect(result.elidedBytes).toBeGreaterThan(0);
	});

	test("keeps a giant trailing line within budget", () => {
		const content = `label\n${"x".repeat(20_000)}`;
		const result = truncateMiddle(content, { maxBytes: 8192, maxLines: 80 });

		expect(result.truncated).toBe(true);
		expect(result.truncatedBy).toBe("middle");
		expect(result.content.startsWith("label\n")).toBe(true);
		expect(result.content).toContain("elided");
		expect(result.outputBytes).toBeLessThanOrEqual(8192 + 64);
	});

	test("marks single-line byte windows so line ranges can be omitted", () => {
		const result = truncateMiddle("x".repeat(20_000), { maxBytes: 8192, maxLines: 80 });

		expect(result.truncatedBy).toBe("middle");
		expect(result.partialByteWindows).toBe(true);
		expect(result.headLines).toBe(1);
		expect(result.tailLines).toBe(1);
	});

	test("formatMiddleElisionMarker uses lines, falling back to bytes for <=1 line", () => {
		expect(formatMiddleElisionMarker(0, 512)).toBe("[…512B elided…]");
		expect(formatMiddleElisionMarker(1, 100)).toBe("[…100B elided…]");
		expect(formatMiddleElisionMarker(123, 4096)).toBe("[…123ln elided…]");
	});
});

describe("OutputSink head-retain mode", () => {
	test("middle elision splices head, marker, and tail", async () => {
		const sink = new OutputSink({ spillThreshold: 6, headBytes: 6 });
		// Total 36 bytes: head ~6, tail ~6, middle ~24 elided.
		const lines = Array.from({ length: 12 }, (_, i) => `L${i}`).join("\n");
		await sink.push(lines);

		const dumped = await sink.dump();
		expect(dumped.truncated).toBe(true);
		expect(dumped.elidedBytes ?? 0).toBeGreaterThan(0);
		expect(dumped.elidedLines ?? 0).toBeGreaterThan(0);
		expect(dumped.output.startsWith("L0\n")).toBe(true);
		expect(dumped.output.endsWith("L11")).toBe(true);
		expect(dumped.output).toContain("elided");
		expect(dumped.totalBytes).toBe(byteLength(lines));
	});

	test("head fills cleanly across chunks without elision when total fits", async () => {
		const sink = new OutputSink({ spillThreshold: 50, headBytes: 4 });
		await sink.push("abcdefgh");
		const dumped = await sink.dump();
		expect(dumped.output).toBe("abcdefgh");
		expect(dumped.truncated).toBe(false);
		expect(dumped.elidedBytes).toBeUndefined();
	});

	test("replace + push appends to tail and emits no elision marker", async () => {
		// Simulates the bash-minimizer flow: large raw stream is replaced with a
		// short minimized text, then an artifact-link line is pushed. The push
		// must land at the END of the buffer (after the minimized text), and the
		// stale pre-replace totals must NOT trigger the middle-elision branch in
		// dump().
		const sink = new OutputSink({ spillThreshold: 1024, headBytes: 64 });
		// Feed a long original stream so #totalBytes/#totalLines climb high.
		const noisy = Array.from({ length: 50 }, (_, i) => `noise line ${i}`).join("\n");
		await sink.push(noisy);

		sink.replace("OK\n");
		await sink.push("[raw output: artifact://8]\n");

		const dumped = await sink.dump();
		expect(dumped.output).toBe("OK\n[raw output: artifact://8]\n");
		expect(dumped.output).not.toContain("elided");
		expect(dumped.elidedBytes).toBeUndefined();
		expect(dumped.elidedLines).toBeUndefined();
		expect(dumped.truncated).toBe(false);
		// Counters realign to the authoritative buffer + the subsequent push.
		expect(dumped.totalBytes).toBe(byteLength("OK\n[raw output: artifact://8]\n"));
	});

	test("middle-elided dump body fits the inline budget (no double truncation)", async () => {
		// Regression: the head and tail windows each had their own full budget,
		// so an elided dump body could reach headBytes + spillThreshold and
		// re-trip enforceInlineByteCap at the tool-result boundary — truncating
		// a second time and saving a duplicate artifact whose id disagreed with
		// the truncation notice's `Read artifact://N for full output`.
		const spillThreshold = 1000;
		const sink = new OutputSink({ spillThreshold, headBytes: 400 });
		const lines = Array.from({ length: 400 }, (_, i) => `line ${i}`).join("\n");
		sink.push(lines);

		const dumped = await sink.dump();
		expect(dumped.truncated).toBe(true);
		expect(dumped.elidedLines ?? 0).toBeGreaterThan(0);
		// Head window + elision marker + tail window share the one budget
		// (small slack for the marker and separators).
		expect(byteLength(dumped.output)).toBeLessThanOrEqual(spillThreshold + 64);

		let saved: string | undefined;
		const capped = await enforceInlineByteCap(dumped.output, {
			maxBytes: spillThreshold + 2048,
			saveArtifact: full => {
				saved = full;
				return "duplicate";
			},
		});
		expect(capped).toBe(dumped.output);
		expect(saved).toBeUndefined();
	});

	test("preview() matches the dump body mid-stream and onChunk already sees the chunk", async () => {
		const previews: string[] = [];
		const sink: OutputSink = new OutputSink({
			spillThreshold: 64,
			headBytes: 16,
			onChunk: () => previews.push(sink.preview()),
		});
		for (let i = 0; i < 40; i++) sink.push(`row ${i}\n`);
		expect(previews.at(-1)).toEndWith("row 39\n");
		const preview = sink.preview();
		const dumped = await sink.dump();
		expect(preview).toBe(dumped.output);
		expect(preview).toStartWith("row 0\n");
		expect(preview).toContain("elided");
	});

	test("preview() omits the newline dump() adds after a trailing carriage return", async () => {
		const sink = new OutputSink({ spillThreshold: 1024 });
		sink.push("progress 50%\r");
		expect(sink.preview()).toBe("progress 50%");
		expect((await sink.dump()).output).toBe("progress 50%\n");
	});
});

describe("OutputSink maxColumns (per-line cap)", () => {
	test("truncates a single overlong line with an ellipsis and drops the rest", async () => {
		const sink = new OutputSink({ maxColumns: 8, spillThreshold: 1000 });
		await sink.push(`short\n${"x".repeat(50)}\nfooter`);

		const dumped = await sink.dump();
		// A per-line column cap trims individual lines but does not truncate the
		// output window: every line is still present, so `truncated` stays false.
		// (Regression: column-cap-only output was misreported as a byte-window
		// truncation, producing a bogus "Showing lines X-Y … limit" footer — #4735.)
		expect(dumped.truncated).toBe(false);
		expect(dumped.output).toContain("short\n");
		expect(dumped.output).toContain("\nfooter");
		expect(dumped.output).toContain("…");
		// The wide line shouldn't appear verbatim.
		expect(dumped.output).not.toContain("x".repeat(50));
		expect(dumped.columnTruncatedLines).toBe(1);
		expect(dumped.columnDroppedBytes ?? 0).toBeGreaterThan(0);
		expect(dumped.columnMax).toBe(8);
		// totalBytes still reflects the raw stream, not the post-cap view.
		expect(dumped.totalBytes).toBe(byteLength(`short\n${"x".repeat(50)}\nfooter`));
	});

	test("column-cap-only output surfaces a column notice, not a window/byte truncation footer", async () => {
		// Regression for #4735: fully-shown output whose only trimming was the
		// per-line column cap must not emit "Showing lines X-Y of Z (…B limit).
		// Read artifact://… for full output" — every line is present.
		const sink = new OutputSink({ maxColumns: 8, spillThreshold: 100_000 });
		const lines = ["a", "b", "c", "x".repeat(50), "d"];
		await sink.push(`${lines.join("\n")}\n`);
		const dumped = await sink.dump();

		const meta = outputMeta().truncationFromSummary(dumped, { direction: "tail" }).get();
		// No window truncation → no styled TUI warning and no range/limit footer.
		expect(meta?.truncation).toBeUndefined();
		expect(meta?.limits?.columnTruncated).toEqual({ maxColumn: 8, unit: "bytes" });

		const notice = formatOutputNotice(meta);
		expect(notice).toContain("Some lines truncated to 8 bytes");
		expect(notice).not.toContain("Showing lines");
		expect(notice).not.toContain("limit");
		expect(notice).not.toContain("artifact://");
	});

	test("column-cap notice advertises the mirrored artifact when one exists", async () => {
		// Regression for #10877: when the per-line cap drops bytes and the raw
		// stream was mirrored into an output artifact, the notice must point at
		// that artifact — matching the tail-truncation notice's recovery pointer.
		const summary = {
			output: "a\nb\nc\n" + "x".repeat(8) + "…\nd",
			truncated: false,
			totalLines: 5,
			totalBytes: 100,
			outputLines: 5,
			outputBytes: 20,
			columnTruncatedLines: 1,
			columnDroppedBytes: 42,
			columnMax: 8,
			artifactId: "77",
		};

		const meta = outputMeta().truncationFromSummary(summary, { direction: "tail" }).get();
		expect(meta?.truncation).toBeUndefined();
		expect(meta?.limits?.columnTruncated).toEqual({ maxColumn: 8, unit: "bytes", artifactId: "77" });

		const notice = formatOutputNotice(meta);
		expect(notice).toContain("Some lines truncated to 8 bytes");
		expect(notice).toContain("Read artifact://77 for full output");
	});

	test("column-cap notice names a raw artifact line per cut line", async () => {
		const dir = await createTempDir();
		const artifactPath = path.join(dir, "output.log");
		const sink = new OutputSink({ artifactPath, artifactId: "77", maxColumns: 8, spillThreshold: 100_000 });
		const wideX = "x".repeat(50);
		const wideY = "y".repeat(50);
		// Split chunks so a cut line straddles a push boundary.
		await sink.push(`a\n${wideX.slice(0, 20)}`);
		await sink.push(`${wideX.slice(20)}\nb\n${wideY}\nc\n`);
		const dumped = await sink.dump();
		expect(dumped.columnTruncatedRange).toEqual({ first: 2, last: 4 });

		const meta = outputMeta().truncationFromSummary(dumped, { direction: "tail" }).get();
		expect(formatOutputNotice(meta)).toContain(
			"Some lines truncated to 8 bytes. Use artifact://77:raw:2-2 to read line 2 whole; cut lines run to line 4, each read the same way",
		);
		// The named lines are the cut lines, whole, in the artifact.
		const artifactLines = (await Bun.file(artifactPath).text()).split("\n");
		expect(artifactLines[1]).toBe(wideX);
		expect(artifactLines[3]).toBe(wideY);
	});

	test("column-cap notice names one line, not a span a single read cannot return", async () => {
		const dir = await createTempDir();
		const sink = new OutputSink({
			artifactPath: path.join(dir, "output.log"),
			artifactId: "77",
			maxColumns: 8,
			spillThreshold: 100_000,
		});
		const lines = Array.from({ length: 8000 }, (_, i) => (i === 0 || i === 7999 ? "w".repeat(50) : `${i + 1}`));
		await sink.push(`${lines.join("\n")}\n`);
		const dumped = await sink.dump();
		expect(dumped.columnTruncatedRange).toEqual({ first: 1, last: 8000 });

		const notice = formatOutputNotice(outputMeta().truncationFromSummary(dumped, { direction: "tail" }).get());
		expect(notice).toContain("Use artifact://77:raw:1-1 to read line 1 whole; cut lines run to line 8000");
		expect(notice).not.toContain(":raw:1-8000");
	});

	test("column-cap notice keeps the plain artifact pointer when the artifact is a head/tail sample", () => {
		const meta = outputMeta()
			.truncationFromSummary(
				{
					output: "x…",
					truncated: false,
					totalLines: 1,
					totalBytes: 100,
					outputLines: 1,
					outputBytes: 4,
					columnTruncatedLines: 1,
					columnTruncatedRange: { first: 1, last: 1 },
					columnMax: 8,
					artifactId: "77",
					artifactElidedBytes: 1024,
				},
				{ direction: "tail" },
			)
			.get();
		const notice = formatOutputNotice(meta);
		expect(notice).not.toContain(":raw:");
		expect(notice).toContain("Read artifact://77 for a head/tail sample");
	});

	test("replace() withholds the cut-line range because the artifact keeps the original stream", async () => {
		const dir = await createTempDir();
		const sink = new OutputSink({
			artifactPath: path.join(dir, "output.log"),
			artifactId: "77",
			maxColumns: 8,
			spillThreshold: 100_000,
		});
		await sink.push("one\ntwo\n");
		sink.replace("rewrote\n");
		await sink.push(`${"z".repeat(50)}\n`);
		const dumped = await sink.dump();
		expect(dumped.columnTruncatedLines).toBe(1);
		expect(dumped.columnTruncatedRange).toBeUndefined();
	});

	test("replace() holds the replacement to the column cap", async () => {
		const sink = new OutputSink({ maxColumns: 8, spillThreshold: 100_000 });
		await sink.push("raw\n");
		const replacement = `ok\n${"x".repeat(50)}\n`;
		sink.replace(replacement);
		const dumped = await sink.dump();
		expect(dumped.output).toBe("ok\nxxxxx…\n");
		expect(dumped.truncated).toBe(false);
		expect(dumped.columnTruncatedLines).toBe(1);
		expect(dumped.totalBytes).toBe(byteLength(replacement));
	});

	test("multibyte line: cap counts UTF-8 bytes and the notice says bytes", async () => {
		// Regression for #10888: a 385-char line is 770 UTF-8 bytes. A char cap of
		// 768 would leave it untouched; the sink enforces bytes, so it trims. The
		// notice must name the enforced unit, not "chars".
		const sink = new OutputSink({ maxColumns: 768, spillThreshold: 100_000 });
		await sink.push("é".repeat(385));
		const dumped = await sink.dump();

		expect(dumped.columnTruncatedLines).toBe(1);
		// 3 bytes reserved for "…" inside the 768-byte cap → 765 bytes of room →
		// 382 two-byte "é" (764 bytes) kept, then the ellipsis.
		const keptAccents = (dumped.output.match(/é/g) ?? []).length;
		expect(keptAccents).toBe(382);
		expect(dumped.output).toContain("…");

		const meta = outputMeta().truncationFromSummary(dumped, { direction: "tail" }).get();
		expect(formatOutputNotice(meta)).toContain("Some lines truncated to 768 bytes");
	});

	test("legacy metadata without a unit falls back to chars", () => {
		// Sessions persisted before the unit field carry `{ maxColumn }` only.
		// Resuming one must not render "768 undefined", and the reconstructed
		// notice must still match the persisted "768 chars" text so stripping works.
		const legacyMeta = { limits: { columnTruncated: { maxColumn: 768 } } };
		const notice = formatOutputNotice(legacyMeta);
		expect(notice).toContain("Some lines truncated to 768 chars");
		expect(notice).not.toContain("undefined");
		expect(stripOutputNotice(`body${notice}`, legacyMeta)).toBe("body");
	});

	test("persists per-line state across chunk boundaries", async () => {
		const sink = new OutputSink({ maxColumns: 4, spillThreshold: 1000 });
		await sink.push("ab"); // 2 bytes into the current line
		await sink.push("cd"); // 4 bytes total — still within cap
		await sink.push("efgh"); // tips over → ellipsis once, then drop rest
		await sink.push("ijkl\n");
		await sink.push("next");

		const dumped = await sink.dump();
		const lines = dumped.output.split("\n");
		expect(lines[0]).toMatch(/^(abcd)?…$|^abcd…$/);
		expect(lines[1]).toBe("next");
		expect(dumped.columnTruncatedLines).toBe(1);
	});

	test("disabled by default — maxColumns: 0 is a passthrough", async () => {
		const sink = new OutputSink({ spillThreshold: 4000 });
		const wide = "y".repeat(2000);
		await sink.push(wide);
		const dumped = await sink.dump();
		expect(dumped.output).toBe(wide);
		expect(dumped.columnTruncatedLines).toBeUndefined();
		expect(dumped.columnDroppedBytes).toBeUndefined();
	});

	test("middle elision math subtracts column-dropped bytes", async () => {
		// Head + tail buffers are tiny; the wide middle line gets column-capped,
		// so its dropped bytes shouldn't be double-counted as "elided from middle".
		const sink = new OutputSink({
			maxColumns: 4,
			spillThreshold: 6,
			headBytes: 6,
		});
		const wideMiddle = "M".repeat(200);
		const input = `head\n${wideMiddle}\ntail`;
		await sink.push(input);
		const dumped = await sink.dump();
		const elided = dumped.elidedBytes ?? 0;
		const dropped = dumped.columnDroppedBytes ?? 0;
		expect(dropped).toBeGreaterThan(0);
		// elided + dropped + kept ≤ totalBytes (with a small slack for the marker/newlines).
		expect(elided + dropped).toBeLessThan(dumped.totalBytes);
	});
});

describe("centralized spillLargeResultToArtifact and session capture budget", () => {
	test("capArtifactText enforces exact byte budget including truncation notice", () => {
		const source = `${"H".repeat(200)}${"M".repeat(2000)}${"T".repeat(200)}`;
		const capped = capArtifactText(source, 256, 64);
		expect(capped.bytes).toBeLessThanOrEqual(256);
		expect(byteLength(capped.content)).toBe(capped.bytes);
		expect(capped.content.startsWith("H".repeat(64))).toBe(true);
		expect(capped.content.endsWith("T".repeat(32))).toBe(true);
		expect(capped.content).toContain("[ARTIFACT TRUNCATED:");
		expect(capped.elidedBytes).toBeGreaterThan(2000);
	});

	test("postProcessToolResult caps spilled artifacts, labels partial samples, and honors session cumulative budget + resume without blocking semantic artifacts", async () => {
		const dir = await createTempDir();
		const sessionsDir = path.join(dir, "sessions");
		const sessionManager = SessionManager.create(dir, sessionsDir);
		await sessionManager.ensureOnDisk();
		try {
			// Per-call cap: 0.0005 MB (~524 B), session cap: 0.0008 MB (~838 B), spill threshold: 0.1 KB (102 B).
			const settings = Settings.isolated({
				"tools.artifactSpillThreshold": 0.1,
				"tools.artifactHeadBytes": 0.03,
				"tools.artifactTailBytes": 0.03,
				"tools.artifactMaxBytes": 0.0005,
				"tools.artifactSessionMaxBytes": 0.0008,
			});
			const context = { sessionManager, settings } as unknown as AgentToolContext;
			const bigPayload = Array.from({ length: 120 }, (_, i) => `row-${String(i).padStart(3, "0")}-payload`).join(
				"\n",
			);

			// 1. Semantic artifacts saved directly do not consume the capture-log budget.
			const artifactManager = sessionManager.getArtifactManager()!;
			const semanticId = await artifactManager.save("S".repeat(4096), "deobfuscate_msynth");
			expect(semanticId).toBeDefined();
			expect(artifactManager.getCapturedLogBytes()).toBe(0);

			// 2. First spilled tool result caps on-disk artifact to <= ~524 B and advertises partial sample.
			const first = await postProcessToolResult(
				{ content: [{ type: "text", text: bigPayload }], details: {} },
				"adb_observe",
				context,
			);
			const firstMeta = first.details?.meta;
			expect(first.isError).toBeUndefined();
			expect(firstMeta?.truncation?.artifactId).toBeDefined();
			expect(firstMeta?.truncation?.artifactBytes).toBeLessThanOrEqual(524);
			expect(firstMeta?.truncation?.artifactElidedBytes).toBeGreaterThan(0);
			const firstPath = await sessionManager.getArtifactPath(firstMeta!.truncation!.artifactId!);
			expect(firstPath).not.toBeNull();
			const firstDiskText = await Bun.file(firstPath!).text();
			expect(byteLength(firstDiskText)).toBe(firstMeta?.truncation?.artifactBytes);
			const firstRendered = first.content.map(b => (b.type === "text" ? b.text : "")).join("\n");
			expect(firstRendered).toContain("head/tail sample");
			expect(firstRendered).not.toContain("for full output");

			// 3. Second spilled tool result clamps to remaining session budget (~314 B) and marks budget exhausted.
			const second = await postProcessToolResult(
				{ content: [{ type: "text", text: bigPayload }], details: {} },
				"adb_observe",
				context,
			);
			const secondMeta = second.details?.meta;
			expect(secondMeta?.truncation?.artifactId).toBeDefined();
			expect(secondMeta?.truncation?.artifactBytes).toBeLessThanOrEqual(838 - firstMeta!.truncation!.artifactBytes!);
			expect(secondMeta?.artifactBudgetExhausted).toBe(true);

			// 4. Repeated spills keep shrinking to the remaining session budget until capture is exhausted;
			//    the exhausted attempt fails boundedly inline without turning the tool into an error or
			//    claiming an artifact was saved.
			let exhaustedMeta: typeof secondMeta;
			let exhaustedText = "";
			for (let attempt = 0; attempt < 6; attempt++) {
				const next = await postProcessToolResult(
					{ content: [{ type: "text", text: bigPayload }], details: {} },
					"adb_observe",
					context,
				);
				expect(next.isError).toBeUndefined();
				if (next.details?.meta?.artifactError === "budget") {
					exhaustedMeta = next.details.meta;
					exhaustedText = next.content.map(b => (b.type === "text" ? b.text : "")).join("\n");
					break;
				}
				expect(artifactManager.getCapturedLogBytes()).toBeLessThanOrEqual(838);
			}
			expect(exhaustedMeta?.artifactError).toBe("budget");
			expect(exhaustedMeta?.artifactBudgetExhausted).toBe(true);
			expect(exhaustedMeta?.truncation?.artifactId).toBeUndefined();
			expect(exhaustedText).toContain("session artifact budget exhausted");
			expect(exhaustedText).not.toContain("artifact://");
			expect(artifactManager.getCapturedLogBytes()).toBeLessThanOrEqual(838);

			// 5. Resumed ArtifactManager over the same directory reconstructs capture-log bytes (excluding semantic logs)
			//    and avoids double counting on rewrite.
			const resumedManager = new ArtifactManager(artifactManager.dir);
			await resumedManager.ensureInitialized();
			expect(resumedManager.getCapturedLogBytes()).toBe(artifactManager.getCapturedLogBytes());
			expect(resumedManager.getRemainingCaptureBudgetBytes(838)).toBe(
				artifactManager.getRemainingCaptureBudgetBytes(838),
			);
			resumedManager.recordCapturedArtifact(firstPath!, firstMeta!.truncation!.artifactBytes!);
			expect(resumedManager.getCapturedLogBytes()).toBe(artifactManager.getCapturedLogBytes());
		} finally {
			await sessionManager.close();
		}
	});

	test("in-flight capture reservations prevent concurrent streaming sinks from overshooting the session budget", async () => {
		const dir = await createTempDir();
		const manager = new ArtifactManager(path.join(dir, "artifacts"));
		await manager.ensureInitialized();
		const sessionBudget = 400;
		const perCallBudget = 256;

		// First in-flight stream allocates and reserves its 256 B cap before finishing.
		const firstAlloc = await manager.allocatePath("bash");
		expect(manager.isCaptureBudgetExhausted(sessionBudget)).toBe(false);
		const firstCap = Math.min(perCallBudget, manager.getRemainingCaptureBudgetBytes(sessionBudget)!);
		manager.reserveCaptureBytes(firstAlloc.path, firstCap);
		expect(manager.getRemainingCaptureBudgetBytes(sessionBudget)).toBe(144);

		// Second concurrent stream started while the first is still running sees only 144 B remaining, not 400 B.
		const secondAlloc = await manager.allocatePath("eval");
		const secondRemaining = manager.getRemainingCaptureBudgetBytes(sessionBudget)!;
		expect(secondRemaining).toBe(144);
		const secondCap = Math.min(perCallBudget, secondRemaining);
		manager.reserveCaptureBytes(secondAlloc.path, secondCap);
		expect(manager.isCaptureBudgetExhausted(sessionBudget)).toBe(true);

		// Third concurrent stream while both are in-flight sees 0 B remaining and fails capture boundedly inline.
		const thirdSink = new OutputSink({
			spillThreshold: 8,
			artifactMaxBytes: perCallBudget,
			artifactSessionBudgetExhausted: manager.isCaptureBudgetExhausted(sessionBudget),
		});
		thirdSink.push("X".repeat(64));
		const thirdSummary = await thirdSink.dump();
		expect(thirdSummary.artifactId).toBeUndefined();
		expect(thirdSummary.artifactError).toBe("budget");
		expect(thirdSummary.artifactBudgetExhausted).toBe(true);

		// Finalizing the first two sinks replaces their reservations with exact on-disk byte counts.
		const firstSink = new OutputSink({
			artifactPath: firstAlloc.path,
			artifactId: firstAlloc.id,
			spillThreshold: 8,
			artifactMaxBytes: firstCap,
			artifactHeadBytes: 32,
			onArtifactFinalized: bytes => manager.recordCapturedArtifact(firstAlloc.path, bytes),
		});
		firstSink.push("A".repeat(600));
		const firstSummary = await firstSink.dump();

		const secondSink = new OutputSink({
			artifactPath: secondAlloc.path,
			artifactId: secondAlloc.id,
			spillThreshold: 8,
			artifactMaxBytes: secondCap,
			artifactHeadBytes: 32,
			artifactCapFromSessionBudget: true,
			onArtifactFinalized: bytes => manager.recordCapturedArtifact(secondAlloc.path, bytes),
		});
		secondSink.push("B".repeat(600));
		const secondSummary = await secondSink.dump();

		expect(firstSummary.artifactBytes).toBeLessThanOrEqual(256);
		expect(secondSummary.artifactBytes).toBeLessThanOrEqual(144);
		expect(secondSummary.artifactBudgetExhausted).toBe(true);
		expect(manager.getCapturedLogBytes()).toBe(firstSummary.artifactBytes! + secondSummary.artifactBytes!);
		expect(manager.getCapturedLogBytes()).toBeLessThanOrEqual(sessionBudget);
	});

	test("concurrent postProcessToolResult fanout reserves in-flight spill bytes so parallel spills cannot overshoot session budget", async () => {
		const dir = await createTempDir();
		const sessionManager = SessionManager.create(dir, path.join(dir, "fanout-sessions"));
		await sessionManager.ensureOnDisk();
		try {
			// Per-call cap ~524 B, session cap ~838 B. Three parallel spills of ~2 KB would each see the
			// full 838 B remaining if only finalized bytes were counted; with in-flight reservations the
			// captured total must stay within the session cap and at most one attempt may fail on budget.
			const settings = Settings.isolated({
				"tools.artifactSpillThreshold": 0.1,
				"tools.artifactHeadBytes": 0.03,
				"tools.artifactTailBytes": 0.03,
				"tools.artifactMaxBytes": 0.0005,
				"tools.artifactSessionMaxBytes": 0.0008,
			});
			const context = { sessionManager, settings } as unknown as AgentToolContext;
			const artifactManager = sessionManager.getArtifactManager()!;
			await artifactManager.ensureInitialized();
			const payload = Array.from({ length: 120 }, (_, i) => `fanout-${String(i).padStart(3, "0")}-data`).join("\n");

			const results = await Promise.all([
				postProcessToolResult({ content: [{ type: "text", text: payload }], details: {} }, "tool_a", context),
				postProcessToolResult({ content: [{ type: "text", text: payload }], details: {} }, "tool_b", context),
				postProcessToolResult({ content: [{ type: "text", text: payload }], details: {} }, "tool_c", context),
			]);

			for (const result of results) expect(result.isError).toBeUndefined();
			const captured = artifactManager.getCapturedLogBytes();
			expect(captured).toBeLessThanOrEqual(838);
			// Each recorded artifact's own bytes are the on-disk size it reported, so no reservation leaked.
			const savedBytes = results.reduce((sum, r) => sum + (r.details?.meta?.truncation?.artifactBytes ?? 0), 0);
			expect(savedBytes).toBe(captured);
			expect(results.filter(r => r.details?.meta?.artifactError === "budget").length).toBeLessThanOrEqual(1);
		} finally {
			await sessionManager.close();
		}
	});
});
