import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { visibleWidth } from "../utils";
import { isNativeLinkEnabled } from "./hyperlink";

/** 在终端不支持 OSC 8 时仍能点击可见网址/真实路径；显式关闭链接时保持关闭。 */
export function contentLinkAt(line: string, col: number): { url: string; start: number } | undefined {
	if (!isNativeLinkEnabled() || col < 0) return undefined;
	const osc8 = /\x1b\]8;([^;\x07\x1b]*);([^\x07\x1b]*)(?:\x07|\x1b\\)/g;
	let cursor = 0;
	let x = 0;
	let open: { url: string; start: number } | undefined;
	for (const match of line.matchAll(osc8)) {
		x += visibleWidth(line.slice(cursor, match.index));
		if (open && col >= open.start && col < x) return open;
		open = match[2] ? { url: match[2], start: x } : undefined;
		cursor = match.index + match[0].length;
	}
	x += visibleWidth(line.slice(cursor));
	if (open && col >= open.start && col < x) return open;

	const plain = Bun.stripANSI(line);
	// 引号/反引号包围的路径允许空格；普通标点不属于网址或路径。
	const tokens = /`([^`]+)`|"([^"\n]+)"|'([^'\n]+)'|[^\s<>[\]{}()，。；：、！？]+/g;
	for (const match of plain.matchAll(tokens)) {
		const quoted = match[1] ?? match[2] ?? match[3];
		const token = (quoted ?? match[0]).replace(/[.,;!?]+$/, "");
		const start = visibleWidth(plain.slice(0, match.index)) + (quoted === undefined ? 0 : 1);
		if (col < start || col >= start + visibleWidth(token)) continue;
		if (/^(?:https?:\/\/|www\.)/i.test(token)) {
			const url = token.startsWith("www.") ? `https://${token}` : token;
			try {
				const parsed = new URL(url);
				if (parsed.protocol === "http:" || parsed.protocol === "https:") return { url: parsed.href, start };
			} catch {
				return undefined;
			}
		}
		const path = token.replace(/:\d+(?::\d+)?$/, "");
		if (!/^(?:\/|~\/|\.\.?\/)|[/\\]|\.[\w-]+$/.test(path)) return undefined;
		const absolute = resolve(path.startsWith("~/") ? `${homedir()}/${path.slice(2)}` : path);
		if (existsSync(absolute)) return { url: pathToFileURL(absolute).href, start };
		return undefined;
	}
	return undefined;
}
