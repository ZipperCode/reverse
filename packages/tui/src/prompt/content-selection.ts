import type { SgrMouseEvent } from "../mouse";
import { compositeLineAt } from "../render/composite";
import { TERMINAL } from "../terminal-capabilities";
import { theme } from "../theme/theme";
import { getSegmenter, sliceByColumn, visibleWidth } from "../utils";

interface Position {
	row: number;
	col: number;
}

export interface ContentMouseResult {
	consume: true;
	copy?: string;
	click?: Position;
}

/** 鼠标上报占用终端原生选择时，在正文单元格上提供拖选；松开即复制。 */
export class ContentSelection {
	#anchor: Position | undefined;
	#head: Position | undefined;
	#rows: readonly string[] = [];
	#width = 0;
	#dragged = false;
	#active = false;

	clear(): boolean {
		const changed = this.#anchor !== undefined;
		this.#anchor = undefined;
		this.#head = undefined;
		this.#rows = [];
		this.#active = false;
		this.#dragged = false;
		return changed;
	}

	sync(rows: readonly string[], width: number): void {
		if (!this.#anchor || !this.#head) return;
		// 只核对选中行；其他回复继续流式输出时仍可复制历史正文。
		const first = Math.min(this.#anchor.row, this.#head.row);
		const last = Math.max(this.#anchor.row, this.#head.row);
		if (
			width !== this.#width ||
			last >= rows.length ||
			rows.slice(first, last + 1).some((row, i) => row !== this.#rows[first + i])
		) {
			this.clear();
		}
	}

	handle(event: SgrMouseEvent, row: number, rows: readonly string[], width: number): ContentMouseResult | undefined {
		if (event.button & 64) return undefined;
		if ((event.button & 3) !== 0) {
			if (this.#active && this.clear()) return { consume: true };
			return undefined;
		}
		if (event.leftClick) {
			this.clear();
			if (row < 0 || row >= rows.length || event.col < 0 || event.col >= width || TERMINAL.isImageLine(rows[row]!))
				return undefined;
			this.#rows = rows.slice();
			this.#width = width;
			this.#anchor = this.#head = { row, col: event.col };
			this.#active = true;
			return { consume: true };
		}
		if (!this.#active || !this.#anchor) return undefined;
		const head = {
			row: Math.max(0, Math.min(rows.length - 1, row)),
			col: Math.max(0, Math.min(width - 1, event.col)),
		};
		if (head.row !== this.#anchor.row || head.col !== this.#anchor.col) this.#dragged = true;
		this.#head = head;
		this.sync(rows, width);
		if (!this.#anchor) return { consume: true };
		if (event.release) {
			this.#active = false;
			if (this.#dragged) return { consume: true, copy: this.text() };
			const click = this.#anchor;
			this.clear();
			return { consume: true, click };
		}
		return event.motion ? { consume: true } : undefined;
	}

	#range(row: number): { start: number; end: number } | undefined {
		if (!this.#anchor || !this.#head || !this.#dragged) return undefined;
		let start = this.#anchor;
		let end = this.#head;
		if (start.row > end.row || (start.row === end.row && start.col > end.col)) [start, end] = [end, start];
		if (row < start.row || row > end.row) return undefined;
		const from = row === start.row ? start.col : 0;
		const to = row === end.row ? end.col + 1 : this.#width;
		// 按字素吸附边界，中文、emoji 和组合字符保持完整。
		let col = 0;
		let first: number | undefined;
		let last = 0;
		for (const { segment } of getSegmenter().segment(Bun.stripANSI(this.#rows[row] ?? ""))) {
			const next = col + visibleWidth(segment);
			if (next > from && col < to) {
				first ??= col;
				last = next;
			}
			col = next;
		}
		return first === undefined ? undefined : { start: first, end: last };
	}

	text(): string {
		if (!this.#anchor || !this.#head || !this.#dragged) return "";
		const first = Math.min(this.#anchor.row, this.#head.row);
		const last = Math.max(this.#anchor.row, this.#head.row);
		const result: string[] = [];
		for (let row = first; row <= last; row++) {
			const range = TERMINAL.isImageLine(this.#rows[row]!) ? undefined : this.#range(row);
			result.push(
				range ? Bun.stripANSI(sliceByColumn(this.#rows[row]!, range.start, range.end - range.start)).trimEnd() : "",
			);
		}
		return result.join("\n");
	}

	paint(rows: readonly string[]): string[] {
		return rows.map((line, row) => {
			const range = this.#range(row);
			if (!range || TERMINAL.isImageLine(line)) return line;
			const selected = sliceByColumn(line, range.start, range.end - range.start);
			return compositeLineAt(
				line,
				theme.bgFill("selectedBg", selected),
				range.start,
				range.end - range.start,
				visibleWidth(line),
			);
		});
	}
}
