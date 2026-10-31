import type { Component } from "../tui";
import {
	type AnimationFrame,
	type TranscriptPresentationTarget,
	type TranscriptViewportSpan,
	trimBlankEdges,
} from "./transcript-container";

export interface TranscriptWindow {
	readonly rows: readonly string[];
	readonly spans: readonly TranscriptViewportSpan[];
	readonly atStart: boolean;
	readonly atEnd: boolean;
}

interface Anchor {
	component: Component;
	index: number;
	/** 裁边后的物理行；-1 表示此组件前的分隔行。 */
	row: number;
}

interface Block {
	rows: readonly string[];
	leading: number;
}

interface Position {
	index: number;
	row: number;
}

/** 只渲染窗口及滚动跨越的组件，历史组件本身始终保留完整内容。 */
export class TranscriptViewport {
	#anchor: Anchor | undefined;
	#followTail = true;
	#pending = 0;

	scrollBy(rows: number): void {
		if (!Number.isFinite(rows)) return;
		const delta = Math.trunc(rows);
		if (delta === 0 || (this.#followTail && delta > 0)) return;
		this.#followTail = false;
		this.#pending += delta;
	}

	scrollToBottom(): void {
		this.#followTail = true;
		this.#pending = 0;
	}

	reset(): void {
		this.#anchor = undefined;
		this.scrollToBottom();
	}

	render(roots: readonly Component[], width: number, height: number, frame: AnimationFrame): TranscriptWindow {
		const cap = Math.max(0, Math.trunc(height));
		if (roots.length === 0) {
			this.reset();
			return { rows: [], spans: [], atStart: true, atEnd: true };
		}
		// 隐藏对话区时不消费滚动，也不丢失被 dock 临时遮住的锚点。
		if (cap === 0) return { rows: [], spans: [], atStart: false, atEnd: this.#followTail };
		const visited = new Map<number, Block>();
		const block = (index: number): Block => {
			const cached = visited.get(index);
			if (cached) return cached;
			const component = roots[index]!;
			(component as Component & TranscriptPresentationTarget).setTranscriptAllocation?.(
				Number.MAX_SAFE_INTEGER,
				frame,
			);
			const raw = component.render(width);
			const rows = trimBlankEdges(raw);
			let leading = 0;
			while (leading < raw.length && !/\S/.test(raw[leading]!)) leading++;
			const result = { rows, leading };
			visited.set(index, result);
			return result;
		};
		const nonempty = (index: number, direction: -1 | 1): number | undefined => {
			for (; index >= 0 && index < roots.length; index += direction) {
				if (block(index).rows.length > 0) return index;
			}
			return undefined;
		};
		const previous = (position: Position): Position | undefined => {
			if (position.row > 0) return { index: position.index, row: position.row - 1 };
			const index = nonempty(position.index - 1, -1);
			if (index === undefined) return undefined;
			return position.row === 0 ? { index: position.index, row: -1 } : { index, row: block(index).rows.length - 1 };
		};
		const next = (position: Position): Position | undefined => {
			if (position.row + 1 < block(position.index).rows.length) {
				return { index: position.index, row: position.row + 1 };
			}
			const index = nonempty(position.index + 1, 1);
			return index === undefined ? undefined : { index, row: -1 };
		};
		const tail = (): Position[] => {
			const index = nonempty(roots.length - 1, -1);
			if (index === undefined) return [];
			let position: Position | undefined = { index, row: block(index).rows.length - 1 };
			const positions: Position[] = [];
			while (position && positions.length < cap) {
				positions.push(position);
				if (positions.length < cap) position = previous(position);
			}
			return positions.reverse();
		};
		let positions: Position[];
		if (this.#followTail) {
			positions = tail();
		} else {
			const anchor = this.#anchor;
			let position: Position | undefined;
			if (anchor) {
				let index = anchor.index;
				if (roots[index] !== anchor.component) {
					const found = roots.indexOf(anchor.component);
					index = found < 0 ? Math.min(index, roots.length - 1) : found;
				}
				const resolved = nonempty(index, 1) ?? nonempty(index - 1, -1);
				if (resolved !== undefined) {
					const row = Math.max(-1, Math.min(anchor.row, block(resolved).rows.length - 1));
					position = { index: resolved, row: row === -1 && nonempty(resolved - 1, -1) === undefined ? 0 : row };
				}
			} else {
				position = tail()[0];
			}
			let delta = this.#pending;
			while (position && delta !== 0) {
				// 同一块内按距离跳转，跨块才解析相邻组件，避免逐行走完整个大块。
				if (delta > 0) {
					const distance = Math.min(delta, block(position.index).rows.length - 1 - position.row);
					position = { index: position.index, row: position.row + distance };
					delta -= distance;
					if (delta === 0) break;
					const after = next(position);
					if (!after) break;
					position = after;
					delta--;
				} else {
					const distance = Math.min(-delta, Math.max(0, position.row));
					position = { index: position.index, row: position.row - distance };
					delta += distance;
					if (delta === 0) break;
					const before = previous(position);
					if (!before) break;
					position = before;
					delta++;
				}
			}
			positions = [];
			while (position && positions.length < cap) {
				positions.push(position);
				position = next(position);
			}
			if (positions.length > 0 && position === undefined) {
				// 到底时向前补满窗口，恢复后续输出的自动跟随。
				positions = tail();
				this.#followTail = true;
			}
		}
		this.#pending = 0;
		const first = positions[0];
		const last = positions[positions.length - 1];
		if (!first || !last) {
			this.reset();
			return { rows: [], spans: [], atStart: true, atEnd: true };
		}
		this.#anchor = { ...first, component: roots[first.index]! };
		const rows: string[] = [];
		const spans: TranscriptViewportSpan[] = [];
		for (const position of positions) {
			const start = rows.length;
			if (position.row === -1) {
				rows.push("");
				continue;
			}
			const rendered = block(position.index);
			rows.push(rendered.rows[position.row]!);
			const component = roots[position.index]!;
			const lastSpan = spans[spans.length - 1];
			if (lastSpan?.component === component && lastSpan.end === start) {
				lastSpan.end++;
			} else {
				const componentRow = rendered.leading + position.row;
				spans.push({ component, start, end: start + 1, getComponentRow: local => componentRow + local });
			}
		}
		return { rows, spans, atStart: previous(first) === undefined, atEnd: next(last) === undefined };
	}
}
