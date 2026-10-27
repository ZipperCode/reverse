/** High-level bucket for anchor vs snapshot-tag edit rejections (#18). */
export type EditRejectionCategory = "anchor_reject" | "hash_reject";

/** ToolResult-like record from direct `edit` execution or a `write` to `xd://edit`. */
export interface EditResultLike {
	toolName?: string;
	isError?: boolean;
	details?: unknown;
	content?: unknown;
}

const REJECTION_CATEGORY_BY_KIND: Record<string, EditRejectionCategory> = {
	unseen_lines: "anchor_reject",
	out_of_range: "anchor_reject",
	ambiguous_boundary: "anchor_reject",
	other_file_tag: "hash_reject",
	stale_tag: "hash_reject",
	unknown_tag: "hash_reject",
	missing_tag: "hash_reject",
};

/** Infer `errorKind` from model-facing diagnostic text when historical entries lack `details.errorKind`. */
export function inferEditErrorKindFromText(text: string): string | undefined {
	if (!text) return undefined;
	if (
		/anchors to lines .* never displayed/i.test(text) ||
		/were not fully displayed\. Read/i.test(text) ||
		/no retained read shows them in full/i.test(text)
	) {
		return "unseen_lines";
	}
	if (
		/Hash #[0-9A-F]{4} was issued in this session for /i.test(text) ||
		/hash #[0-9A-F]{4} was issued for another file in this session/i.test(text)
	) {
		return "other_file_tag";
	}
	if (/hash #[0-9A-F]{4} is not from this session/i.test(text)) {
		return "unknown_tag";
	}
	if (
		/file changed between read and edit/i.test(text) ||
		/Section is bound to #[0-9A-F]{4}, but the current file hashes to #[0-9A-F]{4}/i.test(text)
	) {
		return "stale_tag";
	}
	if (/the header needs this file's current tag, #[0-9A-F]{4}/i.test(text)) {
		return "missing_tag";
	}
	if (/no ops follow the header; put them under this file's current tag/i.test(text)) {
		return "header_only";
	}
	if (/does not exist \(file has \d+ lines\)|is out of range \(file has \d+ lines\)/i.test(text)) {
		return "out_of_range";
	}
	return undefined;
}

/**
 * Extract the engine's `errorKind` from a failed `edit` tool result or a `write` to `xd://edit`.
 * Direct calls store `details.errorKind`; `xd://edit` calls wrap inner details under `details.xdev.inner`.
 * 仅当 `details.xdev.tool === "edit"` 时解包 `xdev.inner`，避免将其他 `xd://` 设备的错误误计入编辑拒绝；
 * `allowTextFallback` 默认关闭以保证实时会话统计仅依赖结构化 `errorKind`，历史 JSONL 回放再按需开启文本推断。
 */
export function extractEditErrorKind(
	result: EditResultLike,
	options?: { allowTextFallback?: boolean },
): string | undefined {
	if (result.isError !== true) return undefined;
	const { toolName, details } = result;
	const isDirectEdit = toolName === undefined || toolName === "edit";
	let isXdevEdit = false;
	let xdevInnerErrorKind: string | undefined;
	if (
		(toolName === undefined || toolName === "write") &&
		details &&
		typeof details === "object" &&
		"xdev" in details &&
		details.xdev &&
		typeof details.xdev === "object" &&
		"tool" in details.xdev &&
		details.xdev.tool === "edit"
	) {
		isXdevEdit = true;
		if (
			"inner" in details.xdev &&
			details.xdev.inner &&
			typeof details.xdev.inner === "object" &&
			"errorKind" in details.xdev.inner &&
			typeof details.xdev.inner.errorKind === "string" &&
			details.xdev.inner.errorKind.length > 0
		) {
			xdevInnerErrorKind = details.xdev.inner.errorKind;
		}
	}
	if (!isDirectEdit && !isXdevEdit) return undefined;

	if (
		isDirectEdit &&
		details &&
		typeof details === "object" &&
		"errorKind" in details &&
		typeof details.errorKind === "string" &&
		details.errorKind.length > 0
	) {
		return details.errorKind;
	}
	if (xdevInnerErrorKind) return xdevInnerErrorKind;
	if (options?.allowTextFallback) {
		const { content } = result;
		let text = "";
		if (typeof content === "string") {
			text = content;
		} else if (Array.isArray(content)) {
			const parts: string[] = [];
			for (const entry of content) {
				if (entry && typeof entry === "object" && "text" in entry && typeof entry.text === "string") {
					parts.push(entry.text);
				}
			}
			text = parts.join("\n");
		}
		return inferEditErrorKindFromText(text);
	}
	return undefined;
}

/** Classify an edit `errorKind` or tool result into `anchor_reject` vs `hash_reject`. */
export function classifyEditRejection(
	kindOrResult: string | EditResultLike | undefined,
): EditRejectionCategory | undefined {
	const kind =
		typeof kindOrResult === "string"
			? kindOrResult
			: kindOrResult
				? extractEditErrorKind(kindOrResult, { allowTextFallback: true })
				: undefined;
	return kind ? REJECTION_CATEGORY_BY_KIND[kind] : undefined;
}
