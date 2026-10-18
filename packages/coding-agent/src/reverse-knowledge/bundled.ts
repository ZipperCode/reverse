import bundledSeedsRaw from "./bundled-seeds.json" with { type: "json" };
import {
	type ReverseKnowledgeRecord,
	type ReverseKnowledgeFilter,
	DEFAULT_KNOWLEDGE_SEARCH_LIMIT,
	MAX_KNOWLEDGE_SEARCH_LIMIT,
} from "./contracts";
import { normalizeTargetFormat } from "../reverse-workflow/contracts";

export const BUNDLED_REVERSE_KNOWLEDGE_SEEDS: readonly ReverseKnowledgeRecord[] =
	Object.freeze(bundledSeedsRaw as ReverseKnowledgeRecord[]);

export function getBundledReverseKnowledgeRecords(): ReverseKnowledgeRecord[] {
	return BUNDLED_REVERSE_KNOWLEDGE_SEEDS.map(r => ({ ...r, metadata: { ...r.metadata } }));
}

export function getBundledReverseKnowledgeRecord(id: string): ReverseKnowledgeRecord | undefined {
	const found = BUNDLED_REVERSE_KNOWLEDGE_SEEDS.find(r => r.id === id);
	return found ? { ...found, metadata: { ...found.metadata } } : undefined;
}

export function matchAndScoreKnowledgeRecords(
	records: readonly ReverseKnowledgeRecord[],
	filter: ReverseKnowledgeFilter = {},
): ReverseKnowledgeRecord[] {
	const limit = Math.min(
		Math.max(filter.limit ?? DEFAULT_KNOWLEDGE_SEARCH_LIMIT, 1),
		MAX_KNOWLEDGE_SEARCH_LIMIT,
	);
	const normalizedFilterFormat = normalizeTargetFormat(filter.format);

	const queryTokens = filter.query
		? filter.query
				.toLowerCase()
				.split(/[\s,;:._\-\\/]+/)
				.filter(t => t.length > 1)
		: [];

	const scored: Array<{ record: ReverseKnowledgeRecord; score: number }> = [];

	for (const record of records) {
		// Status filter: inactive/expired/disabled/merged records excluded by default
		if (!filter.include_inactive) {
			if (record.status && record.status !== "active") {
				continue;
			}
			if (record.expires_at && new Date(record.expires_at).getTime() <= Date.now()) {
				continue;
			}
		}
		if (filter.status && record.status !== filter.status) {
			continue;
		}
		if (filter.include_stale === false && record.stale) {
			continue;
		}

		let score = 0;

		// Format filter
		if (normalizedFilterFormat) {
			if (record.target_format === normalizedFilterFormat) {
				score += 5;
			} else if (record.target_format !== "unknown") {
				// Format mismatch
				continue;
			}
		}

		// Target hash filter
		if (filter.target_hash) {
			const filterHash = filter.target_hash.toLowerCase().trim();
			const recordHash = record.target_hash?.toLowerCase().trim();
			if (recordHash) {
				if (recordHash === filterHash) {
					score += 20; // Exact target match
				} else if (recordHash.startsWith(filterHash) || filterHash.startsWith(recordHash)) {
					score += 10;
				} else {
					// Explicit hash mismatch
					continue;
				}
			} else if (!normalizedFilterFormat && queryTokens.length === 0 && !filter.tool) {
				// Search specifically targeted a binary hash and this record has none
				continue;
			}
		}

		// Tool filter
		if (filter.tool) {
			const filterTool = filter.tool.toLowerCase().trim();
			const recordTool = record.tool?.toLowerCase().trim();
			if (recordTool) {
				if (recordTool === filterTool) {
					score += 6;
				} else if (recordTool.includes(filterTool) || filterTool.includes(recordTool)) {
					score += 3;
				} else {
					continue;
				}
			}
		}

		// Kind filter
		if (filter.kind) {
			if (record.kind !== filter.kind) {
				continue;
			}
			score += 2;
		}

		// Confidence filter
		if (filter.confidence) {
			if (record.confidence !== filter.confidence) {
				continue;
			}
			score += 1;
		}

		// Confidence boost
		if (record.confidence === "high") {
			score += 2;
		}

		// Query tokens matching
		if (queryTokens.length > 0) {
			const titleLower = record.title.toLowerCase();
			const summaryLower = record.summary.toLowerCase();
			const guidanceLower = (record.actionable_guidance ?? "").toLowerCase();
			const patternLower = (record.pattern ?? "").toLowerCase();

			let tokenHits = 0;
			for (const token of queryTokens) {
				if (titleLower.includes(token)) {
					score += 5;
					tokenHits++;
				}
				if (guidanceLower.includes(token)) {
					score += 3;
					tokenHits++;
				}
				if (summaryLower.includes(token)) {
					score += 2;
					tokenHits++;
				}
				if (patternLower.includes(token)) {
					score += 3;
					tokenHits++;
				}
			}

			if (tokenHits === 0) {
				if (queryTokens.length > 0) continue;
			}
		} else {
			// No text query, baseline score for existing items
			score += 1;
		}

		scored.push({ record, score });
	}

	// Sort by score descending, then updated_at descending
	scored.sort((a, b) => {
		if (b.score !== a.score) return b.score - a.score;
		const timeA = a.record.updated_at ? new Date(a.record.updated_at).getTime() : 0;
		const timeB = b.record.updated_at ? new Date(b.record.updated_at).getTime() : 0;
		return timeB - timeA;
	});

	const offset = Math.max(filter.offset ?? 0, 0);
	return scored.slice(offset, offset + limit).map(item => item.record);
}

export function searchBundledReverseKnowledge(
	filter: ReverseKnowledgeFilter = {},
): ReverseKnowledgeRecord[] {
	return matchAndScoreKnowledgeRecords(BUNDLED_REVERSE_KNOWLEDGE_SEEDS, filter);
}
