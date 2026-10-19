import { logger } from "@reverse/utils";
import type { ToolSession } from "../tools/index";
import type { ReverseKnowledgeRecord } from "./contracts";

export interface MnemopiKnowledgeHit {
	id: string;
	content: string;
	similarity?: number;
	metadata?: Record<string, unknown>;
}

export class MnemopiKnowledgeBridge {
	static isAvailable(session: ToolSession): boolean {
		return typeof session.getMnemopiSessionState === "function" && Boolean(session.getMnemopiSessionState());
	}

	static async retain(record: ReverseKnowledgeRecord, session: ToolSession): Promise<string | undefined> {
		try {
			const state = session.getMnemopiSessionState?.();
			if (!state) return undefined;

			const parts: string[] = [
				`[REVERSE_KNOWLEDGE] ${record.title}`,
				`ID: ${record.id}`,
				`Kind: ${record.kind}`,
				`Format: ${record.target_format}`,
			];

			if (record.target_hash) parts.push(`Target SHA256: ${record.target_hash}`);
			if (record.tool) parts.push(`Tool: ${record.tool}`);
			parts.push(`Confidence: ${record.confidence}`);
			parts.push(`Summary: ${record.summary}`);
			if (record.actionable_guidance) parts.push(`Actionable Guidance: ${record.actionable_guidance}`);
			if (record.pattern) parts.push(`Pattern: ${record.pattern}`);
			if (record.source_evidence_ids && record.source_evidence_ids.length > 0) {
				parts.push(`Source Evidence: ${record.source_evidence_ids.join(", ")}`);
			}

			const content = parts.join("\n");
			const importance = record.confidence === "high" ? 0.9 : 0.75;

			const retainedId = state.rememberInScope(content, {
				source: "reverse-knowledge",
				importance,
				metadata: {
					reverse_knowledge_id: record.id,
					target_format: record.target_format,
					...(record.target_hash !== undefined ? { target_hash: record.target_hash } : {}),
					...(record.tool !== undefined ? { tool: record.tool } : {}),
					kind: record.kind,
					...(record.source_evidence_ids !== undefined ? { source_evidence_ids: record.source_evidence_ids } : {}),
				},
			});

			return retainedId;
		} catch (err) {
			logger.warn("MnemopiKnowledgeBridge: retain failed", {
				recordId: record.id,
				error: String(err),
			});
			return undefined;
		}
	}

	static async recall(query: string, session: ToolSession, limit = 5): Promise<MnemopiKnowledgeHit[]> {
		try {
			const state = session.getMnemopiSessionState?.();
			if (!state) return [];

			const results = await state.recallResultsScoped(query);
			const hits: MnemopiKnowledgeHit[] = [];

			for (const result of results) {
				const content = typeof result.content === "string" ? result.content : "";
				if (!content.includes("[REVERSE_KNOWLEDGE]")) continue;

				hits.push({
					id: result.id ?? "",
					content,
					similarity: result.score ?? undefined,
					metadata: result.metadata as Record<string, unknown> | undefined,
				});

				if (hits.length >= limit) break;
			}

			return hits;
		} catch (err) {
			logger.warn("MnemopiKnowledgeBridge: recall failed", {
				query,
				error: String(err),
			});
			return [];
		}
	}
}
