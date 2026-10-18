/**
 * Append-only journal of snapcompact tool-result savings.
 *
 * Snapcompact frames are transient — built per provider request in
 * `transformProviderContext` and never written to session.jsonl — so the tokens
 * they keep off the wire would otherwise leave no trace. This records one line
 * the FIRST time a tool result is imaged in a session:
 *
 *   {"ts":<epochMs>,"session":<sessionFile>,"provider":..,"model":..,"toolCallId":..,"savedTokens":..}
 *
 * Newline-delimited JSON, opened with O_APPEND so concurrent appenders (parallel
 * agents/subagents) never interleave a partial line. Writes are fire-and-forget;
 * a failure is logged at debug and never propagates into the request hot path.
 *
 * Readers MUST dedup by (session, toolCallId): a session resumed in a fresh
 * process re-images the same results and may append a second line. The savings
 * for a given (session, toolCallId) are stable, so any-per-key is correct.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { getStatsDbPath, isEnoent, logger } from "@rva/utils";
/** `~/.omp/.../snapcompact-savings.jsonl`, colocated with stats.db. */
export function snapcompactSavingsJournalPath() {
    return path.join(path.dirname(getStatsDbPath()), "snapcompact-savings.jsonl");
}
export function createSnapcompactSavingsRecorder(getSession, journalPath = snapcompactSavingsJournalPath()) {
    const seen = new Set();
    let dirEnsured = false;
    return async (savings, model) => {
        const session = getSession();
        if (!session)
            return;
        const ts = Date.now();
        const lines = [];
        for (const { toolCallId, savedTokens } of savings) {
            if (savedTokens <= 0 || seen.has(toolCallId))
                continue;
            seen.add(toolCallId);
            lines.push(JSON.stringify({
                ts,
                session,
                provider: model.provider,
                model: model.id,
                toolCallId,
                savedTokens,
            }));
        }
        if (lines.length === 0)
            return;
        try {
            if (!dirEnsured) {
                await fs.mkdir(path.dirname(journalPath), { recursive: true });
                dirEnsured = true;
            }
            await fs.appendFile(journalPath, `${lines.join("\n")}\n`);
        }
        catch (err) {
            logger.debug("snapcompact savings journal append failed", { err: String(err) });
        }
    };
}
/** Read all journal records. Malformed lines are skipped; a missing file is empty. */
export async function readSnapcompactSavingsJournal(journalPath = snapcompactSavingsJournalPath()) {
    let text;
    try {
        text = await Bun.file(journalPath).text();
    }
    catch (err) {
        if (isEnoent(err))
            return [];
        throw err;
    }
    const records = [];
    for (const line of text.split("\n")) {
        if (!line.trim())
            continue;
        try {
            records.push(JSON.parse(line));
        }
        catch {
            /* skip malformed line */
        }
    }
    return records;
}
