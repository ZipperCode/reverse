import { Database } from "bun:sqlite";
import * as fs from "node:fs/promises";
import * as path from "node:path";
const SCHEMA_VERSION = 3;
const PRUNE_DIVISOR = 64;
const MAX_FAILURES = 64;
/** SQLite-backed best-effort cache for conventional commit inference. */
export class CommitInferenceCache {
    #db;
    #ttlSeconds;
    constructor(db, ttlDays) {
        this.#db = db;
        this.#ttlSeconds = Math.max(0, Math.trunc(ttlDays * 24 * 60 * 60));
    }
    /** Open the cache, returning `null` when its directory or database is unavailable. */
    static async open(dbPath, ttlDays) {
        try {
            await fs.mkdir(path.dirname(dbPath), { recursive: true });
            const db = new Database(dbPath, { create: true });
            db.run("PRAGMA journal_mode=WAL");
            db.run("PRAGMA synchronous=NORMAL");
            db.exec(`
				CREATE TABLE IF NOT EXISTS responses (
					key TEXT PRIMARY KEY,
					schema_version INTEGER NOT NULL,
					model TEXT NOT NULL,
					operation TEXT NOT NULL,
					request TEXT NOT NULL,
					response TEXT NOT NULL,
					stop_reason TEXT NOT NULL,
					cost_usd REAL,
					created_at INTEGER NOT NULL,
					accessed_at INTEGER NOT NULL
				);
				CREATE INDEX IF NOT EXISTS idx_commit_responses_created_at ON responses(created_at);
				CREATE TABLE IF NOT EXISTS failures (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					schema_version INTEGER NOT NULL,
					key TEXT NOT NULL,
					model TEXT NOT NULL,
					operation TEXT NOT NULL,
					request TEXT NOT NULL,
					response TEXT NOT NULL,
					error TEXT NOT NULL,
					created_at INTEGER NOT NULL
				);
				CREATE INDEX IF NOT EXISTS idx_commit_failures_created_at ON failures(created_at);
				CREATE TABLE IF NOT EXISTS usage (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					model TEXT NOT NULL,
					operation TEXT NOT NULL,
					input_tokens INTEGER NOT NULL,
					output_tokens INTEGER NOT NULL,
					cache_read_tokens INTEGER NOT NULL,
					cache_write_tokens INTEGER NOT NULL,
					cost_usd REAL,
					created_at INTEGER NOT NULL
				);
				CREATE INDEX IF NOT EXISTS idx_commit_usage_created_at ON usage(created_at);
			`);
            return new CommitInferenceCache(db, ttlDays);
        }
        catch {
            return null;
        }
    }
    /** Read a non-expired response and update its access timestamp. */
    get(key) {
        try {
            const row = this.#db
                .query("SELECT response, stop_reason, created_at, cost_usd FROM responses WHERE key = ? AND schema_version = ?")
                .get(key, SCHEMA_VERSION);
            if (!row)
                return null;
            const now = Math.floor(Date.now() / 1000);
            if (this.#ttlSeconds > 0 && row.created_at < now - this.#ttlSeconds) {
                this.#db.run("DELETE FROM responses WHERE key = ?", [key]);
                return null;
            }
            this.#db.run("UPDATE responses SET accessed_at = ? WHERE key = ?", [now, key]);
            return {
                text: row.response,
                stopReason: row.stop_reason,
                costUsd: row.cost_usd ?? undefined,
            };
        }
        catch {
            return null;
        }
    }
    /** Insert or replace one successfully parsed response. */
    put(input) {
        try {
            const now = Math.floor(Date.now() / 1000);
            this.#db.run(`INSERT OR REPLACE INTO responses
				 (key, schema_version, model, operation, request, response, stop_reason, cost_usd, created_at, accessed_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
                input.key,
                SCHEMA_VERSION,
                input.model,
                input.operation,
                input.request,
                input.response.text,
                input.response.stopReason,
                input.response.costUsd ?? null,
                now,
                now,
            ]);
            if (this.#ttlSeconds > 0 && now % PRUNE_DIVISOR === 0) {
                this.#db.run("DELETE FROM responses WHERE created_at < ?", [now - this.#ttlSeconds]);
            }
        }
        catch { }
    }
    /** Retain a failed response for diagnosis without serving it as a cache hit. */
    putFailure(input) {
        try {
            const now = Math.floor(Date.now() / 1000);
            this.#db.run(`INSERT INTO failures
				 (schema_version, key, model, operation, request, response, error, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [SCHEMA_VERSION, input.key, input.model, input.operation, input.request, input.response, input.error, now]);
            if (this.#ttlSeconds > 0)
                this.#db.run("DELETE FROM failures WHERE created_at < ?", [now - this.#ttlSeconds]);
            this.#db.run("DELETE FROM failures WHERE id NOT IN (SELECT id FROM failures ORDER BY id DESC LIMIT ?)", [
                MAX_FAILURES,
            ]);
        }
        catch { }
    }
    /** Append token and cost accounting for a real provider response. */
    recordUsage(model, operation, usage) {
        try {
            this.#db.run(`INSERT INTO usage
				 (model, operation, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [
                model,
                operation,
                usage.input,
                usage.output,
                usage.cacheRead,
                usage.cacheWrite,
                usage.cost.total,
                Math.floor(Date.now() / 1000),
            ]);
        }
        catch { }
    }
    /** Close the SQLite handle. */
    close() {
        this.#db.close();
    }
}
/** Compute a stable cache key from all behavior-affecting request material. */
export function computeCommitCacheKey(material) {
    const hash = new Bun.CryptoHasher("sha256").update("llm-cache/v1\n");
    for (const [name, value] of [
        ["operation", material.operation],
        ["model", material.model],
        ["api_mode", material.apiMode],
        ["tool_name", material.toolName],
        ["system", material.systemPrompt],
        ["user", material.userPrompt],
    ]) {
        hash.update(name).update("\0").update(value).update("\n");
    }
    if (material.reasoningEffort) {
        hash.update("reasoning_effort").update("\0").update(material.reasoningEffort).update("\n");
    }
    return hash.update("\n").digest("hex");
}
