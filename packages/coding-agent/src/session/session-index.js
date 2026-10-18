var __addDisposableResource = (this && this.__addDisposableResource) || function (env, value, async) {
    if (value !== null && value !== void 0) {
        if (typeof value !== "object" && typeof value !== "function") throw new TypeError("Object expected.");
        var dispose, inner;
        if (async) {
            if (!Symbol.asyncDispose) throw new TypeError("Symbol.asyncDispose is not defined.");
            dispose = value[Symbol.asyncDispose];
        }
        if (dispose === void 0) {
            if (!Symbol.dispose) throw new TypeError("Symbol.dispose is not defined.");
            dispose = value[Symbol.dispose];
            if (async) inner = dispose;
        }
        if (typeof dispose !== "function") throw new TypeError("Object not disposable.");
        if (inner) dispose = function() { try { inner.call(this); } catch (e) { return Promise.reject(e); } };
        env.stack.push({ value: value, dispose: dispose, async: async });
    }
    else if (async) {
        env.stack.push({ async: true });
    }
    return value;
};
var __disposeResources = (this && this.__disposeResources) || (function (SuppressedError) {
    return function (env) {
        function fail(e) {
            env.error = env.hasError ? new SuppressedError(e, env.error, "An error was suppressed during disposal.") : e;
            env.hasError = true;
        }
        var r, s = 0;
        function next() {
            while (r = env.stack.pop()) {
                try {
                    if (!r.async && s === 1) return s = 0, env.stack.push(r), Promise.resolve().then(next);
                    if (r.dispose) {
                        var result = r.dispose.call(r.value);
                        if (r.async) return s |= 2, Promise.resolve(result).then(next, function(e) { fail(e); return next(); });
                    }
                    else s |= 1;
                }
                catch (e) {
                    fail(e);
                }
            }
            if (s === 1) return env.hasError ? Promise.reject(env.error) : Promise.resolve();
            if (env.hasError) throw env.error;
        }
        return next();
    };
})(typeof SuppressedError === "function" ? SuppressedError : function (error, suppressed, message) {
    var e = new Error(message);
    return e.name = "SuppressedError", e.error = error, e.suppressed = suppressed, e;
});
/**
 * Per-session index tables in history.db, keyed by session id:
 *
 * - `session_titles`: session id → display title, written whenever a title is
 *   created or renamed ({@link SessionManager.setSessionName}) and backfilled by
 *   the recent-session fallback scan. Lets the welcome "Recent sessions" list
 *   resolve names from a stat + lookup instead of content-scanning every session
 *   file in the project directory (multi-hundred-ms on dirs with thousands of
 *   sessions). A title has no life beyond its session; `omp gc` drops rows of
 *   archived sessions.
 * - `session_recaps`: append-only journal of idle recaps
 *   ({@link SessionManager.recordRecap}). Recaps are side-channel output that
 *   never enters the session JSONL or LLM context; this table is their only
 *   durable record. `omp gc` drops rows of archived sessions.
 *
 * Holds its own lazily-opened connection instead of {@link HistoryStorage}'s
 * path-pinned singleton: the db path is re-resolved on every call so
 * `setAgentDir`/profile switches (and test isolation) transparently reopen
 * against the right file. Never versions the db — `PRAGMA user_version` is
 * owned by HistoryStorage's rebuild pass, which drops only its own tables.
 */
import { Database } from "bun:sqlite";
import * as fs from "node:fs";
import * as path from "node:path";
import { isSqliteBusyError, sqliteFileIdentity } from "@rva/utils";
import { getHistoryDbPath } from "@rva/utils/dirs";
import { getDbBusyTimeoutMs } from "@rva/utils/env";
import * as logger from "@rva/utils/logger";
const SESSION_INDEX_DDL = `
CREATE TABLE IF NOT EXISTS session_titles (
	session_id TEXT PRIMARY KEY,
	title TEXT NOT NULL,
	updated_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);
CREATE TABLE IF NOT EXISTS session_recaps (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id TEXT NOT NULL,
	cwd TEXT NOT NULL,
	recap TEXT NOT NULL,
	created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);
CREATE INDEX IF NOT EXISTS idx_session_recaps_session ON session_recaps(session_id, created_at);
`;
let handle;
/** Db path whose open failed; skip retries (and log spam) until the path changes. */
let failedPath;
function closeHandle() {
    if (!handle)
        return;
    try {
        handle.upsertTitle.finalize();
        handle.selectTitle.finalize();
        handle.insertRecap.finalize();
        handle.db.close();
    }
    catch { }
    handle = undefined;
}
function openSessionIndex() {
    const dbPath = getHistoryDbPath();
    // A quarantined history.db is unlinked and recreated at the same path, so
    // the path alone still matches a handle pinned to the dead inode. Reopen
    // unless the file behind the path is still the one this handle was opened
    // on. An `undefined` identity means the stat itself failed: no conclusion
    // is safe there, so treat the handle as stale.
    if (handle?.dbPath === dbPath) {
        const identity = sqliteFileIdentity(dbPath);
        if (identity !== undefined && identity === handle.identity)
            return handle;
    }
    if (failedPath === dbPath)
        return undefined;
    closeHandle();
    try {
        fs.mkdirSync(path.dirname(dbPath), { recursive: true });
        const db = new Database(dbPath);
        // Install the busy handler BEFORE any lock-taking statement (see #2421).
        db.run(`PRAGMA busy_timeout = ${getDbBusyTimeoutMs()}`);
        db.run(`PRAGMA journal_mode=WAL;\nPRAGMA synchronous=NORMAL;\n${SESSION_INDEX_DDL}`);
        handle = {
            dbPath,
            identity: sqliteFileIdentity(dbPath),
            db,
            upsertTitle: db.prepare(`
INSERT INTO session_titles (session_id, title, updated_at)
VALUES (?, ?, CAST(strftime('%s','now') AS INTEGER))
ON CONFLICT(session_id) DO UPDATE SET
	title = excluded.title,
	updated_at = excluded.updated_at
			`),
            selectTitle: db.prepare("SELECT title FROM session_titles WHERE session_id = ?"),
            insertRecap: db.prepare("INSERT INTO session_recaps (session_id, cwd, recap) VALUES (?, ?, ?)"),
        };
        failedPath = undefined;
        return handle;
    }
    catch (error) {
        // A busy store is transient (a peer process holds the lock), so it must
        // not latch the path as unusable for the rest of the session.
        if (isSqliteBusyError(error))
            return undefined;
        failedPath = dbPath;
        logger.warn("Session index unavailable", { dbPath, error: String(error) });
        return undefined;
    }
}
/**
 * Record (or replace) the indexed title for a session id. Best-effort: index
 * failures must never break a rename, so errors are logged and swallowed.
 */
export function recordSessionTitle(sessionId, title) {
    const index = openSessionIndex();
    if (!index)
        return;
    try {
        index.upsertTitle.run(sessionId, title);
    }
    catch (error) {
        logger.debug("Session title index write failed", { sessionId, error: String(error) });
    }
}
/** Indexed title for a session id, or undefined when unindexed/unavailable. */
export function lookupSessionTitle(sessionId) {
    const index = openSessionIndex();
    if (!index)
        return undefined;
    try {
        const row = index.selectTitle.get(sessionId);
        return row?.title ?? undefined;
    }
    catch (error) {
        logger.debug("Session title index read failed", { sessionId, error: String(error) });
        return undefined;
    }
}
/**
 * Append an idle recap to the session's recap journal. Best-effort: a journal
 * failure must never disturb the recap display, so errors are logged and swallowed.
 */
export function recordSessionRecap(sessionId, cwd, recap) {
    const index = openSessionIndex();
    if (!index)
        return;
    try {
        index.insertRecap.run(sessionId, cwd, recap);
    }
    catch (error) {
        logger.debug("Session recap journal write failed", { sessionId, error: String(error) });
    }
}
/**
 * Journaled recaps matching `query`, newest first. Best-effort like the
 * writers: an unavailable index or failed read yields an empty list.
 */
export function listSessionRecaps(query = {}) {
    if (query.sessionIds?.length === 0)
        return [];
    const index = openSessionIndex();
    if (!index)
        return [];
    const where = [];
    const params = [];
    if (query.sessionIds) {
        where.push(`session_id IN (${query.sessionIds.map(() => "?").join(", ")})`);
        params.push(...query.sessionIds);
    }
    if (query.cwd !== undefined) {
        where.push("cwd = ?");
        params.push(query.cwd);
    }
    let sql = "SELECT session_id, cwd, recap, created_at FROM session_recaps";
    if (where.length > 0)
        sql += ` WHERE ${where.join(" AND ")}`;
    sql += " ORDER BY created_at DESC, id DESC";
    if (query.limit !== undefined) {
        sql += " LIMIT ?";
        params.push(query.limit);
    }
    try {
        const env_1 = { stack: [], error: void 0, hasError: false };
        try {
            // Ad-hoc SQL (the IN list varies), so prepare and finalize per call
            // instead of growing the connection's statement cache.
            const statement = __addDisposableResource(env_1, index.db.prepare(sql), false);
            return statement.all(...params).map(row => ({
                sessionId: row.session_id,
                cwd: row.cwd,
                recap: row.recap,
                createdAt: row.created_at,
            }));
        }
        catch (e_1) {
            env_1.error = e_1;
            env_1.hasError = true;
        }
        finally {
            __disposeResources(env_1);
        }
    }
    catch (error) {
        logger.debug("Session recap journal read failed", { error: String(error) });
        return [];
    }
}
/** @internal Close the cached connection so the next call re-resolves the db path — test-only. */
export function resetSessionIndexForTests() {
    closeHandle();
    failedPath = undefined;
}
