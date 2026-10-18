import { logger, toError } from "@rva/utils";
import { IndexedSessionStorage, } from "./indexed-session-storage";
import { SessionWriteConflictError } from "./session-storage";
const DEFAULT_PREFIX = "omp:sessions:";
const DEFAULT_SCAN_COUNT = 500;
const WRITE_FULL_SCRIPT = `-- OMP_WRITE_FULL
local expected = ARGV[6]
if expected ~= "" then
	local actual = -1
	if redis.call("EXISTS", KEYS[1]) == 1 then
		actual = redis.call("STRLEN", KEYS[1])
	end
	if actual ~= tonumber(expected) then
		return {0, actual}
	end
end
redis.call("SET", KEYS[1], ARGV[1])
redis.call("HSET", KEYS[2], ARGV[2], ARGV[3])
if ARGV[4] == "1" then
	redis.call("HSET", KEYS[3], ARGV[2], ARGV[5])
else
	redis.call("HDEL", KEYS[3], ARGV[2])
end
return {1, string.len(ARGV[1])}`;
const APPEND_SCRIPT = `-- OMP_APPEND
local size = redis.call("APPEND", KEYS[1], ARGV[1])
redis.call("HSET", KEYS[2], ARGV[2], ARGV[3])
return size`;
const UPDATE_TITLE_SCRIPT = `-- OMP_UPDATE_TITLE
redis.call("HSET", KEYS[1], ARGV[1], ARGV[2])
redis.call("HSET", KEYS[2], ARGV[1], ARGV[3])
return 1`;
function encodeTitleMeta(title) {
    return JSON.stringify(title);
}
function decodeTitleMeta(raw) {
    if (!raw)
        return undefined;
    try {
        const parsed = JSON.parse(raw);
        if (typeof parsed !== "object" || parsed === null)
            return undefined;
        const record = parsed;
        if (typeof record.updatedAt !== "string")
            return undefined;
        const source = record.source === "auto" || record.source === "user" ? record.source : undefined;
        return {
            title: typeof record.title === "string" ? record.title : undefined,
            source,
            updatedAt: record.updatedAt,
        };
    }
    catch {
        return undefined;
    }
}
/**
 * Redis-backed implementation of {@link SessionStorage}. Each session JSONL
 * file maps to a Redis STRING key, with per-key metadata (mtime) tracked in a
 * single sibling HASH. This process keeps only a metadata index (`size`,
 * `mtimeMs`) in memory so synchronous `existsSync` / `statSync` /
 * `listFilesSync` calls remain available without mirroring full content.
 */
export class RedisSessionStorage extends IndexedSessionStorage {
    /**
     * Warm the metadata index with every existing session key under the configured
     * prefix and return the ready-to-use storage. Must be awaited before passing
     * the storage into `SessionManager.create()` so synchronous lookups (session
     * resume, recent sessions, EPERM-backup recovery) see the existing keyspace.
     */
    static async create(options) {
        const storage = new RedisSessionStorage(new RedisSessionStorageBackend(options));
        await storage.initialize();
        return storage;
    }
}
class RedisSessionStorageBackend {
    #client;
    #prefix;
    #scanCount;
    constructor(options) {
        this.#client = options.client;
        this.#prefix = options.prefix ?? DEFAULT_PREFIX;
        this.#scanCount = options.scanCount ?? DEFAULT_SCAN_COUNT;
    }
    init() {
        return Promise.resolve();
    }
    async loadIndex() {
        const filePrefix = this.#fileKey("");
        const metaRaw = await this.#client.hgetall(this.#metaKey());
        const titleRaw = await this.#client.hgetall(this.#titleMetaKey());
        const meta = metaRaw ?? {};
        const titles = titleRaw ?? {};
        const seen = new Set();
        let cursor = "0";
        do {
            const [next, batch] = await this.#client.scan(cursor, "MATCH", `${filePrefix}*`, "COUNT", String(this.#scanCount));
            cursor = next;
            for (const key of batch)
                seen.add(key);
        } while (cursor !== "0");
        const fallbackMtimeMs = Date.now();
        return Promise.all(Array.from(seen, async (key) => {
            const path = key.slice(filePrefix.length);
            const size = await this.#client.strlen(key);
            const rawMtime = meta[path];
            const parsedMtime = rawMtime === undefined ? Number.NaN : Number(rawMtime);
            const title = decodeTitleMeta(titles[path]);
            return {
                path,
                size,
                mtimeMs: Number.isFinite(parsedMtime) ? parsedMtime : fallbackMtimeMs,
                title: title?.title,
                titleSource: title?.source,
                titleUpdatedAt: title?.updatedAt,
            };
        }));
    }
    readFull(path) {
        return this.#client.get(this.#fileKey(path));
    }
    async readSlices(path, prefixBytes, suffixBytes) {
        const key = this.#fileKey(path);
        const head = prefixBytes > 0 ? this.#client.getrange(key, 0, prefixBytes - 1) : Promise.resolve("");
        const tail = suffixBytes > 0 ? this.#client.getrange(key, -suffixBytes, -1) : Promise.resolve("");
        return Promise.all([head, tail]);
    }
    async writeFull(path, content, mtimeMs, title, expectedSize) {
        const result = await this.#client.send("EVAL", [
            WRITE_FULL_SCRIPT,
            "3",
            this.#fileKey(path),
            this.#metaKey(),
            this.#titleMetaKey(),
            content,
            path,
            String(mtimeMs),
            title ? "1" : "0",
            title ? encodeTitleMeta(title) : "",
            expectedSize === undefined ? "" : String(expectedSize ?? -1),
        ]);
        if (expectedSize === undefined)
            return;
        const written = Array.isArray(result) && Number(result[0]) === 1;
        if (written)
            return;
        const encodedActual = Array.isArray(result) ? Number(result[1]) : Number.NaN;
        const actualSize = encodedActual === -1 ? null : Number.isFinite(encodedActual) ? encodedActual : null;
        throw new SessionWriteConflictError(path, expectedSize, actualSize);
    }
    async append(path, line, mtimeMs) {
        await this.#client.send("EVAL", [
            APPEND_SCRIPT,
            "2",
            this.#fileKey(path),
            this.#metaKey(),
            line,
            path,
            String(mtimeMs),
        ]);
    }
    async updateSessionTitle(path, title, mtimeMs) {
        await this.#client.send("EVAL", [
            UPDATE_TITLE_SCRIPT,
            "2",
            this.#metaKey(),
            this.#titleMetaKey(),
            path,
            String(mtimeMs),
            encodeTitleMeta(title),
        ]);
    }
    async truncate(path, mtimeMs) {
        await this.writeFull(path, "", mtimeMs);
    }
    async remove(paths) {
        if (paths.length === 0)
            return;
        await this.#client.del(...paths.map(path => this.#fileKey(path)));
        await this.#client.hdel(this.#metaKey(), ...paths);
        await this.#client.hdel(this.#titleMetaKey(), ...paths);
    }
    async move(src, dst, mtimeMs) {
        await this.#client.rename(this.#fileKey(src), this.#fileKey(dst));
        try {
            const titleMeta = await this.#client.hgetall(this.#titleMetaKey());
            await this.#client.hdel(this.#metaKey(), src);
            await this.#client.hset(this.#metaKey(), dst, String(mtimeMs));
            await this.#client.hdel(this.#titleMetaKey(), src);
            const title = titleMeta[src];
            if (title !== undefined)
                await this.#client.hset(this.#titleMetaKey(), dst, title);
        }
        catch (err) {
            logger.warn("Redis session storage meta rename failed", {
                src,
                dst,
                error: toError(err).message,
            });
        }
    }
    #fileKey(path) {
        return `${this.#prefix}file:${path}`;
    }
    #metaKey() {
        return `${this.#prefix}meta`;
    }
    #titleMetaKey() {
        return `${this.#prefix}title`;
    }
}
