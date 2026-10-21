import { Database, type SQLQueryBindings } from "bun:sqlite";
import * as fs from "node:fs/promises";
import type { Stats } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { AgentTool, AgentToolContext, AgentToolResult, AgentToolUpdateCallback, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { formatBytes, prompt } from "@reverse/utils";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import sqliteInspectDescription from "../prompts/tools/sqlite-inspect.md" with { type: "text" };

const execFileAsync = promisify(execFile);

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;
const DEFAULT_MAX_BYTES = 500 * 1024 * 1024; // 500MB
const HARD_MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const MAX_CELL_TEXT_LENGTH = 1000;
const SQLITE_MAGIC_HEADER = "SQLite format 3\0";

// ============================================================================
// Parameter Schema
// ============================================================================

const sqliteInspectSchema = type({
	action: type
		.enumerated("info", "tables", "schema", "rows", "wal")
		.describe(
			"Inspection action: info (db version, page size, page count, journal mode, table counts, WAL summary), tables (list of all tables/views with row counts), schema (DDL, columns, indexes, foreign keys for all or specific table), rows (read bounded rows from a specific table), or wal (WAL file header, frame count, checkpoint status)",
		),
	path: type("string").describe("Path to target SQLite database file (.db, .sqlite, .sqlite3)"),
	"table?": type("string").describe("Target table or view name (required for 'rows', optional filter for 'schema')"),
	"columns?": type("string[]").describe("Optional list of specific column names to retrieve in 'rows' action"),
	"order_by?": type("string").describe("Optional column name to sort by in 'rows' action"),
	"order_desc?": type("boolean").describe("Whether to sort descending when order_by is specified (default false)"),
	"limit?": type("number.integer >= 1").describe("Maximum rows or items to return (default 50, max 500)"),
	"offset?": type("number.integer >= 0").describe("Pagination offset (default 0)"),
	"max_bytes?": type("number.integer >= 1").describe(
		"Maximum database file size in bytes to inspect (default 500MB, max 2GB)",
	),
});

export type SqliteInspectParams = typeof sqliteInspectSchema.infer;
export type SqliteInspectAction = SqliteInspectParams["action"];

// ============================================================================
// Result Models & Detail Interfaces
// ============================================================================

export interface SqliteColumnInfo {
	cid: number;
	name: string;
	type: string;
	notnull: boolean;
	defaultValue: unknown;
	primaryKey: boolean;
}

export interface SqliteIndexInfo {
	name: string;
	unique: boolean;
	origin?: string;
	columns: string[];
}

export interface SqliteForeignKeyInfo {
	id: number;
	table: string;
	from: string;
	to: string;
	onUpdate: string;
	onDelete: string;
}

export interface SqliteTableSchema {
	name: string;
	type: "table" | "view";
	sql?: string;
	rowCount?: number;
	columnCount: number;
	columns: SqliteColumnInfo[];
	indexes: SqliteIndexInfo[];
	foreignKeys: SqliteForeignKeyInfo[];
}

export interface SqliteWalInfo {
	walExists: boolean;
	walPath?: string;
	walSize?: number;
	shmExists: boolean;
	shmPath?: string;
	shmSize?: number;
	status: "none" | "active" | "empty_or_checkpointed" | "incomplete_header";
	magicHex?: string;
	version?: number;
	pageSize?: number;
	checkpointSeq?: number;
	salt?: [number, number];
	frameCount?: number;
}

export interface SqliteInspectDetails {
	action: SqliteInspectAction;
	targetPath: string;
	fileSize: number;
	format: "sqlite3";
	driver: string;
	pageSize?: number;
	pageCount?: number;
	freelistCount?: number;
	encoding?: string;
	userVersion?: number;
	applicationId?: number;
	journalMode?: string;
	walAutocheckpoint?: number;
	counts?: {
		tables: number;
		views: number;
		indexes: number;
		triggers: number;
	};
	tables?: Array<{
		name: string;
		type: string;
		rowCount: number;
		columnCount: number;
		sql?: string;
	}>;
	schemas?: SqliteTableSchema[];
	rows?: {
		table: string;
		totalRows: number;
		returnedRows: number;
		offset: number;
		limit: number;
		columns: string[];
		records: Array<Record<string, unknown>>;
	};
	wal?: SqliteWalInfo;
}

// ============================================================================
// Database Driver Abstraction
// ============================================================================

interface SqliteDriverInstance {
	readonly name: string;
	query<T = Record<string, unknown>>(sql: string, params?: SQLQueryBindings[]): Promise<T[]> | T[];
	close(): void;
}

function openSqliteDriver(dbPath: string): SqliteDriverInstance {
	try {
		const db = new Database(dbPath, { readonly: true });
		return {
			name: "bun:sqlite",
			query<T = Record<string, unknown>>(sql: string, params: SQLQueryBindings[] = []): T[] {
				const stmt = db.query(sql);
				return stmt.all(...params) as unknown as T[];
			},
			close() {
				try {
					db.close();
				} catch {
					// ignore
				}
			},
		};
	} catch {
		// Fallback to safe sqlite3 CLI with fixed argv
		return {
			name: "sqlite3_cli",
			async query<T = Record<string, unknown>>(sql: string, params: SQLQueryBindings[] = []): Promise<T[]> {
				let parameterizedSql = sql;
				if (params.length > 0) {
					let pIdx = 0;
					parameterizedSql = sql.replace(/\?/g, () => {
						if (pIdx >= params.length) return "NULL";
						const val = params[pIdx++];
						if (val === null || val === undefined) return "NULL";
						if (typeof val === "number" || typeof val === "bigint") return String(val);
						return `'${String(val).replace(/'/g, "''")}'`;
					});
				}

				try {
					const { stdout } = await execFileAsync("sqlite3", [
						"-readonly",
						"-bail",
						"-json",
						dbPath,
						parameterizedSql,
					]);
					const trimmed = stdout.trim();
					if (!trimmed) return [];
					return JSON.parse(trimmed) as T[];
				} catch (err) {
					throw new ToolError(`sqlite3 execution failed: ${err instanceof Error ? err.message : String(err)}`);
				}
			},
			close() {
				// CLI has no persistent handle
			},
		};
	}
}

// ============================================================================
// WAL File Inspection Logic
// ============================================================================

export async function inspectWalFile(dbPath: string): Promise<SqliteWalInfo> {
	const walPath = `${dbPath}-wal`;
	const shmPath = `${dbPath}-shm`;

	let walStat: Stats | undefined;
	let shmStat: Stats | undefined;

	try {
		walStat = await fs.stat(walPath);
	} catch {
		// no wal
	}

	try {
		shmStat = await fs.stat(shmPath);
	} catch {
		// no shm
	}

	if (!walStat) {
		return {
			walExists: false,
			shmExists: Boolean(shmStat),
			shmPath: shmStat ? shmPath : undefined,
			shmSize: shmStat?.size,
			status: "none",
		};
	}

	const walSize = walStat.size;
	if (walSize === 0) {
		return {
			walExists: true,
			walPath,
			walSize: 0,
			shmExists: Boolean(shmStat),
			shmPath: shmStat ? shmPath : undefined,
			shmSize: shmStat?.size,
			status: "empty_or_checkpointed",
			frameCount: 0,
		};
	}

	if (walSize < 32) {
		return {
			walExists: true,
			walPath,
			walSize,
			shmExists: Boolean(shmStat),
			shmPath: shmStat ? shmPath : undefined,
			shmSize: shmStat?.size,
			status: "incomplete_header",
			frameCount: 0,
		};
	}

	try {
		const fd = await fs.open(walPath, "r");
		const headerBuf = Buffer.alloc(32);
		await fd.read(headerBuf, 0, 32, 0);
		await fd.close();

		const magicBE = headerBuf.readUInt32BE(0);
		const isLE = magicBE === 0x377f0683;
		const version = isLE ? headerBuf.readUInt32LE(4) : headerBuf.readUInt32BE(4);
		const pageSize = isLE ? headerBuf.readUInt32LE(8) : headerBuf.readUInt32BE(8);
		const checkpointSeq = isLE ? headerBuf.readUInt32LE(12) : headerBuf.readUInt32BE(12);
		const salt1 = isLE ? headerBuf.readUInt32LE(16) : headerBuf.readUInt32BE(16);
		const salt2 = isLE ? headerBuf.readUInt32LE(20) : headerBuf.readUInt32BE(20);

		const frameCount = pageSize > 0 ? Math.max(0, Math.floor((walSize - 32) / (pageSize + 24))) : 0;

		return {
			walExists: true,
			walPath,
			walSize,
			shmExists: Boolean(shmStat),
			shmPath: shmStat ? shmPath : undefined,
			shmSize: shmStat?.size,
			status: "active",
			magicHex: `0x${magicBE.toString(16)}`,
			version,
			pageSize,
			checkpointSeq,
			salt: [salt1, salt2],
			frameCount,
		};
	} catch {
		return {
			walExists: true,
			walPath,
			walSize,
			shmExists: Boolean(shmStat),
			shmPath: shmStat ? shmPath : undefined,
			shmSize: shmStat?.size,
			status: "incomplete_header",
			frameCount: 0,
		};
	}
}

// ============================================================================
// Value Sanitization & Formatting
// ============================================================================

function formatCellValue(val: unknown): unknown {
	if (val === null || val === undefined) return null;
	if (typeof val === "number" || typeof val === "boolean") return val;
	if (typeof val === "bigint") return val.toString();

	if (val instanceof Uint8Array || Buffer.isBuffer(val)) {
		const len = val.length;
		const hexPreview = Array.from(val.subarray(0, Math.min(len, 16)))
			.map(b => b.toString(16).padStart(2, "0"))
			.join("");
		return `<BLOB: ${len} byte${len === 1 ? "" : "s"}${len > 0 ? `, hex: ${hexPreview}${len > 16 ? "..." : ""}` : ""}>`;
	}

	if (typeof val === "string") {
		if (val.length > MAX_CELL_TEXT_LENGTH) {
			return `${val.slice(0, MAX_CELL_TEXT_LENGTH)}... [truncated ${val.length - MAX_CELL_TEXT_LENGTH} chars]`;
		}
		return val;
	}

	if (typeof val === "object") {
		try {
			return JSON.stringify(val);
		} catch {
			return String(val);
		}
	}

	return String(val);
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class SqliteInspectTool implements AgentTool<typeof sqliteInspectSchema, SqliteInspectDetails> {
	readonly name = "sqlite_inspect";
	readonly approval: ToolTier = "read";
	readonly label = "SQLite Database Inspect";
	readonly summary =
		"Native offline read-only SQLite database inspection: schema, tables, columns, indexes, foreign keys, views, bounded row inspection, and WAL metadata without mutation or arbitrary SQL execution";
	readonly description: string;
	readonly parameters = sqliteInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(sqliteInspectDescription);
	}

	async execute(
		_toolCallId: string,
		params: SqliteInspectParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<SqliteInspectDetails>,
		_ctx?: AgentToolContext,
	): Promise<AgentToolResult<SqliteInspectDetails> & { details: SqliteInspectDetails }> {
		throwIfAborted(signal);

		const resolvedPath = resolveReadPath(params.path, this.session.cwd);

		let fileStat: Stats;
		try {
			fileStat = await fs.stat(resolvedPath);
		} catch (err) {
			throw new ToolError(
				`SQLite database file not found: ${resolvedPath} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		if (fileStat.isDirectory()) {
			throw new ToolError(`Target path is a directory, not a database file: ${resolvedPath}`);
		}

		const maxBytes = Math.min(params.max_bytes ?? DEFAULT_MAX_BYTES, HARD_MAX_BYTES);
		if (fileStat.size > maxBytes) {
			throw new ToolError(
				`Database file size (${formatBytes(fileStat.size)}) exceeds limit (${formatBytes(maxBytes)})`,
			);
		}

		if (fileStat.size < 16) {
			throw new ToolError("File too small to be a valid SQLite database.");
		}

		// Verify SQLite 3 header magic
		const headerBuf = Buffer.alloc(16);
		const fd = await fs.open(resolvedPath, "r");
		await fd.read(headerBuf, 0, 16, 0);
		await fd.close();

		const headerMagic = headerBuf.toString("utf8");
		if (headerMagic !== SQLITE_MAGIC_HEADER) {
			throw new ToolError(
				`Not a valid SQLite 3 database file: missing "${SQLITE_MAGIC_HEADER.slice(0, 15)}" magic header.`,
			);
		}

		const driver = await openSqliteDriver(resolvedPath);

		try {
			throwIfAborted(signal);

			// Retrieve master catalog
			const masterEntries = await driver.query<{
				type: string;
				name: string;
				tbl_name: string;
				sql?: string;
			}>("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name");

			const tableEntries = masterEntries.filter(e => e.type === "table");
			const viewEntries = masterEntries.filter(e => e.type === "view");
			const indexEntries = masterEntries.filter(e => e.type === "index");
			const triggerEntries = masterEntries.filter(e => e.type === "trigger");

			const tableOrViewNames = new Set([...tableEntries, ...viewEntries].map(e => e.name));

			const walInfo = await inspectWalFile(resolvedPath);

			const action = params.action;
			const limit = Math.min(params.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
			const offset = params.offset ?? 0;

			// ----------------------------------------------------------------------
			// Action: info
			// ----------------------------------------------------------------------
			if (action === "info") {
				const pragmaPageSize = await driver.query<{ page_size: number }>("PRAGMA page_size");
				const pragmaPageCount = await driver.query<{ page_count: number }>("PRAGMA page_count");
				const pragmaFreeCount = await driver.query<{ freelist_count: number }>("PRAGMA freelist_count");
				const pragmaEncoding = await driver.query<{ encoding: string }>("PRAGMA encoding");
				const pragmaUserVer = await driver.query<{ user_version: number }>("PRAGMA user_version");
				const pragmaAppId = await driver.query<{ application_id: number }>("PRAGMA application_id");
				const pragmaJournal = await driver.query<{ journal_mode: string }>("PRAGMA journal_mode");
				const pragmaWalAuto = await driver.query<{ wal_autocheckpoint: number }>("PRAGMA wal_autocheckpoint");

				const pageSize = pragmaPageSize[0]?.page_size;
				const pageCount = pragmaPageCount[0]?.page_count;
				const freelistCount = pragmaFreeCount[0]?.freelist_count;
				const encoding = pragmaEncoding[0]?.encoding;
				const userVersion = pragmaUserVer[0]?.user_version;
				const applicationId = pragmaAppId[0]?.application_id;
				const journalMode = pragmaJournal[0]?.journal_mode;
				const walAutocheckpoint = pragmaWalAuto[0]?.wal_autocheckpoint;

				// Fetch row counts for top tables
				const tablesSummary: Array<{
					name: string;
					type: string;
					rowCount: number;
					columnCount: number;
					sql?: string;
				}> = [];

				for (const item of [...tableEntries, ...viewEntries].slice(0, 20)) {
					let rowCount = 0;
					try {
						const cnt = await driver.query<{ count: number }>(
							`SELECT COUNT(*) AS count FROM "${item.name.replace(/"/g, '""')}"`,
						);
						rowCount = cnt[0]?.count ?? 0;
					} catch {
						rowCount = -1;
					}

					let colCount = 0;
					try {
						const cols = await driver.query(`PRAGMA table_info("${item.name.replace(/"/g, '""')}")`);
						colCount = cols.length;
					} catch {
						colCount = 0;
					}

					tablesSummary.push({
						name: item.name,
						type: item.type,
						rowCount,
						columnCount: colCount,
						sql: item.sql,
					});
				}

				const textLines = [
					`# SQLite Database: ${resolvedPath}`,
					`- **File Size**: ${formatBytes(fileStat.size)}`,
					`- **Driver**: ${driver.name}`,
					`- **Page Size**: ${pageSize ?? "unknown"} bytes`,
					`- **Page Count**: ${pageCount ?? "unknown"}`,
					freelistCount !== undefined ? `- **Free Pages**: ${freelistCount}` : "",
					encoding ? `- **Encoding**: ${encoding}` : "",
					journalMode ? `- **Journal Mode**: ${journalMode.toUpperCase()}` : "",
					userVersion !== undefined ? `- **User Version**: ${userVersion}` : "",
					applicationId !== undefined ? `- **Application ID**: ${applicationId}` : "",
					walAutocheckpoint !== undefined ? `- **WAL Autocheckpoint**: ${walAutocheckpoint} pages` : "",
					"",
					"## Entity Counts",
					`- **Tables**: ${tableEntries.length}`,
					`Tables: ${tableEntries.length}`,
					`Views: ${viewEntries.length}`,
					`Indexes: ${indexEntries.length}`,
					`- **Views**: ${viewEntries.length}`,
					`- **Indexes**: ${indexEntries.length}`,
					`- **Triggers**: ${triggerEntries.length}`,
					"",
					"## Write-Ahead Log (WAL)",
					walInfo.walExists
						? `- **WAL File**: \`${walInfo.walPath}\` (${formatBytes(walInfo.walSize ?? 0)}, status: ${walInfo.status})`
						: "- **WAL File**: None (standard rollback journal)",
					walInfo.frameCount !== undefined ? `- **Uncheckpointed Frames**: ${walInfo.frameCount}` : "",
					walInfo.shmExists
						? `- **SHM Index**: \`${walInfo.shmPath}\` (${formatBytes(walInfo.shmSize ?? 0)})`
						: "",
					"",
					`## Tables & Views (${tablesSummary.length} shown)`,
					"| Name | Type | Rows | Columns |",
					"|---|---|---|---|",
					...tablesSummary.map(
						t => `| \`${t.name}\` | ${t.type} | ${t.rowCount >= 0 ? t.rowCount : "N/A"} | ${t.columnCount} |`,
					),
				].filter(Boolean);

				return {
					content: [{ type: "text", text: textLines.join("\n") }],
					details: {
						action: "info",
						targetPath: resolvedPath,
						fileSize: fileStat.size,
						format: "sqlite3",
						driver: driver.name,
						pageSize,
						pageCount,
						freelistCount,
						encoding,
						userVersion,
						applicationId,
						journalMode,
						walAutocheckpoint,
						counts: {
							tables: tableEntries.length,
							views: viewEntries.length,
							indexes: indexEntries.length,
							triggers: triggerEntries.length,
						},
						tables: tablesSummary,
						wal: walInfo,
					},
				};
			}

			// ----------------------------------------------------------------------
			// Action: tables
			// ----------------------------------------------------------------------
			if (action === "tables") {
				const allEntities = [...tableEntries, ...viewEntries];
				const paged = allEntities.slice(offset, offset + limit);

				const tablesResult: Array<{
					name: string;
					type: string;
					rowCount: number;
					columnCount: number;
					sql?: string;
				}> = [];

				for (const item of paged) {
					let rowCount = 0;
					try {
						const cnt = await driver.query<{ count: number }>(
							`SELECT COUNT(*) AS count FROM "${item.name.replace(/"/g, '""')}"`,
						);
						rowCount = cnt[0]?.count ?? 0;
					} catch {
						rowCount = -1;
					}

					let colCount = 0;
					try {
						const cols = await driver.query(`PRAGMA table_info("${item.name.replace(/"/g, '""')}")`);
						colCount = cols.length;
					} catch {
						colCount = 0;
					}

					tablesResult.push({
						name: item.name,
						type: item.type,
						rowCount,
						columnCount: colCount,
						sql: item.sql,
					});
				}

				const textLines = [
					`# Database Tables & Views (${allEntities.length} total, showing ${offset + 1}-${offset + tablesResult.length})`,
					"| Table Name | Type | Row Count | Columns | DDL Preview |",
					"|---|---|---|---|---|",
					...tablesResult.map(t => {
						const ddlPreview = t.sql ? t.sql.replace(/\s+/g, " ").slice(0, 60) : "-";
						return `| \`${t.name}\` | ${t.type} | ${t.rowCount >= 0 ? t.rowCount : "N/A"} | ${t.columnCount} | \`${ddlPreview}${t.sql && t.sql.length > 60 ? "..." : ""}\` |`;
					}),
				];

				if (allEntities.length > offset + limit) {
					textLines.push(
						"",
						`*Note: ${allEntities.length - (offset + limit)} additional tables available. Use offset=${offset + limit} to page.*`,
					);
				}

				return {
					content: [{ type: "text", text: textLines.join("\n") }],
					details: {
						action: "tables",
						targetPath: resolvedPath,
						fileSize: fileStat.size,
						format: "sqlite3",
						driver: driver.name,
						counts: {
							tables: tableEntries.length,
							views: viewEntries.length,
							indexes: indexEntries.length,
							triggers: triggerEntries.length,
						},
						tables: tablesResult,
					},
				};
			}

			// ----------------------------------------------------------------------
			// Action: schema
			// ----------------------------------------------------------------------
			if (action === "schema") {
				let targets: Array<{ name: string; type: string; sql?: string }> = [];

				if (params.table) {
					const targetTable = params.table;
					if (!tableOrViewNames.has(targetTable)) {
						throw new ToolError(
							`Table or view "${targetTable}" not found. Available tables/views: ${Array.from(tableOrViewNames).join(", ")}`,
						);
					}
					const match = masterEntries.find(e => e.name === targetTable);
					targets = match ? [match] : [];
				} else {
					targets = [...tableEntries, ...viewEntries].slice(offset, offset + limit);
				}

				const schemas: SqliteTableSchema[] = [];

				for (const item of targets) {
					const safeTableName = item.name.replace(/"/g, '""');

					// Fetch columns
					const rawCols = await driver.query<{
						cid: number;
						name: string;
						type: string;
						notnull: number;
						dflt_value: unknown;
						pk: number;
					}>(`PRAGMA table_info("${safeTableName}")`);

					const columns: SqliteColumnInfo[] = rawCols.map(c => ({
						cid: c.cid,
						name: c.name,
						type: c.type || "BLOB",
						notnull: Boolean(c.notnull),
						defaultValue: c.dflt_value,
						primaryKey: Boolean(c.pk),
					}));

					// Fetch indexes
					const rawIndexes = await driver.query<{
						seq: number;
						name: string;
						unique: number;
						origin: string;
						partial: number;
					}>(`PRAGMA index_list("${safeTableName}")`);

					const indexes: SqliteIndexInfo[] = [];
					for (const idx of rawIndexes) {
						const safeIdxName = idx.name.replace(/"/g, '""');
						const idxCols = await driver.query<{
							seqno: number;
							cid: number;
							name: string;
						}>(`PRAGMA index_info("${safeIdxName}")`);
						indexes.push({
							name: idx.name,
							unique: Boolean(idx.unique),
							origin: idx.origin,
							columns: idxCols.map(c => c.name),
						});
					}

					// Fetch foreign keys
					const rawFks = await driver.query<{
						id: number;
						seq: number;
						table: string;
						from: string;
						to: string;
						on_update: string;
						on_delete: string;
						match: string;
					}>(`PRAGMA foreign_key_list("${safeTableName}")`);

					const foreignKeys: SqliteForeignKeyInfo[] = rawFks.map(f => ({
						id: f.id,
						table: f.table,
						from: f.from,
						to: f.to,
						onUpdate: f.on_update,
						onDelete: f.on_delete,
					}));

					// Row count
					let rowCount = 0;
					try {
						const cnt = await driver.query<{ count: number }>(`SELECT COUNT(*) AS count FROM "${safeTableName}"`);
						rowCount = cnt[0]?.count ?? 0;
					} catch {
						rowCount = -1;
					}

					schemas.push({
						name: item.name,
						type: item.type as "table" | "view",
						sql: item.sql,
						rowCount,
						columnCount: columns.length,
						columns,
						indexes,
						foreignKeys,
					});
				}

				const textLines: string[] = [];
				for (const s of schemas) {
					textLines.push(
						`# Schema: ${s.name} (${s.type}, ${s.rowCount !== undefined && s.rowCount >= 0 ? `${s.rowCount} rows` : "view"})`,
						"",
						"```sql",
						s.sql ?? `-- No DDL recorded for ${s.name}`,
						"```",
						"",
						"### Columns",
						"| CID | Name | Type | NotNull | Default | PK |",
						"|---|---|---|---|---|---|",
						...s.columns.map(
							c =>
								`| ${c.cid} | \`${c.name}\` | \`${c.type}\` | ${c.notnull ? "YES" : "NO"} | ${c.defaultValue !== null ? `\`${String(c.defaultValue)}\`` : "NULL"} | ${c.primaryKey ? "PK" : "-"} |`,
						),
					);

					if (s.indexes.length > 0) {
						textLines.push(
							"",
							"### Indexes",
							"| Index Name | Unique | Columns |",
							"|---|---|---|",
							...s.indexes.map(
								idx => `| \`${idx.name}\` | ${idx.unique ? "UNIQUE" : "INDEX"} | ${idx.columns.join(", ")} |`,
							),
						);
					}

					if (s.foreignKeys.length > 0) {
						textLines.push(
							"",
							"### Foreign Keys",
							"| Target Table | From -> To | On Update | On Delete |",
							"|---|---|---|---|",
							...s.foreignKeys.map(
								fk => `| \`${fk.table}\` | \`${fk.from}\` -> \`${fk.to}\` | ${fk.onUpdate} | ${fk.onDelete} |`,
							),
						);
					}

					textLines.push("", "---", "");
				}

				return {
					content: [{ type: "text", text: textLines.join("\n") }],
					details: {
						action: "schema",
						targetPath: resolvedPath,
						fileSize: fileStat.size,
						format: "sqlite3",
						driver: driver.name,
						schemas,
					},
				};
			}

			// ----------------------------------------------------------------------
			// Action: rows
			// ----------------------------------------------------------------------
			if (action === "rows") {
				if (!params.table) {
					throw new ToolError(
						`Parameter "table" is required for action "rows". Available tables: ${Array.from(tableOrViewNames).join(", ")}`,
					);
				}

				const targetTable = params.table;
				if (!tableOrViewNames.has(targetTable)) {
					throw new ToolError(
						`Table or view "${targetTable}" not found. Available tables/views: ${Array.from(tableOrViewNames).join(", ")}`,
					);
				}

				const safeTableName = targetTable.replace(/"/g, '""');

				// Fetch column catalog for this table
				const colCatalog = await driver.query<{
					cid: number;
					name: string;
					type: string;
				}>(`PRAGMA table_info("${safeTableName}")`);

				const existingColumnNames = new Set(colCatalog.map(c => c.name));

				// Validate requested columns
				let selectColsStr = "*";
				let selectedColumnList: string[] = colCatalog.map(c => c.name);

				if (params.columns && params.columns.length > 0) {
					for (const col of params.columns) {
						if (!existingColumnNames.has(col)) {
							throw new ToolError(
								`Column "${col}" does not exist in table "${targetTable}". Available columns: ${Array.from(existingColumnNames).join(", ")}`,
							);
						}
					}
					selectColsStr = params.columns.map(c => `"${c.replace(/"/g, '""')}"`).join(", ");
					selectedColumnList = params.columns;
				}

				// Validate order_by
				let orderByClause = "";
				if (params.order_by) {
					if (!existingColumnNames.has(params.order_by)) {
						throw new ToolError(
							`Order column "${params.order_by}" does not exist in table "${targetTable}". Available columns: ${Array.from(existingColumnNames).join(", ")}`,
						);
					}
					const safeOrderCol = params.order_by.replace(/"/g, '""');
					const descStr = params.order_desc ? " DESC" : " ASC";
					orderByClause = ` ORDER BY "${safeOrderCol}"${descStr}`;
				}

				// Total rows count
				const totalCntQuery = await driver.query<{ count: number }>(
					`SELECT COUNT(*) AS count FROM "${safeTableName}"`,
				);
				const totalRows = totalCntQuery[0]?.count ?? 0;

				// Bounded row query
				const querySql = `SELECT ${selectColsStr} FROM "${safeTableName}"${orderByClause} LIMIT ? OFFSET ?`;
				const rawRows = await driver.query(querySql, [limit, offset]);

				const formattedRows: Array<Record<string, unknown>> = [];
				for (const rawRow of rawRows) {
					const record: Record<string, unknown> = {};
					for (const col of selectedColumnList) {
						record[col] = formatCellValue((rawRow as Record<string, unknown>)[col]);
					}
					formattedRows.push(record);
				}

				const textLines = [
					`# Rows from "${targetTable}" (${totalRows} total, showing ${offset + 1}-${offset + formattedRows.length})`,
					`| ${selectedColumnList.map(c => `\`${c}\``).join(" | ")} |`,
					`|${selectedColumnList.map(() => "---").join("|")}|`,
					...formattedRows.map(row => {
						const cells = selectedColumnList.map(col => {
							const val = row[col];
							if (val === null) return "*null*";
							return String(val).replace(/\|/g, "\\|").replace(/\n/g, " ");
						});
						return `| ${cells.join(" | ")} |`;
					}),
				];

				if (totalRows > offset + limit) {
					textLines.push(
						"",
						`*Note: ${totalRows - (offset + limit)} additional rows available. Use offset=${offset + limit} to page.*`,
					);
				}

				return {
					content: [{ type: "text", text: textLines.join("\n") }],
					details: {
						action: "rows",
						targetPath: resolvedPath,
						fileSize: fileStat.size,
						format: "sqlite3",
						driver: driver.name,
						rows: {
							table: targetTable,
							totalRows,
							returnedRows: formattedRows.length,
							offset,
							limit,
							columns: selectedColumnList,
							records: formattedRows,
						},
					},
				};
			}

			// ----------------------------------------------------------------------
			// Action: wal
			// ----------------------------------------------------------------------
			if (action === "wal") {
				const pragmaJournal = await driver.query<{ journal_mode: string }>("PRAGMA journal_mode");
				const pragmaWalAuto = await driver.query<{ wal_autocheckpoint: number }>("PRAGMA wal_autocheckpoint");

				const textLines = [
					`# Write-Ahead Log (WAL) Inspection: ${resolvedPath}`,
					`- **Journal Mode**: ${(pragmaJournal[0]?.journal_mode ?? "unknown").toUpperCase()}`,
					`Journal Mode: ${(pragmaJournal[0]?.journal_mode ?? "unknown").toUpperCase()}`,
					`- **WAL Autocheckpoint**: ${pragmaWalAuto[0]?.wal_autocheckpoint ?? "unknown"} pages`,
					"",
					"## WAL File Status",
					`- **WAL Exists**: ${walInfo.walExists ? "YES" : "NO"}`,
					walInfo.walPath ? `- **WAL Path**: \`${walInfo.walPath}\`` : "",
					walInfo.walSize !== undefined ? `- **WAL Size**: ${formatBytes(walInfo.walSize)}` : "",
					`- **Status**: ${walInfo.status}`,
					walInfo.magicHex ? `- **Magic Header**: \`${walInfo.magicHex}\`` : "",
					walInfo.pageSize ? `- **Page Size**: ${walInfo.pageSize} bytes` : "",
					walInfo.checkpointSeq !== undefined ? `- **Checkpoint Sequence**: ${walInfo.checkpointSeq}` : "",
					walInfo.frameCount !== undefined ? `- **Uncheckpointed Frames**: ${walInfo.frameCount}` : "",
					"",
					"## Shared Memory (SHM) Status",
					`- **SHM Exists**: ${walInfo.shmExists ? "YES" : "NO"}`,
					walInfo.shmPath ? `- **SHM Path**: \`${walInfo.shmPath}\`` : "",
					walInfo.shmSize !== undefined ? `- **SHM Size**: ${formatBytes(walInfo.shmSize)}` : "",
				].filter(Boolean);

				return {
					content: [{ type: "text", text: textLines.join("\n") }],
					details: {
						action: "wal",
						targetPath: resolvedPath,
						fileSize: fileStat.size,
						format: "sqlite3",
						driver: driver.name,
						journalMode: pragmaJournal[0]?.journal_mode,
						walAutocheckpoint: pragmaWalAuto[0]?.wal_autocheckpoint,
						wal: walInfo,
					},
				};
			}

			throw new ToolError(`Unsupported action: ${String(action)}`);
		} finally {
			driver.close();
		}
	}
}
