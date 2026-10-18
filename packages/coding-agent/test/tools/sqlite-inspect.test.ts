import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { Database } from "bun:sqlite";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	SqliteInspectTool,
	type SqliteInspectDetails,
	type ToolSession,
} from "@rva/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@rva/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@rva/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

/**
 * Creates a populated SQLite test database with tables, indexes, views, foreign keys, and rows.
 */
function createPopulatedDb(dbPath: string): void {
	const db = new Database(dbPath);
	db.run("PRAGMA foreign_keys = ON;");
	db.run(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			email TEXT,
			role TEXT DEFAULT 'user',
			avatar BLOB,
			created_at INTEGER
		);
	`);
	db.run("CREATE INDEX idx_users_username ON users(username);");
	db.run(`
		CREATE TABLE posts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			author_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			body TEXT,
			FOREIGN KEY(author_id) REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE
		);
	`);
	db.run("CREATE VIEW v_active_users AS SELECT id, username, role FROM users WHERE role = 'admin';");

	// Insert fixtures
	const insertUser = db.prepare(
		"INSERT INTO users (username, email, role, avatar, created_at) VALUES (?, ?, ?, ?, ?)",
	);
	insertUser.run("alice", "alice@example.com", "admin", Buffer.from([0xca, 0xfe, 0xba, 0xbe]), 1700000000);
	insertUser.run("bob", "bob@example.com", "user", Buffer.from([0xde, 0xad, 0xbe, 0xef]), 1700001000);
	insertUser.run("charlie", "charlie@example.com", "user", null, 1700002000);

	const insertPost = db.prepare("INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)");
	insertPost.run(1, "First Post", "Welcome to reverse engineering!");
	insertPost.run(1, "Second Post", "Deep diving into binary protocols.");

	db.close();
}

// ============================================================================
// Test Suites
// ============================================================================

describe("sqlite_inspect registration and discovery", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes aliases", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("sqlite_inspect");
		expect(normalizeToolName("sqlite_inspect")).toBe("sqlite_inspect");
		expect(normalizeToolName("sqlite")).toBe("sqlite_inspect");
		expect(normalizeToolName("sqlite3")).toBe("sqlite_inspect");
		expect(normalizeToolName("sqlite_analyze")).toBe("sqlite_inspect");
		expect(normalizeToolName("db_inspect")).toBe("sqlite_inspect");
	});

	it("creates tool instance with discoverable loadMode and read approval", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sqlite-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["sqlite_inspect"]);
			const tool = tools.find(t => t.name === "sqlite_inspect") as SqliteInspectTool | undefined;
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("sqlite_inspect");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
			expect(tool?.label).toBe("SQLite Database Inspect");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("sqlite_inspect path validation and errors", () => {
	it("rejects non-existent database file with informative error", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sqlite-miss-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new SqliteInspectTool(session);
			await expect(
				tool.execute("call-1", {
					action: "info",
					path: "missing.db",
				}),
			).rejects.toThrow("SQLite database file not found");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sqlite-dir-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new SqliteInspectTool(session);
			await expect(
				tool.execute("call-2", {
					action: "info",
					path: tempDir,
				}),
			).rejects.toThrow("Target path is a directory");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects non-SQLite file missing magic header", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sqlite-invalid-"));
		try {
			const dummyFile = path.join(tempDir, "invalid.db");
			await fs.writeFile(dummyFile, "THIS IS A TEXT FILE NOT SQLITE!");
			const session = createTestSession(tempDir);
			const tool = new SqliteInspectTool(session);
			await expect(
				tool.execute("call-3", {
					action: "info",
					path: "invalid.db",
				}),
			).rejects.toThrow("Not a valid SQLite 3 database file: missing \"SQLite format 3\" magic header");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("sqlite_inspect action: info and tables", () => {
	let tempDir: string;
	let dbPath: string;

	beforeAll(async () => {
		tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sqlite-info-"));
		dbPath = path.join(tempDir, "test.db");
		createPopulatedDb(dbPath);
	});

	afterAll(async () => {
		await removeWithRetries(tempDir);
	});

	it("retrieves database storage metadata, entity counts, and top tables with action: info", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		const res = await tool.execute("call-info", {
			action: "info",
			path: "test.db",
		});

		expect(res.details.format).toBe("sqlite3");
		expect(res.details.pageSize).toBeGreaterThan(0);
		expect(res.details.counts?.tables).toBe(2); // users, posts
		expect(res.details.counts?.views).toBe(1); // v_active_users

		const tables = res.details.tables ?? [];
		const userTable = tables.find(t => t.name === "users");
		expect(userTable).toBeDefined();
		expect(userTable?.rowCount).toBe(3);
		expect(userTable?.columnCount).toBe(6);

		const postTable = tables.find(t => t.name === "posts");
		expect(postTable).toBeDefined();
		expect(postTable?.rowCount).toBe(2);

		const text = textOf(res);
		expect(text).toContain("SQLite Database:");
		expect(text).toContain("Tables: 2");
		expect(text).toContain("Views: 1");
	});

	it("lists all database tables and views with row counts and DDL with action: tables", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		const res = await tool.execute("call-tables", {
			action: "tables",
			path: "test.db",
		});

		expect(res.details.tables?.length).toBe(3); // users, posts, v_active_users
		const names = res.details.tables?.map(t => t.name);
		expect(names).toContain("users");
		expect(names).toContain("posts");
		expect(names).toContain("v_active_users");

		const text = textOf(res);
		expect(text).toContain("Database Tables & Views");
		expect(text).toContain("users");
		expect(text).toContain("posts");
	});
});

describe("sqlite_inspect action: schema", () => {
	let tempDir: string;
	let dbPath: string;

	beforeAll(async () => {
		tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sqlite-schema-"));
		dbPath = path.join(tempDir, "test.db");
		createPopulatedDb(dbPath);
	});

	afterAll(async () => {
		await removeWithRetries(tempDir);
	});

	it("inspects table columns, constraints, and indexes for specific table", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		const res = await tool.execute("call-schema-users", {
			action: "schema",
			path: "test.db",
			table: "users",
		});

		expect(res.details.schemas?.length).toBe(1);
		const userSchema = res.details.schemas?.[0];
		expect(userSchema?.name).toBe("users");
		expect(userSchema?.type).toBe("table");

		// Column assertions
		const colNames = userSchema?.columns.map(c => c.name);
		expect(colNames).toContain("id");
		expect(colNames).toContain("username");
		expect(colNames).toContain("email");
		expect(colNames).toContain("role");
		expect(colNames).toContain("avatar");
		expect(colNames).toContain("created_at");

		const pkCol = userSchema?.columns.find(c => c.name === "id");
		expect(pkCol?.primaryKey).toBe(true);

		const notNullCol = userSchema?.columns.find(c => c.name === "username");
		expect(notNullCol?.notnull).toBe(true);

		// Index assertions
		const idxNames = userSchema?.indexes.map(i => i.name);
		expect(idxNames).toContain("idx_users_username");

		const text = textOf(res);
		expect(text).toContain("Schema: users");
		expect(text).toContain("Columns");
		expect(text).toContain("Indexes");
	});

	it("inspects foreign key constraints on target table", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		const res = await tool.execute("call-schema-posts", {
			action: "schema",
			path: "test.db",
			table: "posts",
		});

		const postSchema = res.details.schemas?.[0];
		expect(postSchema?.name).toBe("posts");
		expect(postSchema?.foreignKeys.length).toBe(1);

		const fk = postSchema?.foreignKeys[0];
		expect(fk?.table).toBe("users");
		expect(fk?.from).toBe("author_id");
		expect(fk?.to).toBe("id");
		expect(fk?.onUpdate).toBe("CASCADE");
		expect(fk?.onDelete).toBe("CASCADE");

		const text = textOf(res);
		expect(text).toContain("Foreign Keys");
		expect(text).toContain("author_id");
		expect(text).toContain("users");
	});

	it("rejects non-existent table name with informative error", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		await expect(
			tool.execute("call-schema-missing", {
				action: "schema",
				path: "test.db",
				table: "non_existent_table",
			}),
		).rejects.toThrow("Table or view \"non_existent_table\" not found");
	});
});

describe("sqlite_inspect action: rows and safety constraints", () => {
	let tempDir: string;
	let dbPath: string;

	beforeAll(async () => {
		tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sqlite-rows-"));
		dbPath = path.join(tempDir, "test.db");
		createPopulatedDb(dbPath);
	});

	afterAll(async () => {
		await removeWithRetries(tempDir);
	});

	it("requires table parameter for rows action", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		await expect(
			tool.execute("call-rows-no-table", {
				action: "rows",
				path: "test.db",
			}),
		).rejects.toThrow("Parameter \"table\" is required for action \"rows\"");
	});

	it("reads bounded rows and formats BLOB cells safely", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		const res = await tool.execute("call-rows-users", {
			action: "rows",
			path: "test.db",
			table: "users",
			limit: 10,
		});

		expect(res.details.rows).toBeDefined();
		expect(res.details.rows?.totalRows).toBe(3);
		expect(res.details.rows?.returnedRows).toBe(3);

		const records = res.details.rows?.records ?? [];
		expect(records.length).toBe(3);

		// Alice record
		const alice = records[0];
		expect(alice.username).toBe("alice");
		expect(alice.role).toBe("admin");
		// Check that BLOB is safely represented as preview string, not crashing or huge dump
		expect(typeof alice.avatar).toBe("string");
		expect(alice.avatar).toContain("<BLOB: 4 bytes, hex: cafebabe>");

		const text = textOf(res);
		expect(text).toContain("Rows from \"users\"");
		expect(text).toContain("alice");
		expect(text).toContain("cafebabe");
	});

	it("supports column projection and sorting", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		const res = await tool.execute("call-rows-projection", {
			action: "rows",
			path: "test.db",
			table: "users",
			columns: ["id", "username", "role"],
			order_by: "id",
			order_desc: true,
		});

		const records = res.details.rows?.records ?? [];
		expect(records.length).toBe(3);
		// Check sort descending: Charlie (id 3) first
		expect(records[0].username).toBe("charlie");
		expect(records[1].username).toBe("bob");
		expect(records[2].username).toBe("alice");

		// Check projection: only id, username, role
		expect(Object.keys(records[0])).toEqual(["id", "username", "role"]);
	});

	it("rejects invalid/injected column name", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		await expect(
			tool.execute("call-rows-bad-col", {
				action: "rows",
				path: "test.db",
				table: "users",
				columns: ["id", "evil_column'; DROP TABLE users; --"],
			}),
		).rejects.toThrow("Column \"evil_column'; DROP TABLE users; --\" does not exist");
	});

	it("rejects invalid/injected order_by column", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		await expect(
			tool.execute("call-rows-bad-order", {
				action: "rows",
				path: "test.db",
				table: "users",
				order_by: "invalid_col",
			}),
		).rejects.toThrow("Order column \"invalid_col\" does not exist");
	});

	it("pages rows with limit and offset", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		const res = await tool.execute("call-rows-page", {
			action: "rows",
			path: "test.db",
			table: "users",
			limit: 1,
			offset: 1,
			order_by: "id",
		});

		expect(res.details.rows?.returnedRows).toBe(1);
		expect(res.details.rows?.offset).toBe(1);
		const record = res.details.rows?.records[0];
		expect(record?.username).toBe("bob");
	});
});

describe("sqlite_inspect action: wal", () => {
	let tempDir: string;
	let dbPath: string;

	beforeAll(async () => {
		tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sqlite-wal-"));
		dbPath = path.join(tempDir, "wal_test.db");

		const db = new Database(dbPath);
		db.run("PRAGMA journal_mode = WAL;");
		db.run("CREATE TABLE logs (id INTEGER PRIMARY KEY, msg TEXT);");
		db.run("INSERT INTO logs (msg) VALUES ('log entry 1'), ('log entry 2');");
		db.close();
	});

	afterAll(async () => {
		await removeWithRetries(tempDir);
	});

	it("inspects WAL metadata, journal mode, and checkpoint status", async () => {
		const session = createTestSession(tempDir);
		const tool = new SqliteInspectTool(session);
		const res = await tool.execute("call-wal", {
			action: "wal",
			path: "wal_test.db",
		});

		expect(res.details.wal).toBeDefined();
		expect(res.details.journalMode).toBe("wal");
		expect(res.details.wal?.walExists).toBe(true);

		const text = textOf(res);
		expect(text).toContain("Write-Ahead Log (WAL) Inspection");
		expect(text).toContain("Journal Mode: WAL");
	});
});
