/**
 * Read-only views over the user's local history, backing the `archive` eval
 * prelude: recent projects, their sessions with idle recaps, and prompt history.
 *
 * Sources: session JSONL files under the sessions root (stat-ordered; only the
 * listed files get a bounded header/tail scan, never a full transcript read)
 * and history.db (prompt history plus the recap journal). Each view returns
 * plain records and a compact text rendering the prelude prints.
 *
 * Scopes are resolved by the caller: a project is an absolute working
 * directory, and `undefined` spans every project.
 */
import * as path from "node:path";
import { previewLine, shortenPath, TRUNCATE_LENGTHS } from "@rva/tui/render/render-utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { formatAge, formatCount } from "@rva/utils";
import { HistoryStorage } from "../session/history-storage";
import { listSessionRecaps } from "../session/session-index";
import { findSessionFiles, listRecentProjects, listRecentSessions, readSessionInfo, sessionDisplayName, } from "../session/session-listing";
import { sessionDirForCwd } from "../session/session-paths";
/** Display width of a prompt preview in listings; records keep the full text. */
const PROMPT_PREVIEW_WIDTH = 160;
/** Display width of a prompt inside a session detail view. */
const PROMPT_DETAIL_WIDTH = 600;
/**
 * Listed id length. 13 characters cover the 48-bit millisecond timestamp of a
 * UUIDv7 id (and 48 random bits of a UUIDv4), so listed prefixes stay unique
 * in practice while every view accepts any unique prefix.
 */
const SHORT_ID_LENGTH = 13;
/** Recent projects, newest activity first. */
export async function archiveProjects(limit) {
    const projects = await listRecentProjects(limit);
    const recaps = latestRecaps(projects.map(project => project.latest.id));
    const records = projects.map(project => ({
        path: project.cwd,
        sessions: project.sessionCount,
        lastActive: project.latest.modified.toISOString(),
        latest: toArchiveSession(project.latest, recaps.get(project.latest.id)),
    }));
    if (records.length === 0)
        return { text: "No projects with sessions yet.", records };
    const lines = ["Recent projects, newest first:"];
    for (const project of records) {
        lines.push(`- ${shortenPath(project.path)} · ${formatCount("session", project.sessions)} · active ${ago(project.lastActive)}`, `  latest ${shortId(project.latest.id)} · ${project.latest.title}`);
        if (project.latest.recap)
            lines.push(`  recap: ${previewLine(project.latest.recap, TRUNCATE_LENGTHS.RECAP)}`);
    }
    return { text: lines.join("\n"), records };
}
/** Newest non-empty sessions of one project (`cwd`) or of every project. */
export async function archiveSessions(cwd, limit) {
    const sessions = await listRecentSessions({ limit, sessionDir: cwd ? sessionDirForCwd(cwd) : undefined });
    const recaps = latestRecaps(sessions.map(session => session.id));
    const records = sessions.map(session => toArchiveSession(session, recaps.get(session.id)));
    if (records.length === 0)
        return { text: `No sessions ${scopeLabel(cwd)}.`, records };
    const lines = [`Sessions ${scopeLabel(cwd)}, newest first:`];
    for (const session of records) {
        const facts = [shortId(session.id), ago(session.modified)];
        if (!cwd && session.project)
            facts.push(shortenPath(session.project));
        facts.push(formatCount("msg", session.messages));
        if (session.status && session.status !== "complete" && session.status !== "unknown")
            facts.push(session.status);
        facts.push(session.title);
        lines.push(`- ${facts.join(" · ")}`);
        if (session.recap)
            lines.push(`  recap: ${previewLine(session.recap, TRUNCATE_LENGTHS.RECAP)}`);
    }
    return { text: lines.join("\n"), records };
}
/**
 * One session by id prefix or absolute file path, with every recap and its
 * newest `limit` prompts.
 *
 * @throws {ToolError} when no session or several sessions match, or the file is not a session.
 */
export async function archiveSession(idOrFile, limit) {
    const file = path.isAbsolute(idOrFile) ? idOrFile : await resolveSessionFile(idOrFile);
    const info = await readSessionInfo(file);
    if (!info)
        throw new ToolError(`Not a readable session file: ${shortenPath(file)}`);
    const recaps = listSessionRecaps({ sessionIds: [info.id] })
        .map(toArchiveRecap)
        .reverse();
    const prompts = HistoryStorage.open().getRecent(limit, { sessionId: info.id }).map(toArchivePrompt).reverse();
    const record = {
        ...toArchiveSession(info, recaps.at(-1)?.text),
        parent: info.parentSessionPath,
        recaps,
        prompts,
    };
    const facts = [`project ${shortenPath(record.project)}`, `created ${ago(record.created)}`];
    facts.push(`active ${ago(record.modified)}`, formatCount("msg", record.messages));
    if (record.status)
        facts.push(record.status);
    const lines = [`Session ${record.id} · ${record.title}`, facts.join(" · "), `file ${shortenPath(record.file)}`];
    if (record.parent)
        lines.push(`forked from ${shortenPath(record.parent)}`);
    lines.push("");
    if (recaps.length === 0)
        lines.push("No recaps journaled.");
    else {
        lines.push("Recaps, oldest first:");
        for (const recap of recaps)
            lines.push(`- ${ago(recap.at)}: ${previewLine(recap.text, TRUNCATE_LENGTHS.RECAP)}`);
    }
    if (prompts.length === 0)
        lines.push("No prompts in prompt history.");
    else {
        const more = prompts.length === limit ? `latest ${limit}, ` : "";
        lines.push(`Prompts, ${more}oldest first:`);
        for (const prompt of prompts)
            lines.push(`- ${ago(prompt.at)}: ${previewLine(prompt.text, PROMPT_DETAIL_WIDTH)}`);
    }
    return { text: lines.join("\n"), records: record };
}
/** Prompt history of one project (`cwd`) or every project, newest first; `query` switches to token search. */
export function archivePrompts(query, cwd, limit) {
    const history = HistoryStorage.open();
    const filter = { cwd };
    const entries = query ? history.search(query, limit, filter) : history.getRecent(limit, filter);
    const records = entries.map(toArchivePrompt);
    const subject = query ? `${scopeLabel(cwd)} matching ${JSON.stringify(query)}` : scopeLabel(cwd);
    if (records.length === 0)
        return { text: `No prompts ${subject}.`, records };
    const lines = [`Prompts ${subject}, newest first:`];
    for (const prompt of records) {
        const facts = [ago(prompt.at)];
        if (!cwd && prompt.project)
            facts.push(shortenPath(prompt.project));
        if (prompt.session)
            facts.push(shortId(prompt.session));
        if (prompt.uses > 1)
            facts.push(`used ${prompt.uses}×`);
        lines.push(`- ${facts.join(" · ")}`, `  ${previewLine(prompt.text, PROMPT_PREVIEW_WIDTH)}`);
    }
    return { text: lines.join("\n"), records };
}
/** Journaled idle recaps of one project (`cwd`) or every project, newest first. */
export function archiveRecaps(cwd, limit) {
    const records = listSessionRecaps({ cwd, limit }).map(toArchiveRecap);
    if (records.length === 0)
        return { text: `No recaps ${scopeLabel(cwd)}.`, records };
    const lines = [`Recaps ${scopeLabel(cwd)}, newest first:`];
    for (const recap of records) {
        const facts = [ago(recap.at)];
        if (!cwd)
            facts.push(shortenPath(recap.project));
        facts.push(shortId(recap.session));
        lines.push(`- ${facts.join(" · ")}`, `  ${previewLine(recap.text, TRUNCATE_LENGTHS.RECAP)}`);
    }
    return { text: lines.join("\n"), records };
}
async function resolveSessionFile(idPrefix) {
    const files = await findSessionFiles(idPrefix);
    if (files.length === 1)
        return files[0];
    if (files.length === 0)
        throw new ToolError(`No session id starts with "${idPrefix}".`);
    const ids = files.slice(0, 5).map(file => {
        const name = path.basename(file, ".jsonl");
        return name.slice(name.lastIndexOf("_") + 1);
    });
    throw new ToolError(`"${idPrefix}" matches ${files.length} sessions (${ids.join(", ")}); use a longer prefix.`);
}
/** Newest recap per session id. */
function latestRecaps(sessionIds) {
    const latest = new Map();
    for (const row of listSessionRecaps({ sessionIds })) {
        if (!latest.has(row.sessionId))
            latest.set(row.sessionId, row.recap);
    }
    return latest;
}
function toArchiveSession(info, recap) {
    // Headers without a timestamp parse to an Invalid Date, whose toISOString throws.
    const created = Number.isNaN(info.created.getTime()) ? info.modified : info.created;
    return {
        id: info.id,
        file: info.path,
        project: info.cwd,
        title: sessionDisplayName(info),
        created: created.toISOString(),
        modified: info.modified.toISOString(),
        messages: info.messageCount,
        status: info.status,
        recap,
    };
}
function toArchivePrompt(entry) {
    return {
        text: entry.prompt,
        at: new Date(entry.created_at * 1000).toISOString(),
        project: entry.cwd,
        session: entry.sessionId,
        uses: entry.useCount,
    };
}
function toArchiveRecap(row) {
    return {
        text: row.recap,
        at: new Date(row.createdAt * 1000).toISOString(),
        session: row.sessionId,
        project: row.cwd,
    };
}
/** `in ~/project` or `across all projects`, for view headers. */
function scopeLabel(cwd) {
    return cwd ? `in ${shortenPath(cwd)}` : "across all projects";
}
/** Relative age of an ISO timestamp (`5m ago`); sub-minute ages read `just now`. */
function ago(iso) {
    return formatAge(Math.max(1, (Date.now() - Date.parse(iso)) / 1000));
}
function shortId(id) {
    return id.slice(0, SHORT_ID_LENGTH);
}
