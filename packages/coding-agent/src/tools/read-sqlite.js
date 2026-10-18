import { DEFAULT_MAX_LINES, truncateHead } from "@rva/tui/tools/streaming-output";
import { applyListLimit } from "@rva/tui/tools/list-limit";
import { resolveReadPath } from "./path-utils";
import { prependSuffixResolutionNotice, toReadTruncationStats } from "./read-format";
import { findSuffixMatchCached, isNotFoundError, isRemoteMountPath, } from "./read-path-resolution";
import { executeReadQuery, getRowByKey, getRowByRowId, getTableSchema, isSqliteFile, listTables, MAX_RAW_QUERY_ROWS, openSqliteReadConnection, parseSqlitePathCandidates, parseSqliteSelector, queryRows, renderRow, renderSchema, renderTable, renderTableList, resolveTableRowLookup, } from "./sqlite-reader";
import { throwIfAborted } from "./tool-errors";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { toolResult } from "./tool-result";
export async function resolveSqliteReadPath(session, readPath, suffixCache, signal) {
    const candidates = parseSqlitePathCandidates(readPath);
    for (const candidate of candidates) {
        let absolutePath = resolveReadPath(candidate.sqlitePath, session.cwd);
        let suffixResolution;
        try {
            const stat = await Bun.file(absolutePath).stat();
            // Sniffing a FIFO or device can block; leave it to the read tool's rejection.
            if (!stat.isFile())
                continue;
            if (!(await isSqliteFile(absolutePath)))
                continue;
            return {
                absolutePath,
                sqliteSubPath: candidate.subPath,
                queryString: candidate.queryString,
                suffixResolution,
            };
        }
        catch (error) {
            if (!isNotFoundError(error) || isRemoteMountPath(absolutePath))
                continue;
            const suffixMatch = await findSuffixMatchCached(session, suffixCache, candidate.sqlitePath, signal);
            if (!suffixMatch)
                continue;
            try {
                const retryStat = await Bun.file(suffixMatch.absolutePath).stat();
                if (!retryStat.isFile())
                    continue;
                if (!(await isSqliteFile(suffixMatch.absolutePath)))
                    continue;
                absolutePath = suffixMatch.absolutePath;
                suffixResolution = { from: candidate.sqlitePath, to: suffixMatch.displayPath };
                return {
                    absolutePath,
                    sqliteSubPath: candidate.subPath,
                    queryString: candidate.queryString,
                    suffixResolution,
                };
            }
            catch (retryError) {
                if (!isNotFoundError(retryError)) {
                    throw retryError;
                }
            }
        }
    }
    return null;
}
export async function readSqlite(resolvedSqlitePath, signal) {
    throwIfAborted(signal);
    const selectorInput = {
        subPath: resolvedSqlitePath.sqliteSubPath,
        queryString: resolvedSqlitePath.queryString,
    };
    const selector = parseSqliteSelector(selectorInput.subPath, selectorInput.queryString);
    const details = {
        resolvedPath: resolvedSqlitePath.absolutePath,
        suffixResolution: resolvedSqlitePath.suffixResolution,
    };
    let db = null;
    try {
        db = await openSqliteReadConnection(resolvedSqlitePath.absolutePath);
        throwIfAborted(signal);
        switch (selector.kind) {
            case "list": {
                const listLimit = applyListLimit(listTables(db), { limit: 500 });
                const output = prependSuffixResolutionNotice(renderTableList(listLimit.items), resolvedSqlitePath.suffixResolution);
                const truncation = truncateHead(output, { maxLines: Number.MAX_SAFE_INTEGER });
                details.truncation = truncation.truncated ? toReadTruncationStats(truncation) : undefined;
                const resultBuilder = toolResult(details)
                    .text(truncation.content)
                    .sourcePath(resolvedSqlitePath.absolutePath)
                    .limits({ resultLimit: listLimit.meta.resultLimit?.reached });
                if (truncation.truncated) {
                    resultBuilder.truncation(truncation, { direction: "head" });
                }
                return resultBuilder.done();
            }
            case "schema": {
                const sampleRows = queryRows(db, selector.table, { limit: selector.sampleLimit, offset: 0 });
                let output = renderSchema(getTableSchema(db, selector.table), {
                    columns: sampleRows.columns,
                    rows: sampleRows.rows,
                });
                if (sampleRows.rows.length < sampleRows.totalCount) {
                    const remaining = sampleRows.totalCount - sampleRows.rows.length;
                    output += `\n[${remaining} more rows; append :${selector.table}?limit=20&offset=${sampleRows.rows.length} to the database path to continue]`;
                }
                return toolResult(details)
                    .text(prependSuffixResolutionNotice(output, resolvedSqlitePath.suffixResolution))
                    .sourcePath(resolvedSqlitePath.absolutePath)
                    .done();
            }
            case "row": {
                const lookup = resolveTableRowLookup(db, selector.table);
                const row = lookup.kind === "pk"
                    ? getRowByKey(db, selector.table, lookup, selector.key)
                    : getRowByRowId(db, selector.table, selector.key);
                if (!row) {
                    return toolResult(details)
                        .text(prependSuffixResolutionNotice(`No row found in table '${selector.table}' for key '${selector.key}'.`, resolvedSqlitePath.suffixResolution))
                        .sourcePath(resolvedSqlitePath.absolutePath)
                        .done();
                }
                return toolResult(details)
                    .text(prependSuffixResolutionNotice(renderRow(row), resolvedSqlitePath.suffixResolution))
                    .sourcePath(resolvedSqlitePath.absolutePath)
                    .done();
            }
            case "query": {
                const page = queryRows(db, selector.table, selector);
                return toolResult(details)
                    .text(prependSuffixResolutionNotice(renderTable(page.columns, page.rows, {
                    totalCount: page.totalCount,
                    offset: selector.offset,
                    limit: selector.limit,
                    table: selector.table,
                    dbPath: resolvedSqlitePath.absolutePath,
                }), resolvedSqlitePath.suffixResolution))
                    .sourcePath(resolvedSqlitePath.absolutePath)
                    .done();
            }
            case "raw": {
                const result = executeReadQuery(db, selector.sql);
                let output = renderTable(result.columns, result.rows, {
                    totalCount: result.rows.length,
                    offset: 0,
                    limit: result.rows.length || DEFAULT_MAX_LINES,
                    table: "query",
                    dbPath: resolvedSqlitePath.absolutePath,
                });
                if (result.truncated) {
                    output += `\n[Output capped at ${MAX_RAW_QUERY_ROWS} rows; add a LIMIT/OFFSET clause to the query to page through more]`;
                }
                return toolResult(details)
                    .text(prependSuffixResolutionNotice(output, resolvedSqlitePath.suffixResolution))
                    .sourcePath(resolvedSqlitePath.absolutePath)
                    .done();
            }
        }
        throw new ToolError("Unsupported SQLite selector");
    }
    catch (error) {
        if (error instanceof ToolError) {
            throw error;
        }
        throw new ToolError(error instanceof Error ? error.message : String(error));
    }
    finally {
        db?.close();
    }
}
