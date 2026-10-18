import * as fs from "node:fs";
import { isEnoent, isRecord, logger, untilAborted } from "@rva/utils";
import { isPermissionDeniedError, writeFileWithFallback } from "../tools/file-write-fallback";
import { beginPendingDiskWrite, endPendingDiskWrite, FileChangeType, getActiveOrPendingClient, getOrCreateClient, notifyWorkspaceWatchedFiles, sendRequest, } from "./client";
import { getConfig, getServersForFile } from "./config";
import { captureDiagnosticVersions, captureOpenFileVersions, DIAGNOSTICS_PIPELINE_GRACE_MS, deferredDiagnosticsWaitMs, formatContent, getDiagnosticsForFile, INLINE_DIAGNOSTICS_WAIT_TIMEOUT_MS, limitDiagnosticMessages, } from "./diagnostics";
import { FileFormatResult } from "@rva/tui/tools/lsp";
import { notifyFileSaved, splitServers, syncFileContent } from "./servers";
import { summarizeDiagnosticMessages } from "./utils";
const TSSERVER_REQUEST_COMMAND = "typescript.tsserverRequest";
function supportsTsserverRequest(capabilities) {
    if (!isRecord(capabilities))
        return false;
    const executeCommandProvider = capabilities.executeCommandProvider;
    if (!isRecord(executeCommandProvider))
        return false;
    const commands = executeCommandProvider.commands;
    return Array.isArray(commands) && commands.includes(TSSERVER_REQUEST_COMMAND);
}
/**
 * Force tsserver to observe a created path before `didOpen` can pin a cached
 * missing-module resolution. The advertised command is specific to
 * typescript-language-server; every other server proceeds without a barrier.
 */
async function reloadTypeScriptProjectsAfterCreate(cwd, servers, signal, { createMissing = true } = {}) {
    await Promise.all(servers.map(async ([, serverConfig]) => {
        let client;
        try {
            client = createMissing
                ? await getOrCreateClient(serverConfig, cwd, undefined, signal)
                : await getActiveOrPendingClient(serverConfig, cwd, signal);
        }
        catch {
            signal?.throwIfAborted();
            return;
        }
        if (!client)
            return;
        if (!supportsTsserverRequest(client.serverCapabilities))
            return;
        const response = await sendRequest(client, "workspace/executeCommand", {
            command: TSSERVER_REQUEST_COMMAND,
            arguments: [
                "reloadProjects",
                {},
                { executionTarget: 0, expectsResult: true, isAsync: false, lowPriority: false },
            ],
        }, signal);
        if (isRecord(response) && response.success === false) {
            throw new Error("typescript-language-server rejected reloadProjects after a file create");
        }
    }));
}
/** No-op writethrough callback */
export async function writethroughNoop(dst, content, _signal, file, _batch, _getDeferred) {
    await writeFileWithFallback(dst, content, file);
    return { finalContent: content };
}
const writethroughBatches = new Map();
function getOrCreateWritethroughBatch(id, options) {
    const existing = writethroughBatches.get(id);
    if (existing) {
        existing.options.enableFormat ||= options.enableFormat;
        existing.options.enableDiagnostics ||= options.enableDiagnostics;
        existing.options.transformDiagnostics ??= options.transformDiagnostics;
        existing.options.deferredWaitMs = Math.max(existing.options.deferredWaitMs, options.deferredWaitMs);
        return existing;
    }
    const batch = {
        entries: new Map(),
        options: { ...options },
    };
    writethroughBatches.set(id, batch);
    return batch;
}
export async function flushLspWritethroughBatch(id, cwd, signal) {
    const state = writethroughBatches.get(id);
    if (!state) {
        return undefined;
    }
    writethroughBatches.delete(id);
    return (await flushWritethroughBatch(Array.from(state.entries.values()), "", cwd, state.options, signal))
        .diagnostics;
}
function mergeDiagnostics(results, options) {
    const messages = [];
    const servers = new Set();
    let hasResults = false;
    let hasFormatter = false;
    let formatted = false;
    let hasFailed = false;
    let hasUnsupported = false;
    for (const result of results) {
        if (!result)
            continue;
        hasResults = true;
        if (result.server) {
            for (const server of result.server.split(",")) {
                const trimmed = server.trim();
                if (trimmed) {
                    servers.add(trimmed);
                }
            }
        }
        if (result.messages.length > 0) {
            messages.push(...result.messages);
        }
        if (result.formatter !== undefined) {
            hasFormatter = true;
            if (result.formatter === FileFormatResult.FORMATTED) {
                formatted = true;
            }
            else if (result.formatter === FileFormatResult.FAILED) {
                hasFailed = true;
            }
            else if (result.formatter === FileFormatResult.UNSUPPORTED) {
                hasUnsupported = true;
            }
        }
    }
    if (!hasResults && !hasFormatter) {
        return undefined;
    }
    let summary = options.enableDiagnostics ? "no issues" : "OK";
    let errored = false;
    let limitedMessages = messages;
    if (messages.length > 0) {
        const summaryInfo = summarizeDiagnosticMessages(messages);
        summary = summaryInfo.summary;
        errored = summaryInfo.errored;
        limitedMessages = limitDiagnosticMessages(messages);
    }
    // Priority: FAILED > FORMATTED > UNCHANGED > UNSUPPORTED
    const formatter = hasFormatter
        ? hasFailed
            ? FileFormatResult.FAILED
            : formatted
                ? FileFormatResult.FORMATTED
                : hasUnsupported && !formatted
                    ? FileFormatResult.UNSUPPORTED
                    : FileFormatResult.UNCHANGED
        : undefined;
    return {
        server: servers.size > 0 ? Array.from(servers).join(", ") : undefined,
        messages: limitedMessages,
        summary,
        errored,
        formatter,
    };
}
async function scheduleDeferredDiagnosticsFetch(args) {
    try {
        const deferredTimeout = AbortSignal.timeout(Math.max(25000, args.waitMs + DIAGNOSTICS_PIPELINE_GRACE_MS));
        const combined = AbortSignal.any([args.signal, deferredTimeout]);
        const diagnostics = await getDiagnosticsForFile(args.dst, args.cwd, args.servers, {
            signal: combined,
            minVersions: args.minVersions,
            expectedDocumentVersions: args.expectedDocumentVersions,
            timeoutMs: args.waitMs,
        });
        if (args.signal.aborted || diagnostics === undefined)
            return;
        args.callback(diagnostics);
    }
    catch {
        // Cancelled or LSP gave up; silently discard.
    }
}
/**
 * Fetch post-write diagnostics without making the edit/write block on a slow
 * language server.
 *
 * Blocks inline only briefly ({@link INLINE_DIAGNOSTICS_WAIT_TIMEOUT_MS}) for a
 * fresh result. Freshness is enforced by the pre-edit `minVersions` baseline:
 * exact document-version matches return immediately, and unversioned/mismatched
 * publishes must settle with no newer publish before inline acceptance. If
 * nothing fresh arrives in the inline window and a deferred
 * channel is available, the in-flight fetch is handed off to deliver late via
 * `onDeferredDiagnostics`, and this returns `undefined` so the tool result
 * lands immediately. Without a deferred channel (direct/CI callers) it blocks
 * for the standard budget so the result is still returned inline.
 */
async function fetchDiagnosticsWithDeferral(args) {
    const { dst, cwd, servers, minVersions, expectedDocumentVersions, transformDiagnostics, deferredWaitMs, deferred, signal, } = args;
    const apply = (d) => d && transformDiagnostics ? transformDiagnostics(dst, d) : d;
    if (!deferred) {
        // No late-injection channel: block for the standard budget and return inline.
        return apply(await getDiagnosticsForFile(dst, cwd, servers, {
            signal,
            minVersions,
            expectedDocumentVersions,
        }));
    }
    // One background fetch with a generous inner budget; await it only briefly inline.
    const fetchPromise = getDiagnosticsForFile(dst, cwd, servers, {
        signal: deferred.signal,
        minVersions,
        expectedDocumentVersions,
        timeoutMs: deferredWaitMs,
    });
    const INLINE_TIMEOUT = Symbol("inline-diagnostics-timeout");
    const raced = await Promise.race([
        fetchPromise,
        Bun.sleep(INLINE_DIAGNOSTICS_WAIT_TIMEOUT_MS).then(() => INLINE_TIMEOUT),
    ]);
    if (raced !== INLINE_TIMEOUT) {
        return apply(raced);
    }
    // Slow server: deliver late via the deferred channel; nothing inline. The
    // deferred sink (edit tool) applies its own dedup, so pass the raw result.
    void fetchPromise
        .then(diagnostics => {
        if (diagnostics && !deferred.signal.aborted)
            deferred.onDeferredDiagnostics(diagnostics);
    })
        .catch(() => { });
    return undefined;
}
async function runLspWritethrough(dst, content, cwd, options, changeType, signal, file, deferred, runOptions) {
    const { enableFormat, enableDiagnostics } = options;
    const contentAlreadyWritten = runOptions?.contentAlreadyWritten ?? false;
    let finalContent = content;
    // Bytes this operation has committed to disk; `undefined` until they land
    // there (the caller already wrote `content` when `contentAlreadyWritten`).
    let diskContent = contentAlreadyWritten ? content : undefined;
    const writeContent = async (value) => {
        await writeFileWithFallback(dst, value, file);
        diskContent = value;
    };
    /** Commit {@link finalContent} unless those exact bytes are already on disk. */
    const commitWrite = async () => {
        if (diskContent !== finalContent)
            await writeContent(finalContent);
    };
    let writeNotified = false;
    const notifyWriteCommitted = async (notifySignal = signal) => {
        if (writeNotified)
            return;
        writeNotified = true;
        try {
            await notifyWorkspaceWatchedFiles(cwd, [{ filePath: dst, type: changeType }], notifySignal);
        }
        catch (error) {
            if (notifySignal?.aborted && !signal?.aborted) {
                // The operation budget died mid-notify while the caller is still
                // live: allow the post-write retry below to re-announce with the
                // caller's signal (didChangeWatchedFiles is idempotent).
                writeNotified = false;
                return;
            }
            throw error;
        }
    };
    if (!enableFormat && !enableDiagnostics) {
        await commitWrite();
        await notifyWriteCommitted();
        return { finalContent, diagnostics: undefined };
    }
    const config = getConfig(cwd);
    const servers = getServersForFile(config, dst);
    if (servers.length === 0) {
        await commitWrite();
        await notifyWriteCommitted();
        return { finalContent, diagnostics: undefined };
    }
    const { lspServers, customLinterServers } = splitServers(servers);
    const useCustomFormatter = enableFormat && customLinterServers.length > 0;
    // Capture diagnostic versions BEFORE syncing to detect stale diagnostics
    // Bound client creation by the writethrough budget: a hung/broken server
    // must not add its full init wait (30s default) to every edit.
    const minVersionsPromise = enableDiagnostics ? captureDiagnosticVersions(cwd, servers, 5000, signal) : undefined;
    let minVersions = useCustomFormatter ? undefined : await minVersionsPromise;
    let expectedDocumentVersions;
    let formatter;
    let diagnostics;
    let timedOut = false;
    let synced = false;
    let operationSignal;
    // The overlay leads disk from the first sync below until the write commits;
    // bar disk-reconciliation for the file so a concurrent semantic query cannot
    // revert the server to pre-write content.
    beginPendingDiskWrite(dst);
    try {
        const timeoutSignal = AbortSignal.timeout(5000);
        timeoutSignal.addEventListener("abort", () => {
            timedOut = true;
        }, { once: true });
        operationSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
        await untilAborted(operationSignal, async () => {
            if (useCustomFormatter) {
                // Custom linters operate on on-disk input; the shared pre-write also
                // supports implementations that inspect the file before formatting.
                if (diskContent !== content)
                    await writeContent(content);
                const [formattedContent, capturedVersions] = await Promise.all([
                    formatContent(dst, content, cwd, customLinterServers, operationSignal),
                    minVersionsPromise,
                ]);
                finalContent = formattedContent.content;
                minVersions = capturedVersions;
                if (formattedContent.failed) {
                    formatter = FileFormatResult.FAILED;
                }
                else if (formattedContent.unsupported) {
                    formatter = FileFormatResult.UNSUPPORTED;
                }
                else {
                    formatter = finalContent !== content ? FileFormatResult.FORMATTED : FileFormatResult.UNCHANGED;
                }
                await commitWrite();
                await notifyWriteCommitted(operationSignal);
                if (changeType === FileChangeType.Created) {
                    await reloadTypeScriptProjectsAfterCreate(cwd, lspServers, operationSignal, {
                        createMissing: enableDiagnostics,
                    });
                }
                await syncFileContent(dst, finalContent, cwd, lspServers, operationSignal, enableDiagnostics);
            }
            else {
                // Created paths must exist before their first `didOpen`. tsserver also
                // needs an acknowledged project reload: on delayed filesystem watchers
                // (notably macOS FSEvents), opening immediately after the write pins the
                // dependent's cached missing-module resolution indefinitely.
                if (changeType === FileChangeType.Created) {
                    await commitWrite();
                    await notifyWriteCommitted(operationSignal);
                    await reloadTypeScriptProjectsAfterCreate(cwd, lspServers, operationSignal);
                }
                // 1. Sync original content to LSP servers
                await syncFileContent(dst, content, cwd, lspServers, operationSignal);
                // 2. Format in-memory via LSP
                if (enableFormat) {
                    const formatted = await formatContent(dst, content, cwd, lspServers, operationSignal);
                    finalContent = formatted.content;
                    if (formatted.failed) {
                        formatter = FileFormatResult.FAILED;
                    }
                    else if (formatted.unsupported) {
                        formatter = FileFormatResult.UNSUPPORTED;
                    }
                    else {
                        formatter = finalContent !== content ? FileFormatResult.FORMATTED : FileFormatResult.UNCHANGED;
                    }
                }
                // 3. If formatted, sync formatted content to LSP servers
                if (finalContent !== content) {
                    await syncFileContent(dst, finalContent, cwd, lspServers, operationSignal);
                }
                // 4. Write to disk. A formatter-altered body is the only thing left to
                // commit when the create already landed above.
                await commitWrite();
                await notifyWriteCommitted(operationSignal);
            }
            if (enableDiagnostics) {
                expectedDocumentVersions = await captureOpenFileVersions(dst, cwd, lspServers, operationSignal);
            }
            // 5. Notify saved to LSP servers
            await notifyFileSaved(dst, cwd, lspServers, operationSignal, !useCustomFormatter || enableDiagnostics);
        });
        synced = true;
    }
    catch {
        if (timedOut) {
            formatter = undefined;
            diagnostics = undefined;
            // Schedule background diagnostic fetch if caller wants deferred results
            if (deferred && !deferred.signal.aborted && enableDiagnostics) {
                void scheduleDeferredDiagnosticsFetch({
                    dst,
                    cwd,
                    servers,
                    minVersions,
                    expectedDocumentVersions,
                    waitMs: options.deferredWaitMs,
                    signal: deferred.signal,
                    callback: deferred.onDeferredDiagnostics,
                });
            }
        }
        await commitWrite();
        // The write above committed even though the operation budget elapsed:
        // announce it on the caller's signal — the dead `operationSignal` would
        // abort the notify before it ever reaches the server.
        await notifyWriteCommitted();
    }
    finally {
        endPendingDiskWrite(dst);
    }
    if (synced && enableDiagnostics) {
        diagnostics = await fetchDiagnosticsWithDeferral({
            dst,
            cwd,
            servers,
            minVersions,
            expectedDocumentVersions,
            transformDiagnostics: options.transformDiagnostics,
            deferredWaitMs: options.deferredWaitMs,
            deferred,
            signal,
        });
    }
    if (formatter !== undefined) {
        diagnostics ??= {
            server: servers.map(([name]) => name).join(", "),
            messages: [],
            summary: "OK",
            errored: false,
        };
        diagnostics.formatter = formatter;
    }
    return { finalContent, diagnostics };
}
async function flushWritethroughBatch(batch, requestedDst, cwd, options, signal, getDeferred) {
    if (batch.length === 0) {
        return { finalContent: "" };
    }
    const results = [];
    const finalContents = new Map();
    for (const entry of batch) {
        const bundle = getDeferred?.(entry.dst);
        let content;
        try {
            content = await fs.promises.readFile(entry.dst, "utf8");
        }
        catch (error) {
            if (isEnoent(error)) {
                bundle?.finalize(undefined);
                continue;
            }
            // A brokered write may deny read-back even after the write succeeds.
            // Keep the committed request content as the source for diagnostics.
            if (!isPermissionDeniedError(error))
                throw error;
            content = entry.content;
        }
        const deferredInner = bundle &&
            {
                onDeferredDiagnostics: bundle.onDeferredDiagnostics,
                signal: bundle.signal,
            };
        const diag = await runLspWritethrough(entry.dst, content, cwd, options, entry.changeType, signal, entry.file, deferredInner, { contentAlreadyWritten: true });
        finalContents.set(entry.dst, diag.finalContent);
        bundle?.finalize(diag.diagnostics);
        results.push(diag.diagnostics);
    }
    const finalContent = requestedDst
        ? (finalContents.get(requestedDst) ?? batch.find(entry => entry.dst === requestedDst)?.content ?? "")
        : "";
    return {
        finalContent,
        diagnostics: mergeDiagnostics(results, options),
    };
}
/** Create a writethrough callback for LSP aware write operations */
export function createLspWritethrough(cwd, options) {
    const resolvedOptions = {
        enableFormat: options?.enableFormat ?? false,
        enableDiagnostics: options?.enableDiagnostics ?? false,
        transformDiagnostics: options?.transformDiagnostics,
        deferredWaitMs: deferredDiagnosticsWaitMs(options?.requestTimeoutSec),
    };
    return async (dst, content, signal, file, batch, getDeferred) => {
        const changeType = (await Bun.file(dst).exists()) ? FileChangeType.Changed : FileChangeType.Created;
        if (!batch) {
            const bundle = getDeferred?.(dst);
            const deferredInner = bundle &&
                {
                    onDeferredDiagnostics: bundle.onDeferredDiagnostics,
                    signal: bundle.signal,
                };
            const diagnostics = await runLspWritethrough(dst, content, cwd, resolvedOptions, changeType, signal, file, deferredInner);
            bundle?.finalize(diagnostics.diagnostics);
            return diagnostics;
        }
        // File commits are never deferred: the batch owns only LSP post-processing,
        // so a later flush cannot replay an obsolete whole-file snapshot.
        try {
            await writethroughNoop(dst, content, signal, file);
        }
        catch (error) {
            if (batch.flush) {
                const pending = writethroughBatches.get(batch.id);
                if (pending) {
                    writethroughBatches.delete(batch.id);
                    try {
                        await flushWritethroughBatch(Array.from(pending.entries.values()), "", cwd, pending.options, signal, getDeferred);
                    }
                    catch (flushError) {
                        logger.warn("Failed to flush pending LSP batch after final write failure", {
                            batchId: batch.id,
                            error: flushError instanceof Error ? flushError.message : String(flushError),
                        });
                    }
                }
            }
            throw error;
        }
        const state = getOrCreateWritethroughBatch(batch.id, resolvedOptions);
        state.entries.set(dst, { dst, file, changeType, content });
        if (!batch.flush)
            return { finalContent: content };
        writethroughBatches.delete(batch.id);
        const result = await flushWritethroughBatch(Array.from(state.entries.values()), dst, cwd, state.options, signal, getDeferred);
        return result;
    };
}
