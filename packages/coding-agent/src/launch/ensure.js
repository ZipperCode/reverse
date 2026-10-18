/**
 * Quiet daemon-broker ensure helpers shared by broker-owned singleton daemons
 * (shared Chromium, browser relay, LSP mux). Each treats broker/daemon errors
 * as "absent" so ensure loops can retry or adopt a cross-process race winner
 * instead of failing the caller; {@link describeDaemon} instead reports when
 * absence could not be established.
 */
import { logger } from "@rva/utils";
import { throwIfAborted } from "../tools/tool-errors";
import { DaemonBrokerRejectedError } from "./client";
const DEFAULT_READY_TIMEOUT_MS = 30000;
const STOP_TIMEOUT_MS = 5000;
/** Snapshot a broker daemon, treating "unknown daemon" and broker errors as absent. */
export async function describeQuietly(client, name, label, signal) {
    try {
        const result = await client.request({ op: "describe", name }, signal);
        return result.op === "describe" ? result.daemon : undefined;
    }
    catch (error) {
        throwIfAborted(signal);
        logger.debug(`${label} describe failed`, {
            name,
            error: error instanceof Error ? error.message : String(error),
        });
        return undefined;
    }
}
/**
 * Snapshot a broker daemon, telling an unregistered name apart from a failed
 * lookup. The broker reports an unknown name only as a rejection, and rejects
 * requests for other reasons (authentication, validation) the same way, so a
 * rejected `describe` is settled by the broker's daemon list. Use this instead
 * of {@link describeQuietly} when absence authorizes a step that would harm a
 * running daemon.
 */
export async function describeDaemon(client, name, label, signal) {
    try {
        const result = await client.request({ op: "describe", name }, signal);
        return result.op === "describe" ? { status: "found", daemon: result.daemon } : { status: "unknown" };
    }
    catch (error) {
        throwIfAborted(signal);
        logger.debug(`${label} describe failed`, {
            name,
            error: error instanceof Error ? error.message : String(error),
        });
        if (!(error instanceof DaemonBrokerRejectedError))
            return { status: "unknown" };
    }
    try {
        const result = await client.request({ op: "list" }, signal);
        if (result.op !== "list")
            return { status: "unknown" };
        const daemon = result.daemons.find(listed => listed.name === name);
        return daemon ? { status: "found", daemon } : { status: "absent" };
    }
    catch (error) {
        throwIfAborted(signal);
        logger.debug(`${label} list failed`, {
            name,
            error: error instanceof Error ? error.message : String(error),
        });
        return { status: "unknown" };
    }
}
/** Block until the daemon reports ready; undefined on timeout or pre-ready exit. */
export async function waitReady(client, name, label, signal, timeoutMs = DEFAULT_READY_TIMEOUT_MS) {
    try {
        const result = await client.request({ op: "wait", name, for: "ready", timeoutMs }, signal);
        if (result.op !== "wait" || result.timedOut)
            return undefined;
        return result.daemon;
    }
    catch (error) {
        throwIfAborted(signal);
        logger.debug(`${label} ready wait failed`, {
            name,
            error: error instanceof Error ? error.message : String(error),
        });
        return undefined;
    }
}
/**
 * Best-effort stop before replacing a wedged or endpoint-less daemon. Resolves
 * with the broker's post-stop snapshot when one arrived, so callers that need
 * proof the daemon actually ended can require a terminal state; a rejected,
 * unanswered, or aborted stop resolves `undefined` — like the other quiet
 * helpers here, the RPC failure is logged and absorbed rather than thrown.
 * With `id`, a generation another process started since is left running and
 * its snapshot returned.
 */
export async function stopQuietly(client, name, label, signal, id) {
    try {
        const result = await client.request({ op: "stop", name, timeoutMs: STOP_TIMEOUT_MS, id }, signal);
        return result.op === "stop" ? result.daemon : undefined;
    }
    catch (error) {
        throwIfAborted(signal);
        logger.debug(`${label} stop failed`, {
            name,
            error: error instanceof Error ? error.message : String(error),
        });
        return undefined;
    }
}
