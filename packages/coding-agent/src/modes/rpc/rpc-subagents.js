import * as fs from "node:fs/promises";
import { isEnoent } from "@rva/utils";
import { AgentRegistry } from "../../registry/agent-registry";
import { parseSessionEntries } from "../../session/session-loader";
import { TASK_SUBAGENT_EVENT_CHANNEL, TASK_SUBAGENT_LIFECYCLE_CHANNEL, TASK_SUBAGENT_PROGRESS_CHANNEL, } from "../../task";
const MAX_RETAINED_TRANSCRIPT_REFERENCES = 256;
function isSessionMessageEntry(entry) {
    return entry.type === "message";
}
function statusFromLifecycle(status) {
    return status === "started" ? "running" : status;
}
function isTerminalLifecycleStatus(status) {
    return status !== "started";
}
function hasSameOwner(payload, snapshot) {
    if (payload.parentToolCallId !== undefined && snapshot.parentToolCallId !== undefined) {
        return payload.parentToolCallId === snapshot.parentToolCallId;
    }
    if (payload.sessionFile !== undefined && snapshot.sessionFile !== undefined) {
        return payload.sessionFile === snapshot.sessionFile;
    }
    return true;
}
function addPruned(set, value, maxSize) {
    set.delete(value);
    set.add(value);
    while (set.size > maxSize) {
        const oldest = set.keys().next();
        if (oldest.done)
            break;
        set.delete(oldest.value);
    }
}
export async function readRpcSubagentTranscript(sessionFile, fromByte = 0) {
    let startByte = Number.isFinite(fromByte) ? Math.max(0, Math.trunc(fromByte)) : 0;
    const file = Bun.file(sessionFile);
    let size;
    try {
        ({ size } = await fs.stat(sessionFile));
    }
    catch (err) {
        if (!isEnoent(err))
            throw err;
        return {
            sessionFile,
            fromByte: startByte,
            nextByte: startByte,
            reset: false,
            entries: [],
            messages: [],
        };
    }
    let reset = false;
    if (startByte > size) {
        startByte = 0;
        reset = true;
    }
    const text = startByte >= size ? "" : await file.slice(startByte).text();
    const lastNewline = text.lastIndexOf("\n");
    const completeText = lastNewline >= 0 ? text.slice(0, lastNewline + 1) : "";
    const entries = completeText.length > 0 ? parseSessionEntries(completeText) : [];
    const nextByte = startByte + Buffer.byteLength(completeText, "utf8");
    return {
        sessionFile,
        fromByte: startByte,
        nextByte,
        reset,
        entries,
        messages: entries.filter(isSessionMessageEntry).map(entry => entry.message),
    };
}
export class RpcSubagentRegistry {
    #subagents = new Map();
    #transcriptSessionFilesBySubagentId = new Map();
    #staleSubagentIds = new Set();
    #unsubscribers = [];
    #eventUnsubscribe;
    #observabilityBus;
    #output;
    #subscriptionLevel = "off";
    constructor(observabilityBus, output) {
        this.#observabilityBus = observabilityBus;
        this.#output = output;
        this.#unsubscribers.push(observabilityBus.on(TASK_SUBAGENT_LIFECYCLE_CHANNEL, data => {
            this.handleLifecycle(data);
        }), observabilityBus.on(TASK_SUBAGENT_PROGRESS_CHANNEL, data => {
            this.handleProgress(data);
        }));
    }
    dispose() {
        this.#eventUnsubscribe?.();
        this.#eventUnsubscribe = undefined;
        for (const unsubscribe of this.#unsubscribers)
            unsubscribe();
        this.#unsubscribers = [];
        this.#observabilityBus = undefined;
        this.#subagents.clear();
        this.#transcriptSessionFilesBySubagentId.clear();
        this.#staleSubagentIds.clear();
    }
    clear() {
        for (const subagentId of this.#subagents.keys()) {
            addPruned(this.#staleSubagentIds, subagentId, MAX_RETAINED_TRANSCRIPT_REFERENCES);
        }
        for (const subagentId of this.#transcriptSessionFilesBySubagentId.keys()) {
            addPruned(this.#staleSubagentIds, subagentId, MAX_RETAINED_TRANSCRIPT_REFERENCES);
        }
        this.#subagents.clear();
        this.#transcriptSessionFilesBySubagentId.clear();
    }
    setSubscriptionLevel(level) {
        const observabilityBus = this.#observabilityBus;
        if (level === "events" && !this.#eventUnsubscribe && observabilityBus) {
            this.#eventUnsubscribe = observabilityBus.on(TASK_SUBAGENT_EVENT_CHANNEL, data => {
                this.handleEvent(data);
            });
        }
        else if (level !== "events" && this.#eventUnsubscribe) {
            this.#eventUnsubscribe();
            this.#eventUnsubscribe = undefined;
        }
        this.#subscriptionLevel = level;
    }
    getSubscriptionLevel() {
        return this.#subscriptionLevel;
    }
    getSubagents() {
        return [...this.#subagents.values()].sort((a, b) => a.index - b.index || a.id.localeCompare(b.id));
    }
    #rememberTranscriptSession(subagentId, sessionFile) {
        if (!sessionFile)
            return;
        this.#transcriptSessionFilesBySubagentId.delete(subagentId);
        this.#transcriptSessionFilesBySubagentId.set(subagentId, sessionFile);
        while (this.#transcriptSessionFilesBySubagentId.size > MAX_RETAINED_TRANSCRIPT_REFERENCES) {
            const oldest = this.#transcriptSessionFilesBySubagentId.keys().next();
            if (oldest.done)
                break;
            this.#transcriptSessionFilesBySubagentId.delete(oldest.value);
        }
    }
    #hasTranscriptSessionFile(sessionFile) {
        for (const snapshot of this.#subagents.values()) {
            if (snapshot.sessionFile === sessionFile)
                return true;
        }
        for (const transcriptSessionFile of this.#transcriptSessionFilesBySubagentId.values()) {
            if (transcriptSessionFile === sessionFile)
                return true;
        }
        return false;
    }
    handleLifecycle(payload) {
        const existing = this.#subagents.get(payload.id);
        if (existing && !hasSameOwner(payload, existing))
            return;
        if (!existing && payload.status !== "started")
            return;
        if (payload.status === "started") {
            this.#staleSubagentIds.delete(payload.id);
        }
        const sessionFile = payload.sessionFile ?? existing?.sessionFile;
        const snapshot = {
            id: payload.id,
            index: payload.index,
            agent: payload.agent,
            agentSource: payload.agentSource,
            description: payload.description ?? existing?.description,
            status: statusFromLifecycle(payload.status),
            task: existing?.task,
            assignment: existing?.assignment,
            sessionFile,
            parentToolCallId: payload.parentToolCallId ?? existing?.parentToolCallId,
            lastUpdate: Date.now(),
            progress: existing?.progress,
        };
        this.#rememberTranscriptSession(payload.id, sessionFile);
        if (isTerminalLifecycleStatus(payload.status)) {
            this.#subagents.delete(payload.id);
        }
        else {
            this.#subagents.set(payload.id, snapshot);
        }
        if (this.#subscriptionLevel !== "off") {
            this.#output({ type: "subagent_lifecycle", payload });
        }
    }
    handleProgress(payload) {
        const progress = payload.progress;
        if (this.#staleSubagentIds.has(progress.id))
            return;
        const existing = this.#subagents.get(progress.id);
        if (!existing)
            return;
        if (!hasSameOwner(payload, existing))
            return;
        const sessionFile = payload.sessionFile ?? existing?.sessionFile;
        this.#rememberTranscriptSession(progress.id, sessionFile);
        this.#subagents.set(progress.id, {
            id: progress.id,
            index: payload.index,
            agent: payload.agent,
            agentSource: payload.agentSource,
            description: progress.description ?? existing?.description,
            status: progress.status,
            task: payload.task,
            assignment: payload.assignment,
            sessionFile,
            lastUpdate: Date.now(),
            parentToolCallId: payload.parentToolCallId ?? existing?.parentToolCallId,
            progress,
        });
        if (this.#subscriptionLevel !== "off") {
            this.#output({ type: "subagent_progress", payload });
        }
    }
    handleEvent(payload) {
        if (this.#staleSubagentIds.has(payload.id))
            return;
        if (this.#subscriptionLevel !== "events")
            return;
        this.#output({ type: "subagent_event", payload });
    }
    resolveSessionFile(selector) {
        if (selector.subagentId) {
            const snapshot = this.#subagents.get(selector.subagentId);
            const sessionFile = snapshot?.sessionFile ?? this.#transcriptSessionFilesBySubagentId.get(selector.subagentId);
            if (!sessionFile) {
                throw new Error(`Unknown subagent or session file unavailable: ${selector.subagentId}`);
            }
            return sessionFile;
        }
        if (selector.sessionFile) {
            if (this.#hasTranscriptSessionFile(selector.sessionFile))
                return selector.sessionFile;
            throw new Error("Unknown subagent session file");
        }
        throw new Error("get_subagent_messages requires subagentId or sessionFile");
    }
}
/**
 * Resolve a `get_subagents` id to its running, live registry ref, or
 * `undefined` when the host must not reach it (unknown, finished, accepted,
 * parked, aborted, or another session's agent).
 *
 * Agent ids are unique only within one parent session's artifacts scope, and
 * the process-global registry keeps the latest ref per id, so the ref must
 * carry the transcript file this session's roster recorded
 * (`<artifactsDir>/<id>.jsonl`). The ref must also still be `running`: it goes
 * `idle` once the parent accepts its result, before the terminal lifecycle
 * frame prunes the roster, and a running ref always holds a live session.
 */
export function resolveOwnedLiveSubagent(subagentRegistry, subagentId) {
    const snapshot = subagentRegistry.getSubagents().find(candidate => candidate.id === subagentId);
    // Progress can briefly report a terminal status before the terminal
    // lifecycle frame prunes the snapshot; treat that as not running.
    if ((snapshot?.status !== "running" && snapshot?.status !== "pending") || !snapshot.sessionFile)
        return undefined;
    const ref = AgentRegistry.global().get(subagentId);
    if (ref?.kind !== "sub" || ref.status !== "running" || !ref.session || ref.sessionFile !== snapshot.sessionFile) {
        return undefined;
    }
    return { ref, session: ref.session };
}
