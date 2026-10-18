import { type } from "@rva/omptype";
import { TOOL_INTERRUPT_ABORT_REASON, } from "@rva/agent";
import { prompt } from "@rva/utils";
import { IrcBus } from "../irc/bus";
import waitDescription from "../prompts/tools/wait.md" with { type: "text" };
import { buildJobResult, snapshotJobs, undeliveredJobs } from "../async/job-control";
import { hasLiveOwnedService, listServicesTolerant, waitForOwnedServiceCompletion } from "../launch/services";
import { drainPendingInbox, messageResult } from "../irc/messaging";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import { cfgLaunchEnabled } from "./settings";
const waitSchema = type({});
const WAIT_MAX_MS = 30 * 60000;
const PROGRESS_INTERVAL_MS = 500;
function takeQueuedMessage(messaging) {
    if (!messaging)
        return undefined;
    return drainPendingInbox(messaging.registry, messaging.senderId) ?? IrcBus.global().take(messaging.senderId);
}
/** Whether `session` has the `wait` tool active, so prompts may point blocked callers at it. */
export function hasWaitTool(session) {
    return session.isToolActive?.("wait") ?? true;
}
/**
 * Blocks on background jobs and services the calling agent started. Work it
 * did not start never sustains a wait: a peer owes no message — a parent
 * blocked awaiting this very agent stays running — so waiting on peers can
 * park both sides for good. A message arriving mid-wait still ends it.
 */
export class WaitTool {
    session;
    name = "wait";
    label = "Wait";
    summary = "Wait for the next result of a background job or service you started";
    description = prompt.render(waitDescription);
    parameters = waitSchema;
    strict = true;
    interruptible = true;
    approval = "read";
    loadMode = "essential";
    intent = "optional";
    constructor(session) {
        this.session = session;
    }
    async execute(_toolCallId, _params, signal, onUpdate) {
        const registry = this.session.agentRegistry;
        const senderId = this.session.getAgentId?.() ?? undefined;
        const messaging = registry && senderId ? { registry, senderId } : undefined;
        const manager = this.session.asyncJobManager;
        const pending = takeQueuedMessage(messaging);
        if (pending && messaging)
            return messageResult(messaging.senderId, pending);
        // Refreshes owned-service tracking only; jobs are in-process, so a hung
        // broker must not turn every wait into an error.
        if (cfgLaunchEnabled.get(this.session.settings)) {
            await listServicesTolerant(this.session, signal);
            const queued = takeQueuedMessage(messaging);
            if (queued && messaging)
                return messageResult(messaging.senderId, queued);
        }
        const jobs = manager?.getRunningJobs({ ownerId: senderId }) ?? [];
        // An accepted completion whose delivery has not reached the transcript
        // yet (queued, parked on the yield queue, or skipped while an earlier
        // wait watched it) is exactly what this wait is for: return it now.
        const undelivered = manager ? undeliveredJobs(manager, senderId) : [];
        if (manager && undelivered.length > 0) {
            return buildJobResult(this.session, manager, "wait", [...undelivered, ...jobs], []);
        }
        const serviceRunning = hasLiveOwnedService(this.session);
        if (jobs.length === 0 && !serviceRunning) {
            throw new ToolError("Nothing to wait for: no background job or service you started is running. Other agents' results and messages arrive on their own.");
        }
        return this.#blockUntilWake({ jobs, manager, messaging, serviceRunning, signal, onUpdate });
    }
    /** Block until an owned job settles, an owned service finishes, a message arrives, the cap elapses, or the call aborts. */
    async #blockUntilWake(args) {
        const { jobs, manager, messaging, serviceRunning, signal, onUpdate } = args;
        const watchedIds = jobs.map(job => job.id);
        manager?.watchJobs(watchedIds);
        const serviceAbort = new AbortController();
        const serviceLeg = serviceRunning ? waitForOwnedServiceCompletion(this.session, serviceAbort.signal) : undefined;
        const busAbort = new AbortController();
        // Only `busAbort` can reject this leg, and it fires once the wait has settled.
        const busLeg = messaging
            ? IrcBus.global()
                .wait(messaging.senderId, {}, 0, busAbort.signal)
                .catch(() => null)
            : undefined;
        const { promise: timeout, resolve: timedOut } = Promise.withResolvers();
        const timer = setTimeout(timedOut, WAIT_MAX_MS);
        const abort = Promise.withResolvers();
        const onAbort = () => abort.resolve();
        if (signal) {
            if (signal.aborted)
                onAbort();
            else
                signal.addEventListener("abort", onAbort, { once: true });
        }
        const emitProgress = () => onUpdate?.({
            content: [{ type: "text", text: "" }],
            details: { op: "wait", jobs: snapshotJobs(this.session, jobs) },
        });
        const progressTimer = onUpdate && jobs.length > 0 ? setInterval(emitProgress, PROGRESS_INTERVAL_MS) : undefined;
        if (jobs.length > 0)
            emitProgress();
        let wake;
        try {
            wake = await Promise.race([
                ...jobs.map(job => job.promise.then(() => "job")),
                ...(busLeg ? [busLeg.then(() => "message")] : []),
                ...(serviceLeg ? [serviceLeg.then(() => "service")] : []),
                timeout.then(() => "timeout"),
                abort.promise.then(() => "abort"),
            ]);
        }
        finally {
            clearTimeout(timer);
            clearInterval(progressTimer);
            busAbort.abort();
            serviceAbort.abort();
            signal?.removeEventListener("abort", onAbort);
        }
        // Unwatch only after the result is built: a job recovered below is
        // consumed first, while one left unreported (message or interrupt won
        // the race) is re-enqueued for its ordinary async delivery.
        try {
            // A dequeued message wins a photo-finish with a job: the job remains
            // deliverable, whereas a lost message cannot be recovered from the bus.
            const message = await busLeg;
            if (message && messaging)
                return messageResult(messaging.senderId, message);
            if (signal?.aborted) {
                // Steering, a peer IRC, or a completion notice cut the wait short:
                // the designed wake path, so the message injects after a normal
                // result. Any other abort stops the run.
                if (signal.reason === TOOL_INTERRUPT_ABORT_REASON) {
                    return {
                        content: [{ type: "text", text: "Wait interrupted by message." }],
                        details: { op: "wait", jobs: [], interrupted: true },
                        useless: true,
                    };
                }
                throwIfAborted(signal);
            }
            if (manager && jobs.length > 0)
                return buildJobResult(this.session, manager, "wait", jobs, []);
            return {
                content: [
                    {
                        type: "text",
                        text: wake === "service"
                            ? "A service finished. Read proc:// for its status and output."
                            : "Wait limit reached; background work may still be running. Read proc:// for status.",
                    },
                ],
                details: { op: "wait", jobs: [] },
            };
        }
        finally {
            manager?.unwatchJobs(watchedIds);
        }
    }
}
