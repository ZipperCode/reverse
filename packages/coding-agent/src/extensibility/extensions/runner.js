/**
 * Extension runner - executes extensions and manages their lifecycle.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { isNonBlankContext, joinAdditionalContext, } from "@rva/agent";
import { clearContextHistoryIndex, getContextHistoryIndex, markPerCallContextMessage, setContextHistoryIndex, } from "@rva/ai/utils/block-symbols";
import { logger } from "@rva/utils";
import { refreshShellConfigCache } from "@rva/utils/procmgr";
import { MAIN_AGENT_RULE_NAME } from "../../capability/rule";
import { withActiveSettings } from "../../config/settings";
import { theme } from "@rva/tui/theme";
import { MAIN_AGENT_ID } from "../../registry/agent-registry";
import { addFileDeleteFallback, addFileWriteFallback } from "../../tools/file-write-fallback";
import { accumulateToolCallResult, buildAggregatedToolCallResult } from "../shared-events";
import { ManagedTimers } from "./managed-timers";
import { createExtensionModelQuery } from "./model-api";
import { trackUserWaits } from "./user-wait";
import { cfgExtensionHandlersToolCallTimeoutMs } from "../settings";
export const EXTENSION_HANDLER_TIMEOUT_MS = 30000;
let extensionHandlerTimeoutMs = EXTENSION_HANDLER_TIMEOUT_MS;
function throwUnsupportedServiceTierAction() {
    throw new Error("This extension host does not support service-tier actions");
}
export function testSetExtensionHandlerTimeoutMs(timeoutMs) {
    extensionHandlerTimeoutMs = timeoutMs;
}
function normalizeHandlerTimeout(timeoutMs) {
    return Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : EXTENSION_HANDLER_TIMEOUT_MS;
}
/**
 * Dedicated cap for `session_shutdown` handlers. The generic 30s budget is
 * appropriate for events extensions can observe (e.g. `session_start`,
 * `before_provider_request`), but `session_shutdown` is fire-and-forget
 * teardown — extensions receive no result and the user has already asked to
 * leave. A hung handler (e.g. an extension waiting on a stuck IPC pipe to a
 * companion app) MUST NOT hold Ctrl+C / `/exit` hostage for the full window.
 * See issue #2600.
 */
export const SESSION_SHUTDOWN_HANDLER_TIMEOUT_MS = 2000;
let sessionShutdownHandlerTimeoutMs = SESSION_SHUTDOWN_HANDLER_TIMEOUT_MS;
export function testSetSessionShutdownHandlerTimeoutMs(timeoutMs) {
    sessionShutdownHandlerTimeoutMs = timeoutMs;
}
/** Per-event handler budget. Defaults to the generic cap; `session_shutdown`
 *  uses its own short cap so teardown stays prompt. */
function handlerTimeoutForEvent(eventType) {
    return eventType === "session_shutdown" ? sessionShutdownHandlerTimeoutMs : extensionHandlerTimeoutMs;
}
const EXTENSION_HANDLER_TIMEOUT = Symbol("extensionHandlerTimeout");
const EXTENSION_HANDLER_ABORTED = Symbol("extensionHandlerAborted");
/** Events after which the session file and id may differ from what child shells last saw. */
const SESSION_IDENTITY_EVENTS = {
    session_start: true,
    session_switch: true,
    session_branch: true,
};
function attachHandlerSignal(dialogOptions, handlerSignal) {
    if (!dialogOptions)
        return { signal: handlerSignal };
    if (!dialogOptions.signal)
        return { ...dialogOptions, signal: handlerSignal };
    if (dialogOptions.signal === handlerSignal)
        return dialogOptions;
    return { ...dialogOptions, signal: AbortSignal.any([dialogOptions.signal, handlerSignal]) };
}
function createHandlerUIContext(ui, handlerSignal, timeoutBudget) {
    const askDialog = ui.askDialog;
    const approve = ui.approve;
    const runDialog = async (dialog) => {
        timeoutBudget?.pause();
        try {
            return await dialog();
        }
        finally {
            timeoutBudget?.resume();
        }
    };
    const dialogMethods = {
        select: (title, options, dialogOptions) => runDialog(() => ui.select(title, options, attachHandlerSignal(dialogOptions, handlerSignal))),
        confirm: (title, message, dialogOptions) => runDialog(() => ui.confirm(title, message, attachHandlerSignal(dialogOptions, handlerSignal))),
        input: (title, placeholder, dialogOptions) => runDialog(() => ui.input(title, placeholder, attachHandlerSignal(dialogOptions, handlerSignal))),
        askDialog: askDialog
            ? (questions, dialogOptions) => runDialog(() => askDialog.call(ui, questions, attachHandlerSignal(dialogOptions, handlerSignal)))
            : undefined,
        approve: approve
            ? (prompt, dialogOptions) => runDialog(() => approve.call(ui, prompt, attachHandlerSignal(dialogOptions, handlerSignal)))
            : undefined,
        custom: async (factory, options) => {
            let customSettled = false;
            let componentReady = false;
            try {
                return await ui.custom(async (...args) => {
                    const component = await factory(...args);
                    if (!customSettled) {
                        timeoutBudget?.pause();
                        componentReady = true;
                    }
                    return component;
                }, {
                    ...options,
                    signal: options?.signal ? AbortSignal.any([options.signal, handlerSignal]) : handlerSignal,
                });
            }
            finally {
                customSettled = true;
                if (componentReady)
                    timeoutBudget?.resume();
            }
        },
        editor: (title, prefill, dialogOptions, editorOptions) => runDialog(() => ui.editor(title, prefill, attachHandlerSignal(dialogOptions, handlerSignal), editorOptions)),
    };
    const delegatedMethods = new Map();
    return new Proxy(ui, {
        get(target, property) {
            if (Object.hasOwn(dialogMethods, property)) {
                return Reflect.get(dialogMethods, property, dialogMethods);
            }
            const cached = delegatedMethods.get(property);
            if (cached)
                return cached;
            const value = Reflect.get(target, property, target);
            if (typeof value !== "function")
                return value;
            const delegated = value.bind(target);
            delegatedMethods.set(property, delegated);
            return delegated;
        },
    });
}
/**
 * Scope `ctx` to a single handler run without spreading it: `{ ...ctx }` would
 * snapshot live accessors (notably the `model` getter), so a handler calling
 * `pi.setModel()` and then reading `ctx.model` would see a stale model.
 * Prototype delegation keeps every getter live while overriding `ui`.
 */
function createHandlerContext(ctx, handlerSignal, timeoutBudget) {
    const scoped = Object.create(ctx);
    Object.defineProperty(scoped, "ui", {
        value: createHandlerUIContext(ctx.ui, handlerSignal, timeoutBudget),
        enumerable: true,
        configurable: true,
    });
    return scoped;
}
/**
 * Race `work` against a `timeoutMs` budget and optional cancellation signal,
 * clearing the timer and abort listener as soon as one branch settles.
 *
 * We deliberately avoid `Bun.sleep(timeoutMs).then(...)` here: that leaves an
 * uncancellable timer registered with the event loop, so every successful
 * handler race leaks a timer that keeps the process alive until the deadline
 * fires — up to the default 30s cap, which stalls non-interactive CLI exit
 * after any subscribed `tool_call`/`tool_result` handler runs (issue #3948
 * review, `chatgpt-codex-connector[bot]`). `setTimeout` returns a handle we
 * can `clearTimeout` on the winning branch.
 */
async function raceHandlerWithTimeout(work, timeoutMs, signal) {
    if (signal?.aborted)
        return EXTENSION_HANDLER_ABORTED;
    const timeoutController = new AbortController();
    const handlerSignal = signal ? AbortSignal.any([signal, timeoutController.signal]) : timeoutController.signal;
    const { promise: interruptPromise, resolve: resolveInterrupt } = Promise.withResolvers();
    const onAbort = () => resolveInterrupt(EXTENSION_HANDLER_ABORTED);
    signal?.addEventListener("abort", onAbort, { once: true });
    let timer;
    let remainingMs = timeoutMs;
    let activeSince = performance.now();
    let pauseDepth = 0;
    let settled = false;
    const clearTimer = () => {
        if (timer === undefined)
            return;
        clearTimeout(timer);
        timer = undefined;
    };
    const expire = () => {
        if (settled)
            return;
        settled = true;
        clearTimer();
        timeoutController.abort(new DOMException(`Handler timed out after ${timeoutMs}ms`, "TimeoutError"));
        resolveInterrupt(EXTENSION_HANDLER_TIMEOUT);
    };
    const armTimer = () => {
        if (settled || pauseDepth > 0)
            return;
        activeSince = performance.now();
        timer = setTimeout(expire, Math.max(0, remainingMs));
    };
    const settle = () => {
        if (settled)
            return;
        settled = true;
        clearTimer();
    };
    const timeoutBudget = {
        pause: () => {
            if (settled)
                return;
            pauseDepth++;
            if (pauseDepth !== 1)
                return;
            remainingMs = Math.max(0, remainingMs - (performance.now() - activeSince));
            clearTimer();
            if (remainingMs <= 0)
                expire();
        },
        resume: () => {
            if (settled || pauseDepth === 0)
                return;
            pauseDepth--;
            if (pauseDepth === 0)
                armTimer();
        },
    };
    armTimer();
    try {
        if (signal?.aborted)
            return EXTENSION_HANDLER_ABORTED;
        const workPromise = Promise.resolve(work(handlerSignal, timeoutBudget));
        const result = await Promise.race([workPromise, interruptPromise]);
        if (result === EXTENSION_HANDLER_TIMEOUT) {
            await Promise.race([
                workPromise.then(() => undefined, () => undefined),
                Bun.sleep(0),
            ]);
        }
        return result;
    }
    finally {
        settle();
        signal?.removeEventListener("abort", onAbort);
    }
}
const MAX_PENDING_CREDENTIAL_DISABLED = 32;
/**
 * Buffer cap for `mcp_notification` events received before {@link ExtensionRunner.initialize}
 * has run. Sized to match the manager-side buffer in `MCPManager.NOTIFICATION_BUFFER_CAP` so
 * the two layers can't drop different amounts of the same burst — the pipe drains, or it
 * spills, but it does so consistently at both ends. Drop-oldest under pressure.
 */
const MAX_PENDING_MCP_NOTIFICATIONS = 100;
/**
 * Emit `session_shutdown`, dispose file-write-fallback registrations, and clear
 * timers owned by an extension runner.
 *
 * Returns whether any shutdown handlers were present. Fallback disposal and timer
 * cleanup run even when a handler fails so extension background work — and a
 * fallback bound to this session's context — cannot outlive its host.
 */
export async function emitSessionShutdownEvent(extensionRunner) {
    if (!extensionRunner)
        return false;
    try {
        if (!extensionRunner.hasHandlers("session_shutdown"))
            return false;
        await extensionRunner.emit({
            type: "session_shutdown",
        });
        return true;
    }
    finally {
        extensionRunner.disposeFileFallbacks();
        extensionRunner.clearManagedTimers();
    }
}
const noOpUIContext = {
    select: async (_title, _options, _dialogOptions) => undefined,
    confirm: async (_title, _message, _dialogOptions) => false,
    input: async (_title, _placeholder, _dialogOptions) => undefined,
    notify: () => { },
    onTerminalInput: () => () => { },
    setStatus: () => { },
    setWorkingMessage: () => { },
    setWidget: () => { },
    setFooter: () => { },
    setHeader: () => { },
    setTitle: () => { },
    custom: async () => undefined,
    setEditorText: () => { },
    pasteToEditor: () => { },
    getEditorText: () => "",
    editor: async () => undefined,
    addAutocompleteProvider: () => { },
    setEditorComponent: () => { },
    getEditorComponent: () => undefined,
    get theme() {
        return theme;
    },
    getAllThemes: () => Promise.resolve([]),
    getTheme: () => Promise.resolve(undefined),
    setTheme: (_theme) => Promise.resolve({ success: false, error: "UI not available" }),
    getToolsExpanded: () => false,
    setToolsExpanded: () => { },
};
/** Identity reported by a session that is not a subagent and received no explicit identity. */
export const TOP_LEVEL_AGENT = Object.freeze({
    kind: "main",
    id: MAIN_AGENT_ID,
    name: MAIN_AGENT_RULE_NAME,
    depth: 0,
});
/** `ctx.annotations` for hosts that inject no implementation: every call rejects. */
export const UNAVAILABLE_ANNOTATIONS = Object.freeze({
    submit: () => Promise.reject(new Error("ctx.annotations is not available in this host.")),
    open: () => Promise.reject(new Error("ctx.annotations is not available in this host.")),
});
export class ExtensionRunner {
    extensions;
    runtime;
    sessionManager;
    modelRegistry;
    settings;
    localProtocolOptions;
    agent;
    #uiContext;
    #mode = "print";
    #toolApprovalPreviewWaiter;
    #trackUserWait;
    #errorListeners = new Set();
    #getModel = () => undefined;
    #isIdleFn = () => true;
    #waitForIdleFn = async () => { };
    #abortFn = () => { };
    #hasPendingMessagesFn = () => false;
    #getContextUsageFn = () => undefined;
    #compactFn = async () => { };
    #getSystemPromptFn = () => [];
    #runEphemeralTurnFn;
    #ephemeralTurnBlocker = new AsyncLocalStorage();
    #getAsyncJobSnapshotFn = () => null;
    #newSessionHandler = async () => ({ cancelled: false });
    #branchHandler = async () => ({ cancelled: false });
    #navigateTreeHandler = async () => ({ cancelled: false });
    #switchSessionHandler = async () => ({ cancelled: false });
    #reloadHandler = async () => { };
    #shutdownHandler = () => { };
    #resolvePlanReviewFn = () => false;
    #getPendingPlanReviewFn = () => undefined;
    #openPlanReviewFn = async () => false;
    #getMemoryFn;
    #createAnnotations;
    #commandDiagnostics = [];
    #toolRegistrationScope = new AsyncLocalStorage();
    #toolRegistrationBarrier;
    #initialized = false;
    /** Full load order, captured on the first {@link setSuspendedExtensions} call. */
    #loadOrder;
    #suspendedExtensions = new Set();
    /**
     * Buffer for `credential_disabled` events received via {@link emitCredentialDisabled}
     * before {@link initialize} has run. Drained through {@link emit} once initialize sets
     * up the runtime context, so extension handlers see a populated UI/runtime context
     * rather than the constructor's no-op default. Bounded at
     * {@link MAX_PENDING_CREDENTIAL_DISABLED}; oldest entries are dropped under pressure.
     */
    #pendingCredentialDisabled = [];
    /**
     * Buffer for `mcp_notification` events received via {@link emitMcpNotification} before
     * {@link initialize} has run. Two-layer race: `MCPManager` also buffers frames until
     * its first `addNotificationListener` subscriber attaches, but the sdk.ts bridge is
     * registered inside `createAgentSession` — BEFORE the mode controller calls
     * `ExtensionRunner.initialize()`. Without this second buffer, the manager's drain
     * arrives at the bridge → the bridge calls `emitMcpNotification` → the runner drops
     * the frame because `#initialized === false`, and the frame evaporates a second time.
     * Bounded at {@link MAX_PENDING_MCP_NOTIFICATIONS}; oldest entries are dropped under
     * pressure. Drained in {@link initialize} once the runtime/UI context is wired.
     */
    #pendingMcpNotifications = [];
    /**
     * Timers scheduled by extensions through the sanctioned `ctx.setInterval` /
     * `ctx.setTimeout` helpers. Callbacks run with the same isolation as handler
     * dispatch — a throw is logged and routed through {@link onError} instead of
     * escaping to the process `uncaughtException` handler and tearing down the
     * whole session (issue #5664). Handles are `unref`'d and every outstanding
     * timer is cleared on session teardown via {@link clearManagedTimers}.
     */
    #managedTimers = new ManagedTimers((event, error, stack) => this.emitError({ extensionPath: "<timer>", event, error, stack }));
    /**
     * Disposers for the trampolines installed via {@link addFileWriteFallback} and
     * {@link addFileDeleteFallback} — one per extension per seam it registered for.
     * Installed during {@link initialize} (after the UI/runtime context is live, so
     * the bound handler sees a working `ctx.ui`) and drained by
     * {@link disposeFileFallbacks} on session shutdown so a handler from a
     * torn-down session can never fire for a later one sharing the same process.
     *
     * Each trampoline re-reads its extension's handler list at call time rather than
     * closing over a snapshot, matching how `ext.handlers` is re-read on every emit,
     * so an extension that already had a handler for that seam at `initialize` picks
     * up later additions to it. A seam the extension registered NOTHING for gets no
     * trampoline at all, which keeps the registry empty for a host with no fallbacks;
     * the cost is that a first registration for that seam after `initialize` never
     * takes effect, which is why the API documents load-time registration.
     */
    #fileFallbackDisposers = [];
    /**
     * Dedup markers for `tool_call` emission, keyed `${toolCallId}:${toolName}`.
     * The agent loop emits `tool_call` at arg-prep time (before scheduling and
     * `tool_execution_start`) via the session's `beforeToolCall` wiring; the
     * marker tells `ExtensionToolWrapper.execute` not to emit a second event for
     * the same dispatch. Keyed by call id + tool name because a nested xd://
     * device dispatch reuses the model's toolCallId under a different tool name
     * and must still emit its own event. Bounded: markers for calls whose
     * execute path never runs (policy deny, validation failure) would otherwise
     * accumulate for the session's lifetime.
     */
    #emittedToolCalls = new Set();
    #loopToolCalls = new Set();
    /** Records that the loop already emitted `tool_call` for this dispatch. */
    markToolCallEmitted(toolCallId, toolName) {
        if (this.#emittedToolCalls.size >= 512) {
            const oldest = this.#emittedToolCalls.values().next().value;
            if (oldest !== undefined)
                this.#emittedToolCalls.delete(oldest);
        }
        this.#emittedToolCalls.add(`${toolCallId}:${toolName}`);
    }
    /** Consumes a {@link markToolCallEmitted} marker; true when the loop already emitted. */
    consumeToolCallEmitted(toolCallId, toolName) {
        return this.#emittedToolCalls.delete(`${toolCallId}:${toolName}`);
    }
    /** Marks every dispatch prepared by the agent loop, independent of extension handlers. */
    markLoopToolCall(toolCallId, toolName) {
        if (this.#loopToolCalls.size >= 512) {
            const oldest = this.#loopToolCalls.values().next().value;
            if (oldest !== undefined)
                this.#loopToolCalls.delete(oldest);
        }
        this.#loopToolCalls.add(`${toolCallId}:${toolName}`);
    }
    /** Clears a loop marker when pre-dispatch blocked execution before the wrapper ran. */
    clearLoopToolCall(toolCallId, toolName) {
        this.#loopToolCalls.delete(`${toolCallId}:${toolName}`);
    }
    /** Consumes the marker for a loop dispatch; false means non-loop execution. */
    consumeLoopToolCall(toolCallId, toolName) {
        return this.#loopToolCalls.delete(`${toolCallId}:${toolName}`);
    }
    /**
     * Resolves a tool NAME to its native built-in implementation (the pre-extension-override,
     * unwrapped tool) plus a factory for the `AgentToolContext` that native tool expects, or
     * undefined when no native built-in of that name exists. Set by the SDK; backs same-tool
     * `invokeTool`. The context factory is the same one the agent loop uses for tool execution, so a
     * delegated native call sees the ordinary session tool context (ui, cwd, snapshot state, etc.).
     */
    #nativeToolResolver;
    #toolCallPreflight;
    /** Wires the native-tool resolver used by {@link invokeNativeTool}. */
    setNativeToolResolver(resolve) {
        this.#nativeToolResolver = resolve;
    }
    setToolCallPreflight(preflight) {
        this.#toolCallPreflight = preflight;
    }
    async runToolCallPreflightBefore(toolCallId, tool, args, context) {
        return this.#toolCallPreflight?.before?.(toolCallId, tool, args, context);
    }
    async runToolCallPreflightAfter(toolCallId, result, context) {
        return this.#toolCallPreflight?.after?.(toolCallId, result, context);
    }
    cancelToolCallPreflight(toolCallId) {
        this.#toolCallPreflight?.cancel?.(toolCallId);
    }
    /** Whether a native built-in of `name` is available to delegate to. */
    hasNativeTool(name) {
        return this.#nativeToolResolver?.(name) !== undefined;
    }
    /** Guidance a same-name replacement inherits from the native `name` tool it can delegate to. */
    getNativeDelegationGuidance(name) {
        return this.#nativeToolResolver?.(name)?.tool.delegationGuidance ?? "";
    }
    /**
     * Run the native built-in of `name` with `params` and return its result — the delegation target
     * of a same-tool `ctx.invokeTool`. Calls the unwrapped native `execute` directly with the loop's
     * ordinary tool context, so it inherits the caller's already-granted approval (the caller is the
     * same tool) rather than re-running the gate. `depth` guards a wrapper that recurses into itself;
     * it is per call chain (threaded from the caller), not session-global, so concurrent independent
     * delegations do not interfere.
     */
    async invokeNativeTool(name, params, options) {
        const resolved = this.#nativeToolResolver?.(name);
        if (!resolved)
            throw new Error(`invokeTool: no native built-in named "${name}" to delegate to`);
        const depth = options?.depth ?? 0;
        if (depth >= 8) {
            throw new Error(`invokeTool: delegation depth exceeded 8 (recursive invokeTool for "${name}"?)`);
        }
        const toolCallId = `invoke-${name}-${Date.now().toString(36)}-${depth}`;
        return (await resolved.tool.execute(toolCallId, params, options?.signal, options?.onUpdate, options?.callerContext ?? resolved.makeContext()));
    }
    constructor(extensions, runtime, 
    /** Ignored: `cwd` is always read live via the `cwd` getter below, not cached here. */
    _initialCwd, sessionManager, modelRegistry, getMemory, settings, localProtocolOptions, getAsyncJobSnapshot, 
    /** Identity of the agent this runner's session runs; defaults to the top-level agent. */
    agent = TOP_LEVEL_AGENT, 
    /** Builds `ctx.annotations`; supplied by the host that wires the bundled `/annotate` command. */
    createAnnotations) {
        this.extensions = extensions;
        this.runtime = runtime;
        this.sessionManager = sessionManager;
        this.modelRegistry = modelRegistry;
        this.settings = settings;
        this.localProtocolOptions = localProtocolOptions;
        this.agent = agent;
        this.#uiContext = noOpUIContext;
        this.#getMemoryFn = getMemory;
        this.#createAnnotations = createAnnotations;
        this.#getAsyncJobSnapshotFn = getAsyncJobSnapshot ?? (() => null);
    }
    /**
     * Live session directory, not a session-start snapshot: `/move`
     * (`SessionManager.moveTo()`) relocates the owning session by updating
     * `sessionManager`'s own `#cwd`, not a process-global. Reading it here
     * via the getter — instead of caching the constructor-time value in a
     * field — keeps every `ExtensionContext` built below in sync with this
     * session's actual, current directory. Deliberately `sessionManager.getCwd()`
     * rather than `getProjectDir()`: the latter is a single process-wide value
     * that only the interactive TUI's `/move` handler happens to also update
     * (`InteractiveModeContext#applyCwdChange`) — an SDK/ACP host running
     * several concurrent sessions each with their own `cwd` (see
     * `CreateAgentSessionOptions.cwd`) must never have one session's move
     * leak into another's `ctx.cwd` by reading a shared global.
     */
    get cwd() {
        return this.sessionManager.getCwd();
    }
    /**
     * Stable id of the session this runner serves. Read through `sessionManager`
     * for the same reason as {@link cwd}: it is this session's own, never a
     * process-global, so a subagent runner reports itself and not its parent.
     *
     * Used to attribute a denied file write or delete to the session that issued
     * it, since the fallback registry those handlers live in is process-wide.
     */
    get sessionId() {
        return this.sessionManager.getSessionId();
    }
    /**
     * Session settings this runner was constructed with. Used when a direct
     * `tool.execute()` omits execute-time context so approval still sees the
     * user's configured mode (schema default `yolo`) instead of fail-closed.
     */
    get sessionSettings() {
        return this.settings;
    }
    initialize(actions, contextActions, commandContextActions, uiContext, mode = "print") {
        // Copy actions into the shared runtime (all extension APIs reference this)
        this.runtime.sendMessage = actions.sendMessage;
        this.runtime.sendUserMessage = actions.sendUserMessage;
        this.runtime.appendEntry = actions.appendEntry;
        this.runtime.getActiveTools = actions.getActiveTools;
        this.runtime.getAllTools = actions.getAllTools;
        this.runtime.setActiveTools = async (toolNames) => {
            const registrationBarrier = this.#toolRegistrationBarrier;
            if (registrationBarrier)
                await registrationBarrier;
            await actions.setActiveTools(toolNames);
        };
        this.runtime.getCommands = actions.getCommands;
        this.runtime.setModel = actions.setModel;
        this.runtime.getThinkingLevel = actions.getThinkingLevel;
        this.runtime.setThinkingLevel = actions.setThinkingLevel;
        this.runtime.getServiceTiers = actions.getServiceTiers ?? throwUnsupportedServiceTierAction;
        this.runtime.setServiceTier = actions.setServiceTier ?? throwUnsupportedServiceTierAction;
        this.runtime.getSessionName = actions.getSessionName;
        this.runtime.setSessionName = actions.setSessionName;
        this.runtime.registerProvider = (name, config, sourceId) => {
            this.modelRegistry.registerProvider(name, config, sourceId);
        };
        this.runtime.unregisterProvider = name => {
            this.modelRegistry.unregisterProvider(name);
        };
        // Context actions (required)
        this.#getModel = contextActions.getModel;
        this.#isIdleFn = contextActions.isIdle;
        this.#abortFn = contextActions.abort;
        this.#hasPendingMessagesFn = contextActions.hasPendingMessages;
        this.#shutdownHandler = contextActions.shutdown;
        if (contextActions.resolvePlanReview)
            this.#resolvePlanReviewFn = contextActions.resolvePlanReview;
        if (contextActions.getPendingPlanReview)
            this.#getPendingPlanReviewFn = contextActions.getPendingPlanReview;
        if (contextActions.openPlanReview)
            this.#openPlanReviewFn = contextActions.openPlanReview;
        this.#getContextUsageFn = contextActions.getContextUsage;
        this.#compactFn = contextActions.compact;
        this.#getSystemPromptFn = contextActions.getSystemPrompt;
        this.#runEphemeralTurnFn = contextActions.runEphemeralTurn;
        // Command context actions (optional, only for interactive mode)
        if (commandContextActions) {
            this.#waitForIdleFn = commandContextActions.waitForIdle;
            this.#newSessionHandler = commandContextActions.newSession;
            this.#branchHandler = commandContextActions.branch;
            this.#navigateTreeHandler = commandContextActions.navigateTree;
            this.#switchSessionHandler = commandContextActions.switchSession;
            this.#reloadHandler = commandContextActions.reload;
            this.#getContextUsageFn = commandContextActions.getContextUsage;
            this.#compactFn = commandContextActions.compact;
        }
        this.#uiContext =
            uiContext && this.#trackUserWait
                ? trackUserWaits(uiContext, this.#trackUserWait)
                : (uiContext ?? noOpUIContext);
        this.#mode = mode;
        this.#initialized = true;
        // Re-initialize (e.g. a mode switch rewiring UI/runtime actions) must not
        // accumulate duplicate global registrations — drop the prior generation before
        // installing this one's trampolines.
        this.disposeFileFallbacks();
        // Suspended extensions keep a (gated) trampoline so resuming them needs no rewire.
        for (const ext of this.getLoadedExtensions()) {
            // Nothing registered by this extension means no trampoline, so a host with
            // no fallback-registering extension leaves the seam genuinely empty and
            // `hasFileWriteFallback()`/`hasFileDeleteFallback()` false — the invariant
            // the whole feature rests on. Each seam is checked separately, so an
            // extension that only brokers writes never appears in the delete registry.
            if (ext.fileWriteFallbackHandlers.length === 0 && ext.fileDeleteFallbackHandlers.length === 0)
                continue;
            // One trampoline per extension per seam, not per handler: the list is walked
            // at mutation time so a handler this extension adds later still takes effect,
            // and `createContext()` takes no extension argument, so within one invocation
            // a single context is all any of this extension's handlers would have
            // received anyway.
            //
            // The context is built PER INVOCATION rather than captured here, matching
            // every other dispatch site. `createContext()` materializes `cwd` and
            // `hasUI` as values, so a trampoline holding one context for the life of the
            // session would keep handing handlers the workspace this runner initialized
            // in — wrong the moment `SessionManager.moveTo()` relocates the session
            // (`/move`), and a handler that scopes or prompts against `ctx.cwd` would
            // then allow the old workspace and deny the new one. A denied mutation is a
            // rare path, so the extra object costs nothing that matters.
            //
            // Isolation is per HANDLER, not per extension. The registry only sees one
            // trampoline per extension, so a throw escaping this loop would advance the
            // registry to the NEXT extension and skip every later handler this one
            // registered — breaking both the documented "a throwing handler is skipped"
            // contract and registration order for a backup-handler setup.
            if (ext.fileWriteFallbackHandlers.length > 0) {
                this.#fileFallbackDisposers.push(addFileWriteFallback(async (req) => {
                    if (this.#suspendedExtensions.has(ext))
                        return false;
                    const ctx = this.createContext();
                    for (const handler of ext.fileWriteFallbackHandlers) {
                        try {
                            if (await handler(req, ctx))
                                return true;
                        }
                        catch (error) {
                            logger.warn("Extension file write fallback handler threw; trying next handler", {
                                extension: ext.path,
                                error: error instanceof Error ? error.message : String(error),
                            });
                        }
                    }
                    return false;
                }));
            }
            if (ext.fileDeleteFallbackHandlers.length > 0) {
                this.#fileFallbackDisposers.push(addFileDeleteFallback(async (req) => {
                    if (this.#suspendedExtensions.has(ext))
                        return false;
                    const ctx = this.createContext();
                    for (const handler of ext.fileDeleteFallbackHandlers) {
                        try {
                            if (await handler(req, ctx))
                                return true;
                        }
                        catch (error) {
                            logger.warn("Extension file delete fallback handler threw; trying next handler", {
                                extension: ext.path,
                                error: error instanceof Error ? error.message : String(error),
                            });
                        }
                    }
                    return false;
                }));
            }
        }
        // Drain events buffered by emitCredentialDisabled() before initialize ran. The
        // spread adds the `type` discriminator — `event` is the pi-ai shape (no `type`).
        // Deferred by one microtask so callers that register an onError listener
        // synchronously after initialize() see handler errors routed through it.
        const pending = this.#pendingCredentialDisabled.splice(0);
        queueMicrotask(() => {
            for (const event of pending) {
                this.emit({ type: "credential_disabled", ...event }).catch((error) => {
                    logger.warn("credential_disabled handler threw during initialize flush", {
                        provider: event.provider,
                        error: error instanceof Error ? error.message : String(error),
                    });
                });
            }
        });
        // Drain events buffered by emitMcpNotification() before initialize ran, using the
        // same deferred-microtask ordering as the credential-disabled drain above so any
        // onError listener registered synchronously after initialize() still catches
        // handler errors during flush.
        const pendingMcp = this.#pendingMcpNotifications.splice(0);
        queueMicrotask(() => {
            for (const event of pendingMcp) {
                this.emit({ type: "mcp_notification", ...event }).catch((error) => {
                    logger.warn("mcp_notification handler threw during initialize flush", {
                        server: event.server,
                        method: event.method,
                        error: error instanceof Error ? error.message : String(error),
                    });
                });
            }
        });
    }
    /**
     * Forward a `credential_disabled` event from `AuthStorage` to extension handlers.
     *
     * If {@link initialize} has not yet run, the event is buffered and replayed once
     * initialize wires the runtime/UI context. This matters because mode controllers
     * (interactive, RPC, ACP, print, subagent) call `initialize()` AFTER `createAgentSession`
     * returns, but `AuthStorage` can fire `credential_disabled` during startup model probes
     * inside `createAgentSession()`. Without deferral, extension handlers would observe
     * `hasUI=false`, an unset model, and no-op runtime actions on exactly the headline
     * "OAuth invalid_grant during startup" path the event was designed to surface.
     *
     * Always returns; never throws. Errors from handlers are routed through
     * {@link onError} via {@link emit}'s normal isolation.
     */
    async emitCredentialDisabled(event) {
        if (!this.#initialized) {
            if (this.#pendingCredentialDisabled.length >= MAX_PENDING_CREDENTIAL_DISABLED) {
                this.#pendingCredentialDisabled.shift();
            }
            this.#pendingCredentialDisabled.push(event);
            return;
        }
        await this.emit({ type: "credential_disabled", ...event });
    }
    /**
     * Forward an MCP server notification to extension handlers.
     *
     * If {@link initialize} has not yet run, the notification is buffered and replayed
     * once initialize wires the runtime/UI context. Matches the credential-disabled
     * deferral above: the sdk.ts bridge registers `MCPManager.addNotificationListener`
     * inside `createAgentSession` — BEFORE the mode controller calls `initialize()` on
     * this runner — so notification frames drained by the manager (either fresh
     * arrivals or replay from its own startup buffer) can reach us pre-init. Without
     * this buffer they would evaporate for a second time here.
     *
     * Bounded at {@link MAX_PENDING_MCP_NOTIFICATIONS}; oldest entries drop under
     * pressure. Never throws; per-handler errors are routed through {@link onError}
     * via {@link emit}'s normal isolation.
     */
    async emitMcpNotification(event) {
        if (!this.#initialized) {
            if (this.#pendingMcpNotifications.length >= MAX_PENDING_MCP_NOTIFICATIONS) {
                this.#pendingMcpNotifications.shift();
            }
            this.#pendingMcpNotifications.push(event);
            return;
        }
        await this.emit({ type: "mcp_notification", ...event });
    }
    /** Emits a session stop pass that can be cancelled with the active settle signal. */
    async emitSessionStop(event) {
        if (event.signal.aborted)
            return undefined;
        return await this.emit({ type: "session_stop", ...event });
    }
    /**
     * Asks extensions to override a prompt-cache warming decision. The last
     * handler returning an action wins; handler failures are reported through
     * the extension error listeners and leave the warmer's decision standing.
     */
    async emitCacheWarmingDecision(event) {
        let action = event.action;
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get(event.type);
            if (!handlers || handlers.length === 0)
                continue;
            const ctx = this.createContext();
            for (const handler of handlers) {
                const result = (await this.#runHandlerWithTimeout(handler, event, ctx, ext, handlerTimeoutForEvent(event.type)));
                if (result?.action !== undefined)
                    action = result.action;
            }
        }
        return action;
    }
    /** Registers the interactive transcript gate that must settle before a tool approval is presented. */
    setToolApprovalPreviewWaiter(waiter) {
        this.#toolApprovalPreviewWaiter = waiter;
        return () => {
            if (this.#toolApprovalPreviewWaiter === waiter)
                this.#toolApprovalPreviewWaiter = undefined;
        };
    }
    /**
     * Runs each dialog of the UI context the next {@link initialize} receives (tool approvals, extension prompts) as a
     * wait for the user.
     */
    setUserWaitTracker(track) {
        this.#trackUserWait = track;
    }
    /** Waits until the interactive transcript can show the tool call being approved. */
    async waitForToolApprovalPreview(toolCallId) {
        await this.#toolApprovalPreviewWaiter?.(toolCallId);
    }
    getUIContext() {
        return this.#uiContext;
    }
    hasUI() {
        return this.#uiContext !== noOpUIContext;
    }
    getExtensionPaths() {
        return this.extensions.map(e => e.path);
    }
    /** Every extension this runner loaded, in load order, including suspended ones. */
    getLoadedExtensions() {
        return this.#loadOrder ?? this.extensions;
    }
    /** Whether the extension loaded from `extensionPath` is present and not suspended. */
    isExtensionActive(extensionPath) {
        return this.extensions.some(ext => ext.path === extensionPath);
    }
    /**
     * Suspend or resume loaded extensions in place (e.g. after a live `disabledExtensions`
     * edit). A suspended extension keeps its module state but stops contributing event
     * handlers, commands, tools, message renderers, shortcuts, flags, and file fallbacks
     * until resumed. Returns the extensions whose state changed.
     */
    setSuspendedExtensions(shouldSuspend) {
        this.#loadOrder ??= [...this.extensions];
        const suspended = [];
        const resumed = [];
        for (const extension of this.#loadOrder) {
            const suspend = shouldSuspend(extension);
            if (suspend === this.#suspendedExtensions.has(extension))
                continue;
            if (suspend) {
                this.#suspendedExtensions.add(extension);
                suspended.push(extension);
            }
            else {
                this.#suspendedExtensions.delete(extension);
                resumed.push(extension);
            }
        }
        if (suspended.length > 0 || resumed.length > 0) {
            const active = this.#loadOrder.filter(extension => !this.#suspendedExtensions.has(extension));
            this.extensions.splice(0, this.extensions.length, ...active);
        }
        return { suspended, resumed };
    }
    /** Get all registered tools from all extensions. */
    getAllRegisteredTools() {
        const tools = [];
        for (const ext of this.extensions) {
            for (const tool of ext.tools.values()) {
                tools.push(tool);
            }
        }
        return tools;
    }
    /** Get the effective registered tool for a name using normal last-extension-wins precedence. */
    getRegisteredTool(name) {
        for (let index = this.extensions.length - 1; index >= 0; index -= 1) {
            const tool = this.extensions[index]?.tools.get(name);
            if (tool)
                return tool;
        }
        return undefined;
    }
    /**
     * Observe tools registered after extension factories have loaded. Listener
     * promises are drained before the lifecycle handler that registered them
     * completes, keeping the model tool snapshot and system prompt coherent.
     */
    onToolRegistered(listener) {
        const subscriptions = [];
        for (const extension of this.extensions) {
            const trackRegistration = (pending) => {
                const registrationBarrier = pending.then(() => undefined, () => undefined);
                this.#toolRegistrationBarrier = registrationBarrier;
                void registrationBarrier.then(() => {
                    if (this.#toolRegistrationBarrier === registrationBarrier)
                        this.#toolRegistrationBarrier = undefined;
                });
                const scope = this.#toolRegistrationScope.getStore();
                if (scope && !scope.closed) {
                    scope.pending.add(pending);
                    void pending.then(() => scope.pending.delete(pending), () => { });
                    return;
                }
                void pending.catch(error => {
                    this.emitError({
                        extensionPath: extension.path,
                        event: "tool_registration",
                        error: error instanceof Error ? error.message : String(error),
                        stack: error instanceof Error ? error.stack : undefined,
                    });
                });
            };
            const wrapped = toolName => {
                const tool = extension.tools.get(toolName);
                if (!tool)
                    return;
                try {
                    const scope = this.#toolRegistrationScope.getStore();
                    const registrationSignal = scope && !scope.closed ? scope.signal : AbortSignal.timeout(extensionHandlerTimeoutMs);
                    const pending = listener(tool, registrationSignal);
                    if (pending)
                        trackRegistration(pending);
                }
                catch (error) {
                    trackRegistration(Promise.reject(error));
                }
            };
            extension.toolRegistrationListeners ??= new Set();
            extension.toolRegistrationListeners.add(wrapped);
            subscriptions.push({ extension, listener: wrapped });
        }
        return () => {
            for (const subscription of subscriptions) {
                subscription.extension.toolRegistrationListeners?.delete(subscription.listener);
            }
        };
    }
    async #flushToolRegistrations(pendingRegistrations) {
        let firstFailure;
        while (pendingRegistrations.size > 0) {
            const pending = Array.from(pendingRegistrations);
            const settled = await Promise.allSettled(pending);
            for (let index = 0; index < settled.length; index += 1) {
                pendingRegistrations.delete(pending[index]);
                const result = settled[index];
                if (!firstFailure && result?.status === "rejected")
                    firstFailure = result;
            }
        }
        if (firstFailure)
            throw firstFailure.reason;
    }
    /** Composer shapes registered during extension load, with later extensions winning id collisions. */
    getComposerShapes() {
        const shapes = new Map();
        for (const extension of this.extensions) {
            for (const [id, shape] of extension.composerShapes)
                shapes.set(id, shape);
        }
        return [...shapes.values()];
    }
    /**
     * Aggregate the registered CLI flags across a set of extensions (last write
     * wins on name collision). Static so callers that need the flag set before a
     * runner exists — e.g. the CLI resolving `@file`/flag args before session
     * creation — share this exact logic instead of duplicating it.
     */
    static aggregateFlags(extensions) {
        const allFlags = new Map();
        for (const ext of extensions) {
            for (const [name, flag] of ext.flags) {
                allFlags.set(name, flag);
            }
        }
        return allFlags;
    }
    getFlags() {
        return ExtensionRunner.aggregateFlags(this.extensions);
    }
    getFlagValues() {
        return new Map(this.runtime.flagValues);
    }
    setFlagValue(name, value) {
        this.runtime.flagValues.set(name, value);
    }
    static #RESERVED_SHORTCUTS = {
        "ctrl+c": true,
        "ctrl+d": true,
        "ctrl+z": true,
        "ctrl+k": true,
        "ctrl+p": true,
        "ctrl+l": true,
        "ctrl+o": true,
        "ctrl+t": true,
        "ctrl+g": true,
        "alt+m": true,
        // Default chord for `app.message.followUp` (Windows Terminal can't deliver Ctrl+Enter; #1903).
        "ctrl+q": true,
        "shift+tab": true,
        "shift+ctrl+p": true,
        "alt+enter": true,
        escape: true,
        enter: true,
    };
    getShortcuts() {
        const allShortcuts = new Map();
        for (const ext of this.extensions) {
            for (const [key, shortcut] of ext.shortcuts) {
                const normalizedKey = key.toLowerCase();
                if (ExtensionRunner.#RESERVED_SHORTCUTS[normalizedKey]) {
                    logger.warn("Extension shortcut conflicts with built-in shortcut", {
                        key,
                        extensionPath: shortcut.extensionPath,
                    });
                    continue;
                }
                const existing = allShortcuts.get(normalizedKey);
                if (existing) {
                    logger.warn("Extension shortcut conflict", {
                        key,
                        extensionPath: shortcut.extensionPath,
                        existingExtensionPath: existing.extensionPath,
                    });
                }
                allShortcuts.set(normalizedKey, shortcut);
            }
        }
        return allShortcuts;
    }
    onError(listener) {
        this.#errorListeners.add(listener);
        return () => this.#errorListeners.delete(listener);
    }
    emitError(error) {
        for (const listener of this.#errorListeners) {
            listener(error);
        }
    }
    hasHandlers(eventType) {
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get(eventType);
            if (handlers && handlers.length > 0) {
                return true;
            }
        }
        return false;
    }
    getMessageRenderer(customType) {
        for (const ext of this.extensions) {
            const renderer = ext.messageRenderers.get(customType);
            if (renderer) {
                return renderer;
            }
        }
        return undefined;
    }
    getAssistantThinkingRenderers() {
        return this.extensions.flatMap(ext => ext.assistantThinkingRenderers);
    }
    getRegisteredCommands(reserved) {
        this.#commandDiagnostics = [];
        const commands = new Map();
        for (const ext of this.extensions) {
            for (const command of ext.commands.values()) {
                if (reserved?.has(command.name)) {
                    const message = `Extension command '${command.name}' from ${ext.path} conflicts with built-in commands. Skipping.`;
                    this.#commandDiagnostics.push({ type: "warning", message, path: ext.path });
                    if (!this.hasUI()) {
                        logger.warn(message);
                    }
                    continue;
                }
                commands.set(command.name, command);
            }
        }
        return [...commands.values()];
    }
    getCommandDiagnostics() {
        return this.#commandDiagnostics;
    }
    getCommand(name) {
        for (let index = this.extensions.length - 1; index >= 0; index -= 1) {
            const command = this.extensions[index]?.commands.get(name);
            if (command) {
                return command;
            }
        }
        return undefined;
    }
    /**
     * Run an extension-owned callback within this session's settings scope, so a
     * synchronous `SettingsManager.create(ctx.cwd)` inside it resolves THIS
     * session's manager rather than a same-cwd sibling's. Event handlers get this
     * scope via {@link #runHandlerWithTimeout}; slash commands and shortcuts are
     * invoked directly by their controllers and route through here instead.
     */
    runScoped(fn) {
        return withActiveSettings(this.settings, fn);
    }
    /**
     * Creates an extension context, optionally scoped to a provider request model.
     *
     * `delegation` wires the same-tool `ctx.invokeTool` for a re-registered built-in: when `toolName`
     * names an existing native built-in, the context carries an `invokeTool` that runs it (see
     * {@link invokeNativeTool}). The rest inherits the wrapper's own call so a bare
     * `ctx.invokeTool(params)` behaves like the outer call — `context` preserves `toolCall`/provider
     * metadata, `signal`/`onUpdate` default to the wrapper's own channels so aborting the outer tool
     * call stops the native one and native progress still streams, and `depth` bounds recursion per
     * call chain. Explicit options passed to `invokeTool` override the inherited `signal`/`onUpdate`.
     *
     * `agent` replaces this runner's identity as `ctx.agent` for work done on behalf of another
     * agent that shares the runner (the advisor's toolset, see `ExtensionToolWrapper`).
     */
    createContext(model, delegation, agent = this.agent) {
        const getModel = model ? () => model : this.#getModel;
        const runEphemeralTurn = this.#runEphemeralTurnFn;
        const createAnnotations = this.#createAnnotations;
        const sendUserMessage = (text, options) => this.runtime.sendUserMessage(text, options);
        return {
            ui: this.#uiContext,
            mode: this.#mode,
            getContextUsage: () => this.#getContextUsageFn(),
            compact: instructionsOrOptions => this.#compactFn(instructionsOrOptions),
            getAsyncJobSnapshot: () => this.#getAsyncJobSnapshotFn(),
            hasUI: this.hasUI(),
            cwd: this.cwd,
            sessionManager: this.sessionManager,
            modelRegistry: this.modelRegistry,
            isProjectTrusted: () => true,
            agent,
            get model() {
                return getModel();
            },
            models: createExtensionModelQuery(this.modelRegistry, this.settings, getModel),
            isIdle: () => this.#isIdleFn(),
            abort: () => this.#abortFn(),
            hasPendingMessages: () => this.#hasPendingMessagesFn(),
            shutdown: () => this.#shutdownHandler(),
            resolvePlanReview: (reviewId, choice, input) => this.#resolvePlanReviewFn(reviewId, choice, input),
            getPendingPlanReview: () => this.#getPendingPlanReviewFn(),
            openPlanReview: () => this.#openPlanReviewFn(),
            getSystemPrompt: () => this.#getSystemPromptFn(),
            runEphemeralTurn: runEphemeralTurn
                ? async (options) => {
                    if (this.#ephemeralTurnBlocker.getStore()) {
                        throw new Error("runEphemeralTurn cannot be called recursively from an ephemeral turn hook");
                    }
                    // Resolve at call time so a running handler's cancellation is inherited.
                    // A saved context must not retain a completed handler's stale signal.
                    const registrationScope = this.#toolRegistrationScope.getStore();
                    const signals = [
                        options.signal,
                        delegation?.signal,
                        registrationScope && !registrationScope.closed ? registrationScope.signal : undefined,
                    ].filter((signal) => signal !== undefined);
                    // Only hooks reached inside the side-turn pipeline are blocked. The caller's own
                    // delivery callback runs outside the guard so work it starts (lazy subscriptions,
                    // timers) does not inherit a permanent block on later consultations.
                    const onTextDelta = options.onTextDelta;
                    const request = {
                        ...options,
                        onTextDelta: onTextDelta
                            ? (delta) => this.#ephemeralTurnBlocker.exit(() => onTextDelta(delta))
                            : undefined,
                        signal: signals.length ? AbortSignal.any(signals) : undefined,
                    };
                    return await this.#ephemeralTurnBlocker.run("ephemeral turn", () => runEphemeralTurn(request));
                }
                : undefined,
            localProtocolOptions: this.localProtocolOptions,
            memory: this.#getMemoryFn?.(),
            // A getter, not a value: `createHandlerContext` scopes a handler via `Object.create(ctx)`, and
            // `this` here is that receiver, so the overlay mounts through the handler's timeout-aware `ui`.
            get annotations() {
                return createAnnotations ? createAnnotations(() => this, sendUserMessage) : UNAVAILABLE_ANNOTATIONS;
            },
            setInterval: (callback, ms, ...args) => this.#managedTimers.setInterval(callback, ms, ...args),
            setTimeout: (callback, ms, ...args) => this.#managedTimers.setTimeout(callback, ms, ...args),
            clearTimer: timer => this.#managedTimers.clear(timer),
            addAdditionalContext: delegation?.context?.addAdditionalContext,
            invokeTool: delegation !== undefined && this.hasNativeTool(delegation.toolName)
                ? (params, options) => this.invokeNativeTool(delegation.toolName, params, {
                    // Inherit the wrapper's own channels so a bare `ctx.invokeTool(params)` aborts
                    // and streams with the outer call. Explicit options win.
                    signal: options?.signal ?? delegation.signal,
                    onUpdate: options?.onUpdate ?? delegation.onUpdate,
                    depth: (delegation.depth ?? 0) + 1,
                    callerContext: delegation.context,
                })
                : undefined,
        };
    }
    /**
     * Request a graceful shutdown. Called by extension tools and event handlers.
     */
    shutdown() {
        this.#shutdownHandler();
    }
    /**
     * Clear every timer scheduled through `ctx.setInterval` / `ctx.setTimeout`.
     * Called during session teardown so extension background work does not
     * outlive the session (a self-scheduling interval would otherwise keep
     * firing against a disposed session).
     */
    clearManagedTimers() {
        this.#managedTimers.clearAll();
    }
    /**
     * Remove every file write and delete fallback this runner installed into the
     * process-wide registries. Called on session shutdown (and before reinstalling
     * on a re-{@link initialize}) so a handler bound to a torn-down session's
     * context can never fire for another session sharing this process.
     */
    disposeFileFallbacks() {
        for (const dispose of this.#fileFallbackDisposers.splice(0))
            dispose();
    }
    createCommandContext() {
        return {
            ...this.createContext(),
            getContextUsage: () => this.#getContextUsageFn(),
            waitForIdle: () => this.#waitForIdleFn(),
            newSession: options => this.#newSessionHandler(options),
            branch: entryId => this.#branchHandler(entryId),
            navigateTree: (targetId, options) => this.#navigateTreeHandler(targetId, options),
            switchSession: sessionPath => this.#switchSessionHandler(sessionPath),
            reload: () => this.#reloadHandler(),
            compact: instructionsOrOptions => this.#compactFn(instructionsOrOptions),
        };
    }
    #isSessionBeforeEvent(event) {
        return (event.type === "session_before_switch" ||
            event.type === "session_before_branch" ||
            event.type === "session_before_compact" ||
            event.type === "session_before_tree");
    }
    #isSessionShutdownEvent(event) {
        return event.type === "session_shutdown";
    }
    async #runHandlerWithTimeout(handler, event, ctx, ext, timeoutMs, onFailure, outerSignal) {
        // `session_stop` carries its own signal on the event; `tool_call` receives
        // the outer dispatch signal (loop request or wrapper execute) so an abort
        // while a handler awaits a human dialog cancels the dialog and settles the
        // gate without executing the underlying tool. Compose whichever apply.
        const sessionStopSignal = event.type === "session_stop" && "signal" in event && event.signal instanceof AbortSignal
            ? event.signal
            : undefined;
        const signals = [outerSignal, sessionStopSignal].filter((s) => s !== undefined);
        const signal = signals.length === 0 ? undefined : signals.length === 1 ? signals[0] : AbortSignal.any(signals);
        if (signal?.aborted)
            return undefined;
        const registrationScope = { pending: new Set(), closed: false };
        let handlerResult;
        let handlerFailure;
        try {
            handlerResult = await withActiveSettings(this.settings, () => raceHandlerWithTimeout(async (handlerSignal, budget) => {
                registrationScope.signal = handlerSignal;
                let result;
                try {
                    const handlerContext = createHandlerContext(ctx, handlerSignal, event.type === "tool_call" ? budget : undefined);
                    result = await this.#toolRegistrationScope.run(registrationScope, () => handler(event, handlerContext));
                }
                catch (error) {
                    handlerFailure = { error };
                }
                finally {
                    registrationScope.closed = true;
                }
                try {
                    await this.#flushToolRegistrations(registrationScope.pending);
                }
                catch (error) {
                    handlerFailure ??= { error };
                }
                return result;
            }, timeoutMs, signal));
        }
        catch (error) {
            handlerFailure = { error };
        }
        finally {
            registrationScope.closed = true;
        }
        if (handlerResult === EXTENSION_HANDLER_ABORTED)
            return undefined;
        if (handlerResult === EXTENSION_HANDLER_TIMEOUT) {
            const error = `handler timed out after ${timeoutMs}ms`;
            logger.warn("Extension handler timed out", {
                extensionPath: ext.path,
                event: event.type,
                timeoutMs,
            });
            this.emitError({
                extensionPath: ext.path,
                event: event.type,
                error,
            });
            return onFailure?.("timeout", error);
        }
        if (handlerFailure) {
            const message = handlerFailure.error instanceof Error ? handlerFailure.error.message : String(handlerFailure.error);
            const stack = handlerFailure.error instanceof Error ? handlerFailure.error.stack : undefined;
            this.emitError({
                extensionPath: ext.path,
                event: event.type,
                error: message,
                stack,
            });
            return onFailure?.("error", message);
        }
        return handlerResult;
    }
    async emit(event) {
        // Defer the per-event context allocation (and the Promise.race/Bun.sleep
        // timeout machinery) to the first matching handler. Streaming sessions emit
        // message_update / tool_execution_* per delta with usually no extension
        // subscribed; building `ctx` for a zero-handler event is pure waste.
        let ctx;
        let result;
        if (this.#isSessionShutdownEvent(event)) {
            const timeoutMs = handlerTimeoutForEvent(event.type);
            const promises = [];
            for (const ext of this.extensions) {
                const handlers = ext.handlers.get(event.type);
                if (!handlers || handlers.length === 0)
                    continue;
                ctx ??= this.createContext();
                for (const handler of handlers) {
                    promises.push(this.#runHandlerWithTimeout(handler, event, ctx, ext, timeoutMs));
                }
            }
            if (promises.length > 0)
                await Promise.all(promises);
            return result;
        }
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get(event.type);
            if (!handlers || handlers.length === 0)
                continue;
            ctx ??= this.createContext();
            for (const handler of handlers) {
                const handlerResult = await this.#runHandlerWithTimeout(handler, event, ctx, ext, handlerTimeoutForEvent(event.type));
                if (this.#isSessionBeforeEvent(event) && handlerResult) {
                    result = handlerResult;
                    if (result.cancel) {
                        return result;
                    }
                }
                if (event.type === "session.compacting" && handlerResult) {
                    result = handlerResult;
                }
                if (event.type === "session_stop" && handlerResult) {
                    const stopResult = handlerResult;
                    if (stopResult.decision === "block") {
                        return stopResult;
                    }
                    const hasContinuationContext = (typeof stopResult.additionalContext === "string" && stopResult.additionalContext.length > 0) ||
                        (typeof stopResult.reason === "string" && stopResult.reason.length > 0);
                    if (stopResult.continue === true && hasContinuationContext)
                        result ??= stopResult;
                }
            }
        }
        // Handlers for these events export session-scoped environment (a session
        // id, per-session tool config). The shell spawn environment is a cached
        // copy that may predate them or belong to the previous session, so capture
        // process.env for it as soon as they have run. Only the main agent's events
        // do this: in-process subagents share process.env, and a subagent's session
        // start must not hand its values to the parent's commands. A process that
        // hosts several top-level sessions (ACP) still has one spawn environment,
        // which follows the latest of their events.
        if (ctx !== undefined && this.agent.kind === "main" && SESSION_IDENTITY_EVENTS[event.type] === true) {
            refreshShellConfigCache();
        }
        return result;
    }
    /**
     * Run extension rewrites on a detached finalized assistant message. Text may
     * change only in its original block position; all other metadata and blocks
     * remain unchanged. Text replay signatures are tied to their original text.
     *
     * Handlers see a structured clone, but the result is rebuilt from the
     * original blocks: unchanged blocks keep their identity and symbol-keyed
     * provider markers (e.g. `kCursorExecResolved`, which `structuredClone`
     * drops and without which agent-loop re-runs Cursor-settled tool calls).
     */
    async emitAssistantMessage(message, signal) {
        if (!this.hasHandlers("assistant_message"))
            return undefined;
        const ctx = this.createContext();
        const original = message.content;
        // Accepted text per block position; every other field comes from `original`.
        const texts = original.map(block => (block.type === "text" ? block.text : undefined));
        const isRewritten = (index) => {
            const block = original[index];
            return block?.type === "text" && texts[index] !== block.text;
        };
        const currentContent = () => original.map((block, index) => {
            if (block.type !== "text" || !isRewritten(index))
                return block;
            const { textSignature: _stale, ...rest } = block;
            return { ...rest, text: texts[index] };
        });
        const textMetadata = (block) => {
            const { text: _text, textSignature: _textSignature, ...metadata } = block;
            return metadata;
        };
        extensions: for (const ext of this.extensions) {
            const handlers = ext.handlers.get("assistant_message");
            if (!handlers?.length)
                continue;
            for (const handler of handlers) {
                if (signal?.aborted)
                    break extensions;
                // Detach the whole message, not just `content`: in-place edits to `usage`
                // or other fields must not leak into the finalized message.
                const presented = structuredClone({ ...message, content: currentContent() });
                const event = { type: "assistant_message", message: presented };
                const result = (await this.#runHandlerWithTimeout(handler, event, ctx, ext, extensionHandlerTimeoutMs, undefined, signal));
                if (signal?.aborted)
                    break extensions;
                if (result?.content === undefined)
                    continue;
                const replacement = result.content;
                // Compare against a fresh clone: the handler may have mutated `presented`.
                const expected = structuredClone(currentContent());
                if (!Array.isArray(replacement) ||
                    replacement.length !== expected.length ||
                    replacement.some((block, index) => {
                        const previous = expected[index];
                        if (!block || typeof block !== "object" || block.type !== previous?.type)
                            return true;
                        if (block.type !== "text")
                            return !Bun.deepEquals(block, previous);
                        return (typeof block.text !== "string" ||
                            previous?.type !== "text" ||
                            !Bun.deepEquals(textMetadata(block), textMetadata(previous)));
                    })) {
                    this.emitError({
                        extensionPath: ext.path,
                        event: "assistant_message",
                        error: "content replacement may only change text in existing blocks; block positions, non-text blocks, and other metadata must remain unchanged",
                    });
                    continue;
                }
                for (const [index, block] of replacement.entries()) {
                    if (block.type === "text")
                        texts[index] = block.text;
                }
            }
        }
        return original.some((_block, index) => isRewritten(index)) ? currentContent() : undefined;
    }
    /**
     * Emit `tool_result` to every subscribed extension. Returns the full
     * `content`/`details`/`isError` triple only when a handler modified the
     * result; joined `additionalContext` rides along whenever any handler set it.
     */
    async emitToolResult(event, agent) {
        const ctx = this.createContext(undefined, undefined, agent);
        const currentEvent = { ...event };
        let modified = false;
        const contexts = [];
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get("tool_result");
            if (!handlers || handlers.length === 0)
                continue;
            for (const handler of handlers) {
                const handlerResult = (await this.#runHandlerWithTimeout(handler, currentEvent, ctx, ext, extensionHandlerTimeoutMs));
                if (!handlerResult)
                    continue;
                if (handlerResult.content !== undefined) {
                    currentEvent.content = handlerResult.content;
                    modified = true;
                }
                if (handlerResult.details !== undefined) {
                    currentEvent.details = handlerResult.details;
                    modified = true;
                }
                if (handlerResult.isError !== undefined) {
                    currentEvent.isError = handlerResult.isError;
                    modified = true;
                }
                if (isNonBlankContext(handlerResult.additionalContext)) {
                    contexts.push(handlerResult.additionalContext);
                }
            }
        }
        const additionalContext = joinAdditionalContext(contexts);
        if (!modified)
            return additionalContext === undefined ? undefined : { additionalContext };
        return {
            content: currentEvent.content,
            details: currentEvent.details,
            isError: currentEvent.isError,
            ...(additionalContext !== undefined ? { additionalContext } : {}),
        };
    }
    /**
     * Emit a `tool_call` event to every subscribed extension before the tool executes.
     *
     * Each handler is bounded by `extensionHandlers.toolCallTimeoutMs` (default
     * 30s). This matches the timeout policy already applied to `emitToolResult` and every
     * other handler routed through `#runHandlerWithTimeout`; without it a single
     * hung extension (unresolved `await`, network call with no timeout) would
     * park `ExtensionToolWrapper.execute` indefinitely and freeze tool
     * dispatch — see issue #3948.
     *
     * On-timeout policy: **fail-closed** (return `{ block: true }`). This is
     * symmetric with the existing error path below and safer for a
     * pre-execution gate — an unresponsive extension MUST NOT be treated as
     * silent consent to run the tool.
     *
     * `agent` overrides `ctx.agent` when the tool runs for another agent sharing this runner.
     */
    async emitToolCall(event, signal, agent) {
        const ctx = this.createContext(undefined, undefined, agent);
        const timeoutMs = normalizeHandlerTimeout((this.settings ? cfgExtensionHandlersToolCallTimeoutMs.get(this.settings) : undefined) ??
            extensionHandlerTimeoutMs);
        let result;
        const aggregated = { input: undefined, additionalContext: [] };
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get("tool_call");
            if (!handlers || handlers.length === 0)
                continue;
            for (const handler of handlers) {
                const handlerResult = (await this.#runHandlerWithTimeout(handler, event, ctx, ext, timeoutMs, (kind, message) => ({
                    block: true,
                    reason: kind === "timeout"
                        ? `Extension ${ext.path} timed out after ${timeoutMs}ms`
                        : `Extension ${ext.path} failed: ${message}`,
                }), signal));
                if (!handlerResult)
                    continue;
                if (handlerResult.block) {
                    return handlerResult;
                }
                const { additionalContext: _context, input: _input, ...controlResult } = handlerResult;
                accumulateToolCallResult(aggregated, handlerResult);
                result = controlResult;
            }
        }
        if (signal?.aborted) {
            return { block: true, reason: `Tool execution was cancelled while an extension handler was pending` };
        }
        return buildAggregatedToolCallResult(result, aggregated);
    }
    async emitUserBash(event) {
        return this.emitUserEvent(event, "user_bash");
    }
    async emitUserPython(event) {
        return this.emitUserEvent(event, "user_python");
    }
    async emitUserEvent(event, eventName) {
        const ctx = this.createContext();
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get(eventName);
            if (!handlers || handlers.length === 0)
                continue;
            for (const handler of handlers) {
                const handlerResult = await this.#runHandlerWithTimeout(handler, event, ctx, ext, extensionHandlerTimeoutMs);
                if (handlerResult) {
                    return handlerResult;
                }
            }
        }
        return undefined;
    }
    async emitResourcesDiscover(cwd, reason) {
        const ctx = this.createContext();
        const skillPaths = [];
        const promptPaths = [];
        const themePaths = [];
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get("resources_discover");
            if (!handlers || handlers.length === 0)
                continue;
            for (const handler of handlers) {
                const event = { type: "resources_discover", cwd, reason };
                const handlerResult = await this.#runHandlerWithTimeout(handler, event, ctx, ext, extensionHandlerTimeoutMs);
                const result = handlerResult;
                if (result?.skillPaths?.length) {
                    skillPaths.push(...result.skillPaths.map(path => ({ path, extensionPath: ext.path })));
                }
                if (result?.promptPaths?.length) {
                    promptPaths.push(...result.promptPaths.map(path => ({ path, extensionPath: ext.path })));
                }
                if (result?.themePaths?.length) {
                    themePaths.push(...result.themePaths.map(path => ({ path, extensionPath: ext.path })));
                }
            }
        }
        return { skillPaths, promptPaths, themePaths };
    }
    /** Emit input event. Transforms chain, "handled" short-circuits. */
    async emitInput(text, images, source) {
        if (!this.hasHandlers("input"))
            return {};
        const ctx = this.createContext();
        let currentText = text;
        let currentImages = images;
        for (const ext of this.extensions) {
            for (const handler of ext.handlers.get("input") ?? []) {
                const event = { type: "input", text: currentText, images: currentImages, source };
                const result = (await this.#runHandlerWithTimeout(handler, event, ctx, ext, extensionHandlerTimeoutMs));
                if (result?.handled)
                    return result;
                if (result?.text !== undefined)
                    currentText = result.text;
                if (result?.images !== undefined)
                    currentImages = result.images;
            }
        }
        const transformed = {};
        if (currentText !== text)
            transformed.text = currentText;
        if (currentImages !== images)
            transformed.images = currentImages;
        return transformed;
    }
    async emitContext(messages, signal) {
        // Check if any extensions actually have context handlers before building
        // the context object or cloning; this runs on every provider request.
        if (!this.hasHandlers("context"))
            return messages;
        const ctx = this.createContext();
        let currentMessages;
        try {
            currentMessages = structuredClone(messages);
        }
        catch {
            // Messages may contain non-cloneable objects (e.g. in ToolResultMessage.details
            // or ProviderPayload). Fall back to a shallow array clone — extensions should
            // return new message arrays rather than mutating in place.
            currentMessages = [...messages];
        }
        for (let index = 0; index < currentMessages.length; index++) {
            const message = currentMessages[index];
            if (message)
                setContextHistoryIndex(message, index);
        }
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get("context");
            if (!handlers || handlers.length === 0)
                continue;
            for (const handler of handlers) {
                const event = { type: "context", messages: currentMessages };
                const handlerResult = await this.#runHandlerWithTimeout(handler, event, ctx, ext, extensionHandlerTimeoutMs, undefined, signal);
                if (handlerResult && handlerResult.messages) {
                    const nextMessages = handlerResult.messages;
                    for (let index = 0; index < nextMessages.length; index++) {
                        const message = nextMessages[index];
                        if (!message || getContextHistoryIndex(message) !== undefined)
                            continue;
                        const previousMessage = currentMessages[index];
                        if (!previousMessage)
                            continue;
                        const historyIndex = getContextHistoryIndex(previousMessage);
                        if (historyIndex === undefined)
                            continue;
                        setContextHistoryIndex(message, historyIndex);
                        if (!Bun.deepEquals(message, previousMessage))
                            clearContextHistoryIndex(message);
                    }
                    currentMessages = nextMessages;
                }
            }
        }
        for (const message of currentMessages) {
            const historyIndex = getContextHistoryIndex(message);
            const historyMessage = historyIndex === undefined ? undefined : messages[historyIndex];
            if (historyMessage && historyIndex !== undefined)
                setContextHistoryIndex(historyMessage, historyIndex);
            const unchanged = historyMessage !== undefined && Bun.deepEquals(message, historyMessage);
            clearContextHistoryIndex(message);
            if (historyMessage)
                clearContextHistoryIndex(historyMessage);
            if (!unchanged)
                markPerCallContextMessage(message);
        }
        for (const message of messages)
            clearContextHistoryIndex(message);
        // An aborted handler is skipped and its input kept unchanged. Never hand that
        // untransformed (possibly unredacted) context back to a caller as if every hook ran.
        signal?.throwIfAborted();
        return currentMessages;
    }
    /** Runs request payload hooks with the model used for that provider request. */
    async emitBeforeProviderRequest(payload, model, signal) {
        if (!this.hasHandlers("before_provider_request"))
            return payload;
        const ctx = this.createContext(model);
        let currentPayload = payload;
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get("before_provider_request");
            if (!handlers || handlers.length === 0)
                continue;
            for (const handler of handlers) {
                const event = {
                    type: "before_provider_request",
                    payload: currentPayload,
                };
                const handlerResult = await this.#runHandlerWithTimeout(handler, event, ctx, ext, extensionHandlerTimeoutMs, undefined, signal);
                if (handlerResult !== undefined) {
                    currentPayload = handlerResult;
                }
            }
        }
        return currentPayload;
    }
    /** Runs response hooks with the model that produced that provider response. */
    async emitAfterProviderResponse(response, model, signal) {
        if (!this.hasHandlers("after_provider_response"))
            return;
        const ctx = this.createContext(model);
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get("after_provider_response");
            if (!handlers || handlers.length === 0)
                continue;
            for (const handler of handlers) {
                const event = {
                    type: "after_provider_response",
                    status: response.status,
                    headers: response.headers,
                    requestId: response.requestId,
                    metadata: response.metadata,
                };
                await this.#runHandlerWithTimeout(handler, event, ctx, ext, extensionHandlerTimeoutMs, undefined, signal);
            }
        }
    }
    async emitBeforeAgentStart(prompt, images, systemPrompt) {
        if (!this.hasHandlers("before_agent_start"))
            return undefined;
        const ctx = this.createContext();
        const messages = [];
        let currentSystemPrompt = systemPrompt;
        let systemPromptModified = false;
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get("before_agent_start");
            if (!handlers || handlers.length === 0)
                continue;
            for (const handler of handlers) {
                const event = {
                    type: "before_agent_start",
                    prompt,
                    images,
                    systemPrompt: currentSystemPrompt,
                };
                const handlerResult = await this.#runHandlerWithTimeout(handler, event, ctx, ext, extensionHandlerTimeoutMs);
                if (handlerResult) {
                    const result = handlerResult;
                    if (result.message) {
                        messages.push(result.message);
                    }
                    if (result.systemPrompt !== undefined) {
                        currentSystemPrompt =
                            typeof result.systemPrompt === "string" ? [result.systemPrompt] : result.systemPrompt;
                        systemPromptModified = true;
                    }
                }
            }
        }
        if (messages.length > 0 || systemPromptModified) {
            return {
                messages: messages.length > 0 ? messages : undefined,
                systemPrompt: systemPromptModified ? currentSystemPrompt : undefined,
            };
        }
        return undefined;
    }
    /**
     * Runs `before_subagent_spawn` handlers; a `block` short-circuits, the last defined `model` wins.
     * `signal` (the spawn's abort signal) cancels an awaiting handler instead of parking until the timeout.
     */
    async emitBeforeSubagentSpawn(event, signal) {
        if (!this.hasHandlers("before_subagent_spawn"))
            return undefined;
        const ctx = this.createContext();
        let chosen;
        for (const ext of this.extensions) {
            const handlers = ext.handlers.get("before_subagent_spawn");
            if (!handlers || handlers.length === 0)
                continue;
            for (const handler of handlers) {
                const handlerResult = await this.#runHandlerWithTimeout(handler, event, ctx, ext, extensionHandlerTimeoutMs, undefined, signal);
                if (!handlerResult)
                    continue;
                const result = handlerResult;
                if (result.block)
                    return result;
                if (result.model !== undefined)
                    chosen = { model: result.model, note: result.note };
            }
        }
        return chosen;
    }
}
