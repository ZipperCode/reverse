// ── Generators ──────────────────────────────────────────────────────────────
export function* onceGen(choice) {
    yield choice;
}
// ── Queue ───────────────────────────────────────────────────────────────────
export class ToolChoiceQueue {
    #queue = [];
    /**
     * In-flight yield awaiting resolve()/reject(). May outlive the run that
     * claimed it: a pre-model gate stop ends the run without a `turn_end`, and
     * the claim is finalized later — by the next admitted turn's `turn_end`,
     * the abort safety net, or an `unavailable` rejection on redeem.
     */
    #inFlight;
    /**
     * Label of the directive whose last yield was resolved this turn.
     * Consumers (e.g. todo reminder suppression) read via consumeLastServedLabel().
     */
    #lastResolvedLabel;
    /**
     * Non-forcing pending preview invokers, stacked by UNIQUE id. The
     * `xd://resolve` or `xd://reject` dispatch runs the head; the agent-loop's
     * soft-tool-requirement lifecycle drives resolution without this queue forcing `tool_choice`.
     */
    #pendingInvokers = [];
    // ── Push ──────────────────────────────────────────────────────────────
    pushOnce(choice, options) {
        this.push(onceGen(choice), options);
    }
    pushSequence(choices, options) {
        this.push(choices, options);
    }
    push(generator, options) {
        const directive = {
            generator: generator[Symbol.iterator](),
            label: options?.label ?? "anonymous",
            callbacks: {
                onResolved: options?.onResolved,
                onRejected: options?.onRejected,
                onInvoked: options?.onInvoked,
            },
        };
        if (options?.now) {
            this.#queue.unshift(directive);
        }
        else {
            this.#queue.push(directive);
        }
    }
    // ── Consume ───────────────────────────────────────────────────────────
    /**
     * Advance the head directive and return its next yield. Records the value
     * as in-flight until resolve() or reject() is called.
     */
    nextToolChoice() {
        while (this.#queue.length > 0) {
            const head = this.#queue[0];
            const result = head.generator.next();
            if (result.done) {
                this.#queue.shift();
                continue;
            }
            this.#inFlight = { directive: head, yielded: result.value, invoked: false };
            return result.value;
        }
        return undefined;
    }
    // ── Lifecycle ─────────────────────────────────────────────────────────
    /**
     * The in-flight yield completed normally. Directives with onInvoked are only
     * consumed after their requested tool ran; a normal text turn or a different
     * tool call requeues/rejects the directive instead.
     */
    resolve() {
        const inFlight = this.#inFlight;
        if (!inFlight)
            return;
        if (inFlight.directive.callbacks.onInvoked && !inFlight.invoked) {
            this.reject("not_invoked");
            return;
        }
        this.#inFlight = undefined;
        this.#lastResolvedLabel = inFlight.directive.label;
        inFlight.directive.callbacks.onResolved?.({ choice: inFlight.yielded });
    }
    /**
     * The in-flight yield was not served, or the turn aborted/errored.
     * Fires onRejected to let the caller decide: "requeue" replays the exact
     * lost value at the head of the queue; anything else drops it.
     */
    reject(reason) {
        const inFlight = this.#inFlight;
        this.#inFlight = undefined;
        if (!inFlight)
            return;
        const outcome = inFlight.directive.callbacks.onRejected?.({
            choice: inFlight.yielded,
            reason,
        });
        if (outcome === "drop_sequence") {
            const root = inFlight.directive.sequenceRoot ?? inFlight.directive;
            this.#queue = this.#queue.filter(directive => directive !== root && directive.sequenceRoot !== root);
            return;
        }
        if (outcome === "requeue") {
            // Re-queue only the lost yield, not the rest of the sequence. Carry forward
            // callbacks so the replayed yield still executes and finalizes correctly,
            // and can requeue itself again if the next turn also aborts or skips it.
            this.#queue.unshift({
                generator: onceGen(inFlight.yielded),
                label: `${inFlight.directive.label}-requeued`,
                sequenceRoot: inFlight.directive.sequenceRoot ?? inFlight.directive,
                callbacks: {
                    onResolved: inFlight.directive.callbacks.onResolved,
                    onInvoked: inFlight.directive.callbacks.onInvoked,
                    onRejected: inFlight.directive.callbacks.onRejected,
                },
            });
        }
    }
    /** True if there is an in-flight yield that hasn't been resolved or rejected. */
    get hasInFlight() {
        return this.#inFlight !== undefined;
    }
    /** Return the in-flight directive's onInvoked handler and mark it when called. */
    peekInFlightInvoker() {
        const inFlight = this.#inFlight;
        const onInvoked = inFlight?.directive.callbacks.onInvoked;
        if (!inFlight || !onInvoked)
            return undefined;
        return (input) => {
            inFlight.invoked = true;
            return onInvoked(input);
        };
    }
    // ── Non-forcing pending invokers ──────────────────────────────────────
    // Preview producers (queueResolveHandler) register here so a resolve-device
    // write can dispatch to a staged action WITHOUT a forced tool_choice (no
    // messages-cache bust). Stacked by UNIQUE id: a re-register replaces only the same id, so
    // concurrent/sequential previews each survive and resolve independently.
    /** Register (or replace by exact id) a non-forcing pending preview invoker. */
    registerPendingInvoker(id, sourceToolName, onInvoked) {
        this.removePendingInvoker(id);
        this.#pendingInvokers.push({ id, sourceToolName, onInvoked });
    }
    /** Drop the pending invoker with this id (e.g. after it resolves). */
    removePendingInvoker(id) {
        this.#pendingInvokers = this.#pendingInvokers.filter(p => p.id !== id);
    }
    /** Drop every pending preview invoker without touching hard tool-choice directives. */
    clearPendingInvokers() {
        if (this.#pendingInvokers.length === 0)
            return;
        this.#pendingInvokers = [];
    }
    /** True when at least one non-forcing pending preview is registered. */
    get hasPendingInvoker() {
        return this.#pendingInvokers.length > 0;
    }
    /** The head (most-recently registered) pending invoker's handler, for resolve dispatch. */
    peekPendingInvoker() {
        return this.#pendingInvokers.at(-1)?.onInvoked;
    }
    /** The head pending preview's stable id + source tool, for building the agent-level
     *  SoftToolRequirement (the id drives reminder re-injection when the head changes). */
    peekPendingHead() {
        const head = this.#pendingInvokers.at(-1);
        return head ? { id: head.id, sourceToolName: head.sourceToolName } : undefined;
    }
    // ── Cleanup ───────────────────────────────────────────────────────────
    /** Remove all directives with the given label. Rejects in-flight if it matches. */
    removeByLabel(label) {
        if (this.#inFlight?.directive.label === label) {
            this.reject("removed");
        }
        this.#queue = this.#queue.filter(d => d.label !== label);
    }
    /** Empty the queue and reject any in-flight yield. */
    clear() {
        if (this.#inFlight) {
            this.reject("cleared");
        }
        this.#queue = [];
        this.#pendingInvokers = [];
        this.#lastResolvedLabel = undefined;
    }
    // ── Observation ───────────────────────────────────────────────────────
    /** Return the label of the most recently resolved directive, then clear it. */
    consumeLastServedLabel() {
        const label = this.#lastResolvedLabel;
        this.#lastResolvedLabel = undefined;
        return label;
    }
    /** For tests/debug: labels of currently queued directives in order. */
    inspect() {
        return this.#queue.map(d => d.label);
    }
}
