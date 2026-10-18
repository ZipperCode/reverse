export class SpawnRun {
    identity;
    #controller = new AbortController();
    #onUpdate;
    #lastUpdate;
    #onArtifactsRetained;
    #retainedCleanup;
    #discarded = false;
    /** Resolves once the permit is held; rejects with the acquire error when aborted first. */
    started;
    /** The run's payload; rejects only when `started` does. */
    result;
    /** Acquire a permit, then run `body` and release the permit when it settles. */
    constructor(permit, body, identity) {
        this.identity = identity;
        const invokedAt = Date.now();
        this.started = permit.acquire(this.#controller.signal).then(() => ({ invokedAt, acquiredAt: Date.now() }));
        this.result = this.started.then(async (timing) => {
            try {
                return await body({
                    signal: this.#controller.signal,
                    timing,
                    onUpdate: update => {
                        this.#lastUpdate = update;
                        return this.#onUpdate?.(update);
                    },
                    onArtifactsRetained: cleanup => {
                        if (this.#onArtifactsRetained)
                            this.#onArtifactsRetained(cleanup);
                        else if (this.#discarded)
                            void cleanup();
                        else
                            this.#retainedCleanup = cleanup;
                    },
                });
            }
            finally {
                permit.release();
            }
        });
        // Owners await these only after adoption; a discarded run is never awaited.
        void this.result.catch(() => undefined);
    }
    /** Bind the adopting owner: its abort cancels the run, and buffered progress/artifacts flush to it. */
    attach(owner) {
        const signal = owner.signal;
        if (signal?.aborted)
            this.#controller.abort(signal.reason);
        else if (signal) {
            const onAbort = () => this.#controller.abort(signal.reason);
            signal.addEventListener("abort", onAbort, { once: true });
            // The owner signal can outlive the run (a session- or job-scoped signal that never
            // aborts); drop the listener once the run settles so the signal does not pin it.
            const detach = () => signal.removeEventListener("abort", onAbort);
            void this.result.then(detach, detach);
        }
        this.#onUpdate = owner.onUpdate;
        if (this.#lastUpdate)
            void owner.onUpdate?.(this.#lastUpdate);
        this.#onArtifactsRetained = owner.onArtifactsRetained;
        const retained = this.#retainedCleanup;
        this.#retainedCleanup = undefined;
        if (retained) {
            if (owner.onArtifactsRetained)
                owner.onArtifactsRetained(retained);
            else
                void retained();
        }
    }
    /** Abort an unadopted run and drop anything it retained; nothing ever consumes its result. */
    discard(reason) {
        this.#discarded = true;
        this.#controller.abort(new Error(reason));
        const retained = this.#retainedCleanup;
        this.#retainedCleanup = undefined;
        if (retained)
            void retained();
    }
}
