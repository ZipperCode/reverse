function keyOf(key) {
    return `${key.siteId}\0${key.dynamicPath}\0${key.name}\0${key.fingerprint}\0${key.occurrence}`;
}
function runtimeKeyOf(key) {
    return `${key.siteId}\0${key.name}\0${key.fingerprint}`;
}
/**
 * Per-cell one-shot outcome store. Candidates are visible only after their
 * speculative execution settles; normal bridge calls consume each outcome at
 * most once and retain baseline behavior on a miss.
 */
export class ShadowClaimStore {
    #outcomes = new Map();
    #runtimeKeys = new Map();
    #pending = new Map();
    #closed = false;
    register(key, runtimeOccurrence) {
        if (this.#closed)
            return;
        const encoded = keyOf(key);
        if (!this.#pending.has(encoded))
            this.#pending.set(encoded, Promise.withResolvers());
        const runtimeKey = runtimeKeyOf(key);
        let occurrences = this.#runtimeKeys.get(runtimeKey);
        if (!occurrences) {
            occurrences = new Map();
            this.#runtimeKeys.set(runtimeKey, occurrences);
        }
        occurrences.set(runtimeOccurrence, key);
    }
    add(key, outcome) {
        if (this.#closed)
            return;
        this.#outcomes.set(keyOf(key), outcome);
        this.#pending.get(keyOf(key))?.resolve(outcome);
    }
    miss(key) {
        if (this.#closed)
            return;
        const encoded = keyOf(key);
        this.#pending.get(encoded)?.resolve(undefined);
        this.#pending.delete(encoded);
    }
    claim(key, remainingTimeoutMs) {
        if (this.#closed)
            return undefined;
        const encoded = keyOf(key);
        const outcome = this.#outcomes.get(encoded);
        if (!outcome || outcome.virtualDurationMs > remainingTimeoutMs)
            return undefined;
        this.#pending.delete(encoded);
        this.#outcomes.delete(encoded);
        return outcome;
    }
    claimRuntime(key, remainingTimeoutMs) {
        const registered = this.#runtimeKeys.get(runtimeKeyOf(key))?.get(key.occurrence);
        if (!registered)
            return undefined;
        const outcome = this.claim(registered, remainingTimeoutMs);
        if (outcome)
            this.#runtimeKeys.get(runtimeKeyOf(key))?.delete(key.occurrence);
        return outcome;
    }
    async claimRuntimeAsync(key, remainingTimeoutMs, signal) {
        const runtimeKey = runtimeKeyOf(key);
        const registered = this.#runtimeKeys.get(runtimeKey)?.get(key.occurrence);
        if (!registered)
            return undefined;
        const releaseRuntimeKey = () => {
            this.#runtimeKeys.get(runtimeKey)?.delete(key.occurrence);
        };
        if (signal?.aborted) {
            releaseRuntimeKey();
            return undefined;
        }
        const immediate = this.claim(registered, remainingTimeoutMs);
        if (immediate || remainingTimeoutMs <= 0)
            return immediate;
        const pending = this.#pending.get(keyOf(registered));
        if (!pending)
            return undefined;
        let aborted;
        let onAbort;
        if (signal) {
            const abort = Promise.withResolvers();
            aborted = abort.promise;
            onAbort = () => abort.resolve();
            signal.addEventListener("abort", onAbort, { once: true });
        }
        try {
            if (remainingTimeoutMs === Number.MAX_SAFE_INTEGER) {
                if (aborted) {
                    await Promise.race([pending.promise, aborted]);
                }
                else {
                    await pending.promise;
                }
            }
            else {
                const timeout = Promise.withResolvers();
                const timer = setTimeout(timeout.resolve, remainingTimeoutMs);
                try {
                    if (aborted) {
                        await Promise.race([pending.promise, timeout.promise, aborted]);
                    }
                    else {
                        await Promise.race([pending.promise, timeout.promise]);
                    }
                }
                finally {
                    clearTimeout(timer);
                }
            }
        }
        finally {
            if (onAbort)
                signal?.removeEventListener("abort", onAbort);
        }
        if (signal?.aborted) {
            releaseRuntimeKey();
            return undefined;
        }
        const outcome = this.claim(registered, remainingTimeoutMs);
        if (!outcome)
            releaseRuntimeKey();
        return outcome;
    }
    discard() {
        this.#closed = true;
        for (const pending of this.#pending.values())
            pending.resolve(undefined);
        this.#pending.clear();
        this.#outcomes.clear();
        this.#runtimeKeys.clear();
    }
}
