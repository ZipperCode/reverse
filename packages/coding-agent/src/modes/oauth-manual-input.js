export class OAuthManualInputManager {
    #pending;
    waitForInput(providerId) {
        if (this.#pending) {
            this.clear("Manual OAuth input superseded by a new login");
        }
        const pending = this.#createPending(providerId);
        this.#pending = pending;
        return pending.promise;
    }
    tryWaitForInput(providerId) {
        if (this.#pending)
            return undefined;
        return this.waitForInput(providerId);
    }
    tryClaimInput(providerId) {
        if (this.#pending)
            return undefined;
        const pending = this.#createPending(providerId);
        this.#pending = pending;
        return {
            promise: pending.promise,
            clear: (reason) => {
                if (this.#pending !== pending)
                    return;
                this.clear(reason);
            },
        };
    }
    submit(input) {
        if (!this.#pending)
            return false;
        const { resolve } = this.#pending;
        this.#pending = undefined;
        resolve(input);
        return true;
    }
    clear(reason = "Manual OAuth input cleared") {
        if (!this.#pending)
            return;
        const { reject } = this.#pending;
        this.#pending = undefined;
        reject(new Error(reason));
    }
    hasPending() {
        return Boolean(this.#pending);
    }
    get pendingProviderId() {
        return this.#pending?.providerId;
    }
    #createPending(providerId) {
        const { promise, resolve, reject } = Promise.withResolvers();
        return { providerId, resolve, reject, promise };
    }
}
