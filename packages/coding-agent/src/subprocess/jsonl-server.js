import { IpcServer } from "@rva/natives";
import { logger, postmortem } from "@rva/utils";
/**
 * Newline-JSON request loop over a native {@link IpcServer}: the server half of
 * the machine-shared workers (`shared-worker.ts` is the client half;
 * `mlx-server.py` mirrors it in Python) and of the text-prediction daemon.
 * Owns one endpoint — binding, owner-only permissions, and taking over a
 * crashed predecessor's socket are native; a live owner makes {@link serve}
 * reject with `EADDRINUSE` — feeds every connection's request lines to
 * `onRequest`, and exits the process once idle.
 */
export class JsonLineServer {
    #options;
    #connections = new Set();
    #inFlight = 0;
    #idleTimer;
    #server;
    #endpoint = "";
    #stopped = Promise.withResolvers();
    #stopping;
    constructor(options) {
        this.#options = options;
    }
    /** Bind `endpoint` and serve until idle exit or {@link exit}; resolves once the endpoint is released. */
    async serve(endpoint) {
        this.#endpoint = endpoint;
        this.#server = await IpcServer.listen(endpoint, { framing: "lines" }, connection => this.#accept(connection));
        const cancelCleanup = postmortem.register(this.#options.cleanupLabel, () => this.#shutdown());
        this.#armIdle();
        process.stdout.write(`${this.#options.banner(endpoint)}\n`);
        try {
            await this.#stopped.promise;
        }
        finally {
            cancelCleanup();
        }
    }
    /** Count `work` as in flight, holding off idle exit until it settles. */
    async busy(work) {
        this.#inFlight += 1;
        this.#armIdle();
        try {
            return await work();
        }
        finally {
            this.#inFlight -= 1;
            this.#armIdle();
        }
    }
    /** Release the endpoint, then exit the process. */
    exit(reason) {
        logger.debug(`${this.#options.name}: ${reason}; exiting`, { endpoint: this.#endpoint });
        void this.#shutdown().finally(() => process.exit(0));
    }
    #accept(connection) {
        this.#connections.add(connection);
        const reply = { send: message => connection.send(JSON.stringify(message)) };
        connection.start(line => {
            let request;
            try {
                request = JSON.parse(line);
            }
            catch (error) {
                logger.warn(`${this.#options.name}: malformed request line`, { error: String(error) });
                return;
            }
            this.#options.onRequest(request, reply);
        }, () => this.#connections.delete(connection));
    }
    #armIdle() {
        clearTimeout(this.#idleTimer);
        this.#idleTimer = setTimeout(() => {
            if (this.#inFlight > 0) {
                this.#armIdle();
                return;
            }
            this.exit(`idle for ${this.#options.idleMs}ms`);
        }, this.#options.idleMs);
    }
    #shutdown() {
        this.#stopping ??= this.#stop();
        return this.#stopping;
    }
    async #stop() {
        clearTimeout(this.#idleTimer);
        this.#options.beforeStop?.();
        // Clients reconnect on demand.
        for (const connection of this.#connections)
            connection.destroy();
        this.#connections.clear();
        await this.#server?.close();
        this.#server = undefined;
        await this.#options.onStop?.();
        this.#stopped.resolve();
    }
}
