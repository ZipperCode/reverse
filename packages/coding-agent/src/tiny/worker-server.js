import { JsonLineServer } from "../subprocess/jsonl-server";
/** The ONNX worker's endpoint: answers `ping`/`shutdown` inline and serializes `load`/`chat` through one queue. */
export class TinyWorkerServer {
    #options;
    #queue = Promise.resolve();
    #server;
    constructor(options) {
        this.#options = options;
        this.#server = new JsonLineServer({
            name: "tiny-worker",
            cleanupLabel: "tiny-worker",
            idleMs: options.idleMs,
            banner: endpoint => `omp tiny worker listening on ${endpoint}`,
            onRequest: (request, reply) => this.#dispatch(request, reply),
        });
    }
    /** Bind `endpoint` and serve until idle exit or `shutdown`; resolves once the socket is released. */
    serve(endpoint) {
        return this.#server.serve(endpoint);
    }
    #dispatch(request, reply) {
        if (request.type === "ping") {
            reply.send({ type: "pong", id: request.id, tag: this.#options.tag });
            return;
        }
        if (request.type === "shutdown") {
            this.#server.exit("shutdown requested");
            return;
        }
        const run = async () => {
            try {
                await this.#options.handle(request, reply);
            }
            catch (error) {
                reply.send({
                    type: "error",
                    id: request.id,
                    error: error instanceof Error ? (error.stack ?? error.message) : String(error),
                });
            }
        };
        this.#queue = this.#server.busy(() => this.#queue.then(run, run));
    }
}
