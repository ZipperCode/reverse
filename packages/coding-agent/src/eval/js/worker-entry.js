import { parentPort } from "node:worker_threads";
import { consumeWorkerInbox } from "@rva/utils/worker-host";
import { WorkerCore } from "./worker-core";
if (!parentPort)
    throw new Error("js worker-entry: missing parentPort");
const port = parentPort;
// When the CLI host pre-buffered messages (it imports this module dynamically),
// bind that inbox so the parent's already-delivered `init` is replayed. Loaded
// directly (test/SDK fallback), this module's top-level runs synchronously at
// worker start, so the direct `parentPort.on` below wins the flush on its own.
const inbox = consumeWorkerInbox();
const transport = {
    send: (msg) => port.postMessage(msg),
    onMessage: handler => {
        if (inbox)
            return inbox.bind(data => handler(data));
        const wrap = (data) => handler(data);
        port.on("message", wrap);
        return () => port.off("message", wrap);
    },
    close: () => {
        try {
            port.close();
        }
        catch {
            // Already closed.
        }
        // `parentPort.close()` only disconnects the channel in Bun; it does not
        // make the Worker emit `close` or reap ref'ed user handles. Exit from
        // inside the worker after `WorkerCore` has sent the `closed` ack so the
        // host can observe real worker exit without calling `Worker.terminate()`.
        setTimeout(() => process.exit(0), 0);
    },
};
new WorkerCore(transport, { mode: "isolated" });
