import { parentPort } from "node:worker_threads";
import { consumeWorkerInbox, isWorkerHostSelector } from "@rva/utils/worker-host";
import { ComputerWorkerCore } from "./worker";
let started = false;
/** Starts the computer worker once when running inside a Bun worker thread. */
export function startComputerWorker() {
    if (started || !parentPort)
        return;
    started = true;
    const port = parentPort;
    const inbox = consumeWorkerInbox();
    const transport = {
        send(message, transfer) {
            port.postMessage(message, transfer ?? []);
        },
        onMessage(handler) {
            if (inbox)
                return inbox.bind(message => handler(message));
            const listener = (message) => handler(message);
            port.on("message", listener);
            return () => port.off("message", listener);
        },
        close() {
            port.close();
        },
    };
    new ComputerWorkerCore(transport);
}
// Direct-source fallback: loaded as a worker's entry module outside a CLI
// host there is no selector argv, so start immediately. When any CLI-host
// worker re-enters cli.ts (which imports this module statically), the
// selector guard defers to the host's dispatch — an unguarded auto-start
// would hijack the message port of every other worker kind.
if (!Bun.argv.some(isWorkerHostSelector)) {
    startComputerWorker();
}
