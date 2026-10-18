import { workerHostEntry } from "@rva/utils/worker-host";
import { TERMINAL_OUTPUT_WORKER_ARG, } from "./terminal-output-worker-protocol";
/** Replay legacy broker PTY bytes without evaluating xterm in the client process. */
export async function renderTerminalOutputIsolated(output, options) {
    const hostEntry = workerHostEntry();
    const worker = hostEntry
        ? new Worker(hostEntry, { type: "module", argv: [TERMINAL_OUTPUT_WORKER_ARG] })
        : new Worker(new URL("./terminal-output-worker.ts", import.meta.url).href, { type: "module" });
    const pending = Promise.withResolvers();
    const onMessage = (event) => {
        if (event.data.ok)
            pending.resolve(event.data.rows);
        else
            pending.reject(new Error(event.data.error));
    };
    const onError = (event) => {
        pending.reject(event.error instanceof Error ? event.error : new Error(event.message));
    };
    const onClose = () => {
        pending.reject(new Error("Terminal output worker exited before responding"));
    };
    worker.addEventListener("message", onMessage);
    worker.addEventListener("error", onError);
    worker.addEventListener("close", onClose);
    try {
        const request = { output, options };
        worker.postMessage(request);
        return await pending.promise;
    }
    finally {
        worker.removeEventListener("message", onMessage);
        worker.removeEventListener("error", onError);
        worker.removeEventListener("close", onClose);
        worker.terminate();
    }
}
/** Distribution smoke for source, npm-bundle, and compiled worker routing. */
export async function smokeTestTerminalOutputWorker() {
    const rows = await renderTerminalOutputIsolated("old\r\x1b[2K\x1b[1;32mready\x1b[0m", {
        head: false,
        maxRows: 10,
    });
    if (rows?.length !== 1 || rows[0] !== "\x1b[0m\x1b[1;38;5;2mready") {
        throw new Error("terminal output worker smoke mismatch");
    }
}
