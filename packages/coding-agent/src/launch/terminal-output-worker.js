import { parentPort } from "node:worker_threads";
import { consumeWorkerInbox } from "@rva/utils/worker-host";
import { renderTerminalOutput } from "./terminal-output";
if (!parentPort)
    throw new Error("terminal-output-worker: missing parentPort");
const port = parentPort;
const inbox = consumeWorkerInbox();
const handle = async (message) => {
    const request = message;
    let result;
    try {
        result = { ok: true, rows: await renderTerminalOutput(request.output, request.options) };
    }
    catch (error) {
        result = { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
    port.postMessage(result);
    port.close();
};
if (inbox)
    inbox.bind(message => void handle(message));
else
    port.on("message", message => void handle(message));
