/**
 * Worker entry for the project-shared blob daemon (`__omp_worker_blob_broker`).
 *
 * Hosts a {@link LocalBlobBackend} (store + exposure or uploader) plus an HTTP
 * control plane on a Unix socket. Sessions register blobs over the socket;
 * providers fetch them through the exposure. Lazy blobs resolve through a
 * loopback callback into the owning session, so nothing renders — and nothing
 * stays resident — until a provider actually asks for the bytes.
 */
import * as fs from "node:fs";
import { logger } from "@rva/utils";
import { isUploaderKind, LocalBlobBackend } from "./broker";
import { BLOB_BROKER_CONFIG_ENV, BLOB_BROKER_SOCKET_ENV, blobBrokerReadyBanner, RENDER_CALLBACK_PATH, RENDER_CALLBACK_TOKEN_HEADER, } from "./protocol";
import { readBlobBrokerSavingsStatus } from "./savings";
const CALLBACK_TIMEOUT_MS = 30000;
/** Stable identity for a worker config, used by clients to detect drift. */
export function blobBrokerConfigKey(config) {
    return Bun.hash(JSON.stringify(config)).toString(16);
}
function json(body, status = 200) {
    return Response.json(body, { status });
}
async function backendStatus(backend, config, baseUrl) {
    const emptySavings = {
        journalPath: config.persist?.savingsPath ?? "",
        entries: 0,
        imageCount: 0,
        inlineBytes: 0,
        referenceBytes: 0,
        savedBytes: 0,
        byDestination: {},
    };
    let savings = emptySavings;
    if (config.persist?.savingsPath) {
        try {
            savings = await readBlobBrokerSavingsStatus(config.persist.savingsPath);
        }
        catch {
            // Status remains available when the optional savings journal is unreadable.
        }
    }
    return {
        baseUrl,
        lazy: backend.supportsLazy,
        configKey: blobBrokerConfigKey(config),
        ...backend.storeStatus(),
        savings,
    };
}
/** Serve the control plane against a backend; exported for the smoke probe and tests. */
export function createControlHandler(backend, config, baseUrl) {
    return async (request) => {
        const pathname = new URL(request.url).pathname;
        if (request.method === "GET" && pathname === "/info") {
            const info = {
                baseUrl,
                lazy: backend.supportsLazy,
                configKey: blobBrokerConfigKey(config),
            };
            return json(info);
        }
        if (request.method === "GET" && pathname === "/status") {
            return json(await backendStatus(backend, config, baseUrl));
        }
        if (request.method === "POST" && pathname === "/doctor") {
            const body = (await request.json());
            const response = {
                status: await backendStatus(backend, config, baseUrl),
                checks: [
                    { name: "control", ok: true, status: "pass", detail: "daemon control plane is responding" },
                    ...(await backend.doctor(body.probe !== false)),
                ],
            };
            return json(response);
        }
        if (request.method === "POST" && pathname === "/probe") {
            const body = (await request.json());
            const response = await backend.probePublicHealth(body.timeoutMs);
            return json(response);
        }
        if (request.method === "POST" && pathname === "/purge") {
            const body = (await request.json());
            const response = await backend.purge(body);
            return json(response);
        }
        if (request.method === "POST" && pathname === "/blob") {
            const body = (await request.json());
            if (body.data === undefined) {
                const publication = await backend.lookupBlob(body.key);
                return json((publication ? { publication } : { missing: true }));
            }
            const bytes = Buffer.from(body.data, "base64");
            const publication = await backend.ensureBlob(body.key, body.mimeType, () => bytes);
            if (!publication)
                return json({ error: "unavailable" }, 503);
            return json({ publication });
        }
        if (request.method === "POST" && pathname === "/lazy") {
            const body = (await request.json());
            const callback = `http://127.0.0.1:${body.callbackPort}${RENDER_CALLBACK_PATH}${encodeURIComponent(body.key)}`;
            const token = body.callbackToken;
            const publication = await backend.ensureLazy(body.key, body.mimeType, async () => {
                const response = await fetch(callback, {
                    headers: { [RENDER_CALLBACK_TOKEN_HEADER]: token },
                    signal: AbortSignal.timeout(CALLBACK_TIMEOUT_MS),
                });
                if (!response.ok)
                    return null;
                return new Uint8Array(await response.arrayBuffer());
            });
            if (!publication)
                return json({ error: "unavailable" }, 503);
            return json({ publication });
        }
        return json({ error: "not found" }, 404);
    };
}
/** Boot the blob daemon from worker environment variables and serve forever. */
export async function startBlobBrokerFromEnvironment() {
    const socketPath = Bun.env[BLOB_BROKER_SOCKET_ENV];
    const configJson = Bun.env[BLOB_BROKER_CONFIG_ENV];
    if (!socketPath || !configJson) {
        throw new Error(`blob broker worker requires ${BLOB_BROKER_SOCKET_ENV} and ${BLOB_BROKER_CONFIG_ENV}`);
    }
    const config = JSON.parse(configJson);
    const backend = new LocalBlobBackend(config);
    // Bring the exposure up before advertising readiness so a ready daemon is a
    // serving daemon. Uploader configs have nothing to start.
    const baseUrl = isUploaderKind(config.kind) ? "" : await backend.ensureStarted();
    if (baseUrl === null) {
        throw new Error("blob broker exposure failed to start");
    }
    try {
        fs.rmSync(socketPath, { force: true });
    }
    catch {
        // A live daemon holding the socket loses the start race in the broker.
    }
    Bun.serve({ unix: socketPath, fetch: createControlHandler(backend, config, baseUrl) });
    // The daemon broker tears us down with a signal; flush the persisted
    // url index rather than losing the debounced write.
    process.on("SIGTERM", () => {
        backend.stop();
        process.exit(0);
    });
    logger.info("blob-broker daemon up", { kind: config.kind, baseUrl, socketPath });
    // Readiness banner consumed by the daemon broker's ready matcher.
    console.log(blobBrokerReadyBanner(baseUrl || `upload:${config.kind}`));
    // Serve until the daemon broker tears the process down with the project.
    await Promise.withResolvers().promise;
}
