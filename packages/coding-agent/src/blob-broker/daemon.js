/**
 * Client half of the project-shared blob daemon.
 *
 * `connectDaemonBlobBackend` ensures the blob daemon is running under the
 * daemon broker (same lifecycle as the shared Chromium and LSP mux: started on
 * first use, stopped when the last omp process in the project exits), then
 * speaks the HTTP-over-Unix-socket control plane from `protocol.ts`. Every
 * failure returns `null` so callers fall back to an in-process backend.
 */
import * as os from "node:os";
import * as path from "node:path";
import { logger, ptree } from "@rva/utils";
import { daemonClientForProject } from "../launch/client";
import { describeQuietly, stopQuietly, waitReady } from "../launch/ensure";
import { daemonRuntimeDir } from "../launch/paths";
import { resolveWorkerSpawnCmd, SMOKE_TEST_TIMEOUT_MS, workerEnvFromParent } from "../subprocess/worker-client";
import { BLOB_BROKER_CONFIG_ENV, BLOB_BROKER_DAEMON_NAME, BLOB_BROKER_READY_PATTERN, BLOB_BROKER_SOCKET_ENV, BLOB_BROKER_WORKER_ARG, blobBrokerEndpoint, } from "./protocol";
import { blobBrokerConfigKey } from "./server";
const PROBE_TIMEOUT_MS = 1500;
const REQUEST_TIMEOUT_MS = 90000;
const READY_TIMEOUT_MS = 45000;
/** probe→describe→start rounds; bounds cross-process start races and wedged-daemon replacement. */
const ENSURE_ATTEMPTS = 3;
async function fetchUnix(socket, input, init) {
    const response = await fetch(`http://blob-broker.local${input}`, {
        ...init,
        unix: socket,
        signal: AbortSignal.timeout(init?.timeoutMs ?? REQUEST_TIMEOUT_MS),
    });
    if (!response.ok)
        throw new Error(`blob daemon ${input} responded ${response.status}`);
    return (await response.json());
}
async function probeDaemon(socket) {
    try {
        return await fetchUnix(socket, "/info", { timeoutMs: PROBE_TIMEOUT_MS });
    }
    catch {
        return null;
    }
}
async function liveBlobBrokerSocket(projectDir) {
    if (process.platform === "win32")
        return null;
    try {
        const client = await daemonClientForProject(projectDir);
        await client.request({ op: "ping" });
        const socket = blobBrokerEndpoint(daemonRuntimeDir(client.projectDir));
        return (await probeDaemon(socket)) ? socket : null;
    }
    catch {
        return null;
    }
}
/** Query a running blob daemon without starting one; `null` means stopped. */
export async function queryBlobBrokerStatus(projectDir) {
    const socket = await liveBlobBrokerSocket(projectDir);
    return socket ? fetchUnix(socket, "/status") : null;
}
/** Run diagnostics on a running blob daemon; `null` means stopped. */
export async function queryBlobBrokerDoctor(projectDir, request = {}) {
    const socket = await liveBlobBrokerSocket(projectDir);
    if (!socket)
        return null;
    return fetchUnix(socket, "/doctor", {
        method: "POST",
        body: JSON.stringify(request),
    });
}
/**
 * Ensure the configured daemon is active, then issue an actual public health
 * request through its exposure. `null` means the daemon could not be started.
 */
export async function queryBlobBrokerProbe(projectDir, config, request = {}) {
    if (process.platform === "win32")
        return null;
    const info = await ensureBlobDaemon(projectDir, config);
    if (!info)
        return null;
    const socket = await liveBlobBrokerSocket(projectDir);
    if (!socket)
        return null;
    return fetchUnix(socket, "/probe", {
        method: "POST",
        body: JSON.stringify(request),
    });
}
/** Preview or apply cleanup on a running daemon; `null` means stopped. */
export async function queryBlobBrokerPurge(projectDir, request = {}) {
    const socket = await liveBlobBrokerSocket(projectDir);
    if (!socket)
        return null;
    return fetchUnix(socket, "/purge", {
        method: "POST",
        body: JSON.stringify(request),
    });
}
/**
 * Ensure the project's blob daemon runs with `config` and return its info.
 * A live daemon with a different config is replaced (settings changed).
 */
async function ensureBlobDaemon(projectDir, config) {
    const client = await daemonClientForProject(projectDir);
    const socket = blobBrokerEndpoint(daemonRuntimeDir(client.projectDir));
    // The broker connection doubles as the presence lease keeping the daemon alive.
    await client.request({ op: "ping" });
    const wantKey = blobBrokerConfigKey(config);
    const spawn = resolveWorkerSpawnCmd(BLOB_BROKER_WORKER_ARG);
    for (let attempt = 0; attempt < ENSURE_ATTEMPTS; attempt++) {
        const live = await probeDaemon(socket);
        if (live) {
            if (live.configKey === wantKey)
                return live;
            // Exposure settings changed since the daemon started: replace it.
            await stopQuietly(client, BLOB_BROKER_DAEMON_NAME, "blob broker");
        }
        const existing = await describeQuietly(client, BLOB_BROKER_DAEMON_NAME, "blob broker");
        if (existing && existing.state !== "exited" && existing.state !== "failed") {
            if (existing.readyAt === undefined) {
                await waitReady(client, BLOB_BROKER_DAEMON_NAME, "blob broker", undefined, READY_TIMEOUT_MS);
            }
            const adopted = await probeDaemon(socket);
            if (adopted?.configKey === wantKey)
                return adopted;
            // Live record but wrong config or nothing listening: replace it.
            await stopQuietly(client, BLOB_BROKER_DAEMON_NAME, "blob broker");
            continue;
        }
        try {
            const started = await client.request({
                op: "start",
                spec: {
                    name: BLOB_BROKER_DAEMON_NAME,
                    application: spawn.cmd[0],
                    args: spawn.cmd.slice(1),
                    env: {
                        [BLOB_BROKER_SOCKET_ENV]: socket,
                        [BLOB_BROKER_CONFIG_ENV]: JSON.stringify(config),
                    },
                    cwd: spawn.cwd ?? client.projectDir,
                    pty: false,
                    ready: { log: BLOB_BROKER_READY_PATTERN, timeoutMs: READY_TIMEOUT_MS },
                    restart: "no",
                    persist: false,
                    detached: false,
                },
            });
            if (started.op !== "start")
                continue;
            const info = await probeDaemon(socket);
            if (info?.configKey === wantKey)
                return info;
            await stopQuietly(client, BLOB_BROKER_DAEMON_NAME, "blob broker");
        }
        catch (error) {
            // Lost a cross-process start race; the next round adopts the winner.
            logger.debug("blob daemon start contention", {
                name: BLOB_BROKER_DAEMON_NAME,
                error: error instanceof Error ? error.message : String(error),
            });
        }
    }
    return null;
}
class DaemonBlobBackend {
    #socket;
    #callbacks;
    supportsLazy;
    constructor(socket, info, callbacks) {
        this.#socket = socket;
        this.#callbacks = callbacks;
        this.supportsLazy = info.lazy;
    }
    async ensureBlob(key, mimeType, getBytes, getBase64) {
        try {
            // Probe first: persisted/live registrations answer without the bytes
            // ever crossing the socket — the common case on every turn after the
            // first, and on conversation resume.
            const probe = await fetchUnix(this.#socket, "/blob", {
                method: "POST",
                body: JSON.stringify({ key, mimeType }),
            });
            if (probe.publication)
                return probe.publication;
            const { publication } = await fetchUnix(this.#socket, "/blob", {
                method: "POST",
                body: JSON.stringify({ key, mimeType, data: getBase64?.() ?? getBytes().toBase64() }),
            });
            return publication ?? null;
        }
        catch (error) {
            logger.debug("blob daemon ensure failed", {
                error: error instanceof Error ? error.message : String(error),
            });
            return null;
        }
    }
    async ensureLazy(key, mimeType, fetcher) {
        if (!this.supportsLazy)
            return null;
        const callback = await this.#callbacks.ensure();
        if (!callback)
            return null;
        this.#callbacks.register(key, fetcher);
        try {
            const { publication } = await fetchUnix(this.#socket, "/lazy", {
                method: "POST",
                body: JSON.stringify({
                    key,
                    mimeType,
                    callbackPort: callback.port,
                    callbackToken: callback.token,
                }),
            });
            return publication ?? null;
        }
        catch (error) {
            logger.debug("blob daemon lazy ensure failed", {
                error: error instanceof Error ? error.message : String(error),
            });
            return null;
        }
    }
    stop() {
        // The daemon outlives this session; the broker lease handles teardown.
    }
}
/**
 * Connect the project-shared blob daemon, starting it when necessary.
 * Returns `null` (after a debug log) when the shared path is unavailable —
 * including on Windows, where the control plane's Unix socket cannot bind —
 * so the caller falls back to an in-process backend.
 */
export async function connectDaemonBlobBackend(projectDir, config, callbacks) {
    if (process.platform === "win32")
        return null;
    try {
        const client = await daemonClientForProject(projectDir);
        const socket = blobBrokerEndpoint(daemonRuntimeDir(client.projectDir));
        const info = await ensureBlobDaemon(projectDir, config);
        if (!info)
            return null;
        return new DaemonBlobBackend(socket, info, callbacks);
    }
    catch (error) {
        logger.debug("Shared blob daemon unavailable; falling back to in-process broker", {
            error: error instanceof Error ? error.message : String(error),
        });
        return null;
    }
}
/** Exercise worker-host blob daemon startup and the /info probe for distribution smoke tests. */
export async function smokeTestBlobBroker() {
    const socket = path.join(os.tmpdir(), `omp-blob-smoke-${process.pid.toString(36)}.sock`);
    const config = {
        kind: "direct",
        options: {},
        credentials: {},
        bindHost: "127.0.0.1",
    };
    const spawn = resolveWorkerSpawnCmd(BLOB_BROKER_WORKER_ARG);
    const proc = ptree.spawn(spawn.cmd, {
        cwd: spawn.cwd,
        env: workerEnvFromParent({
            [BLOB_BROKER_SOCKET_ENV]: socket,
            [BLOB_BROKER_CONFIG_ENV]: JSON.stringify(config),
        }),
    });
    try {
        const deadline = Date.now() + SMOKE_TEST_TIMEOUT_MS;
        let info = null;
        while (Date.now() < deadline) {
            if (proc.exitCode !== null)
                break;
            info = await probeDaemon(socket);
            if (info)
                break;
            await Bun.sleep(200);
        }
        if (!info) {
            throw new Error(`blob broker smoke failed: no /info response (${proc.peekStderr().slice(-500) || "no stderr"})`);
        }
        const { publication } = await fetchUnix(socket, "/blob", {
            method: "POST",
            body: JSON.stringify({
                key: "smoke",
                mimeType: "image/png",
                data: Buffer.from("smoke-test").toString("base64"),
            }),
        });
        if (!publication)
            throw new Error("blob broker smoke failed: ensure returned no publication");
        if (publication.destination !== "direct" || publication.bytes !== 10) {
            throw new Error("blob broker smoke failed: ensure returned incomplete publication metadata");
        }
        const served = await fetch(publication.url);
        if (!served.ok || (await served.text()) !== "smoke-test") {
            throw new Error(`blob broker smoke failed: blob roundtrip returned ${served.status}`);
        }
        const status = await fetchUnix(socket, "/status");
        if (status.metrics.activeBlobs !== 1 || status.metrics.hits !== 1 || status.metrics.bytesServed !== 10) {
            throw new Error("blob broker smoke failed: status metrics did not roundtrip");
        }
    }
    finally {
        proc.kill();
        await proc.exited.catch(() => { });
    }
}
