/**
 * Cross-process contract for the broker-owned blob daemon.
 *
 * One blob daemon runs per project scope (launched through the same daemon
 * broker that owns the shared Chromium and LSP mux), so every omp process in
 * the project shares one exposure (tunnel or uploader) and one URL per blob.
 * Control traffic rides HTTP over a Unix socket in the daemon runtime dir;
 * public traffic reaches the same store through the exposure.
 */
import * as path from "node:path";
export { BLOB_BROKER_WORKER_ARG } from "../cli/worker-selectors";
/** Environment key carrying the control socket path the worker listens on. */
export const BLOB_BROKER_SOCKET_ENV = "RVA_BLOB_BROKER_SOCKET";
/** Environment key carrying the JSON {@link BlobBrokerWorkerConfig}. */
export const BLOB_BROKER_CONFIG_ENV = "RVA_BLOB_BROKER_CONFIG";
/** Stable broker daemon name for the shared blob broker. */
export const BLOB_BROKER_DAEMON_NAME = "rva.blob.broker";
/** Broker readiness regex matched against the banner printed by the worker. */
export const BLOB_BROKER_READY_PATTERN = String.raw `rva blob broker serving \S+`;
/** Banner printed on stdout once the exposure is up and control is listening. */
export function blobBrokerReadyBanner(baseUrl) {
    return `rva blob broker serving ${baseUrl}`;
}
/** Resolve the control socket path for one project scope. */
export function blobBrokerEndpoint(runtimeDir) {
    return path.join(runtimeDir, "blob-broker.sock");
}
/** Maximum number of fetch-attribution events retained by a blob store. */
export const BLOB_FETCH_EVENT_LIMIT = 100;
/** Path prefix of the session-side render callback server. */
export const RENDER_CALLBACK_PATH = "/render/";
/** Header carrying {@link EnsureLazyRequest.callbackToken} on render callbacks. */
export const RENDER_CALLBACK_TOKEN_HEADER = "x-omp-blob-token";
