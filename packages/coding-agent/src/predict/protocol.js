/**
 * Cross-process contract for the machine-global text-prediction daemon.
 *
 * One daemon per agent directory runs under the `text-predict` global daemon
 * broker (`omp ps --global text-predict`) and serves ghost-text word
 * completion to every omp process over newline-delimited JSON on a native IPC
 * endpoint (`ipcEndpoint`). Each request carries a numeric `id` echoed by its
 * response; responses may arrive out of order.
 */
import * as path from "node:path";
import { ipcEndpoint } from "@rva/natives";
export { TEXT_PREDICT_WORKER_ARG } from "../cli/worker-selectors";
/** Global broker scope owning the daemon. */
export const TEXT_PREDICT_BROKER_SCOPE = "text-predict";
/** Environment key carrying the endpoint the daemon listens on. */
export const TEXT_PREDICT_SOCKET_ENV = "OMP_TEXT_PREDICT_SOCKET";
/** Environment key carrying the agent directory whose history and state the daemon serves. */
export const TEXT_PREDICT_AGENT_DIR_ENV = "OMP_TEXT_PREDICT_AGENT_DIR";
/** Broker readiness regex matched against {@link textPredictReadyBanner}. */
export const TEXT_PREDICT_READY_PATTERN = String.raw `omp text-predict listening on \S+`;
/** Banner printed on stdout once the daemon accepts connections. */
export function textPredictReadyBanner(endpoint) {
    return `omp text-predict listening on ${endpoint}`;
}
/**
 * Daemon identity for one agent directory: the broker daemon name and its
 * endpoint inside the broker runtime dir. Different agent directories (profiles,
 * tests) get separate daemons because history and learned state are per agent dir.
 */
export function textPredictDaemon(runtimeDir, agentDir) {
    const key = Bun.hash.wyhash(path.resolve(agentDir)).toString(16).padStart(16, "0").slice(0, 12);
    return { name: `omp.text-predict.${key}`, endpoint: ipcEndpoint(runtimeDir, `text-predict-${key}`) };
}
