/**
 * HTTP + WebSocket server for the browser relay.
 *
 * Impersonates Chrome's CDP discovery endpoint so the omp browser tool (and
 * any puppeteer client) can connect with a plain `browserURL`:
 * - `GET /json/version` → 200 with `webSocketDebuggerUrl` once the extension
 *   is connected, 503 with a {@link RelayUnavailableInfo} body before that
 *   (`waitForRelayExtension` decides from it whether polling is worthwhile).
 * - `GET /json` / `/json/list` → attachable page targets (debugging aid).
 * - `WS /cdp` → downstream CDP clients (puppeteer).
 * - `WS /ext` → the Chrome extension (token-gated when configured).
 *
 * Binds loopback only: anything that can reach this port can drive the
 * user's logged-in browser.
 */
import { VERSION } from "@rva/utils/dirs";
import { RelayBridge } from "./bridge";
const WS_KEEPALIVE_MS = 30000;
/** Screenshots travel base64-encoded through both websocket legs. */
const MAX_PAYLOAD_BYTES = 256 * 1024 * 1024;
/** Default appearance of the omp tab group. */
const DEFAULT_GROUP = { title: "rva", color: "cyan" };
/** True when `raw` can serve as the authority of a `ws://` URL: no whitespace,
 *  slashes, userinfo, fragments, or control characters, and URL-parseable. */
function isWsAuthority(raw) {
    if (/[\s/\\@#?]|[\x00-\x1f]/.test(raw))
        return false;
    try {
        return new URL(`ws://${raw}`).host.length > 0;
    }
    catch {
        return false;
    }
}
/** Start the relay server on 127.0.0.1. Throws if the port is taken. */
export function startRelayServer(opts) {
    const log = opts.log ?? (() => { });
    const group = opts.group === false ? null : opts.group === true || opts.group === undefined ? DEFAULT_GROUP : opts.group;
    const bridge = new RelayBridge({ log, group });
    const sockets = new Set();
    const startedAt = Date.now();
    const server = Bun.serve({
        hostname: "127.0.0.1",
        port: opts.port,
        fetch(req, srv) {
            const fallback = `127.0.0.1:${srv.port}`;
            const rawHost = req.headers.get("host")?.trim();
            const host = rawHost && isWsAuthority(rawHost) ? rawHost : fallback;
            const requestUrl = rawHost && rawHost !== host && req.url.startsWith(`http://${rawHost}`)
                ? req.url.slice(`http://${rawHost}`.length)
                : req.url;
            const url = new URL(requestUrl, `http://${fallback}`);
            const path = url.pathname.replace(/\/+$/, "") || "/";
            if (path === "/cdp") {
                // Browsers set Origin on websocket upgrades; native CDP clients
                // don't. Reject any Origin so a web page can't drive the relay.
                if (req.headers.get("origin"))
                    return new Response("Forbidden", { status: 403 });
                const data = { role: "cdp" };
                if (srv.upgrade(req, { data }))
                    return undefined;
                return new Response("websocket upgrade required", { status: 426 });
            }
            if (path === "/ext") {
                const origin = req.headers.get("origin");
                if (origin && !origin.startsWith("chrome-extension://")) {
                    return new Response("Forbidden", { status: 403 });
                }
                if (opts.token && url.searchParams.get("token") !== opts.token) {
                    return new Response("Unauthorized", { status: 401 });
                }
                const data = { role: "ext" };
                if (srv.upgrade(req, { data }))
                    return undefined;
                return new Response("websocket upgrade required", { status: 426 });
            }
            if (req.method !== "GET")
                return new Response("Method not allowed", { status: 405 });
            if (path === "/json/version") {
                if (!bridge.ready) {
                    const disconnectedMs = bridge.extensionGoneForMs;
                    const info = {
                        rvaRelayVersion: VERSION,
                        error: "relay extension is not connected",
                        extensionSeen: bridge.extensionSeen,
                        uptimeMs: Date.now() - startedAt,
                        rvaRelayCdpClients: bridge.cdpClientCount,
                        ...(disconnectedMs === null ? {} : { disconnectedMs }),
                    };
                    return Response.json(info, { status: 503 });
                }
                return Response.json(bridge.versionInfo(`ws://${host}/cdp`));
            }
            if (path === "/json" || path === "/json/list") {
                return Response.json(bridge.listTargets());
            }
            return new Response("Not found", { status: 404 });
        },
        websocket: {
            maxPayloadLength: MAX_PAYLOAD_BYTES,
            // Disabled: Bun caps idleTimeout at 255s, and the keepalive pings
            // below already detect dead peers via the websocket close path.
            idleTimeout: 0,
            open(ws) {
                sockets.add(ws);
                if (ws.data.role === "ext") {
                    bridge.extConnected(ws);
                }
                else {
                    ws.data.connId = bridge.cdpConnected(ws);
                }
            },
            message(ws, message) {
                const text = typeof message === "string" ? message : new TextDecoder().decode(message);
                if (ws.data.role === "ext") {
                    bridge.extMessage(ws, text);
                }
                else if (ws.data.connId !== undefined) {
                    bridge.cdpMessage(ws.data.connId, text);
                }
            },
            close(ws) {
                sockets.delete(ws);
                if (ws.data.role === "ext") {
                    bridge.extClosed(ws);
                }
                else if (ws.data.connId !== undefined) {
                    bridge.cdpClosed(ws.data.connId);
                }
            },
        },
    });
    // Puppeteer connections go silent while the agent is idle; protocol-level
    // pings count as activity and keep them under the idle timeout.
    const keepalive = setInterval(() => {
        for (const ws of sockets)
            ws.ping();
    }, WS_KEEPALIVE_MS);
    keepalive.unref();
    const port = server.port ?? opts.port;
    log("relay listening", { port });
    return {
        bridge,
        port,
        stop() {
            clearInterval(keepalive);
            server.stop(true);
        },
    };
}
