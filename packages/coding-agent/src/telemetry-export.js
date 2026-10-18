import { logger } from "@rva/utils";
let otlp;
let initPromise;
/**
 * Whether {@link initTelemetryExport} registered any real OTLP signal provider.
 * The CLI uses this to decide whether to switch on the agent loop's telemetry
 * hooks; metrics and structured logs need those callbacks even when traces are
 * disabled.
 */
export function isTelemetryExportEnabled() {
    return otlp?.isTelemetryExportEnabled() ?? false;
}
/**
 * Merge OTLP metrics/log hooks into an existing agent telemetry config.
 *
 * The caller still owns content-capture policy and custom attributes, and its
 * own `costEstimator` wins. Without one, `modelPricingResolver` makes chat
 * telemetry report each request's provider-computed cost. Beyond that, this
 * only appends host-level metrics/log forwarding for the providers registered
 * by {@link initTelemetryExport}; a passthrough when export is disabled.
 */
export function createTelemetryExportConfig(config, modelPricingResolver) {
    return otlp ? otlp.createTelemetryExportConfig(config, modelPricingResolver) : config;
}
/**
 * Register global trace/log/meter providers when enabled and OTLP endpoints are
 * configured through env. Idempotent, and a no-op when disabled, no signal has
 * an endpoint, or the OTEL kill-switch is engaged.
 *
 * @param exportEnabled `telemetry.otlpExportEnabled`; required so every caller
 *   decides whether the user's opt-out applies.
 */
export async function initTelemetryExport(exportEnabled) {
    if (initPromise)
        return initPromise;
    if (!exportEnabled || process.env.OTEL_SDK_DISABLED?.trim().toLowerCase() === "true")
        return;
    const signalConfig = resolveSignalConfig();
    if (!signalConfig.trace && !signalConfig.log && !signalConfig.metric)
        return;
    initPromise = (async () => {
        // Branch-only: the OTel SDK + OTLP exporter graph loads only when an endpoint is configured.
        const impl = await import("./telemetry-export-otlp");
        await impl.registerProviders(signalConfig);
        otlp = impl;
    })();
    return initPromise;
}
/**
 * Flush buffered spans, log records, and metrics. No-op when export is disabled.
 * Hosts embedding the agent can call this at natural boundaries (e.g. the end
 * of a turn) so telemetry surfaces promptly rather than on the batch interval.
 */
export async function flushTelemetryExport() {
    if (otlp)
        await otlp.flushTelemetryExport();
}
function resolveSignalConfig() {
    return {
        trace: signalEnabled("trace", process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT ?? process.env.OTEL_EXPORTER_OTLP_ENDPOINT, process.env.OTEL_TRACES_EXPORTER, process.env.OTEL_EXPORTER_OTLP_TRACES_PROTOCOL ?? process.env.OTEL_EXPORTER_OTLP_PROTOCOL),
        log: signalEnabled("log", process.env.OTEL_EXPORTER_OTLP_LOGS_ENDPOINT ?? process.env.OTEL_EXPORTER_OTLP_ENDPOINT, process.env.OTEL_LOGS_EXPORTER, process.env.OTEL_EXPORTER_OTLP_LOGS_PROTOCOL ?? process.env.OTEL_EXPORTER_OTLP_PROTOCOL),
        metric: signalEnabled("metric", process.env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT ?? process.env.OTEL_EXPORTER_OTLP_ENDPOINT, process.env.OTEL_METRICS_EXPORTER, process.env.OTEL_EXPORTER_OTLP_METRICS_PROTOCOL ?? process.env.OTEL_EXPORTER_OTLP_PROTOCOL),
    };
}
function signalEnabled(signal, endpoint, exporterSelection, protocolSelection) {
    if (exporterSelection) {
        let hasSelection = false;
        let hasOtlp = false;
        for (const entry of exporterSelection.split(",")) {
            const selection = entry.trim().toLowerCase();
            if (!selection)
                continue;
            hasSelection = true;
            if (selection === "none")
                return false;
            if (selection === "otlp")
                hasOtlp = true;
        }
        if (hasSelection && !hasOtlp)
            return false;
    }
    if (!endpoint)
        return false;
    const protocol = protocolSelection?.trim().toLowerCase();
    if (protocol && protocol !== "http/protobuf") {
        logger.warn(`OTEL ${signal} export disabled: OTEL_EXPORTER_OTLP_PROTOCOL=${protocol} is unsupported`, {
            supported: "http/protobuf",
        });
        return false;
    }
    return true;
}
