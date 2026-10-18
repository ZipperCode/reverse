/**
 * Editor-anchored, right-aligned progress rows above the working line: judge
 * batches (`judge_batch`) and automatic downloads/installs (model weights,
 * tool binaries, browsers, side runtimes). Both render through
 * {@link renderHudProgressRow} so they read as one HUD.
 */
import { renderProgressBar, visibleWidth } from "@rva/tui";
import { col, node, span, text } from "@rva/tui/native/describe";
import { sanitizeStatusText } from "@rva/tui/chrome/shared";
import { formatCost } from "@rva/tui/overlays/agent-hub-renderer";
import { truncateToWidth } from "@rva/tui/render/render-utils";
import { theme } from "@rva/tui/theme";
import { formatBytes } from "@rva/utils";
const PROGRESS_BAR_WIDTH = 18;
const MIN_PROGRESS_BAR_WIDTH = 4;
/**
 * One right-aligned row: `label ━━━─── tail`. When narrow, drops the label,
 * then the bar, then falls back to `fallback` alone.
 */
function renderHudProgressRow(width, row) {
    let tail = row.tail;
    let remaining = width - visibleWidth(tail);
    if (row.bar && remaining > 1) {
        const barWidth = Math.min(PROGRESS_BAR_WIDTH, remaining - 1);
        const bar = renderProgressBar(row.bar.value, barWidth, {
            min: 0,
            max: Math.max(1, row.bar.max),
            minWidth: barWidth,
            maxWidth: barWidth,
            style: {
                filled: "━",
                empty: "─",
                styleFilled: text => theme.fg("accent", text),
                styleEmpty: text => theme.fg("dim", text),
            },
        });
        tail = `${bar} ${tail}`;
        remaining = width - visibleWidth(tail);
    }
    if (remaining > 1) {
        const label = truncateToWidth(sanitizeStatusText(row.label), remaining - 1, "");
        if (label)
            tail = `${theme.fg("dim", label)} ${tail}`;
    }
    if (visibleWidth(tail) > width)
        tail = truncateToWidth(row.fallback, width, "");
    return `${" ".repeat(Math.max(0, width - visibleWidth(tail)))}${tail}`;
}
function rowWidth(width) {
    return Number.isFinite(width) ? Math.max(0, Math.trunc(width)) : 0;
}
/**
 * Native HUD row, right-docked like the ANSI row: dim label, an optional
 * terminal-drawn bar, then the tail. The terminal drops and truncates.
 */
function describeHudRow(key, label, tail, bar) {
    const children = [
        text([span(sanitizeStatusText(label), "dim")], { wrap: "none", truncate: "end", shrink: 1 }),
    ];
    if (bar !== undefined)
        children.push(node("progress", { value: Math.min(1, Math.max(0, bar)), max: { w: "18ch" } }));
    children.push(text(tail, { wrap: "none" }));
    return node("row", { justify: "end", gap: "sm", align: "center", role: "omp.hud.progress" }, children, key);
}
/** Progress rows for concurrent judge batches. */
export class JudgmentBatchProgressHud {
    #batches = new Map();
    #native;
    update(progress) {
        this.#batches.set(progress.id, progress);
        this.#native = undefined;
    }
    delete(id) {
        this.#batches.delete(id);
        this.#native = undefined;
    }
    clear() {
        this.#batches.clear();
        this.#native = undefined;
    }
    describe() {
        this.#native ??= col(Array.from(this.#batches.values(), progress => {
            const tail = [span(`${progress.done}/${progress.total}`, "strong")];
            // Zero cost means unpriced, not free — omit rather than show $0.
            if (progress.cost > 0)
                tail.push(span(` · ${formatCost(progress.cost)}`, "dim"));
            if (progress.failed > 0)
                tail.push(span(` · ${progress.failed} failed`, "warning"));
            return describeHudRow(progress.id, progress.intent, tail, progress.done / Math.max(1, progress.total));
        }), { role: "omp.hud.judge" });
        return this.#native;
    }
    render(width) {
        const available = rowWidth(width);
        if (available === 0)
            return [];
        const rows = [];
        for (const progress of this.#batches.values())
            rows.push(this.#renderRow(progress, available));
        return rows;
    }
    #renderRow(progress, width) {
        const countText = `${progress.done}/${progress.total}`;
        // Zero cost means unpriced (local/native without catalog pricing), not free — omit rather than show $0.
        const costText = progress.cost > 0 ? ` · ${formatCost(progress.cost)}` : "";
        const failedText = progress.failed > 0 ? ` · ${progress.failed} failed` : "";
        const compactFailedText = progress.failed > 0 ? ` +${progress.failed}!` : "";
        let failure = failedText;
        if (failure &&
            visibleWidth(countText) + visibleWidth(costText) + visibleWidth(failure) + MIN_PROGRESS_BAR_WIDTH + 1 >
                width &&
            visibleWidth(countText) + visibleWidth(costText) + visibleWidth(compactFailedText) <= width) {
            failure = compactFailedText;
        }
        const styledCount = theme.bold(theme.fg("text", countText));
        const styledCost = costText ? theme.fg("dim", costText) : "";
        const styledFailure = failure ? theme.fg("warning", failure) : "";
        return renderHudProgressRow(width, {
            label: progress.intent,
            tail: `${styledCount}${styledCost}${styledFailure}`,
            fallback: theme.bold(theme.fg("text", countText)),
            bar: { value: progress.done, max: progress.total },
        });
    }
}
/** Downloads finishing faster than this never appear (warm caches, tiny files). */
const DOWNLOAD_REVEAL_MS = 150;
/** A finished download's `ready` row lingers this long. */
const DOWNLOAD_DONE_RETAIN_MS = 1500;
/** A failed download's row lingers this long so the reason can be read. */
const DOWNLOAD_FAILED_RETAIN_MS = 10000;
/**
 * Progress rows for automatic downloads and installs (see `downloads/activity`):
 * a byte bar when the size is known, the current step otherwise, then a brief
 * `ready` or a lingering failure reason. Owns its reveal/retain timers.
 */
export class DownloadActivityHud {
    #rows = new Map();
    #requestRender;
    /** Last description and the revealed-row signature it was built for. */
    #native;
    #revision = 0;
    constructor(requestRender) {
        this.#requestRender = requestRender;
    }
    update(activity) {
        const now = Date.now();
        this.#revision++;
        let row = this.#rows.get(activity.id);
        if (!row) {
            row = { activity, startedAt: now };
            this.#rows.set(activity.id, row);
            row.timer = setTimeout(() => this.#requestRender(), DOWNLOAD_REVEAL_MS);
            row.timer.unref?.();
        }
        row.activity = activity;
        if (activity.state !== "running") {
            clearTimeout(row.timer);
            const shown = now - row.startedAt >= DOWNLOAD_REVEAL_MS;
            if (activity.state === "done" && !shown) {
                this.#rows.delete(activity.id);
                return;
            }
            const id = activity.id;
            row.timer = setTimeout(() => {
                this.#rows.delete(id);
                this.#revision++;
                this.#requestRender();
            }, activity.state === "failed" ? DOWNLOAD_FAILED_RETAIN_MS : DOWNLOAD_DONE_RETAIN_MS);
            row.timer.unref?.();
        }
        this.#requestRender();
    }
    dispose() {
        for (const row of this.#rows.values())
            clearTimeout(row.timer);
        this.#rows.clear();
        this.#revision++;
    }
    describe() {
        const now = Date.now();
        const shown = [...this.#rows.values()].filter(row => row.activity.state !== "running" || now - row.startedAt >= DOWNLOAD_REVEAL_MS);
        const signature = shown.map(row => row.activity.id).join(",");
        if (this.#native?.revision === this.#revision && this.#native.shown === signature)
            return this.#native.node;
        const nodeOut = col(shown.map(row => this.#describeRow(row.activity)), { role: "omp.hud.downloads" });
        this.#native = { node: nodeOut, revision: this.#revision, shown: signature };
        return nodeOut;
    }
    #describeRow(activity) {
        const key = `${activity.id}`;
        if (activity.state === "failed") {
            const reason = `failed: ${sanitizeStatusText(activity.error ?? "unknown error")}`;
            return describeHudRow(key, activity.label, [span(reason, "warning")]);
        }
        if (activity.state === "done")
            return describeHudRow(key, activity.label, [span("ready", "success")]);
        const { loaded, total } = activity;
        if (total !== undefined && total > 0) {
            const received = loaded ?? 0;
            const label = activity.detail ? `${activity.label} · ${activity.detail}` : activity.label;
            return describeHudRow(key, label, [span(`${formatBytes(received)} / ${formatBytes(total)}`, "strong")], received / total);
        }
        const step = loaded ? formatBytes(loaded) : (activity.detail ?? "downloading…");
        return describeHudRow(key, activity.label, [span(step)]);
    }
    render(width) {
        const available = rowWidth(width);
        if (available === 0)
            return [];
        const now = Date.now();
        const rows = [];
        for (const row of this.#rows.values()) {
            if (row.activity.state === "running" && now - row.startedAt < DOWNLOAD_REVEAL_MS)
                continue;
            rows.push(this.#renderRow(row.activity, available));
        }
        return rows;
    }
    #renderRow(activity, width) {
        if (activity.state === "failed") {
            const reason = `failed: ${sanitizeStatusText(activity.error ?? "unknown error")}`;
            return renderHudProgressRow(width, {
                label: activity.label,
                tail: theme.fg("warning", truncateToWidth(reason, Math.max(8, Math.floor(width * 0.6)))),
                fallback: theme.fg("warning", reason),
            });
        }
        if (activity.state === "done") {
            return renderHudProgressRow(width, {
                label: activity.label,
                tail: theme.fg("success", "ready"),
                fallback: theme.fg("success", `${activity.label} ready`),
            });
        }
        const { loaded, total } = activity;
        if (total !== undefined && total > 0) {
            const received = loaded ?? 0;
            const percent = `${Math.floor((received / total) * 100)}%`;
            return renderHudProgressRow(width, {
                label: activity.detail ? `${activity.label} · ${activity.detail}` : activity.label,
                tail: theme.bold(theme.fg("text", `${formatBytes(received)} / ${formatBytes(total)}`)),
                fallback: theme.bold(theme.fg("text", percent)),
                bar: { value: received, max: total },
            });
        }
        // Size unknown: bytes so far, or the current step (`installing`, `extracting`).
        const step = loaded ? formatBytes(loaded) : (activity.detail ?? "downloading…");
        return renderHudProgressRow(width, {
            label: activity.label,
            tail: theme.fg("text", step),
            fallback: theme.fg("text", `${activity.label} ${step}`),
        });
    }
}
