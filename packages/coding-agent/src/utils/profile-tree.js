/**
 * Shared display-tree machinery for profile summaries (macOS `sample` reports,
 * V8 `.cpuprofile` files). Callers build {@link ProfileNode} trees with a
 * domain-specific metric (on-CPU samples, self microseconds, …); this module
 * merges same-key siblings, flattens direct recursion, collapses pass-through
 * chains, and renders the pruned hot-path tree.
 */
/** Labels longer than this are head-truncated (huge C++ templates, data URLs). */
const MAX_LABEL_CHARS = 160;
/** Merge `b` into `a` (same key), combining values and child lists. */
export function mergeInto(a, b) {
    a.value += b.value;
    a.recursion = Math.max(a.recursion, b.recursion);
    for (const child of b.children) {
        const existing = a.children.find(c => c.key === child.key);
        if (existing)
            mergeInto(existing, child);
        else
            a.children.push(child);
    }
}
/**
 * Flatten direct recursion: children carrying the node's own key are dissolved
 * into it (their children promoted and merged), so a 15-deep recursive spine
 * renders as one annotated node.
 */
export function flattenRecursion(node) {
    while (node.children.some(child => child.key === node.key)) {
        node.recursion++;
        const next = [];
        for (const child of node.children) {
            const promoted = child.key === node.key ? child.children : [child];
            for (const item of promoted) {
                const existing = next.find(c => c.key === item.key);
                if (existing)
                    mergeInto(existing, item);
                else
                    next.push(item);
            }
        }
        node.children = next;
    }
}
/** `n` as a percentage of `total`, one decimal (`"12.3%"`); `"0%"` when total is empty. */
export function formatPct(n, total) {
    if (total <= 0)
        return "0%";
    return `${((100 * n) / total).toFixed(1)}%`;
}
function decoratedLabel(node) {
    let label = node.label.length > MAX_LABEL_CHARS ? `${node.label.slice(0, MAX_LABEL_CHARS - 1)}…` : node.label;
    if (node.recursion > 0)
        label += ` [recursive ×${node.recursion + 1}]`;
    return label;
}
/**
 * Render one hot-path subtree: pass-through chains (single kept child, no own
 * contribution above `minValue`) collapse into a single `a › b › c` line, and
 * children below `minValue` are pruned.
 */
export function renderProfileNode(node, indent, ctx) {
    const chain = [node];
    let cur = node;
    for (;;) {
        flattenRecursion(cur);
        if (cur.recursion > 0)
            break;
        const kept = cur.children.filter(child => child.value >= ctx.minValue);
        if (kept.length !== 1 || cur.value - kept[0].value >= ctx.minValue)
            break;
        cur = kept[0];
        chain.push(cur);
    }
    flattenRecursion(cur);
    const labels = chain.map(decoratedLabel);
    const path = labels.length <= 4
        ? labels.join(" › ")
        : `${labels[0]} › ⋯${labels.length - 2} frames⋯ › ${labels[labels.length - 1]}`;
    const value = ctx.formatValue(chain[0].value).padStart(ctx.valueWidth);
    const pct = formatPct(chain[0].value, ctx.total).padStart(6);
    ctx.out.push(`${value} ${pct}  ${"  ".repeat(indent)}${path}`);
    const kept = cur.children.filter(child => child.value >= ctx.minValue).sort((a, b) => b.value - a.value);
    for (const child of kept)
        renderProfileNode(child, indent + 1, ctx);
}
