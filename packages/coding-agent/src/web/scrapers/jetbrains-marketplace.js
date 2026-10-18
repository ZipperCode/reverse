import { tryParseJson } from "@rva/utils";
import { buildResult, formatNumber, htmlToBasicMarkdown, loadPage } from "./types";
const MARKETPLACE_HOSTS = new Set(["plugins.jetbrains.com"]);
function extractRating(plugin) {
    const rating = plugin.rating;
    if (typeof rating === "number" && Number.isFinite(rating)) {
        return { value: rating, votes: plugin.ratingCount ?? null };
    }
    if (rating && typeof rating === "object") {
        const value = rating.rating ?? rating.value ?? rating.score ?? null;
        const votes = rating.votes ?? rating.totalVotes ?? rating.count ?? plugin.ratingCount ?? null;
        return { value: typeof value === "number" ? value : null, votes: typeof votes === "number" ? votes : null };
    }
    return { value: null, votes: plugin.ratingCount ?? null };
}
function formatBuildCompatibility(update) {
    if (update.sinceUntil)
        return update.sinceUntil;
    if (update.since && update.until)
        return `${update.since} - ${update.until}`;
    if (update.since)
        return `${update.since}+`;
    return null;
}
export const handleJetBrainsMarketplace = async (url, timeout, signal) => {
    try {
        const parsed = new URL(url);
        if (!MARKETPLACE_HOSTS.has(parsed.hostname))
            return null;
        const match = parsed.pathname.match(/^\/plugin\/(\d+)(?:-[^/]+)?(?:\/|$)/);
        if (!match)
            return null;
        const pluginId = match[1];
        const fetchedAt = new Date().toISOString();
        const pluginUrl = `https://plugins.jetbrains.com/api/plugins/${pluginId}`;
        const updatesUrl = `https://plugins.jetbrains.com/api/plugins/${pluginId}/updates?size=1`;
        const [pluginResult, updatesResult] = await Promise.all([
            loadPage(pluginUrl, { timeout, signal }),
            loadPage(updatesUrl, { timeout, signal }),
        ]);
        if (!pluginResult.ok || !updatesResult.ok)
            return null;
        const plugin = tryParseJson(pluginResult.content);
        const updates = tryParseJson(updatesResult.content);
        if (!plugin || !updates)
            return null;
        const update = updates[0];
        if (!plugin?.name)
            return null;
        const vendorName = plugin.vendor?.name ?? plugin.vendor?.publicName;
        const descriptionSource = plugin.description ?? plugin.preview ?? "";
        const description = descriptionSource ? await htmlToBasicMarkdown(descriptionSource) : "";
        const tags = (plugin.tags ?? []).map(tag => tag.name).filter(Boolean);
        const rating = extractRating(plugin);
        const buildCompatibility = update ? formatBuildCompatibility(update) : null;
        let md = `# ${plugin.name}\n\n`;
        if (description)
            md += `${description}\n\n`;
        md += `**Plugin ID:** ${pluginId}\n`;
        if (vendorName)
            md += `**Vendor:** ${vendorName}\n`;
        if (plugin.downloads !== undefined) {
            md += `**Downloads:** ${formatNumber(plugin.downloads)}\n`;
        }
        if (rating.value !== null) {
            md += `**Rating:** ${rating.value.toFixed(2)}`;
            if (rating.votes !== null)
                md += ` (${formatNumber(rating.votes)} votes)`;
            md += "\n";
        }
        if (tags.length)
            md += `**Tags:** ${tags.join(", ")}\n`;
        if (update) {
            md += "\n## Latest Release\n\n";
            if (update.version)
                md += `**Version:** ${update.version}\n`;
            if (update.channel)
                md += `**Channel:** ${update.channel}\n`;
            if (buildCompatibility)
                md += `**Build Compatibility:** ${buildCompatibility}\n`;
            if (update.downloads !== undefined) {
                md += `**Release Downloads:** ${formatNumber(update.downloads)}\n`;
            }
        }
        const compatibility = update?.compatibleVersions ?? {};
        const compatibilityEntries = Object.entries(compatibility).sort(([a], [b]) => a.localeCompare(b));
        if (compatibilityEntries.length) {
            md += "\n## IDE Compatibility\n\n";
            for (const [product, version] of compatibilityEntries) {
                md += `- ${product}: ${version}\n`;
            }
        }
        return buildResult(md, {
            url,
            method: "jetbrains-marketplace",
            fetchedAt,
            notes: ["Fetched via JetBrains Marketplace API"],
        });
    }
    catch { }
    return null;
};
