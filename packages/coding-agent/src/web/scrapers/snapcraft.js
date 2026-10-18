import { tryParseJson } from "@rva/utils";
import { buildResult, formatNumber, loadPage } from "./types";
function formatPublisher(publisher) {
    if (!publisher)
        return null;
    const displayName = publisher["display-name"] ?? publisher.username ?? publisher.id;
    if (!displayName)
        return null;
    if (publisher.username && displayName !== publisher.username) {
        return `${displayName} (@${publisher.username})`;
    }
    return displayName;
}
function formatChannelName(channel) {
    if (!channel)
        return null;
    if (channel.name?.includes("/"))
        return channel.name;
    if (channel.track && channel.risk) {
        const branch = channel.branch ? `/${channel.branch}` : "";
        return `${channel.track}/${channel.risk}${branch}`;
    }
    return channel.name ?? null;
}
function pickVersionFromChannels(entries) {
    const stable = entries.find(entry => entry.channel?.risk === "stable" && entry.version);
    if (stable?.version)
        return stable.version;
    const first = entries.find(entry => entry.version);
    return first?.version;
}
function extractDownloads(snapInfo, data) {
    const candidates = [snapInfo.downloads, snapInfo.download, data.downloads, data.download];
    for (const value of candidates) {
        if (typeof value === "number" && Number.isFinite(value))
            return value;
    }
    return null;
}
export const handleSnapcraft = async (url, timeout, signal) => {
    try {
        const parsed = new URL(url);
        if (parsed.hostname !== "snapcraft.io" && parsed.hostname !== "www.snapcraft.io")
            return null;
        const installMatch = parsed.pathname.match(/^\/install\/([^/]+)\/?$/);
        const directMatch = parsed.pathname.match(/^\/([^/]+)\/?$/);
        if (!installMatch && !directMatch)
            return null;
        const snapName = decodeURIComponent((installMatch ?? directMatch)[1]);
        const fetchedAt = new Date().toISOString();
        const apiUrl = `https://api.snapcraft.io/v2/snaps/info/${encodeURIComponent(snapName)}`;
        const result = await loadPage(apiUrl, {
            timeout,
            signal,
            headers: {
                Accept: "application/json",
                "Snap-Device-Series": "16",
            },
        });
        if (!result.ok)
            return null;
        const data = tryParseJson(result.content);
        if (!data)
            return null;
        const snapInfo = data.snap ?? data;
        const name = snapInfo.title ?? snapInfo.name ?? data.name ?? snapName;
        const summary = snapInfo.summary ?? data.summary;
        const description = snapInfo.description ?? data.description;
        const publisher = formatPublisher(snapInfo.publisher ?? data.publisher);
        const confinement = snapInfo.confinement ?? data.confinement;
        const base = snapInfo.base ?? data.base;
        const channelMap = data["channel-map"] ?? [];
        let version = snapInfo.version ?? data.version;
        if (!version && channelMap.length > 0) {
            version = pickVersionFromChannels(channelMap);
        }
        const downloads = extractDownloads(snapInfo, data);
        const channels = new Map();
        for (const entry of channelMap) {
            const channelName = formatChannelName(entry.channel);
            if (!channelName)
                continue;
            const existing = channels.get(channelName) ?? { architectures: new Set() };
            if (!existing.version && entry.version)
                existing.version = entry.version;
            if (entry.channel?.architecture)
                existing.architectures.add(entry.channel.architecture);
            channels.set(channelName, existing);
        }
        let md = `# ${name}\n\n`;
        if (summary)
            md += `${summary}\n\n`;
        md += `**Version:** ${version ?? "unknown"}`;
        if (confinement)
            md += ` · **Confinement:** ${confinement}`;
        if (base)
            md += ` · **Base:** ${base}`;
        md += "\n";
        if (publisher)
            md += `**Publisher:** ${publisher}\n`;
        if (downloads !== null)
            md += `**Downloads:** ${formatNumber(downloads)}\n`;
        md += "\n";
        if (channels.size > 0) {
            md += "## Channels\n\n";
            const sortedChannels = Array.from(channels.entries()).sort((a, b) => a[0].localeCompare(b[0]));
            for (const [channelName, info] of sortedChannels) {
                const arches = Array.from(info.architectures).sort();
                const versionSuffix = info.version ? `: ${info.version}` : "";
                const archSuffix = arches.length > 0 ? ` (${arches.join(", ")})` : "";
                md += `- ${channelName}${versionSuffix}${archSuffix}\n`;
            }
            md += "\n";
        }
        const descriptionText = description ?? summary;
        if (descriptionText) {
            md += `## Description\n\n${descriptionText}\n`;
        }
        return buildResult(md, { url, method: "snapcraft", fetchedAt, notes: ["Fetched via Snapcraft API"] });
    }
    catch { }
    return null;
};
