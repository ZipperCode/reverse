import { tryParseJson } from "@rva/utils";
import { buildResult, formatIsoDate, formatNumber, htmlToBasicMarkdown, loadPage } from "./types";
function extractAppId(pathname) {
    const detailsMatch = pathname.match(/^\/apps\/details\/([^/]+)\/?$/);
    if (detailsMatch)
        return decodeURIComponent(detailsMatch[1]);
    const appMatch = pathname.match(/^\/apps\/([^/]+)\/?$/);
    if (appMatch)
        return decodeURIComponent(appMatch[1]);
    return null;
}
function parseNumber(value) {
    if (typeof value === "number" && Number.isFinite(value))
        return value;
    if (typeof value === "string") {
        const cleaned = value.replace(/[^0-9.]/g, "");
        if (!cleaned)
            return null;
        const parsed = Number(cleaned);
        if (!Number.isNaN(parsed))
            return parsed;
    }
    return null;
}
function normalizeStringList(value) {
    if (Array.isArray(value)) {
        return value.filter((item) => typeof item === "string" && item.trim().length > 0);
    }
    if (typeof value === "string") {
        return value
            .split(/[,;\n]+/)
            .map(item => item.trim())
            .filter(Boolean);
    }
    return [];
}
function extractInstalls(app) {
    const direct = parseNumber(app.installs);
    if (direct !== null)
        return direct;
    if (!app.metadata)
        return null;
    for (const [key, value] of Object.entries(app.metadata)) {
        if (!key.toLowerCase().includes("install"))
            continue;
        const parsed = parseNumber(value);
        if (parsed !== null)
            return parsed;
    }
    return null;
}
function extractPermissions(app) {
    const permissions = [];
    permissions.push(...normalizeStringList(app.permissions));
    if (app.metadata) {
        for (const [key, value] of Object.entries(app.metadata)) {
            if (!key.toLowerCase().includes("permission"))
                continue;
            const list = normalizeStringList(value);
            if (list.length) {
                permissions.push(...list);
                continue;
            }
            if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
                permissions.push(`${key}: ${String(value)}`);
            }
        }
    }
    return Array.from(new Set(permissions));
}
function screenshotArea(size) {
    if (!size)
        return 0;
    const width = Number(size.width);
    const height = Number(size.height);
    if (!Number.isFinite(width) || !Number.isFinite(height))
        return 0;
    return width * height;
}
function bestScreenshotUrl(sizes) {
    if (!sizes || sizes.length === 0)
        return null;
    let best = sizes[0];
    let bestArea = screenshotArea(best);
    for (const size of sizes) {
        const area = screenshotArea(size);
        if (area > bestArea) {
            best = size;
            bestArea = area;
        }
    }
    return best.src ?? sizes[0].src ?? null;
}
export const handleFlathub = async (url, timeout, signal) => {
    try {
        const parsed = new URL(url);
        if (parsed.hostname !== "flathub.org" && parsed.hostname !== "www.flathub.org")
            return null;
        const appId = extractAppId(parsed.pathname);
        if (!appId)
            return null;
        const apiUrl = `https://flathub.org/api/v2/appstream/${encodeURIComponent(appId)}`;
        const result = await loadPage(apiUrl, { timeout, signal, headers: { Accept: "application/json" } });
        if (!result.ok)
            return null;
        const app = tryParseJson(result.content);
        if (!app)
            return null;
        const fetchedAt = new Date().toISOString();
        const name = app.name ?? app.id ?? appId;
        let md = `# ${name}\n\n`;
        if (app.summary)
            md += `${app.summary}\n\n`;
        md += "## Metadata\n\n";
        md += `**App ID:** ${app.id ?? appId}\n`;
        if (app.developer_name)
            md += `**Developer:** ${app.developer_name}\n`;
        const installs = extractInstalls(app);
        if (installs !== null)
            md += `**Installs:** ${formatNumber(installs)}\n`;
        if (app.categories?.length) {
            md += "\n## Categories\n\n";
            for (const category of app.categories) {
                md += `- ${category}\n`;
            }
        }
        if (app.description) {
            const description = await htmlToBasicMarkdown(app.description);
            if (description)
                md += `\n## Description\n\n${description}\n`;
        }
        const permissions = extractPermissions(app);
        if (permissions.length) {
            md += "\n## Permissions\n\n";
            for (const permission of permissions) {
                md += `- ${permission}\n`;
            }
        }
        if (app.screenshots?.length) {
            md += "\n## Screenshots\n\n";
            for (const screenshot of app.screenshots.slice(0, 5)) {
                const screenshotUrl = bestScreenshotUrl(screenshot.sizes);
                if (!screenshotUrl)
                    continue;
                const caption = screenshot.caption ? ` - ${screenshot.caption}` : "";
                md += `- ${screenshotUrl}${caption}\n`;
            }
        }
        if (app.releases?.length) {
            md += "\n## Releases\n\n";
            for (const release of app.releases.slice(0, 5)) {
                const version = release.version ?? "unknown";
                let line = `- **${version}**`;
                const date = release.timestamp ? formatIsoDate(Number(release.timestamp) * 1000) : "";
                if (date)
                    line += ` (${date})`;
                if (release.type)
                    line += ` · ${release.type}`;
                if (release.url)
                    line += ` · ${release.url}`;
                md += `${line}\n`;
                if (release.description) {
                    const releaseDesc = (await htmlToBasicMarkdown(release.description)).replace(/\n+/g, " ").trim();
                    if (releaseDesc)
                        md += `  - ${releaseDesc}\n`;
                }
            }
        }
        return buildResult(md, {
            url,
            finalUrl: result.finalUrl,
            method: "flathub-appstream",
            fetchedAt,
            notes: ["Fetched via Flathub Appstream API"],
        });
    }
    catch { }
    return null;
};
