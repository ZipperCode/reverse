import { tryParseJson } from "@rva/utils";
import { buildResult, htmlToBasicMarkdown, loadPage } from "./types";
export const handleRawg = async (url, timeout, signal) => {
    try {
        const parsed = new URL(url);
        if (!isRawgHostname(parsed.hostname))
            return null;
        const slug = extractGameSlug(parsed.pathname);
        if (!slug)
            return null;
        const fetchedAt = new Date().toISOString();
        const apiUrl = `https://api.rawg.io/api/games/${encodeURIComponent(slug)}`;
        const result = await loadPage(apiUrl, { timeout, signal, headers: { Accept: "application/json" } });
        if (!result.ok)
            return null;
        const game = tryParseJson(result.content);
        if (!game)
            return null;
        if (requiresApiKey(game))
            return null;
        const title = game.name?.trim() || slug;
        let md = `# ${title}\n\n`;
        if (game.released)
            md += `**Released:** ${game.released}\n`;
        if (typeof game.rating === "number" && !Number.isNaN(game.rating)) {
            md += `**Rating:** ${game.rating.toFixed(2)} / 5\n`;
        }
        const platforms = collectNames(game.platforms?.map(entry => entry.platform?.name));
        if (platforms.length)
            md += `**Platforms:** ${platforms.join(", ")}\n`;
        const genres = collectNames(game.genres?.map(entry => entry.name));
        if (genres.length)
            md += `**Genres:** ${genres.join(", ")}\n`;
        md += `**RAWG:** https://rawg.io/games/${encodeURIComponent(slug)}\n`;
        md += "\n";
        const description = await extractDescription(game);
        if (description) {
            md += `## Description\n\n${description}\n`;
        }
        return buildResult(md, { url, method: "rawg", fetchedAt, notes: ["Fetched via RAWG API"] });
    }
    catch { }
    return null;
};
function isRawgHostname(hostname) {
    return hostname === "rawg.io" || hostname === "www.rawg.io";
}
function extractGameSlug(pathname) {
    const match = pathname.match(/^\/games\/([^/?#]+)/);
    if (!match)
        return null;
    const slug = decodeURIComponent(match[1]);
    return slug ? slug.trim() : null;
}
function requiresApiKey(game) {
    const detail = `${game.detail ?? ""} ${game.error ?? ""}`.toLowerCase();
    return detail.includes("api key") || detail.includes("key is required") || detail.includes("apikey");
}
async function extractDescription(game) {
    if (game.description_raw)
        return game.description_raw.trim();
    if (!game.description)
        return null;
    const markdown = (await htmlToBasicMarkdown(game.description)).trim();
    return markdown || null;
}
function collectNames(values) {
    if (!values?.length)
        return [];
    const names = new Set();
    for (const value of values) {
        const trimmed = value?.trim();
        if (trimmed)
            names.add(trimmed);
    }
    return Array.from(names);
}
