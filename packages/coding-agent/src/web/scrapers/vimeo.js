import { tryParseJson } from "@rva/utils";
import { buildResult, formatMediaDuration, loadPage } from "./types";
/**
 * Extract video ID from various Vimeo URL formats
 */
function extractVideoId(url) {
    try {
        const parsed = new URL(url);
        // player.vimeo.com/video/{id}
        if (parsed.hostname === "player.vimeo.com") {
            const match = parsed.pathname.match(/^\/video\/(\d+)/);
            return match?.[1] ?? null;
        }
        // vimeo.com/{id} or vimeo.com/{user}/{id}
        if (parsed.hostname === "vimeo.com" || parsed.hostname === "www.vimeo.com") {
            const parts = parsed.pathname.split("/").filter(Boolean);
            // Last part should be the video ID
            const lastPart = parts[parts.length - 1];
            if (lastPart && /^\d+$/.test(lastPart)) {
                return lastPart;
            }
        }
        return null;
    }
    catch {
        return null;
    }
}
/**
 * Handle Vimeo URLs via oEmbed API
 */
export const handleVimeo = async (url, timeout, signal) => {
    try {
        const parsed = new URL(url);
        if (!parsed.hostname.includes("vimeo.com"))
            return null;
        const videoId = extractVideoId(url);
        if (!videoId)
            return null;
        const fetchedAt = new Date().toISOString();
        // Use canonical URL for oEmbed (handles staffpicks and other URL formats)
        const canonicalUrl = `https://vimeo.com/${videoId}`;
        const oembedUrl = `https://vimeo.com/api/oembed.json?url=${encodeURIComponent(canonicalUrl)}`;
        const oembedResult = await loadPage(oembedUrl, { timeout, signal });
        if (!oembedResult.ok)
            return null;
        const oembed = tryParseJson(oembedResult.content);
        if (!oembed)
            return null;
        let md = `# ${oembed.title}\n\n`;
        md += `**Author:** [${oembed.author_name}](${oembed.author_url})\n`;
        md += `**Duration:** ${formatMediaDuration(oembed.duration)}\n`;
        if (oembed.upload_date) {
            md += `**Uploaded:** ${oembed.upload_date}\n`;
        }
        md += `**Video ID:** ${videoId}\n\n`;
        if (oembed.description) {
            md += `---\n\n## Description\n\n${oembed.description}\n\n`;
        }
        md += `---\n\n**Thumbnail:** ${oembed.thumbnail_url}\n`;
        // Try to get additional details from video config
        try {
            const configUrl = `https://player.vimeo.com/video/${videoId}/config`;
            const configResult = await loadPage(configUrl, { timeout: Math.min(timeout, 5), signal });
            if (configResult.ok) {
                const config = tryParseJson(configResult.content);
                // Add video quality info if available
                const progressive = config?.request?.files?.progressive;
                if (progressive && progressive.length > 0) {
                    md += `\n**Available Qualities:**\n`;
                    for (const quality of progressive.slice(0, 5)) {
                        md += `- ${quality.quality}: ${quality.width}x${quality.height} @ ${quality.fps}fps\n`;
                    }
                }
            }
        }
        catch {
            // Config fetch is optional - continue without it
        }
        return buildResult(md, { url, method: "vimeo", fetchedAt, notes: ["Fetched via Vimeo oEmbed API"] });
    }
    catch {
        return null;
    }
};
