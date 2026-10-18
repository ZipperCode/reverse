import { buildResult, formatMediaDuration, loadPage } from "./types";
/**
 * Parse Open Graph meta tags from HTML
 */
function parseOpenGraph(html) {
    const og = {};
    const metaPattern = /<meta\s+(?:property|name)="([^"]+)"\s+content="([^"]*)"[^>]*>/gi;
    let match = null;
    while (true) {
        match = metaPattern.exec(html);
        if (match === null)
            break;
        const [, property, content] = match;
        if (property === "og:title")
            og.title = content;
        else if (property === "og:description")
            og.description = content;
        else if (property === "og:audio")
            og.audio = content;
        else if (property === "og:image")
            og.image = content;
        else if (property === "og:type")
            og.type = content;
        else if (property === "music:duration")
            og.duration = content;
        else if (property === "music:album")
            og.album = content;
        else if (property === "music:musician")
            og.musician = content;
        else if (property === "music:release_date")
            og.releaseDate = content;
        else if (property === "twitter:audio:artist_name")
            og.artist = content;
    }
    return og;
}
/**
 * Determine content type from URL path
 */
function getContentType(url) {
    if (url.includes("/episode/"))
        return "podcast-episode";
    if (url.includes("/show/"))
        return "podcast-show";
    if (url.includes("/track/"))
        return "track";
    if (url.includes("/album/"))
        return "album";
    if (url.includes("/playlist/"))
        return "playlist";
    return null;
}
/**
 * Format duration from seconds string
 */
function formatDuration(seconds) {
    if (!seconds)
        return null;
    const num = parseInt(seconds, 10);
    if (Number.isNaN(num))
        return null;
    return formatMediaDuration(num);
}
/**
 * Format output based on content type and available metadata
 */
function formatOutput(contentType, oEmbed, og, url) {
    const sections = [];
    // Title
    const title = og.title || oEmbed.title || "Unknown";
    sections.push(`# ${title}\n`);
    // Type
    sections.push(`**Type**: ${contentType}\n`);
    // Description
    if (og.description) {
        sections.push(`**Description**: ${og.description}\n`);
    }
    // Content-specific metadata
    if (contentType === "track" || contentType === "podcast-episode") {
        if (og.artist || og.musician) {
            sections.push(`**Artist**: ${og.artist || og.musician}\n`);
        }
        if (og.album) {
            sections.push(`**Album**: ${og.album}\n`);
        }
        if (og.duration) {
            const formatted = formatDuration(og.duration);
            if (formatted) {
                sections.push(`**Duration**: ${formatted}\n`);
            }
        }
    }
    if (contentType === "album" && og.releaseDate) {
        sections.push(`**Release Date**: ${og.releaseDate}\n`);
    }
    // Note about limited information
    sections.push("\n---\n");
    if (contentType === "playlist") {
        sections.push("**Note**: Playlist details (tracks, creator, follower count) require authentication. " +
            "Only basic metadata is available without Spotify API credentials.\n");
    }
    else if (contentType === "album") {
        sections.push("**Note**: Track listing and detailed album information require authentication. " +
            "Only basic metadata is available without Spotify API credentials.\n");
    }
    else if (contentType === "podcast-show") {
        sections.push("**Note**: Episode listing and detailed show information require authentication. " +
            "Only basic metadata is available without Spotify API credentials.\n");
    }
    sections.push(`**URL**: ${url}\n`);
    if (oEmbed.thumbnail_url) {
        sections.push(`**Thumbnail**: ${oEmbed.thumbnail_url}\n`);
    }
    else if (og.image) {
        sections.push(`**Image**: ${og.image}\n`);
    }
    return sections.join("\n");
}
export const handleSpotify = async (url, timeout, signal) => {
    // Check if this is a Spotify URL
    if (!url.includes("open.spotify.com/")) {
        return null;
    }
    const contentType = getContentType(url);
    if (!contentType) {
        return null;
    }
    const notes = [];
    let oEmbedData = {};
    let ogData = {};
    // Fetch oEmbed data
    try {
        const oEmbedUrl = `https://open.spotify.com/oembed?url=${encodeURIComponent(url)}`;
        const response = await loadPage(oEmbedUrl, { timeout, signal });
        if (response.ok) {
            oEmbedData = JSON.parse(response.content);
            notes.push("Retrieved metadata via Spotify oEmbed API");
        }
        else {
            notes.push(`oEmbed API returned status ${response.status || "error"}`);
        }
    }
    catch (err) {
        notes.push(`Failed to fetch oEmbed data: ${err instanceof Error ? err.message : String(err)}`);
    }
    // Fetch page HTML for Open Graph metadata
    try {
        const pageResponse = await loadPage(url, { timeout, signal });
        if (pageResponse.ok) {
            ogData = parseOpenGraph(pageResponse.content);
            notes.push("Parsed Open Graph metadata from page HTML");
        }
        else {
            notes.push(`Page fetch returned status ${pageResponse.status || "error"}`);
        }
    }
    catch (err) {
        notes.push(`Failed to fetch page HTML: ${err instanceof Error ? err.message : String(err)}`);
    }
    // Format output
    const output = formatOutput(contentType, oEmbedData, ogData, url);
    return buildResult(output, { url, method: "spotify", fetchedAt: new Date().toISOString(), notes });
};
