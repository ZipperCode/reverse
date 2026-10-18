/**
 * MusicBrainz URL handler for artists, releases, and recordings
 */
import { tryParseJson, USER_AGENT } from "@rva/utils";
import { buildResult, formatMediaDuration, loadPage } from "./types";
const MUSICBRAINZ_HOSTS = new Set(["musicbrainz.org", "www.musicbrainz.org"]);
const MAX_TRACKS = 50;
function parseEntity(url) {
    if (!MUSICBRAINZ_HOSTS.has(url.hostname))
        return null;
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 2)
        return null;
    const entity = parts[0];
    if (entity !== "artist" && entity !== "release" && entity !== "recording")
        return null;
    const mbid = parts[1];
    if (!/^[0-9a-fA-F-]{36}$/.test(mbid))
        return null;
    return { entity, mbid };
}
async function fetchJson(apiUrl, timeout, signal) {
    const result = await loadPage(apiUrl, {
        timeout,
        signal,
        headers: {
            "User-Agent": USER_AGENT,
            Accept: "application/json",
        },
    });
    if (!result.ok)
        return null;
    return tryParseJson(result.content);
}
function formatLifeSpan(life) {
    if (!life)
        return null;
    const begin = life.begin?.trim();
    const end = life.end?.trim();
    if (begin && end)
        return `${begin} - ${end}`;
    if (begin && !end)
        return `${begin} - ${life.ended ? "ended" : "present"}`;
    if (!begin && end)
        return `? - ${end}`;
    if (life.ended !== undefined)
        return life.ended ? "ended" : "present";
    return null;
}
function formatDurationMs(lengthMs) {
    if (!lengthMs || lengthMs <= 0)
        return null;
    return formatMediaDuration(Math.round(lengthMs / 1000));
}
function formatArtistCredits(credits) {
    if (!credits?.length)
        return null;
    const names = credits
        .map(credit => credit.name || credit.artist?.name)
        .filter((name) => Boolean(name));
    if (!names.length)
        return null;
    return names.join(", ");
}
function formatTrack(track) {
    const title = track.title || track.recording?.title || "Untitled";
    const duration = formatDurationMs(track.length ?? track.recording?.length);
    const number = track.number || (track.position ? String(track.position) : null);
    const prefix = number ? `${number}. ` : "- ";
    let line = `${prefix}${title}`;
    if (duration)
        line += ` (${duration})`;
    return line;
}
function buildMediumLabel(medium, includePosition) {
    const parts = [];
    if (includePosition && medium.position)
        parts.push(`Disc ${medium.position}`);
    if (medium.format)
        parts.push(medium.format);
    return parts.length ? parts.join(" - ") : null;
}
function buildArtistMarkdown(artist) {
    let md = `# ${artist.name}\n\n`;
    const meta = [];
    if (artist.type)
        meta.push(`**Type**: ${artist.type}`);
    if (artist.country)
        meta.push(`**Country**: ${artist.country}`);
    const lifeSpan = formatLifeSpan(artist["life-span"]);
    if (lifeSpan)
        meta.push(`**Life Span**: ${lifeSpan}`);
    if (meta.length)
        md += `${meta.join("\n")}\n`;
    return md;
}
function buildReleaseMarkdown(release) {
    let md = `# ${release.title}\n\n`;
    const media = release.media ?? [];
    const totalTracks = release["track-count"] ??
        media.reduce((sum, medium) => sum + (medium["track-count"] ?? medium.tracks?.length ?? 0), 0);
    if (totalTracks) {
        md += `**Tracks**: ${totalTracks}\n\n`;
    }
    if (media.length) {
        md += "## Tracks\n\n";
        const includePosition = media.length > 1;
        for (const medium of media) {
            const label = buildMediumLabel(medium, includePosition);
            if (label)
                md += `### ${label}\n\n`;
            const tracks = medium.tracks ?? [];
            if (tracks.length) {
                const lines = tracks.slice(0, MAX_TRACKS).map(formatTrack).join("\n");
                md += `${lines}\n\n`;
                if (tracks.length > MAX_TRACKS) {
                    md += `_Showing first ${MAX_TRACKS} of ${tracks.length} tracks._\n\n`;
                }
            }
            else if (medium["track-count"]) {
                md += `- ${medium["track-count"]} tracks (details unavailable)\n\n`;
            }
        }
    }
    return md;
}
function buildRecordingMarkdown(recording) {
    let md = `# ${recording.title}\n\n`;
    const meta = [];
    const artists = formatArtistCredits(recording["artist-credit"]);
    if (artists)
        meta.push(`**Artists**: ${artists}`);
    const length = formatDurationMs(recording.length);
    if (length)
        meta.push(`**Length**: ${length}`);
    if (meta.length)
        md += `${meta.join("\n")}\n`;
    return md;
}
export const handleMusicBrainz = async (url, timeout, signal) => {
    try {
        const parsed = new URL(url);
        const parsedEntity = parseEntity(parsed);
        if (!parsedEntity)
            return null;
        const { entity, mbid } = parsedEntity;
        const fetchedAt = new Date().toISOString();
        let md = "";
        if (entity === "artist") {
            const apiUrl = `https://musicbrainz.org/ws/2/artist/${mbid}?fmt=json&inc=url-rels`;
            const artist = await fetchJson(apiUrl, timeout, signal);
            if (!artist)
                return null;
            md = buildArtistMarkdown(artist);
        }
        else if (entity === "release") {
            const apiUrl = `https://musicbrainz.org/ws/2/release/${mbid}?fmt=json&inc=recordings`;
            const release = await fetchJson(apiUrl, timeout, signal);
            if (!release)
                return null;
            md = buildReleaseMarkdown(release);
        }
        else {
            const apiUrl = `https://musicbrainz.org/ws/2/recording/${mbid}?fmt=json`;
            const recording = await fetchJson(apiUrl, timeout, signal);
            if (!recording)
                return null;
            md = buildRecordingMarkdown(recording);
        }
        return buildResult(md, { url, method: "musicbrainz-api", fetchedAt, notes: ["Fetched via MusicBrainz API"] });
    }
    catch { }
    return null;
};
