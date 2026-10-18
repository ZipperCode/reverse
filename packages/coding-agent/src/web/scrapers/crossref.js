import { tryParseJson } from "@rva/utils";
import { buildResult, htmlToBasicMarkdown, loadPage } from "./types";
const DOI_HOSTS = new Set(["doi.org", "dx.doi.org", "www.doi.org"]);
function extractDoi(pathname) {
    const raw = pathname.replace(/^\/+/, "");
    if (!raw)
        return null;
    return decodeURIComponent(raw);
}
function formatAuthors(authors) {
    if (!authors || authors.length === 0)
        return null;
    const names = authors
        .map(author => {
        if (author.name)
            return author.name;
        const parts = [author.given, author.family].filter(Boolean);
        return parts.length > 0 ? parts.join(" ") : null;
    })
        .filter((name) => Boolean(name));
    if (names.length === 0)
        return null;
    return names.join(", ");
}
function formatDate(date) {
    const parts = date?.["date-parts"]?.[0];
    if (!parts || parts.length === 0)
        return null;
    const [year, month, day] = parts;
    if (!year)
        return null;
    const formatted = [
        String(year),
        month ? String(month).padStart(2, "0") : "",
        day ? String(day).padStart(2, "0") : "",
    ].filter(Boolean);
    return formatted.join("-");
}
async function formatAbstract(abstract) {
    if (!abstract)
        return null;
    const normalized = abstract.replace(/<\/?jats:p[^>]*>/g, match => (match.startsWith("</") ? "</p>" : "<p>"));
    const markdown = await htmlToBasicMarkdown(normalized);
    return markdown.trim().length > 0 ? markdown : null;
}
export const handleCrossref = async (url, timeout, signal) => {
    try {
        const parsed = new URL(url);
        if (!DOI_HOSTS.has(parsed.hostname.toLowerCase()))
            return null;
        const doi = extractDoi(parsed.pathname);
        if (!doi)
            return null;
        const fetchedAt = new Date().toISOString();
        const apiUrl = `https://api.crossref.org/works/${encodeURIComponent(doi)}`;
        const result = await loadPage(apiUrl, {
            timeout,
            signal,
            headers: {
                Accept: "application/json",
            },
        });
        if (!result.ok)
            return null;
        const data = tryParseJson(result.content);
        if (!data)
            return null;
        const message = data.message;
        if (!message)
            return null;
        const title = message.title?.[0]?.trim() || "CrossRef Record";
        const authors = formatAuthors(message.author);
        const journal = message["container-title"]?.[0] || message["short-container-title"]?.[0];
        const publisher = message.publisher;
        const published = formatDate(message.published) ||
            formatDate(message["published-print"]) ||
            formatDate(message["published-online"]) ||
            formatDate(message.issued) ||
            formatDate(message.created);
        const doiValue = message.DOI || doi;
        const abstract = await formatAbstract(message.abstract);
        const type = message.type?.replace(/-/g, " ");
        let md = `# ${title}\n\n`;
        if (authors)
            md += `**Authors:** ${authors}\n`;
        if (journal)
            md += `**Journal:** ${journal}\n`;
        if (publisher)
            md += `**Publisher:** ${publisher}\n`;
        if (published)
            md += `**Published:** ${published}\n`;
        md += `**DOI:** ${doiValue}\n`;
        if (type)
            md += `**Type:** ${type}\n`;
        md += "\n---\n\n";
        md += "## Abstract\n\n";
        md += abstract || "No abstract available.";
        md += "\n";
        return buildResult(md, { url, method: "crossref", fetchedAt, notes: ["Fetched via CrossRef API"] });
    }
    catch { }
    return null;
};
