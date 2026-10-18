import { tryParseJson } from "@rva/utils";
import { buildResult, formatIsoDate, htmlToBasicMarkdown, loadPage } from "./types";
// Standalone SE network sites (not *.stackexchange.com subdomains)
const STANDALONE_SE_SITES = {
    "stackoverflow.com": "stackoverflow",
    "superuser.com": "superuser",
    "serverfault.com": "serverfault",
    "askubuntu.com": "askubuntu",
    "mathoverflow.net": "mathoverflow",
    "stackapps.com": "stackapps",
};
/**
 * Extract the API site parameter from a Stack Exchange hostname
 * Returns null if not a recognized SE site
 */
function getSiteParam(hostname) {
    // Remove www. prefix if present
    const host = hostname.replace(/^www\./, "");
    // Check standalone sites first
    if (STANDALONE_SE_SITES[host]) {
        return STANDALONE_SE_SITES[host];
    }
    // Handle *.stackexchange.com subdomains (e.g., unix.stackexchange.com → unix)
    const seMatch = host.match(/^([a-z0-9-]+)\.stackexchange\.com$/);
    if (seMatch) {
        return seMatch[1];
    }
    return null;
}
/**
 * Handle Stack Exchange network URLs via API
 * Supports stackoverflow.com, *.stackexchange.com, superuser.com, serverfault.com, askubuntu.com, etc.
 */
export const handleStackOverflow = async (url, timeout, signal) => {
    try {
        const parsed = new URL(url);
        const site = getSiteParam(parsed.hostname);
        if (!site)
            return null;
        // Extract question ID from URL patterns like /questions/12345/...
        const match = parsed.pathname.match(/\/questions\/(\d+)/);
        if (!match)
            return null;
        const questionId = match[1];
        const fetchedAt = new Date().toISOString();
        // Fetch question with answers
        const apiUrl = `https://api.stackexchange.com/2.3/questions/${questionId}?order=desc&sort=votes&site=${site}&filter=withbody`;
        const qResult = await loadPage(apiUrl, { timeout, signal });
        if (!qResult.ok)
            return null;
        const qData = tryParseJson(qResult.content);
        if (!qData?.items?.length)
            return null;
        const question = qData.items[0];
        let md = `# ${question.title}\n\n`;
        md += `**Score:** ${question.score} · **Answers:** ${question.answer_count}`;
        md += question.is_answered ? " (Answered)" : "";
        md += `\n**Tags:** ${question.tags.join(", ")}\n`;
        md += `**Asked by:** ${question.owner.display_name} · ${formatIsoDate(question.creation_date * 1000)}\n\n`;
        md += `---\n\n## Question\n\n${await htmlToBasicMarkdown(question.body)}\n\n`;
        // Fetch answers
        const aUrl = `https://api.stackexchange.com/2.3/questions/${questionId}/answers?order=desc&sort=votes&site=${site}&filter=withbody`;
        const aResult = await loadPage(aUrl, { timeout, signal });
        if (aResult.ok) {
            const aData = tryParseJson(aResult.content);
            if (aData?.items?.length) {
                md += `---\n\n## Answers\n\n`;
                for (const answer of aData.items.slice(0, 5)) {
                    const accepted = answer.is_accepted ? " (Accepted)" : "";
                    md += `### Score: ${answer.score}${accepted} · by ${answer.owner.display_name}\n\n`;
                    md += `${await htmlToBasicMarkdown(answer.body)}\n\n---\n\n`;
                }
            }
        }
        return buildResult(md, {
            url,
            method: "stackexchange",
            fetchedAt,
            notes: [`Fetched via Stack Exchange API (site=${site})`],
        });
    }
    catch { }
    return null;
};
