import { tryParseJson } from "@rva/utils";
import { buildResult, formatIsoDate, loadPage } from "./types";
/**
 * Handle Reddit URLs via JSON API
 */
export const handleReddit = async (url, timeout, signal) => {
    try {
        const parsed = new URL(url);
        if (!parsed.hostname.includes("reddit.com"))
            return null;
        const fetchedAt = new Date().toISOString();
        // Append .json to get JSON response
        let jsonUrl = `${url.replace(/\/$/, "")}.json`;
        if (parsed.search) {
            jsonUrl = `${url.replace(/\/$/, "").replace(parsed.search, "")}.json${parsed.search}`;
        }
        const result = await loadPage(jsonUrl, { timeout, signal });
        if (!result.ok)
            return null;
        const data = tryParseJson(result.content);
        if (!data)
            return null;
        let md = "";
        // Handle different Reddit URL types
        if (Array.isArray(data) && data.length >= 1) {
            // Post page (with comments)
            const postData = data[0]?.data?.children?.[0]?.data;
            if (postData) {
                md = `# ${postData.title}\n\n`;
                md += `**r/${postData.subreddit}** · u/${postData.author} · ${postData.score} points · ${postData.num_comments} comments\n`;
                md += `*${formatIsoDate(postData.created_utc * 1000)}*\n\n`;
                if (postData.is_self && postData.selftext) {
                    md += `---\n\n${postData.selftext}\n\n`;
                }
                else if (!postData.is_self) {
                    md += `**Link:** ${postData.url}\n\n`;
                }
                // Add comments if available
                if (data.length >= 2 && data[1]?.data?.children) {
                    md += `---\n\n## Top Comments\n\n`;
                    const comments = data[1].data.children.filter((c) => c.kind === "t1").slice(0, 10);
                    for (const { data: comment } of comments) {
                        md += `### u/${comment.author} · ${comment.score} points\n\n`;
                        md += `${comment.body}\n\n---\n\n`;
                    }
                }
            }
        }
        else if (data?.data?.children) {
            // Subreddit or listing page
            const posts = data.data.children.slice(0, 20);
            const subreddit = posts[0]?.data?.subreddit;
            md = `# r/${subreddit || "Reddit"}\n\n`;
            for (const { data: post } of posts) {
                md += `- **${post.title}** (${post.score} pts, ${post.num_comments} comments)\n`;
                md += `  by u/${post.author}\n\n`;
            }
        }
        if (!md)
            return null;
        return buildResult(md, { url, method: "reddit", fetchedAt, notes: ["Fetched via Reddit JSON API"] });
    }
    catch { }
    return null;
};
