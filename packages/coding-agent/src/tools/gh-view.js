import { github } from "../utils/github";
import { appendRepoFlag, buildTextResult, formatAuthor, formatLabels, ghApiHostArgs, normalizeOptionalString, normalizeText, parseIssueUrl, parsePositiveDecimalInt, parseRepoRef, requireNonEmpty, resolveDefaultRepoMemoized, } from "./gh-common";
import { pushLine } from "@rva/tui/tools/gh-format";
import { formatShortSha } from "@rva/tui/tools/gh-format";
import { FILE_PREVIEW_LIMIT } from "./gh-search";
import { getOrFetchView, resolveGithubCacheAuthKey } from "./github-cache";
import { ToolError } from "@rva/tui/tools/tool-errors";
export const GH_REPO_FIELDS = [
    "nameWithOwner",
    "description",
    "url",
    "defaultBranchRef",
    "homepageUrl",
    "forkCount",
    "isArchived",
    "isFork",
    "primaryLanguage",
    "repositoryTopics",
    "stargazerCount",
    "updatedAt",
    "viewerPermission",
    "visibility",
];
export const GH_ISSUE_FIELDS = [
    "author",
    "body",
    "comments",
    "createdAt",
    "labels",
    "number",
    "state",
    "stateReason",
    "title",
    "updatedAt",
    "url",
];
export const GH_ISSUE_FIELDS_NO_COMMENTS = [
    "author",
    "body",
    "createdAt",
    "labels",
    "number",
    "state",
    "stateReason",
    "title",
    "updatedAt",
    "url",
];
export const GH_ISSUE_STATE_REASON_FIELD = "stateReason";
export function ghJsonErrorNamesField(err, field) {
    if (!(err instanceof Error) || !err.message.includes("Unknown JSON field"))
        return false;
    return err.message.includes(`"${field}"`) || err.message.includes(`'${field}'`) || err.message.includes(field);
}
export function dropJsonField(args, field) {
    const next = [...args];
    const jsonIndex = next.indexOf("--json");
    if (jsonIndex < 0)
        return undefined;
    const fields = next[jsonIndex + 1];
    if (!fields)
        return undefined;
    const splitFields = fields.split(",");
    const kept = splitFields.filter(candidate => candidate !== field);
    if (kept.length === splitFields.length)
        return undefined;
    next[jsonIndex + 1] = kept.join(",");
    return next;
}
/** Runs `gh --json` for issue data, retrying without optional stateReason on older gh releases. */
export async function githubIssueJsonWithStateReasonFallback(cwd, args, signal, options) {
    try {
        return await github.json(cwd, [...args], signal, options);
    }
    catch (err) {
        if (!ghJsonErrorNamesField(err, GH_ISSUE_STATE_REASON_FIELD))
            throw err;
        const retryArgs = dropJsonField(args, GH_ISSUE_STATE_REASON_FIELD);
        if (!retryArgs)
            throw err;
        return await github.json(cwd, retryArgs, signal, options);
    }
}
export const GH_PR_FIELDS = [
    "author",
    "baseRefName",
    "body",
    "comments",
    "createdAt",
    "files",
    "headRefName",
    "isDraft",
    "labels",
    "mergeStateStatus",
    "number",
    "reviews",
    "reviewDecision",
    "state",
    "title",
    "updatedAt",
    "url",
];
export const GH_PR_FIELDS_NO_COMMENTS = [
    "author",
    "baseRefName",
    "body",
    "createdAt",
    "files",
    "headRefName",
    "isDraft",
    "labels",
    "mergeStateStatus",
    "number",
    "reviews",
    "reviewDecision",
    "state",
    "title",
    "updatedAt",
    "url",
];
export const GH_REPO_CLONE_FIELDS = ["nameWithOwner", "sshUrl", "url"];
export const REVIEW_COMMENTS_PAGE_SIZE = 100;
export function normalizePrReviewComment(comment) {
    if (typeof comment.id !== "number") {
        return null;
    }
    return {
        author: comment.user ?? null,
        body: comment.body,
        createdAt: normalizeOptionalString(comment.created_at),
        id: comment.id,
        inReplyToId: typeof comment.in_reply_to_id === "number" ? comment.in_reply_to_id : undefined,
        line: typeof comment.line === "number" ? comment.line : undefined,
        originalLine: typeof comment.original_line === "number" ? comment.original_line : undefined,
        path: normalizeOptionalString(comment.path),
        side: normalizeOptionalString(comment.side),
        url: normalizeOptionalString(comment.html_url),
    };
}
export async function fetchPrReviewComments(cwd, repo, prNumber, signal) {
    const ref = parseRepoRef(repo);
    const reviewComments = [];
    let page = 1;
    while (true) {
        const response = await github.json(cwd, [
            "api",
            ...ghApiHostArgs(ref),
            "--method",
            "GET",
            `/repos/${ref.slug}/pulls/${prNumber}/comments`,
            "-F",
            `per_page=${REVIEW_COMMENTS_PAGE_SIZE}`,
            "-F",
            `page=${page}`,
        ], signal, { repoProvided: true });
        const pageComments = response
            .map(comment => normalizePrReviewComment(comment))
            .filter((comment) => comment !== null);
        reviewComments.push(...pageComments);
        // Compare the raw page length: a dropped malformed item must not end
        // pagination early and silently lose the remaining pages.
        if (response.length < REVIEW_COMMENTS_PAGE_SIZE) {
            break;
        }
        page += 1;
    }
    return reviewComments;
}
export function formatCommentsSection(comments) {
    if (!comments || comments.length === 0) {
        return [];
    }
    const visible = comments.filter(comment => !comment.isMinimized);
    const hiddenCount = comments.length - visible.length;
    const lines = ["## Comments", ""];
    if (visible.length === 0) {
        lines.push(`No visible comments. Minimized comments omitted: ${hiddenCount}.`);
        return lines;
    }
    lines[0] = `## Comments (${visible.length})`;
    for (const comment of visible) {
        const author = formatAuthor(comment.author) ?? "unknown";
        const createdAt = comment.createdAt ? ` · ${comment.createdAt}` : "";
        lines.push(`### ${author}${createdAt}`);
        lines.push("");
        lines.push(normalizeText(comment.body) || "No comment body.");
        if (comment.url) {
            lines.push("");
            lines.push(`URL: ${comment.url}`);
        }
        lines.push("");
    }
    if (hiddenCount > 0) {
        lines.push(`Minimized comments omitted: ${hiddenCount}.`);
    }
    return lines;
}
export function formatReviewsSection(reviews) {
    if (!reviews || reviews.length === 0) {
        return [];
    }
    const lines = [`## Reviews (${reviews.length})`, ""];
    for (const review of reviews) {
        const author = formatAuthor(review.author) ?? "unknown";
        const submittedAt = review.submittedAt ? ` - ${review.submittedAt}` : "";
        const state = review.state ? ` [${review.state}]` : "";
        lines.push(`### ${author}${submittedAt}${state}`);
        if (review.commit?.oid) {
            lines.push("");
            lines.push(`Commit: ${formatShortSha(review.commit.oid)}`);
        }
        lines.push("");
        lines.push(normalizeText(review.body) || "No review body.");
        lines.push("");
    }
    return lines;
}
export function formatReviewCommentLocation(comment) {
    if (!comment.path) {
        return undefined;
    }
    const line = comment.line ?? comment.originalLine;
    return line === undefined ? comment.path : `${comment.path}:${line}`;
}
export function formatReviewCommentsSection(comments) {
    if (!comments || comments.length === 0) {
        return [];
    }
    const lines = [`## Review Comments (${comments.length})`, ""];
    for (const comment of comments) {
        const author = formatAuthor(comment.author) ?? "unknown";
        const createdAt = comment.createdAt ? ` · ${comment.createdAt}` : "";
        lines.push(`### ${author}${createdAt}`);
        lines.push("");
        pushLine(lines, "Location", formatReviewCommentLocation(comment));
        pushLine(lines, "Side", comment.side);
        pushLine(lines, "Reply to", comment.inReplyToId);
        pushLine(lines, "URL", comment.url);
        lines.push("");
        lines.push(normalizeText(comment.body) || "No review comment body.");
        lines.push("");
    }
    return lines;
}
export function formatRepoView(data, input) {
    const lines = [];
    const name = data.nameWithOwner ?? input.repo ?? "GitHub Repository";
    lines.push(`# ${name}`);
    lines.push("");
    lines.push(normalizeText(data.description) || "No description provided.");
    lines.push("");
    pushLine(lines, "URL", data.url);
    pushLine(lines, "Default branch", data.defaultBranchRef?.name);
    pushLine(lines, "Branch", normalizeOptionalString(input.branch));
    pushLine(lines, "Visibility", data.visibility ?? undefined);
    pushLine(lines, "Viewer permission", data.viewerPermission ?? undefined);
    pushLine(lines, "Primary language", data.primaryLanguage?.name);
    pushLine(lines, "Stars", data.stargazerCount);
    pushLine(lines, "Forks", data.forkCount);
    pushLine(lines, "Archived", data.isArchived);
    pushLine(lines, "Fork", data.isFork);
    pushLine(lines, "Updated", data.updatedAt);
    pushLine(lines, "Homepage", data.homepageUrl ?? undefined);
    const topics = data.repositoryTopics
        ?.map(topic => topic.name ?? topic.topic?.name)
        .filter((value) => Boolean(value))
        .join(", ");
    pushLine(lines, "Topics", topics || undefined);
    return lines.join("\n").trim();
}
export function formatIssueView(data, input) {
    const lines = [];
    const issueNumber = data.number ?? input.issue;
    lines.push(`# Issue #${issueNumber}: ${data.title ?? "Untitled"}`);
    lines.push("");
    pushLine(lines, "State", data.state);
    pushLine(lines, "State reason", data.stateReason ?? undefined);
    pushLine(lines, "Author", formatAuthor(data.author));
    pushLine(lines, "Created", data.createdAt);
    pushLine(lines, "Updated", data.updatedAt);
    pushLine(lines, "Labels", formatLabels(data.labels));
    pushLine(lines, "URL", data.url);
    lines.push("");
    lines.push("## Body");
    lines.push("");
    lines.push(normalizeText(data.body) || "No description provided.");
    if ((input.comments ?? true) && data.comments) {
        const commentSection = formatCommentsSection(data.comments);
        if (commentSection.length > 0) {
            lines.push("");
            lines.push(...commentSection);
        }
    }
    return lines.join("\n").trim();
}
export function formatPrFiles(files) {
    if (!files || files.length === 0)
        return [];
    const lines = [`## Files (${files.length})`, ""];
    for (const file of files.slice(0, FILE_PREVIEW_LIMIT)) {
        const changeType = file.changeType ?? "CHANGED";
        const additions = file.additions ?? 0;
        const deletions = file.deletions ?? 0;
        lines.push(`- ${file.path ?? "(unknown file)"} [${changeType}] (+${additions} -${deletions})`);
    }
    if (files.length > FILE_PREVIEW_LIMIT) {
        lines.push(`[…${files.length - FILE_PREVIEW_LIMIT} files elided…]`);
    }
    return lines;
}
export function formatPrView(data, input) {
    const lines = [];
    const prIdentifier = data.number ?? input.pr ?? "current";
    lines.push(`# Pull Request #${prIdentifier}: ${data.title ?? "Untitled"}`);
    lines.push("");
    pushLine(lines, "State", data.state);
    pushLine(lines, "Draft", data.isDraft);
    pushLine(lines, "Author", formatAuthor(data.author));
    pushLine(lines, "Base", data.baseRefName);
    pushLine(lines, "Head", data.headRefName);
    pushLine(lines, "Review decision", data.reviewDecision ?? undefined);
    pushLine(lines, "Merge state", data.mergeStateStatus);
    pushLine(lines, "Created", data.createdAt);
    pushLine(lines, "Updated", data.updatedAt);
    pushLine(lines, "Labels", formatLabels(data.labels));
    pushLine(lines, "URL", data.url);
    lines.push("");
    lines.push("## Body");
    lines.push("");
    lines.push(normalizeText(data.body) || "No description provided.");
    const fileSection = formatPrFiles(data.files);
    if (fileSection.length > 0) {
        lines.push("");
        lines.push(...fileSection);
    }
    if ((input.comments ?? true) && data.reviews) {
        const reviewSection = formatReviewsSection(data.reviews);
        if (reviewSection.length > 0) {
            lines.push("");
            lines.push(...reviewSection);
        }
    }
    if ((input.comments ?? true) && data.reviewComments) {
        const reviewCommentsSection = formatReviewCommentsSection(data.reviewComments);
        if (reviewCommentsSection.length > 0) {
            lines.push("");
            lines.push(...reviewCommentsSection);
        }
    }
    if ((input.comments ?? true) && data.comments) {
        const commentSection = formatCommentsSection(data.comments);
        if (commentSection.length > 0) {
            lines.push("");
            lines.push(...commentSection);
        }
    }
    return lines.join("\n").trim();
}
export async function executeRepoView(session, params, signal) {
    const repo = normalizeOptionalString(params.repo);
    const branch = normalizeOptionalString(params.branch);
    const args = ["repo", "view"];
    if (repo) {
        args.push(repo);
    }
    if (branch) {
        args.push("--branch", branch);
    }
    args.push("--json", GH_REPO_FIELDS.join(","));
    const data = await github.json(session.cwd, args, signal, {
        repoProvided: Boolean(repo),
    });
    return buildTextResult(formatRepoView(data, { repo, branch }), data.url);
}
export async function fetchIssueViewFresh(cwd, repo, identifier, includeComments, signal) {
    const args = ["issue", "view", identifier];
    appendRepoFlag(args, repo, identifier);
    args.push("--json", (includeComments ? GH_ISSUE_FIELDS : GH_ISSUE_FIELDS_NO_COMMENTS).join(","));
    const data = await githubIssueJsonWithStateReasonFallback(cwd, args, signal, {
        repoProvided: Boolean(repo),
    });
    const rendered = formatIssueView(data, { issue: identifier, repo, comments: includeComments });
    return { rendered, sourceUrl: data.url, payload: data };
}
export async function fetchPrViewFresh(cwd, repo, number, includeComments, signal) {
    const args = ["pr", "view", String(number)];
    appendRepoFlag(args, repo, String(number));
    args.push("--json", (includeComments ? GH_PR_FIELDS : GH_PR_FIELDS_NO_COMMENTS).join(","));
    const data = await github.json(cwd, args, signal, { repoProvided: true });
    if (includeComments && typeof data.number === "number") {
        data.reviewComments = await fetchPrReviewComments(cwd, repo, data.number, signal);
    }
    const rendered = formatPrView(data, { pr: String(number), repo, comments: includeComments });
    return { rendered, sourceUrl: data.url, payload: data };
}
/**
 * Cache-aware issue/view fetcher. Used by both the `github` tool op and the
 * `issue://` protocol handler so a single shared row services both surfaces.
 */
export async function getOrFetchIssue(options) {
    const identifier = requireNonEmpty(options.issue, "issue");
    if (identifier.startsWith("-")) {
        throw new ToolError(`invalid issue identifier: ${identifier}. Pass an issue number or URL.`);
    }
    const includeComments = options.includeComments ?? true;
    const authKey = options.cacheAuthKey === undefined ? (resolveGithubCacheAuthKey() ?? null) : options.cacheAuthKey;
    const urlParse = parseIssueUrl(identifier);
    // Prefer the URL's repo when the identifier is a full URL; fall back to the
    // explicit `repo` option, then to the cwd's default repo.
    let repo = urlParse.repo ?? normalizeOptionalString(options.repo);
    let cacheNumber = urlParse.issueNumber;
    if (cacheNumber === undefined) {
        cacheNumber = parsePositiveDecimalInt(identifier);
    }
    if (cacheNumber !== undefined && !repo) {
        try {
            repo = await resolveDefaultRepoMemoized(options.cwd, options.signal);
        }
        catch {
            // Resolution failure leaves `repo` undefined: we'll fall through to a
            // direct fetch below so gh produces its own error message instead of
            // us masking it with a friendlier one.
            repo = undefined;
        }
    }
    const doFetch = () => fetchIssueViewFresh(options.cwd, repo, identifier, includeComments, options.signal);
    if (!repo || cacheNumber === undefined) {
        const fresh = await doFetch();
        return { ...fresh, status: "miss", fetchedAt: Date.now() };
    }
    const lookup = await getOrFetchView({
        repo,
        kind: "issue",
        number: cacheNumber,
        includeComments,
        settings: options.settings,
        authKey,
        fetchFresh: doFetch,
    });
    return {
        rendered: lookup.rendered,
        sourceUrl: lookup.sourceUrl,
        payload: lookup.payload,
        status: lookup.status,
        fetchedAt: lookup.fetchedAt,
    };
}
/**
 * Cache-aware PR view fetcher. Caller must supply a numeric PR number;
 * branch-name / current-branch lookups bypass the cache entirely upstream
 * (see `executePrView`).
 */
export async function getOrFetchPr(options) {
    const includeComments = options.includeComments ?? true;
    const authKey = options.cacheAuthKey === undefined ? (resolveGithubCacheAuthKey() ?? null) : options.cacheAuthKey;
    const doFetch = () => fetchPrViewFresh(options.cwd, options.repo, options.number, includeComments, options.signal);
    const lookup = await getOrFetchView({
        repo: options.repo,
        kind: "pr",
        number: options.number,
        includeComments,
        settings: options.settings,
        authKey,
        fetchFresh: doFetch,
    });
    return {
        rendered: lookup.rendered,
        sourceUrl: lookup.sourceUrl,
        payload: lookup.payload,
        status: lookup.status,
        fetchedAt: lookup.fetchedAt,
    };
}
