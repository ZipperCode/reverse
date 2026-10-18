import * as path from "node:path";
import * as vcs from "@rva/natives/vcs";
import { untilAborted } from "@rva/utils";
import { github } from "../utils/github";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { toolResult } from "./tool-result";
export function normalizeText(value) {
    return (value ?? "").replaceAll("\r\n", "\n").replaceAll("\r", "\n").replaceAll("\t", "    ").trim();
}
export function normalizeBlock(value) {
    return (value ?? "").replaceAll("\r\n", "\n").replaceAll("\r", "\n").replaceAll("\t", "    ").trimEnd();
}
export function normalizeOptionalString(value) {
    const normalized = value?.trim();
    return normalized ? normalized : undefined;
}
export function normalizePrIdentifierList(value) {
    if (value === undefined)
        return [];
    const raw = typeof value === "string" ? [value] : value;
    const cleaned = [];
    for (const entry of raw) {
        const trimmed = entry?.trim();
        if (trimmed)
            cleaned.push(trimmed);
    }
    return cleaned;
}
export function requireNonEmpty(value, label) {
    const normalized = normalizeOptionalString(value);
    if (!normalized) {
        throw new ToolError(`${label} must not be empty`);
    }
    return normalized;
}
export function appendRepoFlag(args, repo, identifier) {
    // A full URL identifier already names host, repo, and number; `gh` derives
    // all three from it and rejects a competing `--repo`.
    if (!repo || identifier?.startsWith("https://")) {
        return;
    }
    args.push("--repo", repo);
}
/** The host `gh` assumes when a ref names none and `GH_HOST` is unset. */
export const GITHUB_HOST = "github.com";
/** Split `[HOST/]OWNER/REPO`; anything with another shape is taken as a slug. */
export function parseRepoRef(repo) {
    const firstSlash = repo.indexOf("/");
    if (firstSlash < 0)
        return { slug: repo };
    const secondSlash = repo.indexOf("/", firstSlash + 1);
    if (secondSlash < 0 || repo.includes("/", secondSlash + 1))
        return { slug: repo };
    return { host: repo.slice(0, firstSlash), slug: repo.slice(firstSlash + 1) };
}
/** Join a known host and `OWNER/REPO` into the form `--repo` accepts. */
export function formatRepoRef(host, slug) {
    return host ? `${host}/${slug}` : slug;
}
/**
 * `gh api` endpoint paths carry no host, so a ref has to name its host with a
 * flag instead.
 */
export function ghApiHostArgs(ref) {
    return ref.host ? ["--hostname", ref.host] : [];
}
const REPO_URL_PATTERN = /^https?:\/\/([^/]+)\/([^/]+)\/([^/?#]+)/;
/**
 * `https://HOST/OWNER/REPO` → the repository's identity. The host is dropped
 * only when it is the one `gh` would have assumed anyway, so a bare identity
 * can never be redirected: with `GH_HOST` set elsewhere, even a github.com
 * checkout keeps its host.
 */
export function repoFromUrl(value) {
    const match = REPO_URL_PATTERN.exec(value?.trim() ?? "");
    if (!match)
        return undefined;
    const host = match[1].toLowerCase();
    const slug = `${match[2]}/${match[3]}`;
    return host === defaultGhHost() ? slug : formatRepoRef(host, slug);
}
export const PR_URL_PATTERN = /^https:\/\/([^/]+)\/([^/]+\/[^/]+)\/pull\/(\d+)(?:\/.*)?$/;
export const ISSUE_URL_PATTERN = /^https:\/\/([^/]+)\/([^/]+\/[^/]+)\/issues\/(\d+)(?:\/.*)?$/;
export async function requireCurrentGitBranch(cwd, signal) {
    const repo = vcs.git(cwd);
    const branch = repo ? await repo.currentBranch(signal).catch(() => null) : null;
    if (!branch) {
        throw new ToolError("Current git branch is unavailable. Pass `branch` or `run` explicitly.");
    }
    return branch;
}
export async function requireCurrentGitHead(cwd, signal) {
    const repo = vcs.git(cwd);
    const headSha = repo ? await repo.headSha(signal).catch(() => null) : null;
    if (!headSha) {
        throw new ToolError("Current git HEAD is unavailable. Pass `run` explicitly.");
    }
    return headSha;
}
export function formatAuthor(author) {
    if (!author)
        return undefined;
    if (author.login)
        return `@${author.login}`;
    if (author.name)
        return author.name;
    return undefined;
}
export function formatLabels(labels) {
    const names = labels?.map(label => label.name).filter((value) => Boolean(value)) ?? [];
    if (names.length === 0)
        return undefined;
    return names.join(", ");
}
export function parsePullRequestUrl(value) {
    const normalized = normalizeOptionalString(value);
    if (!normalized) {
        return {};
    }
    const match = normalized.match(PR_URL_PATTERN);
    if (!match) {
        return {};
    }
    return {
        repo: formatRepoRef(match[1], match[2]),
        prNumber: Number(match[3]),
    };
}
/**
 * Parse a digit-only decimal positive integer or return undefined. Rejects
 * `1e2`, `0x10`, `12.0`, leading +/-, or any other shape `Number()` would
 * accept — those would otherwise key the cache against the wrong row.
 */
export function parsePositiveDecimalInt(value) {
    if (!value || !/^\d+$/.test(value))
        return undefined;
    const num = Number(value);
    if (!Number.isSafeInteger(num) || num <= 0)
        return undefined;
    return num;
}
export function parseIssueUrl(value) {
    const normalized = normalizeOptionalString(value);
    if (!normalized)
        return {};
    const match = normalized.match(ISSUE_URL_PATTERN);
    if (!match)
        return {};
    return {
        repo: formatRepoRef(match[1], match[2]),
        issueNumber: Number(match[3]),
    };
}
/** The host `gh` falls back to for any ref that names none. */
export function defaultGhHost() {
    return (process.env.GH_HOST || GITHUB_HOST).toLowerCase();
}
/** The host `gh` will send a ref to, whether or not the ref names one. */
function effectiveHost(ref) {
    return ref.host?.toLowerCase() ?? defaultGhHost();
}
/**
 * Case-insensitive repo comparison over the instance each ref actually
 * resolves to. A host-less ref is not a wildcard: `gh` sends it to `GH_HOST`,
 * so comparing slugs alone would call a bare `owner/repo` the same repository
 * as `ghe.example.com/owner/repo` and let a caller act on one while the
 * request goes to the other.
 */
export function githubRepoSlugEquals(left, right) {
    if (left === undefined)
        return false;
    const leftRef = parseRepoRef(left);
    const rightRef = parseRepoRef(right);
    if (effectiveHost(leftRef) !== effectiveHost(rightRef))
        return false;
    return leftRef.slug.toLowerCase() === rightRef.slug.toLowerCase();
}
/**
 * Ask `gh` which repository the checkout points at, as `[HOST/]OWNER/REPO`.
 *
 * `nameWithOwner` alone would drop the host, and `gh` resolves a host-less
 * `--repo` against `GH_HOST` (github.com by default) — so an enterprise
 * checkout would silently be looked up on github.com. The repo URL carries
 * the host `gh` itself resolved from the remote.
 */
async function resolveRepoFromCwd(cwd, signal) {
    const url = requireNonEmpty(await github.text(cwd, ["repo", "view", "--json", "url", "-q", ".url"], signal), "repo");
    const repo = repoFromUrl(url);
    if (!repo) {
        throw new ToolError(`GitHub CLI returned an unrecognized repository URL: ${url}`);
    }
    return repo;
}
export async function resolveGitHubRepo(cwd, repo, runRepo, signal) {
    if (repo && runRepo && !githubRepoSlugEquals(repo, runRepo)) {
        throw new ToolError("run URL repository does not match the provided repo");
    }
    if (repo) {
        return repo;
    }
    if (runRepo) {
        return runRepo;
    }
    return resolveRepoFromCwd(cwd, signal);
}
/**
 * Process-lifetime cache of `gh repo view` lookups keyed by absolute cwd.
 * Avoids repeated `gh` chatter when the same protocol handler or tool call
 * resolves the default repo many times in a row.
 *
 * The shared lookup is intentionally **not** bound to any caller's
 * AbortSignal. Cancelling one caller would otherwise kill the underlying
 * `gh repo view` for every concurrent waiter on the same cwd. Each caller's
 * signal is honored at the wait point via `untilAborted` instead, so an abort
 * unwinds only that caller.
 */
export const DEFAULT_REPO_RESOLVED = new Map();
export const DEFAULT_REPO_INFLIGHT = new Map();
export async function resolveDefaultRepoMemoized(cwd, signal) {
    const key = path.resolve(cwd);
    const ready = DEFAULT_REPO_RESOLVED.get(key);
    if (ready)
        return ready;
    let pending = DEFAULT_REPO_INFLIGHT.get(key);
    if (!pending) {
        pending = (async () => {
            // No caller signal: this lookup is shared across every concurrent
            // waiter on the same cwd.
            const value = await resolveRepoFromCwd(cwd);
            DEFAULT_REPO_RESOLVED.set(key, value);
            return value;
        })();
        // Drop the in-flight slot on settle so failures don't poison the cache
        // and so a successful resolution survives only in `DEFAULT_REPO_RESOLVED`.
        void pending.then(() => DEFAULT_REPO_INFLIGHT.delete(key), () => DEFAULT_REPO_INFLIGHT.delete(key));
        DEFAULT_REPO_INFLIGHT.set(key, pending);
    }
    return untilAborted(signal, pending);
}
/**
 * Best-effort cached cwd → `owner/repo` resolution that swallows any failure
 * (not a git checkout, no GitHub remote, `gh` unauthenticated, …) into
 * `undefined`. Use where the cwd repo is a convenience fallback, not a safety
 * check.
 */
export async function tryResolveCurrentRepo(cwd, signal) {
    try {
        return await resolveDefaultRepoMemoized(cwd, signal);
    }
    catch {
        return undefined;
    }
}
/**
 * Best-effort fresh cwd → `owner/repo` resolution for safety checks that must
 * reflect the repository currently mounted at `cwd`, not the process-lifetime
 * default-repo cache.
 */
export async function tryResolveCurrentRepoFresh(cwd, signal) {
    try {
        return await resolveGitHubRepo(cwd, undefined, undefined, signal);
    }
    catch {
        return undefined;
    }
}
export async function saveArtifactText(session, toolType, text) {
    const { path: artifactPath, id: artifactId } = (await session.allocateOutputArtifact?.(toolType)) ?? {};
    if (!artifactPath || !artifactId) {
        return undefined;
    }
    await Bun.write(artifactPath, text);
    return artifactId;
}
export function appendArtifactReference(text, artifactId, label) {
    if (!artifactId) {
        return text;
    }
    return `${text}\n\n${label}: artifact://${artifactId}`;
}
export function buildTextResult(text, sourceUrl, details, options) {
    const builder = toolResult(details).text(appendArtifactReference(text, options?.artifactId, options?.artifactLabel ?? "Saved artifact"));
    if (sourceUrl) {
        builder.sourceUrl(sourceUrl);
    }
    if (options?.useless) {
        builder.useless();
    }
    return builder.done();
}
