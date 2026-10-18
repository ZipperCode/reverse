/**
 * X (formerly Twitter) URL vocabulary shared by the X reader
 * (`web/scrapers/twitter.ts`) and the xAI search provider's `x_search` mapping
 * (`web/search/providers/xai.ts`): which hosts serve X, which path segments are
 * account handles, and which page a URL shows.
 */
/** Hosts serving X pages; developer/API subdomains are ordinary web pages. */
const X_HOSTS = {
    "x.com": true,
    "twitter.com": true,
    "www.x.com": true,
    "www.twitter.com": true,
    "mobile.x.com": true,
    "mobile.twitter.com": true,
};
/** First path segments that are X app routes, never account handles. */
const APP_ROUTES = {
    about: true,
    account: true,
    bookmarks: true,
    communities: true,
    compose: true,
    download: true,
    explore: true,
    hashtag: true,
    home: true,
    i: true,
    intent: true,
    jobs: true,
    login: true,
    logout: true,
    messages: true,
    notifications: true,
    privacy: true,
    search: true,
    settings: true,
    share: true,
    signup: true,
    tos: true,
};
const HANDLE_PATTERN = /^[A-Za-z0-9_]{1,15}$/;
const POST_ID_PATTERN = /^\d{1,20}$/;
/** Profile tabs after the handle (`/<handle>/with_replies`); a bare handle shows posts. */
const PROFILE_TABS = { with_replies: "replies", media: "media" };
/** Whether a bare, lowercased host serves X pages. */
export function isXHost(host) {
    return X_HOSTS[host] === true;
}
/** The account handle a path segment names, or `undefined` for app routes and invalid handles. */
export function xHandle(segment) {
    if (!segment || !HANDLE_PATTERN.test(segment) || APP_ROUTES[segment.toLowerCase()] === true)
        return undefined;
    return segment;
}
/**
 * Classify an X URL for the X reader.
 *
 * Returns `null` for non-X URLs so other handlers can claim them. A missing
 * scheme (`www.x.com/jack`, as read paths may omit it) means `https`.
 *
 * @example
 * parseXUrl("https://x.com/jack/status/20/photo/1"); // { kind: "post", id: "20" }
 * parseXUrl("https://x.com/search?q=omp&f=live"); // { kind: "search", query: "omp", latest: true }
 */
export function parseXUrl(url) {
    let parsed;
    try {
        parsed = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`);
    }
    catch {
        return null;
    }
    if (!isXHost(parsed.hostname.toLowerCase()))
        return null;
    const segments = parsed.pathname.split("/").filter(Boolean);
    const [first, second] = segments;
    const filter = parsed.searchParams.get("f");
    if (first === "search") {
        const query = parsed.searchParams.get("q")?.trim();
        if (!query)
            return { kind: "unsupported" };
        if (filter === "user")
            return { kind: "users", query };
        if (filter === "media")
            return { kind: "search", query: `${query} filter:media`, latest: true };
        return { kind: "search", query, latest: filter === "live" };
    }
    if (first === "hashtag" && second)
        return { kind: "search", query: `#${second}`, latest: filter === "live" };
    // `/<handle>/status/<id>[/photo/1]`, `/i/status/<id>`, `/i/web/status/<id>`
    const [status, id] = segments.slice(first === "i" && second === "web" ? 2 : 1);
    if (status === "status" && id && POST_ID_PATTERN.test(id))
        return { kind: "post", id };
    const handle = xHandle(first);
    const tab = second === undefined ? "posts" : Object.hasOwn(PROFILE_TABS, second) ? PROFILE_TABS[second] : undefined;
    if (handle && tab && segments.length <= 2)
        return { kind: "profile", handle, tab };
    return { kind: "unsupported" };
}
