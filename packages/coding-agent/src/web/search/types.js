export * from "@rva/tui/tools/web-search-types";
/** Default hard timeout for each web-search provider transport. */
export const DEFAULT_WEB_SEARCH_TIMEOUT_SECONDS = 60;
/** Maximum configurable hard timeout for each web-search provider transport. */
export const MAX_WEB_SEARCH_TIMEOUT_SECONDS = 300;
/** Provider-specific error with optional HTTP status */
export class SearchProviderError extends Error {
    provider;
    status;
    constructor(provider, message, status) {
        super(message);
        this.provider = provider;
        this.status = status;
        this.name = "SearchProviderError";
    }
}
