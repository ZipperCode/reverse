/** Base class for web search providers. */
export class SearchProvider {
    /**
     * Returns `true` when this provider should run when the user explicitly
     * selects it, even if {@link isAvailable} would reject it for the auto
     * chain. Providers with an unauthenticated fallback kept out of the auto
     * chain (e.g. Perplexity's anonymous ask endpoint) override this so explicit
     * selection still routes through it rather than failing.
     *
     * Defaults to mirroring {@link isAvailable}.
     */
    isExplicitlyAvailable(authStorage, model) {
        return this.isAvailable(authStorage, model);
    }
}
