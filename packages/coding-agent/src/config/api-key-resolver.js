import { markAfterSiblingWait } from "@rva/ai/auth-retry";
import * as AIError from "@rva/ai/error";
import { isUsageLimitOutcome } from "@rva/ai/error/rate-limit";
/**
 * Default implementation of {@link ApiKeyResolverRegistry.resolver}.
 * Also usable standalone for structural registries that don't carry the method.
 */
export function createApiKeyResolver(registry, provider, options = {}) {
    const { sessionId, baseUrl, modelId } = options;
    const resolveKey = (forceRefresh, signal, refreshReason) => registry.getApiKeyWithCredentialForProvider(provider, sessionId, {
        baseUrl,
        modelId,
        forceRefresh,
        signal,
        refreshReason,
    });
    return async ({ lastChance, error, signal, previousKey }) => {
        if (error === undefined) {
            return resolveKey(undefined);
        }
        if (lastChance) {
            // Account constraint (401 / usage / account-rate-limit): rotate to a
            // sibling credential. We do NOT honor the failed account's retry-after
            // here — if a sibling exists we switch immediately, and `rotate` itself
            // sleeps out a sibling block that clears within seconds. Longer
            // no-sibling backoff is owned by `markUsageLimitReached` (default +
            // server usage-report reset) and the outer whole-turn retry layer.
            const rotation = await registry.authStorage.limits.rotate(provider, sessionId, {
                error,
                modelId,
                signal,
                apiKey: previousKey,
            });
            if (!rotation.switched) {
                const status = AIError.status(error);
                const message = error instanceof Error ? error.message : typeof error === "string" ? error : undefined;
                // No sibling for an account-quota failure: stop so the outer
                // whole-turn retry layer can honor the recorded backoff. A hard
                // auth decline can instead mean a peer refreshed the bearer.
                if (AIError.isUsageLimit(error) || isUsageLimitOutcome(status, message))
                    return undefined;
            }
            const resolved = await resolveKey(undefined);
            return rotation.afterSiblingWait ? markAfterSiblingWait(resolved) : resolved;
        }
        return resolveKey(true, signal, AIError.status(error) === 401 ? "auth-recovery" : undefined);
    };
}
