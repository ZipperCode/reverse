import * as AIError from "@rva/ai/error";
import { getProviderDefinition } from "@rva/ai/registry";
function isOAuthAccount(auth) {
    return "credentialId" in auth;
}
function supportsProviderAuth(model) {
    return getProviderDefinition(model.provider)?.nativeAuthApis?.includes(model.api) ?? false;
}
/** Rejects changes to any durable OAuth identity field captured by preflight. */
export function assertSecurityIdentityMatches(account, resolution) {
    if (account.credentialId !== resolution.credentialId ||
        (account.accountId !== undefined && account.accountId !== resolution.accountId) ||
        (account.email !== undefined && account.email !== resolution.email) ||
        (account.organizationId !== undefined && account.organizationId !== resolution.orgId) ||
        (account.organizationName !== undefined && account.organizationName !== resolution.orgName)) {
        throw new Error("Security scan authentication identity mismatch");
    }
}
function selectOAuthAccount(authStorage, provider, requestedCredentialId, sessionId) {
    const accounts = authStorage.oauth.accounts(provider, sessionId);
    const selected = requestedCredentialId !== undefined
        ? accounts.find(account => account.credentialId === requestedCredentialId)
        : (accounts.find(account => account.active) ?? (accounts.length === 1 ? accounts[0] : undefined));
    if (selected) {
        const account = { provider, credentialId: selected.credentialId };
        if (selected.accountId !== undefined)
            account.accountId = selected.accountId;
        if (selected.email !== undefined)
            account.email = selected.email;
        if (selected.orgId !== undefined)
            account.organizationId = selected.orgId;
        if (selected.orgName !== undefined)
            account.organizationName = selected.orgName;
        return account;
    }
    if (requestedCredentialId !== undefined) {
        throw new Error(`Security OAuth credential ${requestedCredentialId} is not available for ${provider}`);
    }
    if (accounts.length > 0) {
        throw new Error(`Multiple OAuth accounts are available for ${provider}; supply credentialId to pin one exact account`);
    }
    return undefined;
}
/** Selects one exact OAuth row for native or Codex Security cloud scans. */
export function selectSecurityOAuthAccount(authStorage, provider, requestedCredentialId, sessionId) {
    const account = selectOAuthAccount(authStorage, provider, requestedCredentialId, sessionId);
    if (!account)
        throw new Error(`Security scans require a stored OAuth account for ${provider}`);
    return account;
}
/** Selects either one exact OAuth row or an explicitly supported provider-owned auth route. */
export function selectSecurityAuth(authStorage, model, requestedCredentialId, sessionId) {
    const account = selectOAuthAccount(authStorage, model.provider, requestedCredentialId, sessionId);
    if (account)
        return account;
    if (supportsProviderAuth(model))
        return { provider: model.provider, api: model.api };
    const nativeApis = getProviderDefinition(model.provider)?.nativeAuthApis;
    if (nativeApis) {
        throw new Error(`Security scans do not support provider authentication for ${model.provider}/${model.api}`);
    }
    throw new Error(`Security scans require a stored OAuth account for ${model.provider}`);
}
/** Resolves one pinned OAuth row and verifies that its durable identity has not changed. */
export async function resolveExactSecurityOAuthAccess(authStorage, account, options) {
    const resolution = await authStorage.oauth.accessById(account.provider, account.credentialId, options);
    if (!resolution)
        throw new Error("The pinned security OAuth credential is unavailable");
    assertSecurityIdentityMatches(account, resolution);
    if (!resolution.ok)
        throw new Error("The pinned security OAuth credential could not be resolved");
    return resolution;
}
/**
 * Build a request credential resolver pinned to one durable OAuth row.
 *
 * Initial resolution and refresh both target the same row. The auth driver's
 * final sibling-rotation step returns `undefined`, so an unavailable account
 * fails the scan rather than crossing an account/workspace boundary.
 */
export function createExactSecurityOAuthResolver(options) {
    const { account, authStorage } = options;
    return model => {
        if (model.provider !== account.provider) {
            throw new Error("Security scan authentication provider mismatch");
        }
        const resolver = async (context) => {
            if (context.lastChance)
                return undefined;
            const resolution = await resolveExactSecurityOAuthAccess(authStorage, account, {
                forceRefresh: context.error !== undefined,
                refreshReason: AIError.status(context.error) === 401 ? "auth-recovery" : undefined,
                signal: context.signal,
            });
            return resolution.accessToken;
        };
        return resolver;
    };
}
/**
 * Builds the scan resolver while preserving either its exact OAuth row or provider-owned auth boundary.
 */
export function createSecurityAuthResolver(options) {
    const { auth, authStorage, providerResolver } = options;
    if (isOAuthAccount(auth))
        return createExactSecurityOAuthResolver({ authStorage, account: auth });
    return model => {
        if (model.provider !== auth.provider) {
            throw new Error("Security scan authentication provider mismatch");
        }
        if (model.api !== auth.api) {
            throw new Error("Security scan authentication API mismatch");
        }
        if (!supportsProviderAuth(model)) {
            throw new Error(`Security scans do not support provider authentication for ${model.provider}/${model.api}`);
        }
        return providerResolver(model);
    };
}
