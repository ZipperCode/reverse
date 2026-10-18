import { REMOTE_REFRESH_SENTINEL } from "@rva/ai";
import { isDefinitiveOAuthFailure } from "@rva/ai/error";
import { getActiveProfile } from "@rva/utils/dirs";
import { expandEnvVarsDeep } from "../discovery/helpers";
import { isManagedMCPOAuthCredentialId, mcpOAuthCredentialId, mcpOAuthCredentialProfile, mcpOAuthServerUrlFromCredentialId, refreshMCPOAuthToken, } from "./oauth-flow";
export function mcpOAuthCredentialIdsForServerUrl(serverUrl) {
    if (!serverUrl)
        return [];
    const ids = [];
    for (const url of [expandEnvVarsDeep(serverUrl), serverUrl]) {
        const id = mcpOAuthCredentialId(url);
        if (!ids.includes(id))
            ids.push(id);
    }
    return ids;
}
export function hasMcpAuthorizationHeader(config) {
    if (config.type !== "http" && config.type !== "sse")
        return false;
    return Object.keys(config.headers ?? {}).some(header => header.toLowerCase() === "authorization");
}
export function lookupMcpOAuthCredentialForServer(authStorage, auth, serverUrl, options = {}) {
    if (!authStorage)
        return undefined;
    if (auth && auth.type !== "oauth")
        return undefined;
    const urlKeyedCredentialIds = mcpOAuthCredentialIdsForServerUrl(serverUrl);
    if (auth?.credentialId &&
        (!auth.credentialId.startsWith("mcp_oauth:profile:") || urlKeyedCredentialIds.includes(auth.credentialId))) {
        const credential = authStorage.credentials.get(auth.credentialId);
        if (credential?.type === "oauth") {
            return { credentialId: auth.credentialId, credential };
        }
    }
    if (options.allowUrlKeyedFallback === false)
        return undefined;
    for (const credentialId of urlKeyedCredentialIds) {
        const credential = authStorage.credentials.get(credentialId);
        if (credential?.type === "oauth") {
            return { credentialId, credential };
        }
    }
    return undefined;
}
export function lookupMcpOAuthCredential(authStorage, config) {
    const auth = config.auth;
    if (config.type !== "http" && config.type !== "sse") {
        return lookupMcpOAuthCredentialForServer(authStorage, auth, undefined);
    }
    if (hasMcpAuthorizationHeader(config)) {
        return lookupMcpOAuthCredentialForServer(authStorage, auth, config.url, { allowUrlKeyedFallback: false });
    }
    return lookupMcpOAuthCredentialForServer(authStorage, auth, config.url);
}
export function selectMcpOAuthRefreshMaterial(credential, auth) {
    return credential.tokenUrl ? credential : auth;
}
/**
 * Refresh a stored MCP OAuth credential via the standard `refresh_token` grant.
 *
 * Refresh material is taken from the credential itself (self-contained modern
 * credentials embed `tokenUrl`/`clientId`/`clientSecret`/`resource`) or, for
 * legacy credentials that carry none, the server's `auth` block. Shared by the
 * local MCP manager and the `omp auth-broker serve` refresh path so a broker
 * with no access to the MCP config can still refresh `mcp_oauth:*` credentials
 * from the vault.
 *
 * `serverUrl` supplies the RFC 8707 fallback resource indicator when neither
 * the credential nor the auth block advertised one; the manager passes the
 * configured server URL, the broker recovers it from the credential id via
 * {@link mcpOAuthServerUrlFromCredentialId}.
 *
 * @throws when no usable refresh token or token endpoint is available.
 */
export function refreshManagedMcpOAuthCredential(credential, opts = {}) {
    const material = selectMcpOAuthRefreshMaterial(credential, opts.auth);
    const tokenUrl = material?.tokenUrl;
    if (!credential.refresh || !tokenUrl) {
        throw new Error("MCP OAuth credential is missing refresh material");
    }
    const authorizationUrl = material && "authorizationUrl" in material ? material.authorizationUrl : undefined;
    const resourceIsFallback = !material?.resource && Boolean(opts.serverUrl);
    const resource = material?.resource ?? (resourceIsFallback ? opts.serverUrl : undefined);
    return refreshMCPOAuthToken(tokenUrl, credential.refresh, material?.clientId, material?.clientSecret, resource, {
        authorizationUrl,
        stripSameOriginResource: resourceIsFallback,
        signal: opts.signal,
    });
}
async function refreshBrokeredMcpOAuthCredential(authStorage, credentialId, provider, signal) {
    const entry = await authStorage.oauth.refresh(credentialId, signal);
    if (entry.credential.type !== "oauth") {
        throw new Error(`Broker returned non-OAuth credential for ${provider}`);
    }
    const refreshed = entry.credential;
    return {
        access: refreshed.access,
        refresh: REMOTE_REFRESH_SENTINEL,
        expires: refreshed.expires,
        accountId: refreshed.accountId,
        email: refreshed.email,
        projectId: refreshed.projectId,
        enterpriseUrl: refreshed.enterpriseUrl,
    };
}
/**
 * Resolve and refresh one stored MCP OAuth row through the durable credential owner.
 *
 * Local rows use their embedded OAuth metadata; broker-redacted rows delegate the
 * grant to the broker. The MCP manager and standalone credential consumers share
 * this path so rotating refresh tokens are persisted before callers receive them.
 *
 * `serverUrl` supplies the RFC 8707 fallback resource indicator; the manager passes
 * the configured server URL for http/sse servers and `undefined` for stdio servers,
 * whose refresh must NOT advertise a resource. Standalone consumers that hold only
 * the credential id (`omp token`) set `recoverServerUrlFromCredentialId` to derive
 * the same fallback resource the http/sse client would use.
 */
export async function refreshStoredManagedMcpOAuthCredential(authStorage, provider, opts = {}) {
    const row = authStorage.credentials
        .list(provider)
        .find(entry => entry.credential.type === "oauth" && (opts.credentialId === undefined || entry.id === opts.credentialId));
    if (row?.credential.type !== "oauth") {
        return { credential: undefined, refreshed: false, removed: false };
    }
    const observedCredential = row.credential;
    const serverUrl = opts.serverUrl ??
        (opts.recoverServerUrlFromCredentialId ? mcpOAuthServerUrlFromCredentialId(provider) : undefined);
    return authStorage.oauth.refreshStored(provider, {
        credentialId: row.id,
        observedCredential,
        credentialFromRow: credential => credential,
        forceRefresh: opts.forceRefresh,
        refreshSkewMs: 5 * 60000,
        canRefresh: current => {
            const material = selectMcpOAuthRefreshMaterial(current, opts.auth);
            return Boolean(current.refresh && material?.tokenUrl);
        },
        refresh: (current, signal) => current.refresh === REMOTE_REFRESH_SENTINEL
            ? refreshBrokeredMcpOAuthCredential(authStorage, row.id, provider, signal)
            : refreshManagedMcpOAuthCredential(current, {
                serverUrl,
                auth: opts.auth,
                signal,
            }),
        mergeRefreshedCredential: (current, refreshed) => {
            const material = selectMcpOAuthRefreshMaterial(current, opts.auth);
            const resourceIsFallback = !material?.resource && Boolean(serverUrl);
            return {
                ...current,
                ...refreshed,
                tokenUrl: material?.tokenUrl,
                clientId: material?.clientId,
                clientSecret: material?.clientSecret,
                resource: resourceIsFallback ? undefined : material?.resource,
                authorizationUrl: material && "authorizationUrl" in material ? material.authorizationUrl : undefined,
            };
        },
        isDefinitiveFailure: error => isDefinitiveOAuthFailure(error instanceof Error ? error.message : String(error)),
        disabledCause: error => `oauth refresh failed: ${error instanceof Error ? error.message : String(error)}`,
        keepCredentialOnRefreshFailure: opts.keepCredentialOnRefreshFailure ?? true,
        onRefreshFailure: opts.onRefreshFailure,
    });
}
export async function removeManagedMcpOAuthCredential(authStorage, credentialId) {
    if (!isManagedMCPOAuthCredentialId(credentialId))
        return false;
    const scopedProfile = mcpOAuthCredentialProfile(credentialId);
    if (scopedProfile !== undefined && scopedProfile !== (getActiveProfile() ?? "default"))
        return false;
    if (authStorage.credentials.get(credentialId)?.type !== "oauth")
        return false;
    await authStorage.credentials.remove(credentialId);
    return true;
}
export async function removeManagedMcpOAuthCredentials(authStorage, credentialIds) {
    let removed = false;
    for (const credentialId of credentialIds) {
        removed = (await removeManagedMcpOAuthCredential(authStorage, credentialId)) || removed;
    }
    return removed;
}
