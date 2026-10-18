/** Toggle an installed marketplace or npm plugin using the same precedence as the CLI. */
export async function setInstalledPluginEnabled(name, options) {
    if (options.marketplaceIds.has(name)) {
        await options.marketplace.setPluginEnabled(name, options.enabled, options.scope);
    }
    else {
        await options.npm.setEnabled(name, options.enabled);
    }
}
