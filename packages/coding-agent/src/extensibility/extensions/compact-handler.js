export async function runExtensionCompact(session, instructionsOrOptions) {
    const instructions = typeof instructionsOrOptions === "string" ? instructionsOrOptions : undefined;
    const options = instructionsOrOptions && typeof instructionsOrOptions === "object" ? instructionsOrOptions : undefined;
    await session.compact(instructions, options);
}
/**
 * Helper for wiring the `setModel` action of an {@link ExtensionContext}.
 *
 * Returns false when no API key is available for the requested model.
 */
export async function runExtensionSetModel(session, model) {
    const key = await session.modelRegistry.getApiKey(model);
    if (!key)
        return false;
    await session.setModel(model);
    return true;
}
