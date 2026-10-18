import { replaceTabs, shortenPath, TRUNCATE_LENGTHS, truncateToWidth } from "@rva/tui/render/render-utils";
/** Formats extension load failures for user-visible startup diagnostics. */
export function formatExtensionLoadNotifications(errors) {
    const messages = [];
    for (const { path, error } of errors) {
        const displayPath = truncateToWidth(replaceTabs(shortenPath(path)), TRUNCATE_LENGTHS.CONTENT);
        const displayError = truncateToWidth(replaceTabs(error.replace(/\s+/g, " ").trim()), TRUNCATE_LENGTHS.LONG);
        messages.push(`Failed to load extension ${displayPath}: ${displayError}`);
    }
    return messages;
}
