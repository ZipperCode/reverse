import { isSettingsInitialized, Settings, settings } from "./settings";
import { cfgLanguage } from "../modes/settings";
import { resolveEffectiveLocale } from "@rva/utils/i18n";
let cachedReadOnlySettings;
/**
 * Returns effective settings for reading locale without writing or opening storage.
 * If global Settings singleton is initialized, reuses it.
 * Otherwise loads canonical read-only settings using existing Settings.loadReadOnly().
 */
export async function loadEffectiveSettings() {
    if (isSettingsInitialized()) {
        return Settings.instance;
    }
    if (!cachedReadOnlySettings) {
        cachedReadOnlySettings = await Settings.loadReadOnly();
    }
    return cachedReadOnlySettings;
}
/**
 * Resolves the effective UI locale (RVA_LANG > persisted config > default "en").
 * Uses canonical Settings (or loadReadOnly()) to respect profile, project, and overlay layers.
 */
export function getEffectiveLocale() {
    const env = process.env.RVA_LANG;
    if (env && env.trim()) {
        return resolveEffectiveLocale(env);
    }
    if (isSettingsInitialized()) {
        return resolveEffectiveLocale(cfgLanguage.get(settings));
    }
    if (cachedReadOnlySettings) {
        return resolveEffectiveLocale(cfgLanguage.get(cachedReadOnlySettings));
    }
    return resolveEffectiveLocale();
}
