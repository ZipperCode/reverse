/**
 * Core i18n types and helpers for reverse.
 *
 * Supports "en" (default) and "zh-CN".
 * Respects REVERSE_LANG environment variable override.
 */

export type SupportedLocale = "en" | "zh-CN";

export const SUPPORTED_LOCALES: readonly SupportedLocale[] = ["en", "zh-CN"] as const;
export const DEFAULT_LOCALE: SupportedLocale = "en";

/**
 * Normalizes a locale string into a SupportedLocale.
 * Non-zh or unrecognized strings default to "en".
 */
export function normalizeLocale(locale: string | null | undefined): SupportedLocale {
	if (!locale) return DEFAULT_LOCALE;
	const trimmed = locale.trim().toLowerCase().replace(/_/g, "-");
	if (trimmed === "zh" || trimmed.startsWith("zh-")) {
		return "zh-CN";
	}
	return "en";
}

/**
 * Gets the current environment-defined locale (from REVERSE_LANG), if set.
 * Returns undefined if REVERSE_LANG is not set or empty.
 */
export function getEnvLocale(): SupportedLocale | undefined {
	const env = process.env.REVERSE_LANG;
	if (env && env.trim()) {
		return normalizeLocale(env);
	}
	return undefined;
}

/**
 * Resolves the effective locale given an explicit setting value.
 * Precedence:
 * 1. REVERSE_LANG environment variable (if present)
 * 2. Explicit configured language setting
 * 3. Default locale ("en")
 */
export function resolveEffectiveLocale(configuredLanguage?: string | null): SupportedLocale {
	const envLocale = getEnvLocale();
	if (envLocale) return envLocale;
	if (configuredLanguage) return normalizeLocale(configuredLanguage);
	return DEFAULT_LOCALE;
}

