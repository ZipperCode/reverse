/** A translated option label/description, keyed by the option's stored value. */
export interface OptionTranslation {
	readonly label?: string;
	readonly description?: string;
}

/** Chinese display text for one setting; omitted fields fall back to the English definition. */
export interface SettingTranslation {
	readonly label?: string;
	readonly description?: string;
	readonly warning?: string;
	/** Stored option value -> translated label/description. */
	readonly options?: Record<string, OptionTranslation>;
}
