/**
 * Settings declared by this domain (see `config/registry.ts`). Declaration order is the
 * settings-panel order; `config/all-settings.ts` registers every domain.
 */
import { register } from "../config/registry";

const EMPTY_STRING_ARRAY: string[] = [];

export const cfgStreamRedactPatterns = register({
	id: "stream.redactPatterns",
	type: "array",
	default: EMPTY_STRING_ARRAY,
	ui: {
		tab: "interaction",
		group: "Stream",
		label: "Extra Redaction Patterns",
		description:
			"Additional regular expressions redacted from every streamed row, on top of env/secrets.yml values and built-in credential shapes",
	},
});
