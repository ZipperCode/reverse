/**
 * Defines lazy proxy properties on a wrapper so it forwards to the underlying tool.
 */
import { isArkSchema } from "@reverse/ai/utils/schema";

const ENUMERABLE_PROTOTYPE_TOOL_KEYS: Readonly<Record<string, true>> = {
	name: true,
	description: true,
	parameters: true,
	strict: true,
	deferLoading: true,
	customFormat: true,
	customWireName: true,
	native: true,
	examples: true,
	label: true,
	hidden: true,
	readsSkillUris: true,
	deferrable: true,
	loadMode: true,
	summary: true,
	delegationGuidance: true,
	concurrency: true,
	speculation: true,
	lenientArgValidation: true,
	interruptible: true,
	intent: true,
	approval: true,
};

export function applyToolProxy<TTool extends object>(tool: TTool, wrapper: object): void {
	const visited = new Set<PropertyKey>();
	let current: object | null = tool;

	while (current && current !== Object.prototype) {
		const isOwn = current === tool;
		for (const key of Reflect.ownKeys(current)) {
			if (key === "constructor" || visited.has(key) || key in wrapper) {
				continue;
			}
			const descriptor = Object.getOwnPropertyDescriptor(current, key);
			if (!descriptor) continue;
			visited.add(key);
			const enumerable = isOwn
				? descriptor.enumerable === true
				: typeof descriptor.get === "function" &&
					typeof key === "string" &&
					ENUMERABLE_PROTOTYPE_TOOL_KEYS[key] === true;
			Object.defineProperty(wrapper, key, {
				get() {
					const value = (tool as Record<PropertyKey, unknown>)[key];
					if (typeof value !== "function") return value;
					// Callable schema values (ArkType `Type`, e.g. the `parameters` schema)
					// must pass through untouched: `bind()` returns a bare bound function
					// that drops the schema surface (`toJsonSchema`/`assert`/own keys), so a
					// bound schema later stringifies to `undefined` and poisons wire-schema
					// and token accounting. Only genuine methods are bound so `this` is
					// preserved through the wrapper.
					if (isArkSchema(value) || typeof value.bind !== "function") return value;
					return value.bind(tool);
				},
				enumerable,
				configurable: true,
			});
		}
		current = Object.getPrototypeOf(current);
	}
}
