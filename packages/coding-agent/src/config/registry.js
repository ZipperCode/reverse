/**
 * Settings registry: typed handles for every setting.
 *
 * A setting is declared once with {@link register}, next to the domain that uses it, and read through
 * its handle against a scope — a {@link Settings} instance or anything carrying one (an
 * `AgentSession`, a `ToolSession`). Values are cached per scope and recomputed only when the scope's
 * layers change, so reads are safe on hot paths. {@link Derived.map} and {@link combine} build
 * memoized derivations; {@link Derived.listen} observes changes of a handle or derivation.
 *
 * @example
 * // lsp/settings.ts
 * export const cfgLspDiagnosticsOnWrite = register({
 * 	id: "lsp.diagnosticsOnWrite",
 * 	type: "boolean",
 * 	default: true,
 * 	ui: { tab: "files", group: "LSP", label: "Diagnostics on Write", description: "…" },
 * });
 *
 * // consumer
 * if (cfgLspDiagnosticsOnWrite.get(session)) …
 * cfgLspDiagnosticsOnWrite.listen(session, enabled => …);
 *
 * Declaration order is significant: the settings panel lists a tab's settings in registration order
 * (sections follow `TAB_GROUPS`), and `config/all-settings.ts` imports every domain in that order.
 */
import { logger, parseFlag } from "@rva/utils";
function settingsOf(scope) {
    return "settings" in scope ? scope.settings : scope;
}
/** Next {@link Derived.slot}; handles and derivations form a closed, module-level set. */
let nextSlot = 0;
/**
 * Read-only value computed from one or more settings. Reads are memoized per scope and recomputed
 * only when an input setting's effective value changes; derivation functions must be pure.
 */
export class Derived {
    /**
     * Process-unique index of this handle/derivation: its entry in every `Settings.valueCache`,
     * and for leaf settings its change-listener bucket.
     */
    slot = nextSlot++;
    /** Latest value in `scope`. */
    get(scope) {
        const settings = settingsOf(scope);
        const revision = settings.revision;
        const cached = settings.valueCache[this.slot];
        if (cached?.revision === revision)
            return cached.value;
        const inputs = this.inputs(settings);
        if (!cached) {
            const value = this.compute(inputs, settings);
            settings.valueCache[this.slot] = { revision, inputs, value };
            return value;
        }
        if (!sameInputs(cached.inputs, inputs)) {
            const value = this.compute(inputs, settings);
            // Keep identity stable across equal recomputations so downstream derivations and
            // listeners comparing by identity don't churn on unrelated layer rebuilds.
            if (!settingValuesEqual(cached.value, value))
                cached.value = value;
            cached.inputs = inputs;
        }
        cached.revision = revision;
        return cached.value;
    }
    /** Derives a memoized value from this one. */
    map(fn) {
        return new MappedValue(this, fn);
    }
    /**
     * Calls `onChange(next, previous)` whenever this value changes in `scope`, coalesced per microtask
     * so a bulk reload touching several inputs fires once. When `scope` owns a lifetime
     * ({@link SettingsScope.addDisposer}, e.g. an `AgentSession`), the listener is removed with it.
     * Errors and rejections are logged, never thrown. Returns an unsubscribe function.
     */
    listen(scope, onChange) {
        const settings = settingsOf(scope);
        const sources = this.sources;
        const run = (next, previous) => {
            try {
                const result = onChange(next, previous);
                if (result instanceof Promise)
                    result.catch(error => reportListenerError(sources, error));
            }
            catch (error) {
                reportListenerError(sources, error);
            }
        };
        let current = this.get(settings);
        let queued = false;
        let active = true;
        const stop = settings.onEffectiveChange(sources, () => {
            if (queued)
                return;
            queued = true;
            // One recompute per microtask, however many inputs a bulk reload touched.
            queueMicrotask(() => {
                queued = false;
                if (!active)
                    return;
                const next = this.get(settings);
                if (settingValuesEqual(next, current))
                    return;
                const previous = current;
                current = next;
                run(next, previous);
            });
        });
        const unsubscribe = () => {
            active = false;
            stop();
        };
        if ("settings" in scope)
            scope.addDisposer?.(unsubscribe);
        return unsubscribe;
    }
}
/**
 * Deep equality of setting values that, unlike `Bun.deepEquals`, also compares the key order of
 * plain objects: record order carries precedence (`edit.modelVariants` takes the first match), so a
 * reorder is a change. Values other than plain objects and arrays compare with `Bun.deepEquals`.
 */
export function settingValuesEqual(a, b) {
    if (Object.is(a, b))
        return true;
    if (isArray(a) && isArray(b)) {
        if (a.length !== b.length)
            return false;
        for (let i = 0; i < a.length; i++)
            if (!settingValuesEqual(a[i], b[i]))
                return false;
        return true;
    }
    if (!isPlainObject(a) || !isPlainObject(b))
        return Bun.deepEquals(a, b);
    // Positional key comparison needs `b`'s keys materialized; `a` streams.
    const otherKeys = Object.keys(b);
    let index = 0;
    for (const key in a) {
        if (key !== otherKeys[index++] || !settingValuesEqual(a[key], b[key]))
            return false;
    }
    return index === otherKeys.length;
}
function isArray(value) {
    return Array.isArray(value);
}
function isPlainObject(value) {
    if (typeof value !== "object" || value === null)
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function sameInputs(a, b) {
    if (a.length !== b.length)
        return false;
    for (let i = 0; i < a.length; i++)
        if (!Object.is(a[i], b[i]))
            return false;
    return true;
}
function reportListenerError(sources, error) {
    logger.warn("Settings: listener failed", {
        settings: sources.map(source => source.id).join(","),
        error: String(error),
    });
}
class MappedValue extends Derived {
    #source;
    #fn;
    constructor(source, fn) {
        super();
        this.#source = source;
        this.#fn = fn;
    }
    get sources() {
        return this.#source.sources;
    }
    inputs(settings) {
        return [this.#source.get(settings)];
    }
    compute(inputs) {
        return this.#fn(inputs[0]);
    }
}
class CombinedValue extends Derived {
    #keys;
    #parts;
    #fn;
    #sources;
    constructor(parts, fn) {
        super();
        this.#keys = Object.keys(parts);
        this.#parts = this.#keys.map(key => parts[key]);
        this.#fn = fn;
        this.#sources = [...new Set(this.#parts.flatMap(part => part.sources))];
    }
    get sources() {
        return this.#sources;
    }
    inputs(settings) {
        return this.#parts.map(part => part.get(settings));
    }
    compute(inputs) {
        const values = {};
        for (let i = 0; i < this.#keys.length; i++)
            values[this.#keys[i]] = inputs[i];
        return this.#fn(values);
    }
}
export function combine(parts, fn) {
    return fn ? new CombinedValue(parts, fn) : new CombinedValue(parts, values => values);
}
/**
 * Handle for one registered setting. Reads resolve, in precedence order: the definition's
 * environment variable, runtime override, `--config` overlay, project, global, then the default.
 */
export class Setting extends Derived {
    id;
    /** {@link id} split into its dotted path, as addressed within a settings layer. */
    segments;
    definition;
    #sources;
    /** Environment variable supplying this value, if declared (see {@link SettingEnv}). */
    envName;
    /** How {@link envName} yields to configured layers: `false` = it overrides them (see {@link SettingEnv}). */
    envFallback;
    #parseEnv;
    /** Last raw environment text parsed, and its result: the variable is parsed once per distinct value. */
    #envRaw;
    #envParsed;
    constructor(definition) {
        super();
        this.id = definition.id;
        this.segments = definition.id.split(".");
        this.definition = definition;
        this.#sources = [this];
        const env = definition.env;
        this.envName = typeof env === "string" ? env : env?.name;
        this.#parseEnv =
            typeof env === "object" && env.parse ? env.parse : env ? raw => this.#parseEnvText(raw) : undefined;
        this.envFallback = typeof env === "object" ? (env.fallback ?? false) : false;
    }
    get sources() {
        return this.#sources;
    }
    /** Fresh copy of the default value (arrays/records are cloned so callers may mutate). */
    get default() {
        const value = this.definition.default;
        return (typeof value === "object" && value !== null ? structuredClone(value) : value);
    }
    /** Declared value kind. */
    get type() {
        return this.definition.type;
    }
    /** Allowed values for enum settings. */
    get enumValues() {
        return this.definition.type === "enum" ? this.definition.values : undefined;
    }
    /** Settings-panel metadata; `undefined` for config-file-only settings. */
    get ui() {
        return this.definition.ui;
    }
    /** Whether the value is a credential (explicit marker or legacy `ui.secret`). */
    get isCredential() {
        return this.definition.credential === true || this.ui?.secret === true;
    }
    /** Value supplied by the environment variable, or `undefined` when unset or unparseable. */
    envValue() {
        if (!this.envName || !this.#parseEnv)
            return undefined;
        const raw = Bun.env[this.envName];
        if (raw === undefined)
            return undefined;
        if (raw !== this.#envRaw) {
            this.#envParsed = this.#parseEnv(raw);
            this.#envRaw = raw;
        }
        return this.#envParsed;
    }
    /** Env value that currently takes effect in `scope`: a fallback env yields to a configured layer. */
    #effectiveEnv(scope) {
        const value = this.envValue();
        if (value === undefined || !this.envFallback)
            return value;
        const settings = settingsOf(scope);
        if (this.envFallback === true)
            return settings.isConfigured(this) ? undefined : value;
        const configured = settings.rawValue(this);
        return configured === undefined || (typeof configured === "string" && configured.trim() === "")
            ? value
            : undefined;
    }
    get(scope) {
        return this.#effectiveEnv(scope) ?? super.get(scope);
    }
    /**
     * Value from the settings layers alone (runtime, `--config` overlay, project, global, default),
     * ignoring the environment variable — what the settings panel shows and edits.
     */
    layered(scope) {
        return super.get(scope);
    }
    /**
     * Parses user- or agent-supplied text (`omp config set`, `write cfg://…`) into a value of this
     * setting's type. Booleans accept true/false, yes/no, on/off, 1/0; arrays and records take JSON;
     * strings and enums accept bare text or a JSON-quoted string.
     *
     * @throws Error when the text does not fit the type or enum values.
     */
    parse(text) {
        const value = this.#parseText(text);
        return (this.definition.normalize ? this.definition.normalize(value) : value);
    }
    #parseText(text) {
        const trimmed = text.trim();
        switch (this.definition.type) {
            case "boolean": {
                const lower = trimmed.toLowerCase();
                if (["true", "1", "yes", "on"].includes(lower))
                    return true;
                if (["false", "0", "no", "off"].includes(lower))
                    return false;
                throw new Error(`Invalid boolean value: ${text}. Use true/false, yes/no, on/off, or 1/0`);
            }
            case "number": {
                const parsed = trimmed === "" ? Number.NaN : Number(trimmed);
                if (!Number.isFinite(parsed))
                    throw new Error(`Invalid number: ${text}`);
                return parsed;
            }
            case "array":
            case "record": {
                let parsed;
                try {
                    parsed = JSON.parse(trimmed);
                }
                catch {
                    throw new Error(`Invalid ${this.definition.type} JSON: ${text}`);
                }
                if (!this.accepts(parsed))
                    throw new Error(`Invalid ${this.definition.type} JSON: ${text}`);
                return parsed;
            }
            case "string":
            case "enum": {
                let value = trimmed;
                if (value.startsWith('"')) {
                    try {
                        const unquoted = JSON.parse(value);
                        if (typeof unquoted === "string")
                            value = unquoted;
                    }
                    catch {
                        // Not a JSON string literal; keep the bare text.
                    }
                }
                const valid = this.enumValues;
                if (valid && !valid.includes(value)) {
                    throw new Error(`Invalid value: ${text}. Valid values: ${valid.join(", ")}`);
                }
                return value;
            }
        }
    }
    /** Whether `value` fits this setting's declared type (and enum values). */
    accepts(value) {
        switch (this.definition.type) {
            case "boolean":
                return typeof value === "boolean";
            case "number":
                return typeof value === "number" && Number.isFinite(value);
            case "string":
                return typeof value === "string";
            case "enum":
                return typeof value === "string" && this.definition.values.includes(value);
            case "array":
                return Array.isArray(value);
            case "record":
                return typeof value === "object" && value !== null && !Array.isArray(value);
        }
    }
    #parseEnvText(raw) {
        if (this.definition.type === "boolean")
            return raw === "" ? undefined : parseFlag(raw);
        if (raw.trim() === "")
            return undefined;
        try {
            return this.parse(raw);
        }
        catch {
            return undefined;
        }
    }
    inputs(settings) {
        return [settings.rawValue(this)];
    }
    compute(inputs, settings) {
        const raw = inputs[0];
        if (raw === undefined || this.accepts(raw)) {
            // A fixed value re-arms this instance's warning, so breaking it again is reported again.
            settings.warnState.invalid.delete(this.id);
            return raw === undefined ? this.default : raw;
        }
        const warned = settings.warnState.invalid;
        if (!warned.has(this.id) || !Bun.deepEquals(warned.get(this.id), raw)) {
            warned.set(this.id, raw);
            logger.warn("Settings: ignoring invalid value, using the default", { setting: this.id, value: raw });
        }
        return this.default;
    }
    /**
     * Registry plumbing run by `Settings` before every write (handle writes and constructor overrides).
     *
     * @throws Error when `value` names an entry outside {@link ArrayDefinition.items}, fails `validate`
     * (checked first for their specific messages), or does not fit the declared type ({@link accepts}).
     */
    assertWritable(value) {
        const unknown = this.#unknownItems(value);
        if (unknown.length > 0 && this.definition.type === "array" && this.definition.items) {
            const { values, label } = this.definition.items;
            const noun = unknown.length === 1 ? label : `${label}s`;
            throw new Error(`Unknown ${noun}: ${unknown.join(", ")}. Valid ${label}s: ${values.join(", ")}`);
        }
        this.definition.validate?.(value);
        if (!this.accepts(value)) {
            const expected = this.enumValues ? `one of ${this.enumValues.join(", ")}` : `a ${this.definition.type}`;
            throw new Error(`Invalid value for ${this.id}: ${Bun.inspect(value)} (expected ${expected})`);
        }
    }
    /**
     * Registry plumbing run by `Settings` on every load/reload for the value `settings` configures.
     *
     * @throws Error when `raw` fails `validate`. Unknown {@link ArrayDefinition.items} entries only warn,
     * once each per instance.
     */
    checkConfigured(settings, raw) {
        this.definition.validate?.(raw);
        const unknown = this.#unknownItems(raw);
        const items = settings.warnState.items;
        let warned = items.get(this.id);
        // Entries no longer configured re-arm, so adding one back is reported again.
        for (const entry of warned ?? [])
            if (!unknown.includes(entry))
                warned?.delete(entry);
        if (unknown.length === 0)
            return;
        if (!warned) {
            warned = new Set();
            items.set(this.id, warned);
        }
        const label = this.definition.type === "array" ? this.definition.items?.label : undefined;
        for (const entry of unknown) {
            if (warned.has(entry))
                continue;
            warned.add(entry);
            logger.warn(`Settings: unknown ${label} ${entry}`, { setting: this.id });
        }
    }
    /** Entries of `value` outside the declared {@link ArrayDefinition.items}, formatted for messages. */
    #unknownItems(value) {
        const items = this.definition.type === "array" ? this.definition.items : undefined;
        if (!items || !Array.isArray(value))
            return [];
        const unknown = new Set();
        for (const entry of value) {
            if (!items.values.includes(entry))
                unknown.add(typeof entry === "string" ? JSON.stringify(entry) : String(entry));
        }
        return [...unknown];
    }
    /**
     * Persists `value` to the global config; `undefined` removes the key ({@link unset}).
     *
     * @throws Error when the value does not fit the definition (see {@link assertWritable}).
     */
    set(scope, value) {
        if (value === undefined)
            settingsOf(scope).unsetGlobalValue(this);
        else
            settingsOf(scope).writeValue(this, this.#normalize(value), "global");
    }
    /**
     * Runtime-only override (not persisted); `undefined` removes it ({@link clearOverride}).
     *
     * @throws Error when the value does not fit the definition (see {@link assertWritable}).
     */
    override(scope, value) {
        if (value === undefined)
            settingsOf(scope).clearOverrideValue(this);
        else
            settingsOf(scope).writeValue(this, this.#normalize(value), "override");
    }
    /**
     * Removes the key from the persisted global config: any other layer or environment variable that
     * configures this setting still applies, otherwise the default.
     */
    unset(scope) {
        settingsOf(scope).unsetGlobalValue(this);
    }
    /**
     * Persists one entry of this record setting to the global config; `undefined` removes the entry.
     * The record's other entries, persisted or supplied by another layer, stay as they are.
     *
     * @throws Error when this is not a record setting or the entry does not fit the definition.
     */
    setEntry(scope, key, value) {
        settingsOf(scope).writeEntry(this, key, value === undefined ? undefined : this.#normalizeEntry(key, value));
    }
    /**
     * Adds (`member`) or removes `item` in this list setting's persisted global value, leaving every
     * other item as it is.
     *
     * @throws Error when this is not a list setting or the resulting list does not fit the definition.
     */
    setMember(scope, item, options) {
        settingsOf(scope).writeMember(this, item, options);
    }
    /**
     * Holds the default as a runtime override only while no persisted layer — global, project,
     * `--config` overlay — configures this setting; no-op when the environment or any layer already
     * configures it, and dropped by a global write ({@link set}, {@link setEntry}, {@link setMember}) or
     * {@link unset} of this setting or when a reload or re-scope configures it (protocol-host defaults).
     */
    pinDefault(scope) {
        if (this.envValue() === undefined)
            settingsOf(scope).pinDefaultValue(this);
    }
    #normalize(value) {
        return this.definition.normalize ? this.definition.normalize(value) : value;
    }
    /** `value` as the `key` entry of this record, normalized like a whole-record write. */
    #normalizeEntry(key, value) {
        const normalize = this.definition.normalize;
        return normalize ? normalize({ [key]: value })[key] : value;
    }
    /** Removes a runtime override, restoring the persisted/default value. */
    clearOverride(scope) {
        settingsOf(scope).clearOverrideValue(this);
    }
    /** Whether the environment or any settings layer (runtime, overlay, project, global) sets this value. */
    isConfigured(scope) {
        return this.envValue() !== undefined || settingsOf(scope).isConfigured(this);
    }
    /** Layer supplying the effective value. */
    provenance(scope) {
        return this.#effectiveEnv(scope) !== undefined ? "env" : settingsOf(scope).getProvenance(this);
    }
}
// ═══════════════════════════════════════════════════════════════════════════
// Registry
// ═══════════════════════════════════════════════════════════════════════════
const byId = new Map();
const ordered = [];
/**
 * Declares a setting and returns its typed handle.
 *
 * @throws Error when `id` is already registered.
 */
export function register(definition) {
    if (byId.has(definition.id))
        throw new Error(`Setting "${definition.id}" is registered twice`);
    const handle = new Setting(definition);
    byId.set(definition.id, handle);
    ordered.push(handle);
    return handle;
}
/** Handle for `id`, or `undefined` when no setting has that id. */
export function lookup(id) {
    return byId.get(id);
}
/** Every registered setting, in declaration order. */
export function all() {
    return ordered;
}
/**
 * Registry plumbing run by `Settings` when it derives `target` from `source` (overlays, cwd clones):
 * `target` takes over `source`'s warn-once diagnostics, so the values it inherits are not reported again.
 */
export function inheritWarnings(target, source) {
    const { invalid, items } = target.warnState;
    invalid.clear();
    items.clear();
    for (const [id, value] of source.warnState.invalid)
        invalid.set(id, value);
    for (const [id, entries] of source.warnState.items)
        items.set(id, new Set(entries));
}
const effects = new Set();
/** Outstanding {@link bindEffects} holds, oldest first; the last one drives effects. */
const effectHolds = [];
let effectBinding;
/**
 * Declares a process-wide side effect of a setting (theme, credential redaction, request limits…).
 * It follows the settings instance bound with {@link bindEffects}: applied immediately on bind and
 * on every change. Unlike {@link Derived.listen}, application is synchronous — it lands inside the
 * write or reload that caused it, so code reading the affected process state right after
 * `set`/`override` sees the new value. Errors and rejections are logged, never thrown. Subagent
 * overlays and isolated instances never drive effects. Returns a function removing the effect
 * (module-level declarations never call it; test-scoped effects do).
 */
export function effect(value, apply) {
    let applied;
    const run = (next) => {
        applied = { value: next };
        try {
            const result = apply(next);
            if (result instanceof Promise)
                result.catch(error => reportListenerError(value.sources, error));
        }
        catch (error) {
            reportListenerError(value.sources, error);
        }
    };
    const entry = {
        bind: settings => {
            let current = value.get(settings);
            const unsubscribe = settings.onEffectiveChange(value.sources, () => {
                const next = value.get(settings);
                if (settingValuesEqual(next, current))
                    return;
                current = next;
                run(next);
            });
            run(current);
            return unsubscribe;
        },
        reset: defaults => {
            if (!applied)
                return;
            const next = value.get(defaults);
            if (!settingValuesEqual(next, applied.value))
                run(next);
        },
    };
    effects.add(entry);
    effectBinding?.stops.set(entry, entry.bind(effectBinding.settings));
    return () => {
        effects.delete(entry);
        effectBinding?.stops.get(entry)?.();
        effectBinding?.stops.delete(entry);
    };
}
/**
 * Makes `settings` drive every {@link effect} (the process-global instance, the top-level session's
 * settings in SDK embeddings, an ACP session's workspace settings) until the returned release is
 * called. Holds stack: the most recent outstanding hold drives effects, and releasing it hands them
 * back to the previous hold (re-applying its values). Holding the same instance twice takes two
 * holds; the release is idempotent and never ends another holder's hold.
 */
export function bindEffects(settings) {
    const hold = { settings };
    effectHolds.push(hold);
    syncEffectBinding();
    return () => {
        const index = effectHolds.indexOf(hold);
        if (index === -1)
            return;
        effectHolds.splice(index, 1);
        syncEffectBinding();
    };
}
/** Points effects at the newest hold's instance, re-subscribing only when that instance changed. */
function syncEffectBinding() {
    const settings = effectHolds.at(-1)?.settings;
    if (effectBinding?.settings === settings)
        return;
    stopEffectBinding();
    if (!settings)
        return;
    const binding = { settings, stops: new Map() };
    effectBinding = binding;
    // An effect declared while binding binds itself (see `effect`); the guard skips it here.
    for (const entry of effects) {
        if (!binding.stops.has(entry))
            binding.stops.set(entry, entry.bind(settings));
    }
}
function stopEffectBinding() {
    const binding = effectBinding;
    effectBinding = undefined;
    for (const stop of binding?.stops.values() ?? [])
        stop();
}
/** Instance currently driving effects, if any. */
export function effectsSettings() {
    return effectBinding?.settings;
}
/** Drops every {@link bindEffects} hold, so no instance drives effects (test teardown). */
export function unbindEffects() {
    effectHolds.length = 0;
    stopEffectBinding();
}
/**
 * Test reset: drops every effect hold and re-applies each effect whose last applied value differs
 * from the one `defaults` yields (restoring process state an earlier test changed).
 */
export function resetRegistryForTest(defaults) {
    unbindEffects();
    for (const entry of effects)
        entry.reset(defaults);
}
