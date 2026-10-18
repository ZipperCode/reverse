import { ThinkingLevel } from "@rva/agent";
import { THINKING_EFFORTS } from "@rva/catalog/effort";
import { AUTO_THINKING, parseConfiguredThinkingLevel } from "@rva/tui/thinking";
import { isRecord } from "@rva/utils";
import { cfgDefaultThinkingLevel } from "../session/settings";
import { pickDefaultAvailableModel, resolveModelRoleValue } from "./model-resolver";
import { cfgModelPresets, cfgModelRoleStorage } from "./model-settings";
/** Preset names: a letter, then letters, digits, `-` or `_` (the model hub's role-name rule). */
const PRESET_NAME_PATTERN = /^[a-zA-Z][\w-]*$/;
export function isValidModelPresetName(name) {
    return PRESET_NAME_PATTERN.test(name);
}
/** Validate one raw `modelPresets` entry; hand-edited config can hold anything. */
function parseModelPreset(raw) {
    if (!isRecord(raw))
        return "it is not a mapping";
    const roles = raw.modelRoles;
    if (!isRecord(roles))
        return "`modelRoles` is missing or not a mapping";
    const modelRoles = {};
    for (const role of Object.keys(roles)) {
        const value = roles[role];
        if (typeof value !== "string" || value.trim() === "")
            return `role \`${role}\` is not a model selector`;
        modelRoles[role] = value;
    }
    const level = raw.defaultThinkingLevel;
    if (level === undefined)
        return { modelRoles };
    const thinking = typeof level === "string" ? parseConfiguredThinkingLevel(level) : undefined;
    if (thinking === undefined || !isDefaultThinkingLevel(thinking)) {
        return "`defaultThinkingLevel` is not a thinking level";
    }
    return { modelRoles, defaultThinkingLevel: thinking };
}
function isDefaultThinkingLevel(level) {
    return level === AUTO_THINKING || THINKING_EFFORTS.some(effort => effort === level);
}
/** Look a preset up whole from the highest layer owning its name — same-name entries never merge. */
export function getModelPreset(settings, name) {
    const owned = settings.getOwnedModelPreset(name);
    if (!owned)
        return { kind: "missing" };
    const parsed = parseModelPreset(owned.entry);
    return typeof parsed === "string" ? { kind: "invalid", reason: parsed } : { kind: "found", preset: parsed };
}
/** Saved preset names, sorted; names a `--config`/runtime `null` tombstone hides are left out. */
export function getModelPresetNames(settings) {
    return Object.keys(cfgModelPresets.get(settings))
        .filter(name => settings.getOwnedModelPreset(name) !== undefined)
        .sort((a, b) => a.localeCompare(b));
}
/**
 * First saved preset (by name) the current setup matches: identical effective
 * role assignments and, when the preset records one, the same default thinking
 * level. Undefined when the roles were edited past every preset.
 */
export function findActiveModelPreset(settings) {
    const roles = settings.getModelRoles();
    // Same filter as `saveModelPreset`: empty selectors are never stored.
    const roleIds = Object.keys(roles).filter(role => roles[role]);
    const thinking = cfgDefaultThinkingLevel.get(settings);
    return getModelPresetNames(settings).find(name => {
        const lookup = getModelPreset(settings, name);
        if (lookup.kind !== "found")
            return false;
        const { modelRoles, defaultThinkingLevel } = lookup.preset;
        if (defaultThinkingLevel !== undefined && defaultThinkingLevel !== thinking)
            return false;
        const presetIds = Object.keys(modelRoles);
        return (presetIds.length === roleIds.length &&
            presetIds.every(role => Object.hasOwn(roles, role) && roles[role] === modelRoles[role]));
    });
}
/**
 * Save the effective role assignments and `defaultThinkingLevel` as `name` in the
 * global config, overwriting a preset of the same name. Only this entry is
 * written, so presets defined by a project config are never copied globally.
 *
 * @throws Error when `name` is not a valid preset name.
 */
export function saveModelPreset(settings, name) {
    if (!isValidModelPresetName(name)) {
        throw new Error(`Invalid preset name "${name}": use a letter, then letters, digits, - or _`);
    }
    const modelRoles = {};
    for (const [role, selector] of Object.entries(settings.getModelRoles())) {
        if (selector)
            modelRoles[role] = selector;
    }
    const preset = { modelRoles, defaultThinkingLevel: cfgDefaultThinkingLevel.get(settings) };
    cfgModelPresets.setEntry(settings, name, preset);
    return preset;
}
/**
 * Delete `name` from the global config. A preset only a project (or `--config`)
 * file defines is reported as `project`: it has to be removed from that file.
 * The same applies when another layer defines the same name: the global entry is
 * removed but the preset keeps listing, so `project` is reported instead of a
 * false `deleted`.
 */
export function deleteModelPreset(settings, name) {
    const global = settings.getGlobalSettings().modelPresets;
    if (isRecord(global) && Object.hasOwn(global, name)) {
        cfgModelPresets.setEntry(settings, name, undefined);
        return settings.getOwnedModelPreset(name) ? "project" : "deleted";
    }
    return settings.getOwnedModelPreset(name) ? "project" : "missing";
}
/**
 * Layer above global config that still defines preset `name`, if any — so a
 * global save can warn that the just-saved entry is shadowed and won't apply.
 */
export function modelPresetShadowOwner(settings, name) {
    const owned = settings.getOwnedModelPreset(name);
    return owned && owned.source !== "global" ? owned.source : undefined;
}
const SOURCE_LABELS = {
    env: "environment",
    runtime: "command line",
    overlay: "--config file",
    project: "project config",
    global: "global config",
    default: "default",
};
/** Status line after saving `name`, naming the higher layer whose same-name preset still wins, if any. */
export function modelPresetSavedMessage(settings, name) {
    const owner = modelPresetShadowOwner(settings, name);
    if (owner === undefined)
        return `Saved model preset "${name}"`;
    return `Saved model preset "${name}" to the global config, but the ${SOURCE_LABELS[owner]} still defines a preset of the same name, which takes precedence`;
}
/** Serialize default-role mutations with the model hub's assign/unassign paths. */
let modelRoleMutationTail = Promise.resolve();
export async function acquireModelRoleMutation() {
    const previous = modelRoleMutationTail;
    const { promise, resolve } = Promise.withResolvers();
    modelRoleMutationTail = previous.then(() => promise);
    await previous;
    return resolve;
}
function presetCandidates(session) {
    const scoped = session.scopedModels.map(entry => entry.model);
    return scoped.length > 0 ? scoped : session.getAvailableModels();
}
function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
}
/** First authed model for a preset with no `default`, mirroring startup's automatic pick. */
function pickAutomaticDefault(session, candidates) {
    return pickDefaultAvailableModel(candidates.filter(candidate => session.modelRegistry.hasConfiguredAuth(candidate)), provider => session.modelRegistry.hasConcreteAuth(provider));
}
/**
 * Where `default` lands once the preset is written: its model and thinking selector.
 * Without an explicit `:level` on the selector, the preset's own `defaultThinkingLevel`
 * applies even when a higher layer still decides the setting — the switch is for this
 * session; the shadowing layer is reported separately.
 */
function resolveLiveDefault(settings, session, candidates, preset) {
    const roleValue = settings.getModelRole("default");
    const fallbackLevel = preset.defaultThinkingLevel ?? parseConfiguredThinkingLevel(cfgDefaultThinkingLevel.get(settings));
    if (!roleValue) {
        const model = pickAutomaticDefault(session, candidates);
        return model ? { model, thinkingLevel: fallbackLevel } : "no model with configured credentials is available";
    }
    const resolved = resolveModelRoleValue(roleValue, candidates, { settings });
    if (!resolved.model)
        return `default model \`${roleValue}\` is not available`;
    if (!session.modelRegistry.hasConfiguredAuth(resolved.model)) {
        return `no credentials for ${resolved.model.provider}/${resolved.model.id}`;
    }
    return {
        model: resolved.model,
        thinkingLevel: resolved.explicitThinkingLevel ? resolved.thinkingLevel : fallbackLevel,
    };
}
/** Write the preset's roles into the model hub's storage scope, clearing roles it leaves out. */
function writePresetRoles(settings, preset) {
    const project = cfgModelRoleStorage.get(settings) === "project";
    const roles = new Set([...Object.keys(settings.getModelRoles()), ...Object.keys(preset.modelRoles)]);
    if (project) {
        for (const role of roles) {
            const value = Object.hasOwn(preset.modelRoles, role) ? preset.modelRoles[role] : undefined;
            if (value !== undefined)
                settings.setProjectModelRole(role, value);
            else if (settings.getProjectModelRole(role) || settings.getModelRoleProvenance(role) === "runtime") {
                settings.clearProjectModelRole(role);
            }
        }
    }
    else {
        for (const role of roles) {
            if (Object.hasOwn(preset.modelRoles, role)) {
                settings.setModelRole(role, preset.modelRoles[role]);
                continue;
            }
            // Skip roles neither the global layer nor a runtime override owns:
            // deleting them would dirty the save queue without changing anything.
            if (settings.getGlobalModelRole(role) === undefined && settings.getModelRoleProvenance(role) !== "runtime") {
                continue;
            }
            settings.setModelRole(role, undefined);
        }
    }
    if (preset.defaultThinkingLevel !== undefined) {
        cfgDefaultThinkingLevel.set(settings, preset.defaultThinkingLevel);
    }
}
function shadowedRoles(settings, preset) {
    const effective = settings.getModelRoles();
    const roles = new Set([...Object.keys(effective), ...Object.keys(preset.modelRoles)]);
    const shadowed = [];
    for (const role of [...roles].sort((a, b) => a.localeCompare(b))) {
        const expected = Object.hasOwn(preset.modelRoles, role) ? preset.modelRoles[role] : undefined;
        const actual = Object.hasOwn(effective, role) ? effective[role] : undefined;
        if (expected !== actual) {
            shadowed.push({ role, expected, actual, source: settings.getModelRoleProvenance(role) });
        }
    }
    return shadowed;
}
function shadowedThinking(settings, preset) {
    const expected = preset.defaultThinkingLevel;
    if (expected === undefined)
        return undefined;
    const actual = cfgDefaultThinkingLevel.get(settings);
    if (actual === expected)
        return undefined;
    return { expected, actual, source: cfgDefaultThinkingLevel.provenance(settings) };
}
/**
 * Apply preset `name`: persist its roles and thinking level, then switch the
 * live session to the resulting default model and thinking level.
 *
 * The preset's own default is checked before anything is written, so a preset
 * whose model is gone leaves settings untouched. A live switch that still fails
 * afterwards is reported as `failed`, never as a completed switch.
 */
export async function applyModelPreset(settings, session, name) {
    const release = await acquireModelRoleMutation();
    try {
        return await applyModelPresetLocked(settings, session, name);
    }
    finally {
        release();
    }
}
async function applyModelPresetLocked(settings, session, name) {
    const lookup = getModelPreset(settings, name);
    if (lookup.kind !== "found")
        return lookup;
    const { preset } = lookup;
    const candidates = presetCandidates(session);
    const presetDefault = Object.hasOwn(preset.modelRoles, "default") ? preset.modelRoles.default : undefined;
    if (presetDefault) {
        // Resolve against the preset's own roles overlaid on the current ones:
        // a default written as an alias (`@slow`) must see the state the write
        // produces, not the current roles.
        const roleLookup = {
            getModelRole: (role) => Object.hasOwn(preset.modelRoles, role) ? preset.modelRoles[role] : settings.getModelRole(role),
        };
        const resolved = resolveModelRoleValue(presetDefault, candidates, { settings, roleLookup });
        if (!resolved.model)
            return { kind: "unavailable", reason: `default model \`${presetDefault}\` is not available` };
        if (!session.modelRegistry.hasConfiguredAuth(resolved.model)) {
            return {
                kind: "unavailable",
                reason: `no credentials for ${resolved.model.provider}/${resolved.model.id}`,
            };
        }
    }
    else if (!pickAutomaticDefault(session, candidates)) {
        // No `default` to apply and nothing to fall back to: refuse before writing.
        return { kind: "unavailable", reason: "no model with configured credentials is available" };
    }
    writePresetRoles(settings, preset);
    const shadowed = shadowedRoles(settings, preset);
    const thinkingShadow = shadowedThinking(settings, preset);
    const live = resolveLiveDefault(settings, session, candidates, preset);
    if (typeof live === "string")
        return { kind: "failed", reason: live, shadowed };
    try {
        await session.setModel(live.model, "default", { persist: false });
    }
    catch (error) {
        return { kind: "failed", reason: errorMessage(error), shadowed };
    }
    // setModel re-applies the model's default or keeps the current level; the preset decides instead.
    // `:inherit` means "no explicit level": leave what setModel applied rather than clearing the session level.
    if (live.thinkingLevel !== undefined && live.thinkingLevel !== ThinkingLevel.Inherit) {
        session.setThinkingLevel(live.thinkingLevel);
    }
    return {
        kind: "switched",
        model: live.model,
        thinkingLevel: live.thinkingLevel,
        shadowed,
        shadowedThinking: thinkingShadow,
    };
}
function describeRoleValue(value) {
    return value ?? "(unset)";
}
/** One line per role (and the thinking level) the preset could not set, for status output. */
export function describeShadowedRoles(shadowed, thinking) {
    const lines = shadowed.map(entry => `${entry.role}: ${describeRoleValue(entry.actual)} from ${SOURCE_LABELS[entry.source]} (preset: ${describeRoleValue(entry.expected)})`);
    if (thinking) {
        lines.push(`defaultThinkingLevel: ${describeRoleValue(thinking.actual)} from ${SOURCE_LABELS[thinking.source]} (preset: ${thinking.expected})`);
    }
    return lines;
}
/** True when the switch applied the whole preset: switched, with no role or thinking level still decided elsewhere. */
export function isCleanModelPresetSwitch(result) {
    return result.kind === "switched" && result.shadowed.length === 0 && result.shadowedThinking === undefined;
}
/** Short summary of a switch outcome for status lines and command output. */
export function formatModelPresetSwitch(name, result) {
    switch (result.kind) {
        case "missing":
            return `Preset not found: ${name}`;
        case "invalid":
            return `Preset "${name}" is malformed: ${result.reason}`;
        case "unavailable":
            return `Preset "${name}" not applied: ${result.reason}`;
        case "failed":
            return `Preset "${name}" roles saved, but the model was not switched: ${result.reason}`;
        case "switched": {
            const thinking = result.thinkingLevel ? ` · ${result.thinkingLevel}` : "";
            const model = `${result.model.provider}/${result.model.id}${thinking}`;
            const elsewhere = describeShadowedRoles(result.shadowed, result.shadowedThinking);
            if (elsewhere.length === 0)
                return `Switched to preset "${name}" (${model})`;
            return `Switched to preset "${name}" (${model}); still set elsewhere: ${elsewhere.join("; ")}`;
        }
    }
}
