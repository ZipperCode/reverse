import { TERMINAL } from "@rva/tui";
import { isNativeRendering } from "@rva/tui/native/state";
import { resolveEffectiveLocale } from "@rva/utils/i18n";
import { TUI_TRANSLATIONS_ZH_CN } from "@rva/tui/i18n/zh-CN";
import { SETTING_TRANSLATIONS_ZH_CN } from "../i18n/zh-CN/settings";
import { cfgLanguage, cfgTuiVimMode } from "../modes/settings";
import { SETTING_TABS } from "@rva/tui/overlays/settings-defs";
import { isSettingsInitialized, Settings, settings } from "./settings";
import { orderedSettings } from "./all-settings";
import { lookup } from "./registry";
import { cfgPlanAutosave, cfgPlanEnabled } from "../plan-mode/settings";
import { cfgRetryUsageAwareFallback, cfgDefaultThinkingLevel, normalizeProviderMaxInFlightRequests, validateProviderMaxInFlightRequests, } from "../session/settings";
import { cfgAutolearnEnabled } from "../autolearn/settings";
import { cfgMemoryBackend } from "../memory-backend/settings";
import { cfgAdvisorEnabled } from "../advisor/settings";
import { cfgContextFilesExtra } from "../session/context-settings";
/** Condition over the global settings; hidden (false) until they are initialized. */
function whenSettings(test) {
    return () => isSettingsInitialized() && test(Settings.instance);
}
const CONDITIONS = {
    macOS: () => process.platform === "darwin",
    hasImageProtocol: () => !!TERMINAL.imageProtocol,
    nativeRendering: () => isNativeRendering(),
    advisorEnabled: whenSettings(s => cfgAdvisorEnabled.get(s) === true),
    vimModeEnabled: whenSettings(s => cfgTuiVimMode.get(s) === true),
    hindsightActive: whenSettings(s => cfgMemoryBackend.get(s) === "hindsight"),
    mnemopiActive: whenSettings(s => cfgMemoryBackend.get(s) === "mnemopi"),
    autolearnActive: whenSettings(s => cfgAutolearnEnabled.get(s) === true),
    autoThinkingActive: whenSettings(s => cfgDefaultThinkingLevel.get(s) === "auto"),
    usageAwareFallbackEnabled: whenSettings(s => cfgRetryUsageAwareFallback.get(s) === true),
    planModeEnabled: whenSettings(s => cfgPlanEnabled.get(s)),
    planAutosaveEnabled: whenSettings(s => cfgPlanEnabled.get(s) && cfgPlanAutosave.get(s)),
    // The editor writes the global layer; hide it so a project-supplied list is never promoted to global.
    contextFilesExtraNotProject: whenSettings(s => cfgContextFilesExtra.provenance(s) !== "project"),
};
/** Description suffix telling the panel user that an environment variable is in play. */
function envNote(setting, locale) {
    if (!setting.envName || setting.envValue() === undefined)
        return "";
    if (locale === "zh-CN") {
        return setting.envFallback
            ? ` 未设置时，回退到 $${setting.envName}。`
            : ` 设置了 $${setting.envName} 时，将覆盖此设置。`;
    }
    return setting.envFallback
        ? ` Unset, it falls back to $${setting.envName}.`
        : ` $${setting.envName} overrides this setting while it is set.`;
}
/**
 * Adapt the application schema and settings store to the terminal overlay. The panel shows and
 * edits the value of the settings layers, never an environment-supplied one (so an env credential
 * is never pre-filled or written to config); descriptions note an active environment variable.
 */
export function createSettingsHost() {
    const entries = [];
    const resolveLanguage = () => {
        const raw = isSettingsInitialized() ? cfgLanguage.get(settings) : undefined;
        return resolveEffectiveLocale(raw);
    };
    let currentLocale = resolveLanguage();
    const populate = () => {
        currentLocale = resolveLanguage();
        const nextEntries = [];
        for (const tab of SETTING_TABS) {
            for (const setting of orderedSettings()) {
                const ui = setting.ui;
                if (ui?.tab !== tab)
                    continue;
                const note = envNote(setting, currentLocale);
                const tr = currentLocale === "zh-CN" ? SETTING_TRANSLATIONS_ZH_CN[setting.id] : undefined;
                const label = tr?.label ?? ui.label;
                const rawDesc = tr?.description ?? ui.description;
                const description = note ? `${rawDesc}${note}` : rawDesc;
                const warning = tr?.warning ?? ui.warning;
                const groupLabel = currentLocale === "zh-CN" && ui.group ? (TUI_TRANSLATIONS_ZH_CN.groups[ui.group] ?? ui.group) : ui.group;
                let options = ui.options;
                if (ui.options === "runtime" && setting.id === "composer.shape" && tr?.options) {
                    options = Object.entries(tr.options).map(([value, o]) => ({
                        value,
                        label: o.label ?? value,
                        description: o.description,
                    }));
                }
                else if (Array.isArray(ui.options) && tr?.options) {
                    options = ui.options.map(opt => {
                        const optTr = tr.options?.[opt.value];
                        if (!optTr)
                            return opt;
                        return {
                            value: opt.value,
                            label: optTr.label ?? opt.label,
                            description: optTr.description ?? opt.description,
                        };
                    });
                }
                nextEntries.push({
                    path: setting.id,
                    type: setting.type,
                    defaultValue: setting.default,
                    ui: {
                        ...ui,
                        label,
                        description,
                        warning,
                        groupLabel,
                        canonicalLabel: ui.label,
                        canonicalDescription: ui.description,
                        options,
                    },
                    enumValues: setting.enumValues,
                    credential: setting.isCredential,
                    condition: ui.condition ? CONDITIONS[ui.condition] : undefined,
                });
            }
        }
        if (host) {
            host.entries = nextEntries;
            host.locale = currentLocale;
        }
        return nextEntries;
    };
    const resolve = (path) => {
        const setting = lookup(path);
        if (!setting)
            throw new Error(`Unknown setting: ${path}`);
        return setting;
    };
    const host = {
        entries: [],
        locale: currentLocale,
        get: path => lookup(path)?.layered(settings),
        set: (path, value) => resolve(path).set(settings, value),
        unset: path => resolve(path).unset(settings),
        normalizeProviderLimits: normalizeProviderMaxInFlightRequests,
        validateProviderLimits: validateProviderMaxInFlightRequests,
        reload: populate,
    };
    host.entries = populate();
    return host;
}
