import { runProviderSetupWizard as runProviderWizard } from "@rva/tui/setup/lazy";
import { ALL_SCENES, CURRENT_SETUP_VERSION, runSetupWizard as runWizard, selectSetupScenes as selectScenes, } from "@rva/tui/setup/wizard";
import { captureBrowserSession } from "../utils/browser-session";
import { copyToClipboard } from "../utils/clipboard";
import { createModelBrowserSource } from "./model-browser-source";
import { cfgColorBlindMode, cfgComposerShape, cfgSetupVersion, cfgSymbolPreset, cfgThemeDark, cfgThemeLight, } from "./settings";
import { cfgDisabledProviders, cfgModelRoleStorage } from "../config/model-settings";
export { ALL_SCENES, CURRENT_SETUP_VERSION };
export { runStartupSplash } from "@rva/tui/setup/startup-splash";
/** Bind application preferences and runtime effects to the setup presentation. */
export function createSetupHost(ctx) {
    const modelSource = createModelBrowserSource(ctx.settings, model => ctx.session.effectiveServiceTier(model));
    return {
        ui: ctx.ui,
        get statusLine() {
            return ctx.statusLine;
        },
        get composerShape() {
            return cfgComposerShape.get(ctx.settings);
        },
        get symbolPreset() {
            return cfgSymbolPreset.get(ctx.settings);
        },
        get colorBlindMode() {
            return cfgColorBlindMode.get(ctx.settings);
        },
        get disabledProviders() {
            return cfgDisabledProviders.get(ctx.settings);
        },
        get authStorage() {
            return ctx.session.modelRegistry.authStorage;
        },
        modelSource,
        getModels: () => ({
            available: ctx.session.modelRegistry.getAvailable("all"),
            all: ctx.session.modelRegistry.getAll("all"),
            current: ctx.session.model,
        }),
        refreshModels: () => ctx.session.modelRegistry.refresh("online-if-uncached"),
        selectModel: async (model, selector) => {
            const projectScope = cfgModelRoleStorage.get(ctx.settings) === "project";
            await ctx.session.setModel(model, "default", { selector, persist: !projectScope });
            if (projectScope)
                ctx.settings.setProjectModelRole("default", selector);
            await ctx.settings.flush();
        },
        refreshProvider: provider => ctx.session.modelRegistry.refreshProvider(provider, "online"),
        saveComposerShape: async (shape) => {
            cfgComposerShape.set(ctx.settings, shape);
            await ctx.settings.flush();
        },
        saveSymbolPreset: preset => {
            cfgSymbolPreset.set(ctx.settings, preset);
        },
        saveColorBlindMode: enabled => {
            cfgColorBlindMode.set(ctx.settings, enabled);
        },
        saveTheme: (mode, name) => {
            (mode === "dark" ? cfgThemeDark : cfgThemeLight).set(ctx.settings, name);
        },
        captureBrowserSession,
        copyToClipboard,
        openInBrowser: url => ctx.openInBrowser(url),
        markComplete: version => markSetupWizardComplete(ctx.settings, version),
        playWelcomeIntro: () => ctx.playWelcomeIntro(),
        showError: message => ctx.showError(message),
        showCustomProviderWizard: () => ctx.showCustomProviderWizard(),
    };
}
/** Persist completion only after the setup overlay finishes. */
export async function markSetupWizardComplete(settings, version = CURRENT_SETUP_VERSION) {
    cfgSetupVersion.set(settings, version);
    await settings.flush();
}
/** Select eligible setup scenes using the application's live capabilities. */
export function selectSetupScenes(storedVersion, scenes, ctx, options = {}) {
    return selectScenes(storedVersion, scenes, ctx ? createSetupHost(ctx) : undefined, options);
}
/** Run setup with application-owned persistence and provider effects. */
export function runSetupWizard(ctx, scenes = ALL_SCENES, options = {}) {
    return runWizard(createSetupHost(ctx), scenes, options);
}
/** Open provider setup without advancing onboarding or replaying the welcome intro. */
export function runProviderSetupWizard(ctx) {
    return runProviderWizard(createSetupHost(ctx));
}
