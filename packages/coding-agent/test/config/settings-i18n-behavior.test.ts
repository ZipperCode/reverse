import { afterEach, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import {
	getGroupLabel,
	getSettingsForTab,
	getTabLead,
	getTabMetadata,
	type SettingDef,
	type SettingsHost,
} from "@reverse/tui/overlays/settings-defs";
import { SettingsSelectorComponent } from "@reverse/tui/overlays/settings-selector";
import { initTheme } from "@reverse/tui/theme";
import { createSettingsHost } from "@reverse/coding-agent/config/settings-ui";
import { createPluginSettingsHost } from "@reverse/coding-agent/extensibility/plugins/settings-host";
import { lookup } from "@reverse/coding-agent/config/registry";
import { resetSettingsForTest, Settings } from "@reverse/coding-agent/config/settings";
import { SETTING_TRANSLATIONS_ZH_CN } from "../../src/i18n/zh-CN/settings";

const CJK = /[\u4e00-\u9fff]/;

async function initSettings(overrides: Record<string, unknown> = {}): Promise<void> {
	resetSettingsForTest();
	delete process.env.REVERSE_LANG;
	await Settings.init({ inMemory: true, overrides });
}

function settingDef(host: SettingsHost, tab: "appearance", path: string): SettingDef {
	const def = getSettingsForTab(host.entries, tab).find(candidate => candidate.path === path);
	if (!def) throw new Error(`missing setting def: ${path}`);
	return def;
}

beforeAll(async () => {
	await initTheme();
});

describe("settings i18n behavior", () => {
	let originalLang: string | undefined;

	beforeEach(async () => {
		originalLang = process.env.REVERSE_LANG;
		await initSettings();
	});

	afterEach(() => {
		if (originalLang === undefined) delete process.env.REVERSE_LANG;
		else process.env.REVERSE_LANG = originalLang;
		resetSettingsForTest();
	});

	it("defaults to English and keeps canonical metadata available for search", () => {
		const host = createSettingsHost();
		expect(host.locale).toBe("en");

		const def = settingDef(host, "appearance", "theme.dark");
		expect(def.label).toBe(def.canonicalLabel ?? "");
		expect(def.description).toBe(def.canonicalDescription ?? "");
		expect(def.groupLabel).toBe(def.group);
	});

	it("localizes labels, groups, options and tab leads when the language setting is zh-CN", async () => {
		await initSettings({ language: "zh-CN" });
		const host = createSettingsHost();
		expect(host.locale).toBe("zh-CN");

		const def = settingDef(host, "appearance", "theme.dark");
		expect(def.label).not.toBe(def.canonicalLabel);
		expect(CJK.test(def.label)).toBe(true);
		expect(def.groupLabel).not.toBe(def.group);
		expect(CJK.test(def.groupLabel ?? "")).toBe(true);

		const options = settingDef(host, "appearance", "statusLine.preset");
		expect(options.type).toBe("submenu");
		if (options.type !== "submenu") throw new Error("expected submenu");
		const minimal = options.options.find(option => option.value === "minimal");
		expect(minimal?.value).toBe("minimal");
		expect(CJK.test(minimal?.label ?? "")).toBe(true);
		expect(CJK.test(minimal?.description ?? "")).toBe(true);

		expect(getTabMetadata("appearance", "zh-CN").label).not.toBe(getTabMetadata("appearance", "en").label);
		expect(CJK.test(getTabLead("appearance", "zh-CN"))).toBe(true);
	});

	it("gives REVERSE_LANG precedence over the configured language and refreshes the host", async () => {
		await initSettings({ language: "zh-CN" });
		process.env.REVERSE_LANG = "en";
		const host = createSettingsHost();
		expect(host.locale).toBe("en");
		expect(settingDef(host, "appearance", "theme.dark").label).toBe(
			settingDef(host, "appearance", "theme.dark").canonicalLabel ?? "",
		);

		delete process.env.REVERSE_LANG;
		host.reload?.();
		expect(host.locale).toBe("zh-CN");
		expect(CJK.test(settingDef(host, "appearance", "theme.dark").label ?? "")).toBe(true);
	});

	it("falls back per field when a translation or option translation is absent", async () => {
		await initSettings({ language: "zh-CN" });
		const settingId = "theme.dark";
		const savedSetting = SETTING_TRANSLATIONS_ZH_CN[settingId];
		delete SETTING_TRANSLATIONS_ZH_CN[settingId];
		try {
			const host = createSettingsHost();
			const def = settingDef(host, "appearance", settingId);
			expect(def.label).toBe(def.canonicalLabel ?? "");
			expect(def.description).toBe(def.canonicalDescription ?? "");
		} finally {
			SETTING_TRANSLATIONS_ZH_CN[settingId] = savedSetting;
		}

		const optionSettingId = "symbolPreset";
		const savedOption = SETTING_TRANSLATIONS_ZH_CN[optionSettingId]?.options?.nerd;
		if (savedOption) delete SETTING_TRANSLATIONS_ZH_CN[optionSettingId]?.options?.nerd;
		try {
			const host = createSettingsHost();
			const def = settingDef(host, "appearance", optionSettingId);
			if (def.type !== "submenu") throw new Error("expected submenu");
			const nerd = def.options.find(option => option.value === "nerd");
			const english = lookup(optionSettingId)?.ui?.options;
			expect(nerd?.label).toBe(
				Array.isArray(english) ? english.find(option => option.value === "nerd")?.label : undefined,
			);
		} finally {
			if (savedOption) SETTING_TRANSLATIONS_ZH_CN[optionSettingId]!.options!.nerd = savedOption;
		}
	});

	it("finds a setting by its canonical English text through the real selector under zh-CN", async () => {
		await initSettings({ language: "zh-CN" });
		const host = createSettingsHost();
		const def = settingDef(host, "appearance", "theme.dark");
		const selector = new SettingsSelectorComponent(
			{
				availableThinkingLevels: [],
				thinkingLevel: undefined,
				availableThemes: ["dark", "light"],
				providers: [],
				settings: host,
				plugins: createPluginSettingsHost(process.cwd()),
			},
			{ onChange: () => {}, onCancel: () => {} },
		);

		for (const ch of "terminal background") selector.handleInput(ch);
		const rendered = selector.render(120).join("\n");
		expect(rendered).not.toContain("未找到匹配的设置");
		expect(rendered).toContain(def.label);
	});

	it("falls back to canonical text for unknown groups", () => {
		expect(getGroupLabel("Unknown Group", "zh-CN")).toBe("Unknown Group");
	});

	it("re-renders live on language switch en -> zh-CN -> en and updates frame chrome", async () => {
		await initSettings();
		const host = createSettingsHost();
		const selector = new SettingsSelectorComponent(
			{
				availableThinkingLevels: [],
				thinkingLevel: undefined,
				availableThemes: ["dark", "light"],
				providers: [],
				settings: host,
				plugins: createPluginSettingsHost(process.cwd()),
				requestRender: () => {},
			},
			{ onChange: () => {}, onCancel: () => {} },
		);

		// 1. Initial state: English chrome
		const initialFrame = selector.render(120);
		expect(initialFrame[0]).toContain("Settings");
		expect(initialFrame[1]).toContain("Appearance");

		// 2. Search "Language", navigate to row, and toggle to zh-CN via handleInput
		for (const ch of "Language") selector.handleInput(ch);
		selector.handleInput("\x1b[A");
		selector.handleInput("\x1b[A");
		selector.handleInput("\n"); // open submenu
		selector.handleInput("\x1b[B"); // move down to 简体中文
		selector.handleInput("\n"); // submit selection

		// Assert SAME selector instance rendered in Chinese and persisted in host
		const zhFrame = selector.render(120);
		expect(zhFrame[0]).toContain("设置");
		expect(zhFrame[1]).toContain("外观");
		expect(host.get("language")).toBe("zh-CN");

		// 3. Toggle back to English via handleInput on the SAME selector instance
		selector.handleInput("\n"); // open submenu again
		selector.handleInput("\x1b[A"); // move up to English
		selector.handleInput("\n"); // submit selection

		// Assert SAME selector instance rendered in English and persisted in host
		const enFrame = selector.render(120);
		expect(enFrame[0]).toContain("Settings");
		expect(enFrame[1]).toContain("Appearance");
		expect(host.get("language")).toBe("en");
	});
});
