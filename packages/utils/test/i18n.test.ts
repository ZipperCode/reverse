import { afterEach, describe, expect, it } from "bun:test";
import {
	DEFAULT_LOCALE,
	getEnvLocale,
	normalizeLocale,
	resolveEffectiveLocale,
	SUPPORTED_LOCALES,
} from "../src/i18n";

describe("utils/i18n", () => {
	const savedEnv = process.env.REVERSE_LANG;
	afterEach(() => {
		if (savedEnv === undefined) delete process.env.REVERSE_LANG;
		else process.env.REVERSE_LANG = savedEnv;
	});

	it("has supported locales and default locale", () => {
		expect(SUPPORTED_LOCALES).toContain("en");
		expect(SUPPORTED_LOCALES).toContain("zh-CN");
		expect(DEFAULT_LOCALE).toBe("en");
	});

	it("normalizes locale variants correctly", () => {
		expect(normalizeLocale(undefined)).toBe("en");
		expect(normalizeLocale("")).toBe("en");
		expect(normalizeLocale("en")).toBe("en");
		expect(normalizeLocale("en-US")).toBe("en");
		expect(normalizeLocale("fr")).toBe("en");

		expect(normalizeLocale("zh")).toBe("zh-CN");
		expect(normalizeLocale("zh-CN")).toBe("zh-CN");
		expect(normalizeLocale("zh_CN")).toBe("zh-CN");
		expect(normalizeLocale("zh_CN.UTF-8")).toBe("zh-CN");
		expect(normalizeLocale("zh-Hans")).toBe("zh-CN");
		expect(normalizeLocale("zh-TW")).toBe("zh-CN");
	});

	it("reads REVERSE_LANG override from environment", () => {
		expect(getEnvLocale()).toBeUndefined();

		process.env.REVERSE_LANG = "zh-CN";
		expect(getEnvLocale()).toBe("zh-CN");

		process.env.REVERSE_LANG = "en";
		expect(getEnvLocale()).toBe("en");

		process.env.REVERSE_LANG = "invalid";
		expect(getEnvLocale()).toBe("en");
	});

	it("resolves effective locale with correct precedence", () => {
		// Default
		expect(resolveEffectiveLocale()).toBe("en");
		expect(resolveEffectiveLocale(null)).toBe("en");

		// Configured setting
		expect(resolveEffectiveLocale("zh-CN")).toBe("zh-CN");
		expect(resolveEffectiveLocale("en")).toBe("en");

		// REVERSE_LANG takes precedence over configured setting
		process.env.REVERSE_LANG = "zh-CN";
		expect(resolveEffectiveLocale("en")).toBe("zh-CN");

		process.env.REVERSE_LANG = "en";
		expect(resolveEffectiveLocale("zh-CN")).toBe("en");
	});
});
