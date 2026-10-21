/**
 * Regression test for `loadCliExtensionProviders`.
 *
 * One-shot CLIs (`reverse bench`, dry-balance) build a bare `ModelRegistry` that
 * only knows built-in catalog providers. Before the helper existed they never
 * loaded extensions, so a provider contributed by an extension
 * (`pi.registerProvider(...)`, e.g. a custom OpenAI-compatible gateway under
 * `~/.reverse/agent/extensions/`) was invisible to model resolution and
 * `reverse bench <provider>/<model>` failed with "Model not found".
 *
 * Contract under test: after `loadCliExtensionProviders` drains the extension's
 * provider registrations into the registry, a `provider/id` selector for that
 * extension provider resolves. Discovery is disabled and the extension path is
 * passed explicitly so the test never touches the developer's real `~/.reverse`.
 */

import { afterAll, beforeAll, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import { AuthStorage } from "@reverse/ai";
import { parseArgs } from "@reverse/coding-agent/cli/args";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { getModelMatchPreferences, resolveCliModel } from "@reverse/coding-agent/config/model-resolver";
import { resetSettingsForTest, Settings } from "@reverse/coding-agent/config/settings";
import { buildSessionOptions } from "@reverse/coding-agent/main";
import { loadCliExtensionProviders } from "@reverse/coding-agent/sdk";
import { TempDir } from "@reverse/utils";

let tmp: TempDir;
let extPath: string;
let dbPath: string;

beforeAll(async () => {
	tmp = await TempDir.create("@cli-ext-providers-");
	extPath = tmp.join("ext.ts");
	dbPath = tmp.join("auth.db");
	await fs.writeFile(
		extPath,
		`export default function (pi) {
	pi.registerProvider("bench-gw", {
		baseUrl: "https://example.com/v1",
		apiKey: "literal-test-key",
		api: "openai-completions",
		models: [{
			id: "bench-model",
			name: "Bench Model",
			reasoning: false,
			input: ["text"],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 128000,
			maxTokens: 4096,
		}],
	});
}
`,
	);
});

afterAll(async () => {
	resetSettingsForTest();
	await tmp.remove();
});

test("loadCliExtensionProviders makes extension providers resolvable by selector", async () => {
	const authStorage = await AuthStorage.create(dbPath);
	try {
		const settings = await Settings.init({
			inMemory: true,
			cwd: tmp.path(),
			overrides: { extensions: [extPath], disabledExtensions: [] },
		});
		const modelRegistry = new ModelRegistry(authStorage);
		const preferences = getModelMatchPreferences(settings);

		// Before the drain the extension provider is unknown: resolution fails.
		const before = resolveCliModel({ cliModel: "bench-gw/bench-model", modelRegistry, preferences });
		expect(before.model).toBeUndefined();

		await loadCliExtensionProviders(modelRegistry, settings, tmp.path(), {
			disableExtensionDiscovery: true,
			additionalExtensionPaths: [extPath],
		});

		// After the drain the same selector resolves to the extension provider.
		const after = resolveCliModel({ cliModel: "bench-gw/bench-model", modelRegistry, preferences });
		expect(after.error).toBeUndefined();
		expect(after.model?.provider).toBe("bench-gw");
		expect(after.model?.id).toBe("bench-model");
	} finally {
		authStorage.close();
	}
});

test("buildSessionOptions defers model resolution when provider and model are set alongside explicit extensions", async () => {
	const authStorage = await AuthStorage.create(tmp.join("auth-defer.db"));
	try {
		const settings = await Settings.init({ inMemory: true, cwd: tmp.path() });
		const modelRegistry = new ModelRegistry(authStorage);
		const parsed = parseArgs([
			"-p",
			"--provider",
			"bench-gw",
			"--model",
			"bench-model",
			"--no-extensions",
			"-e",
			extPath,
		]);
		const options = await buildSessionOptions(parsed, [], undefined, modelRegistry, settings);
		expect(options.modelPattern).toBe("bench-gw/bench-model");
		expect(options.model).toBeUndefined();
	} finally {
		authStorage.close();
	}
});
