import { afterEach, describe, expect, it } from "bun:test";
import { TUI } from "@reverse/tui";
import {
	CustomProviderWizard,
	type CustomProviderWizardOutput,
	type CustomWizardModel,
} from "@reverse/tui/overlays/custom-provider-wizard";
import type { TspNode } from "@reverse/wire";
import { TspHarness } from "./native/tsp-harness";
import { VirtualTerminal } from "./virtual-terminal";

let harness: TspHarness | undefined;

afterEach(() => {
	harness?.stop();
	harness = undefined;
});

const itemLabel = (node: TspNode): string =>
	node.k === "item" && typeof node.p?.label === "string" ? node.p.label : "";

const nativeTexts = (harness: TspHarness): string[] =>
	harness
		.findAll(node => node.k === "text")
		.map(node => (node.k === "text" && typeof node.p?.text === "string" ? node.p.text : ""))
		.filter(text => text.length > 0);

const nodeActions = (node: TspNode): { click?: string } | undefined => {
	const props = node.p as { actions?: { click?: string } } | undefined; // TSP action bindings are outside TspProps.
	return props?.actions;
};

async function clickAction(harness: TspHarness, surface: string, act: string): Promise<void> {
	const node = harness.find(candidate => candidate.k === "row" && nodeActions(candidate)?.click === act);
	if (!node) throw new Error(`native ${act} action missing`);
	harness.event({ ev: "action", sf: surface, id: node.id, act, mods: [] });
	await harness.render();
}

function currentInputId(harness: TspHarness): string {
	const input = harness.find(candidate => candidate.k === "input");
	if (!input) throw new Error("native input missing");
	return input.id;
}

async function typeInto(harness: TspHarness, surface: string, inputId: string, text: string): Promise<void> {
	const input = harness.byId(inputId);
	let value = input?.k === "input" ? (input.p?.text ?? "") : "";
	for (const char of text) {
		harness.event({
			ev: "edit",
			sf: surface,
			id: inputId,
			from: value.length,
			to: value.length,
			text: char,
			cursor: value.length + 1,
			len: value.length,
		});
		value += char;
	}
	await harness.render();
}

async function typeCurrentInput(harness: TspHarness, surface: string, text: string): Promise<void> {
	await typeInto(harness, surface, currentInputId(harness), text);
}

/** Fill provider id, protocol, and base URL, stopping on the optional API-key step. */
async function advanceToApiKeyStep(
	harness: TspHarness,
	surface: string,
	providerId: string,
	baseUrl: string,
): Promise<void> {
	await typeCurrentInput(harness, surface, providerId);
	await clickAction(harness, surface, "next");

	const protocolList = harness.find(candidate => candidate.k === "list");
	if (!protocolList) throw new Error("protocol list missing");
	const openaiChoice = harness.findAll(candidate => candidate.k === "item")[0];
	if (!openaiChoice) throw new Error("protocol item missing");
	harness.event({ ev: "select", sf: surface, id: protocolList.id, item: openaiChoice.id });
	harness.event({ ev: "activate", sf: surface, id: protocolList.id, item: openaiChoice.id });
	await harness.render();

	await typeCurrentInput(harness, surface, baseUrl);
	await clickAction(harness, surface, "next");
}

interface PendingResult<T> {
	promise: Promise<T>;
	resolve: (value: T) => void;
	reject: (reason?: unknown) => void;
}

function deferred<T>(): PendingResult<T> {
	let resolve!: (value: T) => void;
	let reject!: (reason?: unknown) => void;
	const promise = new Promise<T>((onResolve, onReject) => {
		resolve = onResolve;
		reject = onReject;
	});
	return { promise, resolve, reject };
}

describe("CustomProviderWizard native keyboard path", () => {
	it("accepts split native edits, backspace, and Enter through the action bar", async () => {
		let wizard!: CustomProviderWizard;
		harness = await TspHarness.start(tui => {
			wizard = new CustomProviderWizard(
				{ fetchModels: async () => [] },
				() => {},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();

		const input = h.find(node => node.k === "input");
		expect(input).toBeDefined();
		const surface = h.terminal.surface!;
		expect(h.terminal.docs.get(surface)?.focus).toBe(input!.id);
		const inputId = input!.id;

		const type = (text: string) => {
			let value = String((h.byId(inputId)?.p as { text?: string } | undefined)?.text ?? "");
			for (const char of text) {
				const length = value.length;
				h.event({
					ev: "edit",
					sf: surface,
					id: inputId,
					from: length,
					to: length,
					text: char,
					cursor: length + 1,
					len: length,
				});
				value += char;
			}
		};

		type("my-provider");
		await h.render();
		expect(h.byId(inputId)?.p).toMatchObject({ text: "my-provider", cursor: 11 });

		h.event({ ev: "edit", sf: surface, id: inputId, from: 10, to: 11, text: "", cursor: 10, len: 11 });
		await h.render();
		expect(h.byId(inputId)?.p).toMatchObject({ text: "my-provide", cursor: 10 });

		type("r");
		await h.render();
		expect(h.byId(inputId)?.p).toMatchObject({ text: "my-provider", cursor: 11 });

		const next = h.find(node => {
			const props = node.p as { actions?: { click?: string } } | undefined;
			return node.k === "row" && props?.actions?.click === "next";
		});
		if (!next) throw new Error("native Continue action missing");
		h.event({ ev: "action", sf: surface, id: next.id, act: "next", mods: [] });
		await h.render();

		expect(h.find(node => node.k === "list")).toBeDefined();
		expect(wizard.focused).toBe(true);
	});

	it("keeps native select navigation non-destructive, toggles on activate, and preserves selections through search", async () => {
		const discovered: CustomWizardModel[] = [
			{
				id: "alpha-model",
				name: "Alpha Model",
				contextWindow: 200_000,
				contextSource: "endpoint",
				maxTokens: 8_192,
				maxTokensSource: "endpoint",
				input: ["text", "image"],
				reasoning: true,
			},
			{
				id: "beta-model",
				name: "Beta Model",
				contextWindow: 128_000,
				contextSource: "catalog",
				maxTokens: 4_096,
				maxTokensSource: "catalog",
				input: ["text"],
				reasoning: false,
			},
		];
		let output: CustomProviderWizardOutput | undefined;
		let fetchOptions: { baseUrl: string; api: string; apiKey?: string } | undefined;
		let wizard!: CustomProviderWizard;
		harness = await TspHarness.start(tui => {
			wizard = new CustomProviderWizard(
				{
					fetchModels: async options => {
						fetchOptions = options;
						return discovered;
					},
				},
				result => {
					output = result;
				},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;

		await typeCurrentInput(h, surface, "native-contract");
		await clickAction(h, surface, "next");

		const protocolList = h.find(candidate => candidate.k === "list");
		if (!protocolList) throw new Error("protocol list missing");
		const openaiChoice = h.findAll(candidate => candidate.k === "item")[0];
		if (!openaiChoice) throw new Error("protocol item missing");
		h.event({ ev: "select", sf: surface, id: protocolList.id, item: openaiChoice.id });
		h.event({ ev: "activate", sf: surface, id: protocolList.id, item: openaiChoice.id });
		await h.render();

		await typeCurrentInput(h, surface, "https://native.example/v1");
		await clickAction(h, surface, "next");
		await typeCurrentInput(h, surface, "top-secret-token");
		await clickAction(h, surface, "next");
		await h.until(() =>
			h.findAll(candidate => candidate.k === "item").some(item => itemLabel(item).includes("alpha-model")),
		);
		expect(fetchOptions).toMatchObject({
			baseUrl: "https://native.example/v1",
			api: "openai-completions",
			apiKey: "top-secret-token",
		});

		const listNode = () => {
			const list = h.find(candidate => candidate.k === "list");
			if (!list) throw new Error("model list missing");
			return list;
		};
		const modelItem = (id: string) => {
			const item = h
				.findAll(candidate => candidate.k === "item")
				.find(candidate => itemLabel(candidate).includes(id));
			if (!item) throw new Error(`model item ${id} missing`);
			return item;
		};
		const labelFor = (id: string) => itemLabel(modelItem(id));

		expect(h.findAll(candidate => candidate.k === "list")).toHaveLength(1);
		expect(h.findAll(candidate => candidate.k === "item")).toHaveLength(2);
		expect(labelFor("alpha-model")).toContain("[x]");
		expect(labelFor("beta-model")).toContain("[x]");

		const beta = modelItem("beta-model");
		h.event({ ev: "select", sf: surface, id: listNode().id, item: beta.id });
		await h.render();
		expect(labelFor("beta-model")).toContain("[x]");
		const navigatedList = listNode();
		expect(navigatedList.k === "list" ? navigatedList.p?.selected : undefined).toBe(beta.id);

		h.event({ ev: "activate", sf: surface, id: listNode().id, item: beta.id });
		await h.render();
		expect(labelFor("beta-model")).toContain("[ ]");

		const alpha = modelItem("alpha-model");
		h.event({ ev: "select", sf: surface, id: listNode().id, item: alpha.id });
		await h.render();
		expect(labelFor("alpha-model")).toContain("[x]");
		expect(labelFor("beta-model")).toContain("[ ]");

		const searchId = currentInputId(h);
		await typeInto(h, surface, searchId, "alpha");
		const visibleLabels = h.findAll(candidate => candidate.k === "item").map(itemLabel);
		expect(visibleLabels.filter(label => label.includes("model"))).toHaveLength(1);
		expect(visibleLabels[0]).toContain("alpha-model");
		expect(labelFor("alpha-model")).toContain("[x]");

		const searchNode = h.byId(searchId);
		const searchText = searchNode?.k === "input" ? (searchNode.p?.text ?? "") : "";
		h.event({
			ev: "edit",
			sf: surface,
			id: searchId,
			from: 0,
			to: searchText.length,
			text: "",
			cursor: 0,
			len: searchText.length,
		});
		await h.render();
		expect(labelFor("alpha-model")).toContain("[x]");
		expect(labelFor("beta-model")).toContain("[ ]");

		await clickAction(h, surface, "next");
		const summary = nativeTexts(h).join("\n");
		expect(summary).toContain("Provider ID: native-contract");
		expect(summary).toContain("API Protocol: openai-completions");
		expect(summary).toContain("Base URL: https://native.example/v1");
		expect(summary).toContain("API Key: [Configured (securely stored in agent.db)]");
		expect(summary).not.toContain("top-secret-token");
		expect(summary).toContain("Selected Models (1):");
		expect(summary).toContain(
			"• alpha-model (Alpha Model) - ctx: 200000 (endpoint) · max: 8192 (endpoint) · [text, image] · reasoning",
		);
		expect(summary).not.toContain("beta-model");
		await clickAction(h, surface, "next");
		await h.until(() => output !== undefined);

		expect(output).toMatchObject({
			providerId: "native-contract",
			api: "openai-completions",
			baseUrl: "https://native.example/v1",
		});
		expect(output?.models).toEqual([
			{
				id: "alpha-model",
				name: "Alpha Model",
				contextWindow: 200_000,
				maxTokens: 8_192,
				input: ["text", "image"],
				reasoning: true,
			},
		]);
	});

	it("renders every selected model with its metadata in native confirm", async () => {
		harness = await TspHarness.start(tui => {
			const wizard = new CustomProviderWizard(
				{
					fetchModels: async () => [
						{
							id: "alpha-model",
							name: "Alpha Model",
							contextWindow: 200_000,
							contextSource: "endpoint",
							maxTokens: 8_192,
							maxTokensSource: "endpoint",
							input: ["text", "image"],
							reasoning: true,
						},
						{
							id: "beta-model",
							name: "Beta Model",
							contextWindow: 128_000,
							contextSource: "catalog",
							maxTokens: 4_096,
							maxTokensSource: "catalog",
							input: ["text"],
						},
					],
				},
				() => {},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;

		await advanceToApiKeyStep(h, surface, "native-confirm", "https://native.example/v1");
		await clickAction(h, surface, "next");
		await h.until(() => h.findAll(candidate => candidate.k === "item").length === 2);
		await clickAction(h, surface, "next");

		const summary = nativeTexts(h).join("\n");
		expect(summary).toContain("Selected Models (2):");
		expect(summary).toContain(
			"• alpha-model (Alpha Model) - ctx: 200000 (endpoint) · max: 8192 (endpoint) · [text, image] · reasoning",
		);
		expect(summary).toContain("• beta-model (Beta Model) - ctx: 128000 (catalog) · max: 4096 (catalog) · [text]");
	});

	it("aborts discovery on back and ignores a late result", async () => {
		const pending = deferred<CustomWizardModel[]>();
		let signal: AbortSignal | undefined;
		let output: CustomProviderWizardOutput | undefined;
		harness = await TspHarness.start(tui => {
			const wizard = new CustomProviderWizard(
				{
					fetchModels: options => {
						signal = options.signal;
						return pending.promise;
					},
				},
				result => {
					output = result;
				},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;

		await advanceToApiKeyStep(h, surface, "native-back", "https://native.example/v1");
		await clickAction(h, surface, "next");
		expect(signal).toBeDefined();
		expect(signal?.aborted).toBe(false);

		await clickAction(h, surface, "back");
		expect(signal?.aborted).toBe(true);

		pending.resolve([{ id: "late-model", name: "Late Model" }]);
		await h.render();
		expect(h.findAll(candidate => candidate.k === "item")).toHaveLength(0);
		expect(
			h.find(
				candidate =>
					candidate.k === "text" &&
					typeof candidate.p?.text === "string" &&
					candidate.p.text.includes("Step 4: API Key"),
			),
		).toBeDefined();
		expect(output).toBeUndefined();
	});

	it("keeps only the newest discovery result after a restart", async () => {
		const first = deferred<CustomWizardModel[]>();
		const second = deferred<CustomWizardModel[]>();
		const signals: AbortSignal[] = [];
		let calls = 0;
		harness = await TspHarness.start(tui => {
			const wizard = new CustomProviderWizard(
				{
					fetchModels: options => {
						if (options.signal) signals.push(options.signal);
						calls += 1;
						return calls === 1 ? first.promise : second.promise;
					},
				},
				() => {},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;

		await advanceToApiKeyStep(h, surface, "native-restart", "https://native.example/v1");
		await clickAction(h, surface, "next");
		expect(signals).toHaveLength(1);
		expect(signals[0]?.aborted).toBe(false);

		await clickAction(h, surface, "back");
		expect(signals[0]?.aborted).toBe(true);
		await clickAction(h, surface, "next");
		expect(signals).toHaveLength(2);

		second.resolve([{ id: "newest-model", name: "Newest Model" }]);
		await h.until(() =>
			h.findAll(candidate => candidate.k === "item").some(item => itemLabel(item).includes("newest-model")),
		);

		first.resolve([{ id: "stale-model", name: "Stale Model" }]);
		await h.render();
		const labels = h.findAll(candidate => candidate.k === "item").map(itemLabel);
		expect(labels).toHaveLength(1);
		expect(labels[0]).toContain("newest-model");
		expect(labels.some(label => label.includes("stale-model"))).toBe(false);
	});

	it("aborts discovery on cancel and ignores a late result", async () => {
		const pending = deferred<CustomWizardModel[]>();
		let signal: AbortSignal | undefined;
		let cancelled = 0;
		let output: CustomProviderWizardOutput | undefined;
		harness = await TspHarness.start(tui => {
			const wizard = new CustomProviderWizard(
				{
					fetchModels: options => {
						signal = options.signal;
						return pending.promise;
					},
				},
				result => {
					output = result;
				},
				() => {
					cancelled += 1;
				},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;

		await advanceToApiKeyStep(h, surface, "native-cancel", "https://native.example/v1");
		await clickAction(h, surface, "next");
		expect(signal?.aborted).toBe(false);

		await clickAction(h, surface, "cancel");
		expect(cancelled).toBe(1);
		expect(signal?.aborted).toBe(true);

		pending.resolve([{ id: "late-cancel-model", name: "Late Cancel" }]);
		await h.render();
		expect(h.findAll(candidate => candidate.k === "item")).toHaveLength(0);
		expect(cancelled).toBe(1);
		expect(output).toBeUndefined();
	});

	it("ignores a late discovery result after dispose", async () => {
		const pending = deferred<CustomWizardModel[]>();
		let signal: AbortSignal | undefined;
		let output: CustomProviderWizardOutput | undefined;
		let wizard!: CustomProviderWizard;
		harness = await TspHarness.start(tui => {
			wizard = new CustomProviderWizard(
				{
					fetchModels: options => {
						signal = options.signal;
						return pending.promise;
					},
				},
				result => {
					output = result;
				},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;

		await advanceToApiKeyStep(h, surface, "native-dispose", "https://native.example/v1");
		await clickAction(h, surface, "next");
		expect(signal?.aborted).toBe(false);

		wizard.dispose();
		expect(signal?.aborted).toBe(true);
		pending.resolve([{ id: "late-dispose-model", name: "Late Dispose" }]);
		await h.render();
		expect(output).toBeUndefined();
	});

	it("labels an unknown max output in native, ANSI, and confirm views", async () => {
		let wizard!: CustomProviderWizard;
		harness = await TspHarness.start(tui => {
			wizard = new CustomProviderWizard(
				{
					fetchModels: async () => [
						{
							id: "context-only-model",
							name: "Context Only",
							contextWindow: 64_000,
							contextSource: "endpoint",
							input: ["text"],
						},
					],
				},
				() => {},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;
		const unknownMax = "max: unknown (output fallback applies)";
		const plainRender = () => Bun.stripANSI(wizard.render(200).join("\n")).replace(/\s+/g, " ");

		await advanceToApiKeyStep(h, surface, "native-unknown-max", "https://native.example/v1");
		await clickAction(h, surface, "next");
		await h.until(() => h.findAll(candidate => candidate.k === "item").length > 0);

		const modelItem = h.findAll(candidate => candidate.k === "item")[0];
		const detail = modelItem?.k === "item" ? modelItem.p?.detail : undefined;
		expect(typeof detail === "string" ? detail : "").toContain(unknownMax);
		expect(plainRender()).toContain(unknownMax);

		await clickAction(h, surface, "next");
		expect(
			h.findAll(candidate => candidate.k === "text" && candidate.p?.text === "Confirm Configuration"),
		).toHaveLength(1);
		expect(nativeTexts(h).join("\n")).toContain(unknownMax);
		expect(plainRender()).toContain(unknownMax);
	});

	it("applies a native paste and focuses the URL input after a native protocol activate", async () => {
		let wizard!: CustomProviderWizard;
		harness = await TspHarness.start(tui => {
			wizard = new CustomProviderWizard(
				{ fetchModels: async () => [] },
				() => {},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;
		const providerInput = h.find(node => node.k === "input");
		if (!providerInput) throw new Error("provider input missing");

		h.event({
			ev: "edit",
			sf: surface,
			id: providerInput.id,
			from: 0,
			to: 0,
			text: "pasted-provider",
			cursor: 15,
			len: 0,
		});
		await h.render();
		expect(h.byId(providerInput.id)?.p).toMatchObject({ text: "pasted-provider", cursor: 15 });

		const next = h.find(node => {
			const props = node.p as { actions?: { click?: string } } | undefined;
			return node.k === "row" && props?.actions?.click === "next";
		});
		if (!next) throw new Error("native Continue action missing");
		h.event({ ev: "action", sf: surface, id: next.id, act: "next", mods: [] });
		await h.render();

		const protocolList = h.find(node => node.k === "list");
		if (!protocolList) throw new Error("protocol list missing");
		const protocols = h.findAll(node => node.k === "item");
		expect(protocols.length).toBeGreaterThan(1);
		const responses = protocols[1]!;
		h.event({ ev: "select", sf: surface, id: protocolList.id, item: responses.id });
		h.event({ ev: "activate", sf: surface, id: protocolList.id, item: responses.id });
		await h.render();

		const urlInput = h.find(node => node.k === "input");
		if (!urlInput) throw new Error("URL input missing after protocol activate");
		expect(h.terminal.docs.get(surface)?.focus).toBe(urlInput.id);
		const url = "https://api.example.test/v1";
		h.event({
			ev: "edit",
			sf: surface,
			id: urlInput.id,
			from: 0,
			to: 0,
			text: url,
			cursor: url.length,
			len: 0,
		});
		await h.render();
		expect(h.byId(urlInput.id)?.p).toMatchObject({ text: url, cursor: url.length });
		expect(
			h.find(node => {
				const props = node.p as { text?: string } | undefined;
				return Boolean(node.k === "text" && props?.text?.includes("Step 3: Base URL"));
			}),
		).toBeDefined();
	});
});

describe("CustomProviderWizard ANSI keyboard path", () => {
	it("accepts split characters, Backspace, and Enter through the focused TUI", () => {
		const terminal = new VirtualTerminal(100, 40);
		const tui = new TUI(terminal);
		const wizard = new CustomProviderWizard(
			{ fetchModels: async () => [] },
			() => {},
			() => {},
			() => tui.requestRender(),
			"en",
		);
		tui.addChild(wizard);
		tui.setFocus(wizard);
		tui.start();

		try {
			for (const char of "my-provider") {
				terminal.sendInput(char);
				tui.renderNow();
			}
			expect(terminal.getViewport().join("\n")).toContain("my-provider");

			terminal.sendInput("\x7f");
			tui.renderNow();
			const afterBackspace = terminal.getViewport().join("\n");
			expect(afterBackspace).toContain("my-provide");
			expect(afterBackspace).not.toContain("my-provider");

			terminal.sendInput("r");
			tui.renderNow();
			expect(terminal.getViewport().join("\n")).toContain("my-provider");

			terminal.sendInput("\r");
			tui.renderNow();
			expect(terminal.getViewport().join("\n")).toContain("Step 2: API Protocol");
		} finally {
			wizard.dispose();
			tui.stop();
		}
	});

	it("drives manage mode via single 'r' key, Space toggles, and Enter confirmation", async () => {
		const terminal = new VirtualTerminal(100, 40);
		const tui = new TUI(terminal);
		const fetchGate = Promise.withResolvers<CustomWizardModel[]>();
		const completionGate = Promise.withResolvers<CustomProviderWizardOutput>();

		const managed: CustomProviderWizardOutput = {
			providerId: "ansi-managed",
			api: "openai-completions",
			baseUrl: "http://127.0.0.1:8080/v1",
			models: [
				{ id: "stale-model", name: "Stale Model" },
				{ id: "retained-model", name: "Retained Model" },
			],
		};

		const wizard = new CustomProviderWizard(
			{
				fetchModels: () => fetchGate.promise,
				managedProvider: managed,
			},
			res => {
				completionGate.resolve(res);
			},
			() => {},
			() => tui.requestRender(),
			"en",
		);

		tui.addChild(wizard);
		tui.setFocus(wizard);
		tui.start();

		try {
			tui.renderNow();
			expect(terminal.getViewport().join("\n")).toContain("Manage Models");
			expect(terminal.getViewport().join("\n")).toContain("stale-model");
			expect(terminal.getViewport().join("\n")).toContain("retained-model");

			// Trigger R refresh via single 'r' key
			terminal.sendInput("r");
			fetchGate.resolve([
				{ id: "retained-model", name: "Retained Model" },
				{ id: "new-model", name: "New Model" },
			]);
			await fetchGate.promise;
			await Promise.resolve();
			await Promise.resolve();
			tui.renderNow();
			const afterRefresh = terminal.getViewport().join("\n");
			expect(afterRefresh).toContain("new-model");

			// Cursor is at index 0 (stale-model). Space toggles stale-model (uncheck it)
			terminal.sendInput(" ");
			tui.renderNow();

			// Down to index 1 (retained-model)
			terminal.sendInput("\x1b[B");
			tui.renderNow();

			// Down to index 2 (new-model)
			terminal.sendInput("\x1b[B");
			tui.renderNow();

			// Space toggles new-model (check it)
			terminal.sendInput(" ");
			tui.renderNow();

			// Enter advances to Confirm Model Changes
			terminal.sendInput("\r");
			tui.renderNow();

			const confirmView = terminal.getViewport().join("\n");
			expect(confirmView).toContain("Confirm Model Changes");
			expect(confirmView).toContain("+ Added Models (1):");
			expect(confirmView).toContain("- Removed Models (1):");

			// Enter confirms and saves
			terminal.sendInput("\r");
			tui.renderNow();

			const completedConfig = await completionGate.promise;
			expect(completedConfig.models.map(m => m.id)).toEqual(["retained-model", "new-model"]);
		} finally {
			wizard.dispose();
			tui.stop();
		}
	});
});

describe("CustomProviderWizard managedProvider native path", () => {
	it("starts in model selection offline without network, allows removing a model, and saves", async () => {
		let fetchCalled = false;
		let output: CustomProviderWizardOutput | undefined;
		const managed: CustomProviderWizardOutput = {
			providerId: "local-gateway",
			api: "openai-completions",
			baseUrl: "http://127.0.0.1:8080/v1",
			apiKey: "secret-key",
			models: [
				{ id: "stale-model", name: "Stale Model", contextWindow: 4096 },
				{ id: "retained-model", name: "Retained Model", contextWindow: 8192 },
			],
		};

		harness = await TspHarness.start(tui => {
			const wizard = new CustomProviderWizard(
				{
					fetchModels: async () => {
						fetchCalled = true;
						return [];
					},
					managedProvider: managed,
				},
				res => {
					output = res;
				},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;

		expect(fetchCalled).toBe(false);
		expect(h.findAll(candidate => candidate.k === "text" && candidate.p?.text === "Manage Models")).toHaveLength(1);

		const items = h.findAll(candidate => candidate.k === "item");
		expect(items).toHaveLength(2);
		expect(itemLabel(items[0]!)).toContain("[x] stale-model");
		expect(itemLabel(items[1]!)).toContain("[x] retained-model");

		const staleItem = items[0]!;
		const detail = staleItem.k === "item" ? staleItem.p?.detail : undefined;
		expect(String(detail)).toContain("(configured)");

		// Deselect stale-model offline
		const list = h.find(candidate => candidate.k === "list");
		if (!list) throw new Error("list missing");
		h.event({ ev: "activate", sf: surface, id: list.id, item: staleItem.id });
		await h.render();

		const updatedItems = h.findAll(candidate => candidate.k === "item");
		expect(itemLabel(updatedItems[0]!)).toContain("[ ] stale-model");
		expect(itemLabel(updatedItems[1]!)).toContain("[x] retained-model");

		// Advance to confirm
		await clickAction(h, surface, "next");
		expect(
			h.findAll(candidate => candidate.k === "text" && candidate.p?.text === "Confirm Model Changes"),
		).toHaveLength(1);

		const texts = nativeTexts(h).join("\n");
		expect(texts).toContain("Unchanged (existing credentials)");
		expect(texts).toContain("- Removed Models (1):");
		expect(texts).toContain("- stale-model");
		expect(texts).toContain("Final Configured Models (1):");
		expect(texts).toContain("• retained-model");

		await clickAction(h, surface, "next");
		await h.until(() => output !== undefined);

		expect(fetchCalled).toBe(false);
		expect(output?.models).toEqual([
			{
				id: "retained-model",
				name: "Retained Model",
				contextWindow: 8192,
				maxTokens: undefined,
				input: undefined,
				reasoning: undefined,
			},
		]);
	});

	it("allows deselecting all models in manage mode and confirms zero models", async () => {
		let output: CustomProviderWizardOutput | undefined;
		const managed: CustomProviderWizardOutput = {
			providerId: "empty-target",
			api: "openai-completions",
			baseUrl: "http://127.0.0.1:8080/v1",
			models: [{ id: "lone-model", name: "Lone Model" }],
		};

		harness = await TspHarness.start(tui => {
			const wizard = new CustomProviderWizard(
				{
					fetchModels: async () => [],
					managedProvider: managed,
				},
				res => {
					output = res;
				},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;

		const list = h.find(candidate => candidate.k === "list");
		const item = h.findAll(candidate => candidate.k === "item")[0]!;
		// Deselect lone model -> 0 models selected
		h.event({ ev: "activate", sf: surface, id: list!.id, item: item.id });
		await h.render();

		// Enter / next should succeed without error
		await clickAction(h, surface, "next");
		expect(
			h.findAll(candidate => candidate.k === "text" && candidate.p?.text === "Confirm Model Changes"),
		).toHaveLength(1);

		const texts = nativeTexts(h).join("\n");
		expect(texts).toContain("No models configured (0 selected).");
		expect(texts).toContain("- Removed Models (1):");

		await clickAction(h, surface, "next");
		await h.until(() => output !== undefined);

		expect(output?.models).toEqual([]);
		expect(output?.providerId).toBe("empty-target");
	});

	it("cancels on Esc from initial manage selection", async () => {
		let cancelled = false;
		const managed: CustomProviderWizardOutput = {
			providerId: "cancel-target",
			api: "openai-completions",
			baseUrl: "http://127.0.0.1:8080/v1",
			models: [{ id: "m1", name: "M1" }],
		};

		harness = await TspHarness.start(tui => {
			const wizard = new CustomProviderWizard(
				{
					fetchModels: async () => [],
					managedProvider: managed,
				},
				() => {},
				() => {
					cancelled = true;
				},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;

		await clickAction(h, surface, "cancel");
		expect(cancelled).toBe(true);
	});

	it("R refresh merges existing-first, preserves selections, and marks new candidates unchecked", async () => {
		let output: CustomProviderWizardOutput | undefined;
		let fetchCallArgs: { baseUrl: string; api: string; apiKey?: string } | undefined;
		const fetchGate = Promise.withResolvers<CustomWizardModel[]>();
		const managed: CustomProviderWizardOutput = {
			providerId: "merge-target",
			api: "anthropic-messages",
			baseUrl: "https://api.anthropic.example/v1",
			apiKey: "anthropic-key",
			models: [
				{ id: "stale-model", name: "Custom Stale Name", contextWindow: 4096 },
				{ id: "retained-model", name: "Custom Retained Name", contextWindow: 8192 },
			],
		};

		harness = await TspHarness.start(tui => {
			const wizard = new CustomProviderWizard(
				{
					fetchModels: async opts => {
						fetchCallArgs = opts;
						return fetchGate.promise;
					},
					managedProvider: managed,
				},
				res => {
					output = res;
				},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;

		// Click native refresh action
		await clickAction(h, surface, "refresh");
		fetchGate.resolve([
			{
				id: "retained-model",
				name: "Endpoint Discovered Name",
				contextWindow: 16384,
				contextSource: "endpoint",
				maxTokens: 4096,
				maxTokensSource: "endpoint",
			},
			{
				id: "new-model",
				name: "Brand New Model",
				contextWindow: 32768,
				contextSource: "endpoint",
				maxTokens: 8192,
				maxTokensSource: "endpoint",
			},
		]);
		await h.until(() =>
			h.findAll(candidate => candidate.k === "item").some(item => itemLabel(item).includes("new-model")),
		);
		expect(fetchCallArgs).toMatchObject({
			baseUrl: "https://api.anthropic.example/v1",
			api: "anthropic-messages",
			apiKey: "anthropic-key",
		});

		const items = h.findAll(candidate => candidate.k === "item");
		expect(items).toHaveLength(3);
		// Order: stale-model, retained-model, new-model
		expect(itemLabel(items[0]!)).toContain("[x] stale-model");
		expect(itemLabel(items[1]!)).toContain("[x] retained-model");
		expect(itemLabel(items[2]!)).toContain("[ ] new-model");

		// Metadata check: existing retained-model custom name and contextWindow preserved!
		const retainedDetail = items[1]!.k === "item" ? items[1]!.p?.detail : undefined;
		expect(String(retainedDetail)).toContain("ctx: 8192 (configured)");
		expect(String(retainedDetail)).toContain("max: 4096 (endpoint)");

		// Check new-model
		const list = h.find(candidate => candidate.k === "list");
		h.event({ ev: "activate", sf: surface, id: list!.id, item: items[2]!.id });
		await h.render();

		// Deselect stale-model
		h.event({ ev: "activate", sf: surface, id: list!.id, item: items[0]!.id });
		await h.render();

		await clickAction(h, surface, "next");
		const texts = nativeTexts(h).join("\n");
		expect(texts).toContain("+ Added Models (1):");
		expect(texts).toContain("+ new-model");
		expect(texts).toContain("- Removed Models (1):");
		expect(texts).toContain("- stale-model");
		expect(texts).toContain("Final Configured Models (2):");
		expect(texts).toContain("• retained-model");
		expect(texts).toContain("• new-model");

		await clickAction(h, surface, "next");
		await h.until(() => output !== undefined);

		expect(output?.models.map(m => m.id)).toEqual(["retained-model", "new-model"]);
	});

	it("fetch error during refresh allows Esc to return to model list safely", async () => {
		const managed: CustomProviderWizardOutput = {
			providerId: "error-target",
			api: "openai-completions",
			baseUrl: "http://127.0.0.1:8080/v1",
			models: [{ id: "safe-model", name: "Safe Model" }],
		};

		const fetchGate = Promise.withResolvers<CustomWizardModel[]>();
		harness = await TspHarness.start(tui => {
			const wizard = new CustomProviderWizard(
				{
					fetchModels: () => fetchGate.promise,
					managedProvider: managed,
				},
				() => {},
				() => {},
				() => tui.requestRender(),
				"en",
			);
			tui.addChild(wizard);
			tui.setFocus(wizard);
		});
		const h = harness;
		await h.render();
		const surface = h.terminal.surface!;

		// Click refresh -> fail via rejection
		await clickAction(h, surface, "refresh");
		fetchGate.reject(new Error("Network offline"));
		await h.until(() => nativeTexts(h).some(t => t.includes("Network offline")));

		// Click back (Esc) returns to selectModels
		await clickAction(h, surface, "back");
		await h.until(() =>
			h.findAll(candidate => candidate.k === "item").some(item => itemLabel(item).includes("safe-model")),
		);

		const items = h.findAll(candidate => candidate.k === "item");
		expect(items).toHaveLength(1);
		expect(itemLabel(items[0]!)).toContain("[x] safe-model");
	});
});
