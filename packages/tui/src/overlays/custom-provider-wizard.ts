/**
 * Custom Provider Add Wizard Component
 *
 * Interactive multi-step wizard for configuring custom OpenAI/Anthropic-compatible providers.
 * Supports automatic model discovery from endpoints with searchable multiselect,
 * displaying real metadata and omitting unknown limits from persistent config.
 */
import type { Api } from "@reverse/ai";
import { formatKeyHint } from "../app-keybindings";
import { boundKeys, editorKey, editorKeys } from "../chrome/keybinding-hints";
import type { KeyName } from "../key-hint-format";
import { OverlayPanel } from "../chrome/overlay-box";
import { TextFormField, type FormFieldTheme } from "../components/form";
import { Input } from "../components/input";
import { SelectList } from "../components/select-list";
import { WizardStep, type WizardStepKind } from "../components/wizard-step";
import { Container, matchesKey, Spacer, Text, wrapTextWithAnsi, type Component } from "../index";
import { getKeybindings } from "../keybindings";
import { matchesAppInterrupt, matchesSelectDown, matchesSelectUp } from "../keybinding-matchers";
import { col, compact, node, row, span, text } from "../native/describe";
import { type DescribeContext, leafKey, type NativeChild, type NativeNode, type NativeUiEvent } from "../native/node";
import { actionBar, actionButton } from "../native/overlay";
import { ensureThemeSync, getSelectListTheme, theme } from "../theme/theme";
import type { Focusable } from "../tui";
import type { SgrMouseEvent } from "../mouse";
import { resolveEffectiveLocale, type SupportedLocale } from "@reverse/utils/i18n";

export interface CustomWizardModel {
	id: string;
	name: string;
	contextWindow?: number;
	contextSource?: "endpoint" | "catalog" | "configured";
	maxTokens?: number;
	maxTokensSource?: "endpoint" | "catalog" | "configured";
	input?: ("text" | "image")[];
	reasoning?: boolean;
}

export interface CustomProviderWizardOutput {
	providerId: string;
	api: Api;
	baseUrl: string;
	apiKey?: string;
	models: CustomWizardModel[];
}

export interface CustomProviderWizardDeps {
	existingProviderIds?: readonly string[];
	validateProviderId?(id: string): string | undefined;
	fetchModels(options: {
		baseUrl: string;
		api: Api;
		apiKey?: string;
		signal?: AbortSignal;
	}): Promise<CustomWizardModel[]>;
	managedProvider?: CustomProviderWizardOutput;
}

export type CustomProviderWizardStep =
	| "providerId"
	| "api"
	| "baseUrl"
	| "apiKey"
	| "fetching"
	| "selectModels"
	| "confirm";

interface NativeStepActions {
	back?: string;
	backKey?: KeyName;
	next?: string;
	nextKey?: KeyName;
	refresh?: string;
	refreshKey?: KeyName;
}

interface NativeWizardStep {
	title: string;
	lead?: string;
	optional?: boolean;
	body: readonly NativeChild[];
	choices?: readonly { label: string; description?: string }[];
	actions: NativeStepActions;
}

function getFormTheme(): FormFieldTheme {
	ensureThemeSync();
	return {
		label: (t: string) => theme.fg("accent", t),
		description: (t: string) => theme.fg("muted", t),
		error: (t: string) => theme.fg("error", `${theme.status.error} ${t}`),
		hint: (t: string) => theme.fg("dim", t),
	};
}

function formatProvenance(
	source: "endpoint" | "catalog" | "configured" | undefined,
	t: (en: string, zh: string) => string,
): string {
	if (source === "endpoint") return t("endpoint", "端点声明");
	if (source === "catalog") return t("catalog", "官方目录");
	return t("configured", "已配置");
}

function formatModelMetadata(m: CustomWizardModel, t: (en: string, zh: string) => string): string {
	const metaParts: string[] = [];
	if (m.contextWindow !== undefined) {
		const src = formatProvenance(m.contextSource, t);
		metaParts.push(`ctx: ${m.contextWindow} (${src})`);
	} else {
		metaParts.push(t("ctx: unknown (runtime defaults apply)", "ctx: 未知 (运行时使用默认值)"));
	}
	if (m.maxTokens !== undefined) {
		const src = formatProvenance(m.maxTokensSource, t);
		metaParts.push(`max: ${m.maxTokens} (${src})`);
	} else {
		metaParts.push(t("max: unknown (output fallback applies)", "max: 未知 (运行时使用默认输出上限)"));
	}
	if (m.input && m.input.length > 0) {
		metaParts.push(`[${m.input.join(", ")}]`);
	}
	if (m.reasoning) {
		metaParts.push("reasoning");
	}
	return metaParts.join(" · ");
}

function mergeModelMetadata(existing: CustomWizardModel, discovered: CustomWizardModel): CustomWizardModel {
	return {
		id: existing.id,
		name: existing.name || discovered.name,
		contextWindow: existing.contextWindow ?? discovered.contextWindow,
		contextSource: existing.contextWindow !== undefined ? existing.contextSource : discovered.contextSource,
		maxTokens: existing.maxTokens ?? discovered.maxTokens,
		maxTokensSource: existing.maxTokens !== undefined ? existing.maxTokensSource : discovered.maxTokensSource,
		input: existing.input ?? discovered.input,
		reasoning: existing.reasoning ?? discovered.reasoning,
	};
}

class ModelMultiSelectList implements Component {
	constructor(
		private getItems: () => CustomWizardModel[],
		private getSelectedIds: () => Set<string>,
		private getSelectedIndex: () => number,
		private t: (en: string, zh: string) => string,
	) {}

	render(width: number): readonly string[] {
		const items = this.getItems();
		const selectedIds = this.getSelectedIds();
		const selectedIndex = this.getSelectedIndex();
		const lines: string[] = [];

		if (items.length === 0) {
			lines.push(`  ${theme.fg("muted", this.t("No matching models found.", "未找到匹配的模型。"))}`);
			return lines;
		}

		const visibleCount = Math.min(items.length, 8);
		const start = Math.max(0, Math.min(selectedIndex - Math.floor(visibleCount / 2), items.length - visibleCount));
		const end = Math.min(items.length, start + visibleCount);

		for (let i = start; i < end; i++) {
			const item = items[i];
			const isCursor = i === selectedIndex;
			const isChecked = selectedIds.has(item.id);

			const cursorPrefix = isCursor ? theme.fg("accent", `${theme.nav.cursor} `) : "  ";
			const boxGlyph = isChecked ? theme.checkbox.checked : theme.checkbox.unchecked;
			const boxStr = theme.fg(isChecked ? "success" : "dim", `${boxGlyph} `);

			const modelNameStr = item.name && item.name !== item.id ? ` (${item.name})` : "";
			const labelStr = isCursor
				? theme.bold(theme.fg("accent", `${item.id}${modelNameStr}`))
				: theme.fg("text", `${item.id}${modelNameStr}`);

			const metaParts = formatModelMetadata(item, this.t);
			const metaStr = theme.fg("dim", ` · ${metaParts}`);
			const line = `${cursorPrefix}${boxStr}${labelStr}${metaStr}`;
			lines.push(...wrapTextWithAnsi(line, width));
		}

		if (items.length > visibleCount) {
			const scrollHint = this.t(
				`(${selectedIndex + 1}/${items.length} models, use ↑/↓ to scroll)`,
				`(${selectedIndex + 1}/${items.length} 个模型，使用 ↑/↓ 滚动)`,
			);
			lines.push(`  ${theme.fg("dim", scrollHint)}`);
		}

		return lines;
	}
}

export class CustomProviderWizard extends OverlayPanel implements Focusable {
	#deps: CustomProviderWizardDeps;
	#locale: SupportedLocale;
	#isManageMode: boolean;
	#initialManagedModels: Map<string, CustomWizardModel> = new Map();
	#currentStep: CustomProviderWizardStep = "providerId";
	#providerId = "";
	#api: Api = "openai-completions";
	#baseUrl = "";
	#apiKey = "";

	// Discovered models & multi-select state
	#discoveredModels: CustomWizardModel[] = [];
	#selectedModelIds: Set<string> = new Set();
	#modelSearchInput: Input = new Input();
	#modelSelectedIndex = 0;
	#fetchAbort: AbortController | null = null;
	#fetchError: string | null = null;
	#fetchGeneration = 0;
	#disposed = false;

	#contentContainer: Container;
	#step: WizardStep | null = null;
	#stepKind: WizardStepKind = "input";
	#inputField: TextFormField | null = null;
	#currentSelectList: SelectList | null = null;
	#selectedIndex = 0;
	#validationError: string | null = null;
	#nativeStep: NativeWizardStep = { title: "", body: [], actions: {} };
	#native: NativeNode | undefined;
	#saving = false;
	#focused = true;

	#onCompleteCallback: (config: CustomProviderWizardOutput) => void | Promise<void>;
	#onCancelCallback: () => void;
	#onRenderCallback: (() => void) | null = null;

	constructor(
		deps: CustomProviderWizardDeps,
		onComplete: (config: CustomProviderWizardOutput) => void | Promise<void>,
		onCancel: () => void,
		onRender?: () => void,
		locale?: SupportedLocale,
	) {
		const effectiveLocale = locale ?? resolveEffectiveLocale();
		const isManageMode = Boolean(deps.managedProvider);
		const title = isManageMode
			? effectiveLocale === "zh-CN"
				? "管理自定义大模型提供商"
				: "Manage Custom Model Provider"
			: effectiveLocale === "zh-CN"
				? "添加自定义大模型提供商"
				: "Add Custom Model Provider";
		ensureThemeSync();
		super(title, isManageMode ? "reverse.overlay.customProviderManage" : "reverse.overlay.customProviderAdd");
		this.#deps = deps;
		this.#locale = effectiveLocale;
		this.#isManageMode = isManageMode;
		this.#onCompleteCallback = onComplete;
		this.#onCancelCallback = onCancel;
		this.#onRenderCallback = onRender ?? null;

		if (isManageMode && deps.managedProvider) {
			this.#providerId = deps.managedProvider.providerId;
			this.#api = deps.managedProvider.api;
			this.#baseUrl = deps.managedProvider.baseUrl;
			this.#apiKey = deps.managedProvider.apiKey ?? "";
			const initialModels = deps.managedProvider.models ?? [];
			this.#discoveredModels = [...initialModels];
			this.#selectedModelIds = new Set(initialModels.map(m => m.id));
			this.#initialManagedModels = new Map(initialModels.map(m => [m.id, m]));
			this.#currentStep = "selectModels";
		}

		this.addChild(new Spacer(1));
		this.#contentContainer = new Container();
		this.addChild(this.#contentContainer);
		this.addChild(new Spacer(1));

		this.#renderStep();
	}

	get focused(): boolean {
		return this.#focused;
	}

	set focused(value: boolean) {
		this.#focused = value;
		if (this.#inputField) {
			this.#inputField.focused = value;
		}
	}

	#requestRender(): void {
		this.#onRenderCallback?.();
	}

	#cancelWizard(): void {
		this.#fetchAbort?.abort();
		this.#onCancelCallback();
	}

	#show(step: WizardStep, native: NativeWizardStep): void {
		step.setMaxHeight(undefined);
		this.#step = step;
		this.#contentContainer.clear();
		this.#contentContainer.addChild(step);
		this.#nativeStep = native;
		this.#native = undefined;
		if (this.#focused && this.#inputField) {
			this.#inputField.focused = true;
		}
	}

	#t(en: string, zh: string): string {
		return this.#locale === "zh-CN" ? zh : en;
	}

	#renderStep(): void {
		this.#inputField = null;
		this.#currentSelectList = null;
		this.#stepKind = "input";

		switch (this.#currentStep) {
			case "providerId":
				this.#renderProviderIdStep();
				break;
			case "api":
				this.#renderApiStep();
				break;
			case "baseUrl":
				this.#renderBaseUrlStep();
				break;
			case "apiKey":
				this.#renderApiKeyStep();
				break;
			case "fetching":
				this.#renderFetchingStep();
				break;
			case "selectModels":
				this.#renderSelectModelsStep();
				break;
			case "confirm":
				this.#renderConfirmStep();
				break;
		}

		this.#requestRender();
	}

	#showInputStep(options: {
		stepTitle: string;
		lead: string;
		initial: string;
		placeholder?: string;
		hint?: string;
		optional?: boolean;
		secret?: boolean;
		empty?: "submit" | "reject";
		emptyError?: string;
		validate?: (value: string) => string | undefined;
		onSubmit: (value: string) => void;
		onCancel: () => void;
	}): void {
		this.#stepKind = "input";
		const cancelKey = (boundKeys("app.interrupt", ["escape"])[0] ?? "escape") as KeyName;
		const submitKey = (getKeybindings().getKeys("tui.input.submit")[0] ?? "enter") as KeyName;

		const field = new TextFormField({
			theme: getFormTheme(),
			label: options.lead,
			details: options.placeholder ? [new Text(theme.fg("muted", options.placeholder), 0, 0)] : undefined,
			initialValue: options.initial,
			secret: options.secret,
			hint: options.hint,
			empty: options.empty ?? (options.optional ? "submit" : "reject"),
			emptyError:
				options.emptyError ?? (options.optional ? undefined : this.#t("A value is required.", "此项为必填项。")),
			validate: options.validate,
			onSubmit: options.onSubmit,
			onCancel: options.onCancel,
			requestRender: () => this.#requestRender(),
		});

		this.#inputField = field;
		if (this.#validationError) {
			field.setError(this.#validationError);
			this.#validationError = null;
		}

		const caption = options.hint
			? text(options.hint, { role: "reverse.customProvider.note", wrap: "word" })
			: undefined;

		this.#show(
			new WizardStep({
				kind: "input",
				heading: new Text(theme.fg("accent", theme.bold(options.stepTitle)), 0, 0),
				content: field,
			}),
			{
				title: options.stepTitle,
				lead: options.lead,
				optional: options.optional,
				body: [
					node(
						"col",
						{ role: "reverse.customProvider.field", gap: "xs" },
						compact([field.input, caption]),
						"field",
					),
				],
				actions: {
					back: this.#currentStep === "providerId" ? undefined : this.#t("Back", "返回"),
					backKey: cancelKey,
					next: this.#t("Continue", "继续"),
					nextKey: submitKey,
				},
			},
		);
	}

	#renderProviderIdStep(): void {
		this.#showInputStep({
			stepTitle: this.#t("Step 1: Provider ID", "第 1 步：提供商标识"),
			lead: this.#t("Provider ID:", "提供商标识 (Provider ID)："),
			placeholder: this.#t("e.g. my-gateway, deepseek, local-vllm", "例如 my-gateway, deepseek, local-vllm"),
			hint: this.#t(
				"Letters, numbers, '.', '-', '_'. Enter to proceed, Esc to cancel.",
				"字母、数字、点、减号或下划线。Enter 下一步，Esc 取消。",
			),
			initial: this.#providerId,
			empty: "reject",
			emptyError: this.#t("Provider ID is required.", "提供商标识不能为空。"),
			validate: value => {
				const id = value.trim();
				if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(id)) {
					return this.#t(
						"ID must start with alphanumeric and contain only letters, numbers, '.', '-', '_'.",
						"标识必须以字母或数字开头，且仅包含字母、数字、点、减号或下划线。",
					);
				}
				if (this.#deps.existingProviderIds) {
					const lower = id.toLowerCase();
					if (this.#deps.existingProviderIds.some(existing => existing.toLowerCase() === lower)) {
						return this.#t(`Provider "${id}" already exists.`, `提供商 "${id}" 已存在。`);
					}
				}
				if (this.#deps.validateProviderId) {
					return this.#deps.validateProviderId(id);
				}
				return undefined;
			},
			onSubmit: value => {
				this.#providerId = value.trim();
				this.#currentStep = "api";
				this.#selectedIndex = 0;
				this.#renderStep();
			},
			onCancel: () => this.#cancelWizard(),
		});
	}

	#renderApiStep(): void {
		this.#stepKind = "choice";
		const cancelKey = (boundKeys("app.interrupt", ["escape"])[0] ?? "escape") as KeyName;
		const submitKey = (getKeybindings().getKeys("tui.input.submit")[0] ?? "enter") as KeyName;

		const choices = [
			{
				value: "openai-completions",
				label: "OpenAI Chat Completions",
				description: this.#t(
					"Standard chat completions protocol (POST /chat/completions)",
					"标准聊天补全协议 (POST /chat/completions)，兼容绝大多数 OpenAI 兼容服务",
				),
			},
			{
				value: "openai-responses",
				label: "OpenAI Responses",
				description: this.#t(
					"OpenAI Responses protocol (POST /responses)",
					"OpenAI 新版 Responses 协议 (POST /responses)",
				),
			},
			{
				value: "anthropic-messages",
				label: "Anthropic Messages",
				description: this.#t(
					"Anthropic Messages protocol (POST /messages)",
					"Anthropic Messages 协议 (POST /messages)",
				),
			},
		];

		const items = choices.map(choice => ({
			value: choice.value,
			label: choice.label,
			description: choice.description,
		}));

		const list = new SelectList(items, choices.length, getSelectListTheme(), {
			search: "never",
			renderItem: ({ item, selected, width }) => {
				const prefix = selected ? theme.fg("accent", `${theme.nav.cursor} `) : "  ";
				const label = selected ? theme.fg("accent", item.label) : item.label;
				const lines = wrapTextWithAnsi(prefix + label, width);
				if (item.description && !selected) {
					lines.push(...wrapTextWithAnsi(`    ${theme.fg("dim", item.description)}`, width));
				}
				return lines;
			},
		});

		this.#currentSelectList = list;
		list.setSelectedIndex(this.#selectedIndex);
		list.onSelect = item => {
			this.#api = item.value as Api;
			this.#currentStep = "baseUrl";
			this.#renderStep();
		};

		const hint = this.#t(
			`[${editorKeys("tui.select.up", "tui.select.down")} select · ${editorKey("tui.select.confirm")} confirm · ${editorKey("tui.select.cancel")} back]`,
			`[${editorKeys("tui.select.up", "tui.select.down")} 选择 · ${editorKey("tui.select.confirm")} 确认 · ${editorKey("tui.select.cancel")} 返回]`,
		);

		this.#show(
			new WizardStep({
				kind: "choice",
				heading: new Text(
					theme.fg("accent", theme.bold(this.#t("Step 2: API Protocol", "第 2 步：选择 API 协议"))),
					0,
					0,
				),
				content: list,
				footer: new Text(theme.fg("muted", hint), 0, 0),
			}),
			{
				title: this.#t("Step 2: API Protocol", "第 2 步：选择 API 协议"),
				body: [],
				choices,
				actions: {
					back: this.#t("Back", "返回"),
					backKey: cancelKey,
					next: this.#t("Continue", "继续"),
					nextKey: submitKey,
				},
			},
		);
	}

	#renderBaseUrlStep(): void {
		const placeholder =
			this.#api === "anthropic-messages" ? "https://api.anthropic.com/v1" : "https://api.openai.com/v1";

		this.#showInputStep({
			stepTitle: this.#t("Step 3: Base URL", "第 3 步：端点地址"),
			lead: this.#t("API Base URL:", "API 基础端点地址 (Base URL)："),
			placeholder: `e.g. ${placeholder}`,
			hint: this.#t(
				"Must start with http:// or https://. Enter to proceed, Esc to go back.",
				"必须以 http:// 或 https:// 开头。Enter 下一步，Esc 返回。",
			),
			initial: this.#baseUrl || (this.#api === "anthropic-messages" ? "https://api.anthropic.com/v1" : ""),
			empty: "reject",
			emptyError: this.#t("Base URL is required.", "基础端点地址不能为空。"),
			validate: value => {
				const trimmed = value.trim();
				if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
					return this.#t("URL must start with http:// or https://.", "URL 必须以 http:// 或 https:// 开头。");
				}
				try {
					new URL(trimmed);
				} catch {
					return this.#t("Invalid URL format.", "无效的 URL 格式。");
				}
				return undefined;
			},
			onSubmit: value => {
				this.#baseUrl = value.trim();
				this.#currentStep = "apiKey";
				this.#renderStep();
			},
			onCancel: () => {
				this.#currentStep = "api";
				this.#renderStep();
			},
		});
	}

	#renderApiKeyStep(): void {
		this.#showInputStep({
			stepTitle: this.#t("Step 4: API Key", "第 4 步：API 密钥"),
			lead: this.#t("API Key (optional):", "API 密钥（可选）："),
			hint: this.#t(
				"Optional. Leave blank for keyless local endpoints (Ollama/vLLM). Secret is stored in SQLite agent.db, not models.yml.",
				"可选。留空即为免密端点 (Ollama/vLLM)。密钥将安全存储于 SQLite 凭证库，不会写入 models.yml 明文。",
			),
			initial: this.#apiKey,
			secret: true,
			optional: true,
			empty: "submit",
			onSubmit: value => {
				this.#apiKey = value.trim();
				this.#currentStep = "fetching";
				this.#fetchError = null;
				this.#renderStep();
				void this.#runFetchModels();
			},
			onCancel: () => {
				this.#currentStep = "baseUrl";
				this.#renderStep();
			},
		});
	}

	#triggerRefresh(): void {
		this.#fetchAbort?.abort();
		this.#currentStep = "fetching";
		this.#fetchError = null;
		this.#renderStep();
		void this.#runFetchModels();
	}

	async #runFetchModels(): Promise<void> {
		this.#fetchAbort?.abort();
		const controller = new AbortController();
		this.#fetchAbort = controller;
		const generation = ++this.#fetchGeneration;

		try {
			const models = await this.#deps.fetchModels({
				baseUrl: this.#baseUrl,
				api: this.#api,
				apiKey: this.#apiKey || undefined,
				signal: controller.signal,
			});

			// 仅在当前请求依然有效且未被中止、向导仍处于 fetching 状态时应用结果
			if (
				this.#disposed ||
				controller.signal.aborted ||
				this.#fetchAbort !== controller ||
				this.#fetchGeneration !== generation ||
				this.#currentStep !== "fetching"
			) {
				return;
			}

			if (this.#isManageMode) {
				const initialIds = new Set(this.#initialManagedModels.keys());
				const endpointMap = new Map(models.map(m => [m.id, m]));
				const merged: CustomWizardModel[] = [];

				// 1. Existing models in their initial configured order:
				for (const [id, initial] of this.#initialManagedModels) {
					const endpoint = endpointMap.get(id);
					if (endpoint) {
						merged.push(mergeModelMetadata(initial, endpoint));
					} else {
						merged.push(initial);
					}
				}

				// 2. Newly discovered candidates from endpoint (in endpoint order):
				for (const endpoint of models) {
					if (!initialIds.has(endpoint.id)) {
						merged.push(endpoint);
					}
				}

				// 3. Retain any other previously discovered models:
				const seenIds = new Set(merged.map(m => m.id));
				for (const prev of this.#discoveredModels) {
					if (!seenIds.has(prev.id)) {
						merged.push(prev);
						seenIds.add(prev.id);
					}
				}

				this.#discoveredModels = merged;
			} else {
				this.#discoveredModels = models;
				this.#selectedModelIds = new Set(models.map(m => m.id));
			}
			this.#modelSearchInput.setValue("");
			this.#modelSelectedIndex = 0;
			this.#selectedIndex = 0;
			this.#currentStep = "selectModels";
			this.#renderStep();
		} catch (error) {
			// 若当前请求已被取消或已被后续探测接替，则静默忽略过时异常
			if (
				this.#disposed ||
				controller.signal.aborted ||
				this.#fetchAbort !== controller ||
				this.#fetchGeneration !== generation ||
				this.#currentStep !== "fetching"
			) {
				return;
			}
			this.#fetchError = error instanceof Error ? error.message : String(error);
			this.#renderStep();
		} finally {
			// 仅在当前活动控制器属于本轮请求时清理引用，避免冲掉并发起动的新请求
			if (this.#fetchAbort === controller) {
				this.#fetchAbort = null;
			}
		}
	}

	#renderFetchingStep(): void {
		this.#stepKind = "choice";
		const cancelKey = (boundKeys("app.interrupt", ["escape"])[0] ?? "escape") as KeyName;
		const submitKey = (getKeybindings().getKeys("tui.input.submit")[0] ?? "enter") as KeyName;
		const container = new Container();

		if (this.#fetchError) {
			container.addChild(new Text(theme.fg("error", `✗ ${this.#fetchError}`), 0, 0));
			container.addChild(new Spacer(1));
			const retryHint = this.#isManageMode
				? this.#t("[Enter / R] Retry  [Esc] Back to model list", "[Enter / R] 重试  [Esc] 返回模型列表")
				: this.#t("[Enter / R] Retry  [Esc] Back to edit API Key", "[Enter / R] 重试  [Esc] 返回修改密钥与端点");
			container.addChild(new Text(theme.fg("dim", retryHint), 0, 0));

			this.#show(
				new WizardStep({
					kind: "choice",
					heading: new Text(
						theme.fg("error", theme.bold(this.#t("Model Discovery Failed", "获取模型列表失败"))),
						0,
						0,
					),
					content: container,
				}),
				{
					title: this.#t("Discovery Failed", "获取模型失败"),
					body: [
						text(this.#fetchError, { role: "reverse.customProvider.error", tone: "error", wrap: "word" }),
						text(retryHint, { tone: "muted", wrap: "word" }),
					],
					actions: {
						back: this.#t("Back", "返回"),
						backKey: cancelKey,
						next: this.#t("Retry", "重试"),
						nextKey: submitKey,
					},
				},
			);
			return;
		}

		container.addChild(
			new Text(
				theme.fg(
					"accent",
					this.#t("Discovering available models from endpoint…", "正在从端点探测获取可用模型列表…"),
				),
				0,
				0,
			),
		);
		container.addChild(new Text(theme.fg("dim", this.#t("Press Esc to cancel.", "按 Esc 可取消返回。")), 0, 0));

		this.#show(
			new WizardStep({
				kind: "choice",
				heading: new Text(theme.fg("accent", theme.bold(this.#t("Fetching Models", "正在获取模型"))), 0, 0),
				content: container,
			}),
			{
				title: this.#t("Fetching Models", "正在获取模型"),
				body: [
					node("spinner", {
						style: "dots",
						label: [span(this.#t("Fetching models…", "正在获取模型…"), "accent")],
					}),
				],
				actions: {
					back: this.#t("Cancel", "取消"),
					backKey: cancelKey,
				},
			},
		);
	}

	#getFilteredDiscoveredModels(): CustomWizardModel[] {
		const query = this.#modelSearchInput.getValue().trim().toLowerCase();
		if (!query) return this.#discoveredModels;
		return this.#discoveredModels.filter(
			m => m.id.toLowerCase().includes(query) || (m.name && m.name.toLowerCase().includes(query)),
		);
	}

	#renderSelectModelsStep(): void {
		this.#stepKind = "choice";
		const cancelKey = (boundKeys("app.interrupt", ["escape"])[0] ?? "escape") as KeyName;
		const submitKey = (getKeybindings().getKeys("tui.input.submit")[0] ?? "enter") as KeyName;
		const container = new Container();

		const searchPrompt = this.#t("Search models: ", "搜索模型: ");
		const searchWidth = 60;
		const searchLine = theme.fg("muted", searchPrompt) + (this.#modelSearchInput.render(searchWidth)[0] ?? "");
		container.addChild(new Text(searchLine, 0, 0));
		container.addChild(new Spacer(1));

		const listComponent = new ModelMultiSelectList(
			() => this.#getFilteredDiscoveredModels(),
			() => this.#selectedModelIds,
			() => this.#modelSelectedIndex,
			(en, zh) => this.#t(en, zh),
		);
		container.addChild(listComponent);

		if (this.#validationError) {
			container.addChild(new Spacer(1));
			container.addChild(new Text(theme.fg("error", `${theme.status.error} ${this.#validationError}`), 0, 0));
		}

		const countHint = this.#isManageMode
			? this.#t(
					`[${this.#selectedModelIds.size}/${this.#discoveredModels.length} selected] [Space] Toggle · [R / Ctrl+R] Refresh · [Enter] Continue · [Esc] Cancel`,
					`[已选 ${this.#selectedModelIds.size}/${this.#discoveredModels.length}] [空格] 勾选/取消 · [R / Ctrl+R] 刷新 · [Enter] 继续 · [Esc] 取消`,
				)
			: this.#t(
					`[${this.#selectedModelIds.size}/${this.#discoveredModels.length} selected] [Space] Toggle · [Enter] Continue · [Esc] Back`,
					`[已选 ${this.#selectedModelIds.size}/${this.#discoveredModels.length}] [空格] 勾选/取消 · [Enter] 继续 · [Esc] 返回`,
				);

		const stepHeading = this.#isManageMode
			? this.#t("Manage Models", "管理模型")
			: this.#t("Step 5: Select Models", "第 5 步：选择模型");

		const nativeTitle = this.#isManageMode
			? this.#t("Manage Models", "管理模型")
			: this.#t("Select Models", "选择模型");

		const filtered = this.#getFilteredDiscoveredModels();
		const nativeChoices = filtered.map(m => ({
			label: `${this.#selectedModelIds.has(m.id) ? "[x] " : "[ ] "}${m.id}${m.name && m.name !== m.id ? ` (${m.name})` : ""}`,
			description: formatModelMetadata(m, (en, zh) => this.#t(en, zh)),
		}));

		this.#show(
			new WizardStep({
				kind: "choice",
				heading: new Text(theme.fg("accent", theme.bold(stepHeading)), 0, 0),
				content: container,
				footer: new Text(theme.fg("muted", countHint), 0, 0),
			}),
			{
				title: nativeTitle,
				body: compact([
					node(
						"col",
						{ role: "reverse.customProvider.search", gap: "xs" },
						[
							node(
								"input",
								{
									text: this.#modelSearchInput.getValue(),
									cursor: this.#modelSearchInput.getCursor(),
									placeholder: this.#t("Search models…", "搜索模型…"),
								},
								undefined,
								"model-search",
							),
						],
						"search-input",
					),
					text(countHint, { role: "reverse.customProvider.help", wrap: "word" }),
					this.#validationError
						? text(this.#validationError, { role: "reverse.customProvider.error", tone: "error", wrap: "word" })
						: undefined,
				]),
				choices: nativeChoices,
				actions: {
					back: this.#isManageMode ? this.#t("Cancel", "取消") : this.#t("Back", "返回"),
					backKey: cancelKey,
					next: this.#t("Continue", "继续"),
					nextKey: submitKey,
					...(this.#isManageMode
						? {
								refresh: this.#t("Refresh", "刷新"),
								refreshKey: "r" as KeyName,
							}
						: {}),
				},
			},
		);
	}

	#renderConfirmStep(): void {
		this.#stepKind = "choice";
		const cancelKey = (boundKeys("app.interrupt", ["escape"])[0] ?? "escape") as KeyName;
		const submitKey = (getKeybindings().getKeys("tui.input.submit")[0] ?? "enter") as KeyName;
		const container = new Container();

		const authLabel = this.#isManageMode
			? this.#t("Unchanged (existing credentials)", "保持现有凭证")
			: this.#apiKey
				? this.#t("[Configured (securely stored in agent.db)]", "[已提供（安全存储于本地 SQLite 凭据库）]")
				: this.#t("[Keyless / None]", "[免密 / 无密钥]");

		const selectedModels = this.#discoveredModels.filter(m => this.#selectedModelIds.has(m.id));

		const nativeBody: NativeChild[] = [
			text(
				this.#isManageMode
					? this.#t("Summary of Model Management:", "模型管理汇总：")
					: this.#t("Summary of Custom Provider:", "自定义提供商汇总："),
				{
					role: "reverse.customProvider.summaryTitle",
				},
			),
			text(`${this.#t("Provider ID:", "提供商标识:")} ${this.#providerId}`),
			text(`${this.#t("API Protocol:", "API 协议:")} ${this.#api}`),
			text(`${this.#t("Base URL:", "端点地址:")} ${this.#baseUrl}`),
			text(`${this.#t("API Key:", "API 密钥:")} ${authLabel}`),
		];

		if (this.#isManageMode) {
			const initialIds = new Set(this.#initialManagedModels.keys());
			const addedModels = selectedModels.filter(m => !initialIds.has(m.id));
			const removedModels = Array.from(this.#initialManagedModels.values()).filter(
				m => !this.#selectedModelIds.has(m.id),
			);

			container.addChild(new Text(theme.bold(this.#t("Summary of Model Management:", "模型管理汇总：")), 0, 0));
			container.addChild(
				new Text(
					`  ${theme.fg("dim", this.#t("Provider ID:", "提供商标识:"))} ${theme.fg("accent", this.#providerId)}`,
					0,
					0,
				),
			);
			container.addChild(new Text(`  ${theme.fg("dim", this.#t("API Protocol:", "API 协议:"))} ${this.#api}`, 0, 0));
			container.addChild(
				new Text(`  ${theme.fg("dim", this.#t("Base URL:", "端点地址:"))}     ${this.#baseUrl}`, 0, 0),
			);
			container.addChild(new Text(`  ${theme.fg("dim", this.#t("API Key:", "API 密钥:"))}      ${authLabel}`, 0, 0));
			container.addChild(new Spacer(1));

			if (addedModels.length > 0) {
				container.addChild(
					new Text(
						theme.bold(
							theme.fg(
								"success",
								this.#t(`+ Added Models (${addedModels.length}):`, `+ 新增模型 (${addedModels.length})：`),
							),
						),
						0,
						0,
					),
				);
				for (const m of addedModels) {
					const nameStr = m.name && m.name !== m.id ? ` (${m.name})` : "";
					const meta = formatModelMetadata(m, (en, zh) => this.#t(en, zh));
					container.addChild(
						new Text(`  + ${theme.fg("success", m.id)}${nameStr} - ${theme.fg("dim", meta)}`, 0, 0),
					);
				}
				container.addChild(new Spacer(1));

				nativeBody.push(
					text(this.#t(`+ Added Models (${addedModels.length}):`, `+ 新增模型 (${addedModels.length})：`)),
					...addedModels.map(m => {
						const nameStr = m.name && m.name !== m.id ? ` (${m.name})` : "";
						const meta = formatModelMetadata(m, (en, zh) => this.#t(en, zh));
						return text(`+ ${m.id}${nameStr} - ${meta}`);
					}),
				);
			}

			if (removedModels.length > 0) {
				container.addChild(
					new Text(
						theme.bold(
							theme.fg(
								"error",
								this.#t(
									`- Removed Models (${removedModels.length}):`,
									`- 移除模型 (${removedModels.length})：`,
								),
							),
						),
						0,
						0,
					),
				);
				for (const m of removedModels) {
					const nameStr = m.name && m.name !== m.id ? ` (${m.name})` : "";
					container.addChild(new Text(`  - ${theme.fg("error", m.id)}${nameStr}`, 0, 0));
				}
				container.addChild(new Spacer(1));

				nativeBody.push(
					text(this.#t(`- Removed Models (${removedModels.length}):`, `- 移除模型 (${removedModels.length})：`)),
					...removedModels.map(m => {
						const nameStr = m.name && m.name !== m.id ? ` (${m.name})` : "";
						return text(`- ${m.id}${nameStr}`);
					}),
				);
			}

			if (selectedModels.length === 0) {
				container.addChild(
					new Text(
						theme.fg("warning", this.#t("No models configured (0 selected).", "未配置任何模型 (已选 0 个)。")),
						0,
						0,
					),
				);
				nativeBody.push(text(this.#t("No models configured (0 selected).", "未配置任何模型 (已选 0 个)。")));
			} else {
				container.addChild(
					new Text(
						theme.bold(
							this.#t(
								`Final Configured Models (${selectedModels.length}):`,
								`最终保留模型 (${selectedModels.length})：`,
							),
						),
						0,
						0,
					),
				);
				for (const m of selectedModels) {
					const nameStr = m.name && m.name !== m.id ? ` (${m.name})` : "";
					const meta = formatModelMetadata(m, (en, zh) => this.#t(en, zh));
					container.addChild(
						new Text(`  • ${theme.fg("accent", m.id)}${nameStr} - ${theme.fg("dim", meta)}`, 0, 0),
					);
				}

				nativeBody.push(
					text(
						this.#t(
							`Final Configured Models (${selectedModels.length}):`,
							`最终保留模型 (${selectedModels.length})：`,
						),
					),
					...selectedModels.map(m => {
						const nameStr = m.name && m.name !== m.id ? ` (${m.name})` : "";
						const meta = formatModelMetadata(m, (en, zh) => this.#t(en, zh));
						return text(`• ${m.id}${nameStr} - ${meta}`);
					}),
				);
			}
		} else {
			container.addChild(new Text(theme.bold(this.#t("Summary of Custom Provider:", "自定义提供商汇总：")), 0, 0));
			container.addChild(
				new Text(`  ${theme.fg("dim", "Provider ID:")} ${theme.fg("accent", this.#providerId)}`, 0, 0),
			);
			container.addChild(new Text(`  ${theme.fg("dim", "API Protocol:")} ${this.#api}`, 0, 0));
			container.addChild(new Text(`  ${theme.fg("dim", "Base URL:")}     ${this.#baseUrl}`, 0, 0));
			container.addChild(new Text(`  ${theme.fg("dim", "API Key:")}      ${authLabel}`, 0, 0));
			container.addChild(new Spacer(1));
			container.addChild(
				new Text(
					theme.bold(
						this.#t(`Selected Models (${selectedModels.length}):`, `所选模型 (${selectedModels.length})：`),
					),
					0,
					0,
				),
			);

			for (const m of selectedModels) {
				const nameStr = m.name && m.name !== m.id ? ` (${m.name})` : "";
				const meta = formatModelMetadata(m, (en, zh) => this.#t(en, zh));
				container.addChild(new Text(`  • ${theme.fg("accent", m.id)}${nameStr} - ${theme.fg("dim", meta)}`, 0, 0));
			}

			nativeBody.push(
				text(this.#t(`Selected Models (${selectedModels.length}):`, `所选模型 (${selectedModels.length})：`)),
				...selectedModels.map(m => {
					const nameStr = m.name && m.name !== m.id ? ` (${m.name})` : "";
					const meta = formatModelMetadata(m, (en, zh) => this.#t(en, zh));
					return text(`• ${m.id}${nameStr} - ${meta}`);
				}),
			);
		}

		if (this.#validationError) {
			container.addChild(new Spacer(1));
			container.addChild(new Text(theme.fg("error", `${theme.status.error} ${this.#validationError}`), 0, 0));
			nativeBody.push(
				text(this.#validationError, { role: "reverse.customProvider.error", tone: "error", wrap: "word" }),
			);
		}

		const saveText = this.#isManageMode
			? this.#t("Save Changes", "保存修改")
			: this.#t("Save Provider", "确认保存提供商");
		const cancelText = this.#t("Back", "返回");
		const hint = this.#t(
			`[${formatKeyHint("enter")} ${saveText} · ${editorKey("tui.select.cancel")} ${cancelText}]`,
			`[${formatKeyHint("enter")} ${saveText} · ${editorKey("tui.select.cancel")} ${cancelText}]`,
		);

		const confirmTitle = this.#isManageMode
			? this.#t("Confirm Model Changes", "确认模型变更")
			: this.#t("Confirm Configuration", "确认配置");

		this.#show(
			new WizardStep({
				kind: "confirm",
				heading: new Text(theme.fg("accent", theme.bold(confirmTitle)), 0, 0),
				content: container,
				footer: new Text(theme.fg("muted", hint), 0, 0),
			}),
			{
				title: confirmTitle,
				body: nativeBody,
				actions: {
					back: cancelText,
					backKey: cancelKey,
					next: saveText,
					nextKey: submitKey,
				},
			},
		);
	}

	async #submitFinal(): Promise<void> {
		if (this.#saving) return;
		this.#saving = true;
		this.#requestRender();

		const selectedModels = this.#discoveredModels.filter(m => this.#selectedModelIds.has(m.id));

		try {
			await this.#onCompleteCallback({
				providerId: this.#providerId,
				api: this.#api,
				baseUrl: this.#baseUrl,
				apiKey: this.#apiKey || undefined,
				models: selectedModels.map(m => ({
					id: m.id,
					name: m.name,
					contextWindow: m.contextWindow,
					maxTokens: m.maxTokens,
					input: m.input,
					reasoning: m.reasoning,
				})),
			});
		} catch (error) {
			this.#saving = false;
			this.#validationError = error instanceof Error ? error.message : String(error);
			this.#renderStep();
		}
	}

	handleInput(keyData: string): void {
		if (this.#saving) return;

		// Handle Ctrl+C to cancel wizard immediately
		if (keyData === "\x03") {
			this.#cancelWizard();
			return;
		}

		if (this.#inputField) {
			this.#step?.handleInput(keyData);
			return;
		}

		if (matchesAppInterrupt(keyData)) {
			if (this.#currentStep === "providerId" || (this.#isManageMode && this.#currentStep === "selectModels")) {
				this.#cancelWizard();
				return;
			}
			this.#goBack();
			return;
		}

		if (this.#currentStep === "fetching") {
			if (this.#fetchError && (matchesKey(keyData, "enter") || keyData.toLowerCase() === "r")) {
				this.#fetchError = null;
				this.#renderStep();
				void this.#runFetchModels();
				return;
			}
			return;
		}

		if (this.#currentStep === "selectModels") {
			const items = this.#getFilteredDiscoveredModels();

			if (keyData === " ") {
				// Toggle highlighted model
				const current = items[this.#modelSelectedIndex];
				if (current) {
					if (this.#selectedModelIds.has(current.id)) {
						this.#selectedModelIds.delete(current.id);
					} else {
						this.#selectedModelIds.add(current.id);
					}
					this.#validationError = null;
					this.#renderStep();
				}
				return;
			}

			if (matchesSelectUp(keyData)) {
				if (items.length > 0) {
					this.#modelSelectedIndex = (this.#modelSelectedIndex - 1 + items.length) % items.length;
					this.#renderStep();
				}
				return;
			}

			if (matchesSelectDown(keyData)) {
				if (items.length > 0) {
					this.#modelSelectedIndex = (this.#modelSelectedIndex + 1) % items.length;
					this.#renderStep();
				}
				return;
			}

			const queryEmpty = this.#modelSearchInput.getValue().length === 0;
			const isRefreshKey = keyData === "\x12" || (queryEmpty && keyData.toLowerCase() === "r");
			if (this.#isManageMode && isRefreshKey) {
				this.#triggerRefresh();
				return;
			}

			if (matchesKey(keyData, "enter") || matchesKey(keyData, "return") || keyData === "\n") {
				if (!this.#isManageMode && this.#selectedModelIds.size === 0) {
					this.#validationError = this.#t("Please select at least one model.", "请至少选择一个模型。");
					this.#renderStep();
					return;
				}
				this.#validationError = null;
				this.#currentStep = "confirm";
				this.#renderStep();
				return;
			}

			// Filter text typing
			this.#modelSearchInput.handleInput(keyData);
			this.#modelSelectedIndex = 0;
			this.#renderStep();
			return;
		}

		if (this.#currentStep === "confirm") {
			if (matchesKey(keyData, "enter") || matchesKey(keyData, "return") || keyData === "\n") {
				void this.#submitFinal();
				return;
			}
		}

		if (this.#stepKind === "choice") {
			if (this.#currentSelectList) {
				this.#currentSelectList.handleInput(keyData);
				this.#requestRender();
				return;
			}
		}
	}

	handleNativeEvent(event: NativeUiEvent): void {
		if (this.#saving) return;
		if (event.type === "action") {
			this.#runAction(event.act);
			return;
		}
		if (event.type === "edit" || event.type === "undo") {
			if (this.#currentStep === "selectModels") {
				this.#modelSearchInput.handleNativeEvent(event);
				this.#modelSelectedIndex = 0;
				this.#renderStep();
				return;
			}
			this.#inputField?.input.handleNativeEvent(event);
			this.#requestRender();
			return;
		}
		if (event.type !== "select" && event.type !== "activate") return;

		if (this.#currentStep === "selectModels") {
			const items = this.#getFilteredDiscoveredModels();
			const idx = Number(event.item);
			if (Number.isInteger(idx) && items[idx]) {
				this.#modelSelectedIndex = idx;
				this.#selectedIndex = idx;
				if (event.type === "activate") {
					const id = items[idx].id;
					if (this.#selectedModelIds.has(id)) {
						this.#selectedModelIds.delete(id);
					} else {
						this.#selectedModelIds.add(id);
					}
				}
				this.#renderStep();
			}
			return;
		}

		if (leafKey(event.key) !== `choices-${this.#currentStep}`) return;
		if (this.#inputField) return;
		const index = Number(event.item);
		if (!Number.isInteger(index) || index < 0) return;
		this.#selectedIndex = index;
		if (this.#currentSelectList) {
			this.#currentSelectList.setSelectedIndex(index);
		}
		if (event.type === "activate") {
			if (this.#currentStep === "api") {
				const apis: Api[] = ["openai-completions", "openai-responses", "anthropic-messages"];
				if (apis[index]) {
					this.#api = apis[index];
					this.#currentStep = "baseUrl";
					this.#renderStep();
				}
			}
		}
		this.#requestRender();
	}

	#runAction(act: string): void {
		switch (act) {
			case "cancel":
				this.#cancelWizard();
				return;
			case "back":
				this.#fetchAbort?.abort();
				if (this.#currentStep === "providerId" || (this.#isManageMode && this.#currentStep === "selectModels")) {
					this.#cancelWizard();
				} else {
					this.#goBack();
				}
				break;
			case "refresh":
				if (this.#currentStep === "selectModels" || this.#currentStep === "fetching") {
					this.#triggerRefresh();
				}
				break;
			case "next":
				if (this.#inputField) {
					this.#inputField.submit();
				} else if (this.#currentStep === "fetching" && this.#fetchError) {
					this.#fetchError = null;
					this.#renderStep();
					void this.#runFetchModels();
				} else if (this.#currentStep === "selectModels") {
					if (!this.#isManageMode && this.#selectedModelIds.size === 0) {
						this.#validationError = this.#t("Please select at least one model.", "请至少选择一个模型。");
						this.#renderStep();
						return;
					}
					this.#validationError = null;
					this.#currentStep = "confirm";
					this.#renderStep();
				} else if (this.#currentStep === "confirm") {
					void this.#submitFinal();
				} else if (this.#currentStep === "api") {
					const apis: Api[] = ["openai-completions", "openai-responses", "anthropic-messages"];
					if (apis[this.#selectedIndex]) {
						this.#api = apis[this.#selectedIndex];
						this.#currentStep = "baseUrl";
						this.#renderStep();
					}
				}
				break;
			default:
				return;
		}
		this.#requestRender();
	}

	#goBack(): void {
		this.#fetchAbort?.abort();
		switch (this.#currentStep) {
			case "providerId":
				this.#cancelWizard();
				break;
			case "api":
				this.#currentStep = "providerId";
				this.#renderStep();
				break;
			case "baseUrl":
				this.#currentStep = "api";
				this.#renderStep();
				break;
			case "apiKey":
				this.#currentStep = "baseUrl";
				this.#renderStep();
				break;
			case "fetching":
				this.#fetchAbort?.abort();
				if (this.#isManageMode) {
					this.#currentStep = "selectModels";
				} else {
					this.#currentStep = "apiKey";
				}
				this.#renderStep();
				break;
			case "selectModels":
				this.#fetchAbort?.abort();
				if (this.#isManageMode) {
					this.#cancelWizard();
				} else {
					this.#currentStep = "apiKey";
					this.#renderStep();
				}
				break;
			case "confirm":
				this.#currentStep = "selectModels";
				this.#renderStep();
				break;
		}
	}

	#describeActions(actions: NativeStepActions): NativeNode {
		const cancelKey = (boundKeys("app.interrupt", ["escape"])[0] ?? "escape") as KeyName;
		const cancelLabel = this.#t("Cancel", "取消");
		const buttons: (NativeNode | null)[] = [
			actionButton(cancelLabel, "cancel", { keys: actions.back === undefined ? actions.backKey : cancelKey }),
			null,
		];
		if (actions.back) {
			buttons.push(actionButton(actions.back, "back", { keys: actions.backKey }));
		}
		if (actions.refresh) {
			buttons.push(actionButton(actions.refresh, "refresh", { keys: actions.refreshKey }));
		}
		if (actions.next) {
			buttons.push(actionButton(actions.next, "next", { keys: actions.nextKey, tone: "accent" }));
		}
		return actionBar(buttons);
	}

	override describe(_cx: DescribeContext): NativeNode {
		if (this.#native) return this.#native;
		const step = this.#nativeStep;
		const titleRow = row(
			compact([
				text(step.title, { role: "reverse.customProvider.title", wrap: "word" }),
				step.optional && text(this.#t("Optional", "可选"), { role: "reverse.customProvider.tag" }),
			]),
			{ gap: "sm", align: "center" },
		);
		const head = compact([
			titleRow,
			step.lead ? text(step.lead, { role: "reverse.customProvider.lead", wrap: "word" }) : undefined,
		]);
		const children: NativeChild[] = [
			node("col", { role: "reverse.customProvider.head", gap: "xs" }, head, "head"),
			...step.body,
		];
		if (step.choices) {
			const items = step.choices.map((choice, index) =>
				node(
					"item",
					{
						label: choice.label,
						...(choice.description ? { detail: choice.description } : {}),
					},
					undefined,
					String(index),
				),
			);
			const selectedKey =
				this.#currentStep === "selectModels" ? String(this.#modelSelectedIndex) : String(this.#selectedIndex);
			children.push(
				node(
					"list",
					{ selected: selectedKey, role: "reverse.customProvider.choices" },
					items,
					`choices-${this.#currentStep}`,
				),
			);
		}
		children.push(this.#describeActions(step.actions));
		const sheet = node(
			"overlay",
			{ role: this.nativeRole, head: this.title, anchor: "center", size: "md", modal: true },
			[col(children, { gap: "lg" })],
			"sheet",
		);
		this.#native = col([sheet]);
		return this.#native;
	}

	override render(width: number): readonly string[] {
		return super.render(width);
	}

	routeMouse(event: SgrMouseEvent, line: number, col: number): void {
		this.#step?.routeMouse(event, line, col);
	}

	override dispose(): void {
		this.#disposed = true;
		this.#fetchAbort?.abort();
		super.dispose();
	}
}
