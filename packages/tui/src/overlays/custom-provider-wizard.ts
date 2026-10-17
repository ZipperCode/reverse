/**
 * Custom Provider Add Wizard Component
 *
 * Interactive multi-step wizard for configuring custom OpenAI/Anthropic-compatible providers.
 */
import type { Api } from "@rva/ai";
import { formatKeyHint } from "../app-keybindings";
import { editorKey, editorKeys, interruptKey } from "../chrome/keybinding-hints";
import { OverlayPanel } from "../chrome/overlay-box";
import { TextFormField, type FormFieldTheme } from "../components/form";
import { SelectList } from "../components/select-list";
import { WizardStep, type WizardStepKind } from "../components/wizard-step";
import { Container, matchesKey, Spacer, Text, truncateToWidth, wrapTextWithAnsi } from "../index";
import { matchesAppInterrupt, matchesSelectDown, matchesSelectUp } from "../keybinding-matchers";
import { col, compact, node, row, span, text } from "../native/describe";
import type { DescribeContext, NativeChild, NativeNode } from "../native/node";
import { actionBar, actionButton } from "../native/overlay";
import { plainText } from "../native/spans";
import { isNativeRendering } from "../native/state";
import { ensureThemeSync, getSelectListTheme, theme } from "../theme/theme";
import type { SgrMouseEvent } from "../mouse";
import { resolveEffectiveLocale, type SupportedLocale } from "@rva/utils/i18n";

export interface CustomWizardModel {
	id: string;
	name: string;
	contextWindow: number;
	maxTokens: number;
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
}

export type CustomProviderWizardStep =
	| "providerId"
	| "api"
	| "baseUrl"
	| "apiKey"
	| "modelId"
	| "modelName"
	| "contextWindow"
	| "maxTokens"
	| "addAnother"
	| "confirm";

const MAX_DISPLAY_WIDTH = 76;

function getFormTheme(): FormFieldTheme {
	ensureThemeSync();
	return {
		label: (text: string) => theme.fg("accent", text),
		description: (text: string) => theme.fg("muted", text),
		error: (text: string) => theme.fg("error", `${theme.status.error} ${text}`),
		hint: (text: string) => theme.fg("dim", text),
	};
}

export class CustomProviderWizard extends OverlayPanel {
	#deps: CustomProviderWizardDeps;
	#locale: SupportedLocale;
	#currentStep: CustomProviderWizardStep = "providerId";
	#providerId = "";
	#api: Api = "openai-completions";
	#baseUrl = "";
	#apiKey = "";
	#models: CustomWizardModel[] = [];
	#currentModelId = "";
	#currentModelName = "";
	#currentContextWindow = 128000;
	#currentMaxTokens = 4096;

	#contentContainer: Container;
	#step: WizardStep | null = null;
	#stepKind: WizardStepKind = "input";
	#inputField: TextFormField | null = null;
	#currentSelectList: SelectList | null = null;
	#selectedIndex = 0;
	#validationError: string | null = null;
	#native: NativeNode | undefined;
	#saving = false;

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
		const title = effectiveLocale === "zh-CN" ? "添加自定义大模型提供商" : "Add Custom Model Provider";
		ensureThemeSync();
		super(title, "rva.overlay.customProviderAdd");
		this.#deps = deps;
		this.#locale = effectiveLocale;
		this.#onCompleteCallback = onComplete;
		this.#onCancelCallback = onCancel;
		this.#onRenderCallback = onRender ?? null;

		this.addChild(new Spacer(1));
		this.#contentContainer = new Container();
		this.addChild(this.#contentContainer);
		this.addChild(new Spacer(1));

		this.#renderStep();
	}

	#requestRender(): void {
		this.#onRenderCallback?.();
	}

	#show(step: WizardStep, native: NativeNode): void {
		step.setMaxHeight(undefined);
		this.#step = step;
		this.#contentContainer.clear();
		this.#contentContainer.addChild(step);
		this.#native = native;
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
			case "modelId":
				this.#renderModelIdStep();
				break;
			case "modelName":
				this.#renderModelNameStep();
				break;
			case "contextWindow":
				this.#renderContextWindowStep();
				break;
			case "maxTokens":
				this.#renderMaxTokensStep();
				break;
			case "addAnother":
				this.#renderAddAnotherStep();
				break;
			case "confirm":
				this.#renderConfirmStep();
				break;
		}

		this.#requestRender();
	}

	#renderProviderIdStep(): void {
		const lead = this.#t("Provider ID:", "提供商标识 (Provider ID)：");
		const placeholder = this.#t("e.g. my-gateway, deepseek, siliconflow", "例如 my-gateway, deepseek, local-vllm");
		const hint = this.#t("Letters, numbers, '.', '-', '_'. Enter to proceed, Esc to cancel.", "字母、数字、点、减号或下划线。Enter 下一步，Esc 取消。");

		const field = new TextFormField({
			theme: getFormTheme(),
			label: lead,
			details: [new Text(theme.fg("muted", placeholder), 0, 0)],
			initialValue: this.#providerId,
			hint,
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
			onCancel: () => this.#onCancelCallback(),
			requestRender: () => this.#requestRender(),
		});

		this.#inputField = field;
		if (this.#validationError) {
			field.setError(this.#validationError);
			this.#validationError = null;
		}

		this.#show(
			new WizardStep({
				kind: "input",
				heading: new Text(theme.fg("accent", theme.bold(this.#t("Step 1: Provider ID", "第 1 步：提供商标识"))), 0, 0),
				content: field,
			}),
			col([field]),
		);
	}

	#renderApiStep(): void {
		this.#stepKind = "choice";
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
				description: this.#t("OpenAI Responses protocol (POST /responses)", "OpenAI 新版 Responses 协议 (POST /responses)"),
			},
			{
				value: "anthropic-messages",
				label: "Anthropic Messages",
				description: this.#t("Anthropic Messages protocol (POST /messages)", "Anthropic Messages 协议 (POST /messages)"),
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
				heading: new Text(theme.fg("accent", theme.bold(this.#t("Step 2: API Protocol", "第 2 步：选择 API 协议"))), 0, 0),
				content: list,
				footer: new Text(theme.fg("muted", hint), 0, 0),
			}),
			col([list]),
		);
	}

	#renderBaseUrlStep(): void {
		const lead = this.#t("API Base URL:", "API 基础端点地址 (Base URL)：");
		const placeholder =
			this.#api === "anthropic-messages" ? "https://api.anthropic.com/v1" : "https://api.openai.com/v1";
		const hint = this.#t("Must start with http:// or https://. Enter to proceed, Esc to go back.", "必须以 http:// 或 https:// 开头。Enter 下一步，Esc 返回。");

		const field = new TextFormField({
			theme: getFormTheme(),
			label: lead,
			details: [new Text(theme.fg("muted", `e.g. ${placeholder}`), 0, 0)],
			initialValue: this.#baseUrl || (this.#api === "anthropic-messages" ? "https://api.anthropic.com/v1" : ""),
			hint,
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
			requestRender: () => this.#requestRender(),
		});

		this.#inputField = field;
		this.#show(
			new WizardStep({
				kind: "input",
				heading: new Text(theme.fg("accent", theme.bold(this.#t("Step 3: Base URL", "第 3 步：端点地址"))), 0, 0),
				content: field,
			}),
			col([field]),
		);
	}

	#renderApiKeyStep(): void {
		const lead = this.#t("API Key (optional):", "API 密钥（可选）：");
		const hint = this.#t(
			"Optional. Leave blank for keyless local endpoints (Ollama/vLLM). Secret is stored in SQLite agent.db, not models.yml.",
			"可选。留空即为免密端点 (Ollama/vLLM)。密钥将安全存储于 SQLite 凭证库，不会写入 models.yml 明文。",
		);

		const field = new TextFormField({
			theme: getFormTheme(),
			label: lead,
			secret: true,
			initialValue: this.#apiKey,
			hint,
			empty: "submit",
			onSubmit: value => {
				this.#apiKey = value.trim();
				this.#currentStep = "modelId";
				this.#renderStep();
			},
			onCancel: () => {
				this.#currentStep = "baseUrl";
				this.#renderStep();
			},
			requestRender: () => this.#requestRender(),
		});

		this.#inputField = field;
		this.#show(
			new WizardStep({
				kind: "input",
				heading: new Text(theme.fg("accent", theme.bold(this.#t("Step 4: API Key", "第 4 步：API 密钥"))), 0, 0),
				content: field,
			}),
			col([field]),
		);
	}

	#renderModelIdStep(): void {
		const modelIndex = this.#models.length + 1;
		const lead = this.#t(`Model #${modelIndex} ID:`, `模型 #${modelIndex} 标识 (Model ID)：`);
		const placeholder = this.#t("e.g. gpt-4o, claude-3-7-sonnet, llama-3", "例如 gpt-4o, claude-3-7-sonnet, deepseek-chat");
		const hint = this.#t("Required. The model identifier sent to the endpoint.", "必填。向服务端请求时发送的模型 ID。");

		const field = new TextFormField({
			theme: getFormTheme(),
			label: lead,
			details: [new Text(theme.fg("muted", placeholder), 0, 0)],
			initialValue: this.#currentModelId,
			hint,
			empty: "reject",
			emptyError: this.#t("Model ID is required.", "模型 ID 不能为空。"),
			onSubmit: value => {
				this.#currentModelId = value.trim();
				this.#currentStep = "modelName";
				this.#renderStep();
			},
			onCancel: () => {
				if (this.#models.length > 0) {
					this.#currentStep = "addAnother";
				} else {
					this.#currentStep = "apiKey";
				}
				this.#renderStep();
			},
			requestRender: () => this.#requestRender(),
		});

		this.#inputField = field;
		this.#show(
			new WizardStep({
				kind: "input",
				heading: new Text(theme.fg("accent", theme.bold(this.#t("Step 5: Model ID", "第 5 步：模型标识"))), 0, 0),
				content: field,
			}),
			col([field]),
		);
	}

	#renderModelNameStep(): void {
		const lead = this.#t("Model Display Name (optional):", "模型显示名称（可选）：");
		const placeholder = this.#currentModelId;
		const hint = this.#t("Leave blank to use Model ID as display name.", "直接回车默认与模型 ID 相同。");

		const field = new TextFormField({
			theme: getFormTheme(),
			label: lead,
			details: [new Text(theme.fg("muted", `Default: ${placeholder}`), 0, 0)],
			initialValue: this.#currentModelName,
			hint,
			empty: "submit",
			onSubmit: value => {
				this.#currentModelName = value.trim() || this.#currentModelId;
				this.#currentStep = "contextWindow";
				this.#renderStep();
			},
			onCancel: () => {
				this.#currentStep = "modelId";
				this.#renderStep();
			},
			requestRender: () => this.#requestRender(),
		});

		this.#inputField = field;
		this.#show(
			new WizardStep({
				kind: "input",
				heading: new Text(theme.fg("accent", theme.bold(this.#t("Step 6: Model Name", "第 6 步：显示名称"))), 0, 0),
				content: field,
			}),
			col([field]),
		);
	}

	#renderContextWindowStep(): void {
		const lead = this.#t("Context Window Tokens:", "上下文窗口 Tokens 大小：");
		const hint = this.#t("Positive integer (e.g. 128000, 200000). Enter to proceed.", "正整数（如 128000、200000）。Enter 下一步。");

		const field = new TextFormField({
			theme: getFormTheme(),
			label: lead,
			initialValue: String(this.#currentContextWindow),
			hint,
			empty: "submit",
			validate: value => {
				const num = Number(value.trim());
				if (!Number.isSafeInteger(num) || num <= 0) {
					return this.#t("Context window must be a positive integer.", "上下文窗口必须为正整数。");
				}
				return undefined;
			},
			onSubmit: value => {
				const num = Number(value.trim());
				this.#currentContextWindow = Number.isSafeInteger(num) && num > 0 ? num : 128000;
				this.#currentStep = "maxTokens";
				this.#renderStep();
			},
			onCancel: () => {
				this.#currentStep = "modelName";
				this.#renderStep();
			},
			requestRender: () => this.#requestRender(),
		});

		this.#inputField = field;
		this.#show(
			new WizardStep({
				kind: "input",
				heading: new Text(theme.fg("accent", theme.bold(this.#t("Step 7: Context Window", "第 7 步：上下文窗口"))), 0, 0),
				content: field,
			}),
			col([field]),
		);
	}

	#renderMaxTokensStep(): void {
		const lead = this.#t("Max Output Tokens:", "最大输出 Tokens (Max Tokens)：");
		const hint = this.#t("Positive integer (e.g. 4096, 8192). Enter to save model.", "正整数（如 4096、8192）。Enter 暂存此模型。");

		const field = new TextFormField({
			theme: getFormTheme(),
			label: lead,
			initialValue: String(this.#currentMaxTokens),
			hint,
			empty: "submit",
			validate: value => {
				const num = Number(value.trim());
				if (!Number.isSafeInteger(num) || num <= 0) {
					return this.#t("Max tokens must be a positive integer.", "最大输出 Tokens 必须为正整数。");
				}
				if (num > this.#currentContextWindow) {
					return this.#t("Max tokens cannot exceed context window.", "最大输出不能大于上下文窗口。");
				}
				return undefined;
			},
			onSubmit: value => {
				const num = Number(value.trim());
				this.#currentMaxTokens = Number.isSafeInteger(num) && num > 0 ? num : 4096;

				// Save this model into list
				this.#models.push({
					id: this.#currentModelId,
					name: this.#currentModelName || this.#currentModelId,
					contextWindow: this.#currentContextWindow,
					maxTokens: this.#currentMaxTokens,
				});

				// Reset temporary model state
				this.#currentModelId = "";
				this.#currentModelName = "";
				this.#currentContextWindow = 128000;
				this.#currentMaxTokens = 4096;

				this.#currentStep = "addAnother";
				this.#selectedIndex = 0;
				this.#renderStep();
			},
			onCancel: () => {
				this.#currentStep = "contextWindow";
				this.#renderStep();
			},
			requestRender: () => this.#requestRender(),
		});

		this.#inputField = field;
		this.#show(
			new WizardStep({
				kind: "input",
				heading: new Text(theme.fg("accent", theme.bold(this.#t("Step 8: Max Output Tokens", "第 8 步：最大输出"))), 0, 0),
				content: field,
			}),
			col([field]),
		);
	}

	#renderAddAnotherStep(): void {
		this.#stepKind = "choice";
		const choices = [
			{
				value: "done",
				label: this.#t(`Save provider (${this.#models.length} model(s) added)`, `完成并保存提供商（已添加 ${this.#models.length} 个模型）`),
				description: this.#t("Proceed to review and save this provider", "进入概览并保存此提供商配置"),
			},
			{
				value: "add",
				label: this.#t("+ Add another model to this provider", "+ 为此提供商继续添加另一个模型"),
				description: this.#t("Define another model ID and limits", "配置更多可用模型 ID 与限制"),
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
			if (item.value === "add") {
				this.#currentStep = "modelId";
			} else {
				this.#currentStep = "confirm";
			}
			this.#renderStep();
		};

		const hint = this.#t(
			`[${editorKeys("tui.select.up", "tui.select.down")} select · ${editorKey("tui.select.confirm")} confirm]`,
			`[${editorKeys("tui.select.up", "tui.select.down")} 选择 · ${editorKey("tui.select.confirm")} 确认]`,
		);

		this.#show(
			new WizardStep({
				kind: "choice",
				heading: new Text(theme.fg("accent", theme.bold(this.#t("Models Configured", "模型配置列表"))), 0, 0),
				content: list,
				footer: new Text(theme.fg("muted", hint), 0, 0),
			}),
			col([list]),
		);
	}

	#renderConfirmStep(): void {
		this.#stepKind = "choice";
		const container = new Container();

		const authLabel = this.#apiKey
			? this.#t("[Configured (securely stored in agent.db)]", "[已提供（安全存储于本地 SQLite 凭据库）]")
			: this.#t("[Keyless / None]", "[免密 / 无密钥]");

		container.addChild(new Text(theme.bold(this.#t("Summary of Custom Provider:", "自定义提供商汇总：")), 0, 0));
		container.addChild(new Text(`  ${theme.fg("dim", "Provider ID:")} ${theme.fg("accent", this.#providerId)}`, 0, 0));
		container.addChild(new Text(`  ${theme.fg("dim", "API Protocol:")} ${this.#api}`, 0, 0));
		container.addChild(new Text(`  ${theme.fg("dim", "Base URL:")}     ${this.#baseUrl}`, 0, 0));
		container.addChild(new Text(`  ${theme.fg("dim", "API Key:")}      ${authLabel}`, 0, 0));
		container.addChild(new Spacer(1));
		container.addChild(new Text(theme.bold(this.#t(`Models (${this.#models.length}):`, `包含模型 (${this.#models.length})：`)), 0, 0));

		for (const m of this.#models) {
			const nameStr = m.name !== m.id ? ` (${m.name})` : "";
			container.addChild(
				new Text(
					`  • ${theme.fg("accent", m.id)}${nameStr} - ${theme.fg("dim", `ctx: ${m.contextWindow}, max: ${m.maxTokens}`)}`,
					0,
					0,
				),
			);
		}

		if (this.#validationError) {
			container.addChild(new Spacer(1));
			container.addChild(new Text(theme.fg("error", `${theme.status.error} ${this.#validationError}`), 0, 0));
		}

		const saveText = this.#t("Save Provider", "确认保存提供商");
		const cancelText = this.#t("Back", "返回");
		const hint = this.#t(
			`[${formatKeyHint("enter")} ${saveText} · ${editorKey("tui.select.cancel")} ${cancelText}]`,
			`[${formatKeyHint("enter")} ${saveText} · ${editorKey("tui.select.cancel")} ${cancelText}]`,
		);

		this.#show(
			new WizardStep({
				kind: "confirm",
				heading: new Text(theme.fg("accent", theme.bold(this.#t("Confirm Configuration", "确认配置"))), 0, 0),
				content: container,
				footer: new Text(theme.fg("muted", hint), 0, 0),
			}),
			col([container]),
		);
	}

	async #submitFinal(): Promise<void> {
		if (this.#saving) return;
		this.#saving = true;
		this.#requestRender();

		try {
			await this.#onCompleteCallback({
				providerId: this.#providerId,
				api: this.#api,
				baseUrl: this.#baseUrl,
				apiKey: this.#apiKey || undefined,
				models: this.#models,
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
			this.#onCancelCallback();
			return;
		}

		if (this.#inputField) {
			this.#step?.handleInput(keyData);
			return;
		}

		if (matchesAppInterrupt(keyData)) {
			if (this.#currentStep === "providerId") {
				this.#onCancelCallback();
				return;
			}
			this.#goBack();
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

	#goBack(): void {
		switch (this.#currentStep) {
			case "providerId":
				this.#onCancelCallback();
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
			case "modelId":
				this.#currentStep = this.#models.length > 0 ? "addAnother" : "apiKey";
				this.#renderStep();
				break;
			case "modelName":
				this.#currentStep = "modelId";
				this.#renderStep();
				break;
			case "contextWindow":
				this.#currentStep = "modelName";
				this.#renderStep();
				break;
			case "maxTokens":
				this.#currentStep = "contextWindow";
				this.#renderStep();
				break;
			case "addAnother":
				this.#currentStep = "confirm";
				this.#renderStep();
				break;
			case "confirm":
				this.#currentStep = "addAnother";
				this.#renderStep();
				break;
		}
	}

	override describe(_cx: DescribeContext): NativeNode {
		return this.#native ?? col([]);
	}

	override render(width: number): readonly string[] {
		return super.render(width);
	}

	routeMouse(event: SgrMouseEvent, line: number, col: number): void {
		this.#step?.routeMouse(event, line, col);
	}
}
