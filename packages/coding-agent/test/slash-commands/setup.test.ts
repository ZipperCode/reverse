import { describe, expect, it, vi } from "bun:test";
import type { InteractiveModeContext } from "@reverse/coding-agent/modes/types";
import { executeBuiltinSlashCommand } from "@reverse/coding-agent/slash-commands/builtin-registry";
import { executeSafeCatalogCommand } from "../../src/cli/setup-reverse";
import { SKILL_TOOL_CATALOG } from "../../src/extensibility/skill-tool-catalog";

function createRuntime() {
	const showProviderSetup = vi.fn(async () => {});
	const showCustomProviderWizard = vi.fn(async () => {});
	const showCommandReport = vi.fn();
	const showWarning = vi.fn();
	const setText = vi.fn();
	return {
		showProviderSetup,
		showCustomProviderWizard,
		showCommandReport,
		showWarning,
		setText,
		runtime: {
			ctx: {
				editor: { setText } as unknown as InteractiveModeContext["editor"],
				showProviderSetup,
				showCustomProviderWizard,
				showCommandReport,
				showWarning,
			} as unknown as InteractiveModeContext,
			handleBackgroundCommand: () => {},
		},
	};
}

function createInteractiveRuntime(options?: {
	selectorChoices?: (string | undefined)[];
	confirmResult?: boolean;
	installCallback?: (item: unknown) => Promise<{ success: boolean; message?: string } | void>;
}) {
	const showProviderSetup = vi.fn(async () => {});
	const showCustomProviderWizard = vi.fn(async () => {});
	const showCommandReport = vi.fn();
	const showWarning = vi.fn();
	const showStatus = vi.fn();
	const showError = vi.fn();
	const setText = vi.fn();

	const choices = [...(options?.selectorChoices ?? [])];
	const showHookSelector = vi.fn(async (_title: string, items: unknown[]) => {
		if (choices.length === 0) return undefined;
		const nextChoice = choices.shift();
		if (!nextChoice) return undefined;
		if (Array.isArray(items)) {
			for (const it of items) {
				let label: string | undefined;
				if (typeof it === "string") {
					label = it;
				} else if (it && typeof it === "object" && "label" in it && typeof it.label === "string") {
					label = it.label;
				}
				if (!label) continue;
				if (
					label === nextChoice ||
					label.toLowerCase().includes(nextChoice.toLowerCase()) ||
					(nextChoice.includes("(") && label.includes(nextChoice))
				) {
					return label;
				}
			}
		}
		return nextChoice;
	});
	const showHookConfirm = vi.fn(async (_title: string, _message: string) => {
		return options?.confirmResult ?? true;
	});

	const ctx = {
		editor: { setText } as unknown as InteractiveModeContext["editor"],
		isTTY: true,
		showProviderSetup,
		showCustomProviderWizard,
		showCommandReport,
		showWarning,
		showStatus,
		showError,
		showHookSelector,
		showHookConfirm,
		installReverseItem: options?.installCallback,
	} as unknown as InteractiveModeContext;

	return {
		showProviderSetup,
		showCustomProviderWizard,
		showCommandReport,
		showWarning,
		showStatus,
		showError,
		showHookSelector,
		showHookConfirm,
		setText,
		runtime: {
			ctx,
			handleBackgroundCommand: () => {},
		},
	};
}

describe("/setup slash command", () => {
	it("opens provider setup for /setup", async () => {
		const harness = createRuntime();

		const handled = await executeBuiltinSlashCommand("/setup", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showProviderSetup).toHaveBeenCalledTimes(1);
		expect(harness.setText).toHaveBeenCalledWith("");
	});

	it("opens provider setup for /setup providers", async () => {
		const harness = createRuntime();

		const handled = await executeBuiltinSlashCommand("/setup providers", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showProviderSetup).toHaveBeenCalledTimes(1);
		expect(harness.showWarning).not.toHaveBeenCalled();
		expect(harness.setText).toHaveBeenCalledWith("");
	});

	it("opens provider setup through the /providers alias", async () => {
		const harness = createRuntime();

		const handled = await executeBuiltinSlashCommand("/providers", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showProviderSetup).toHaveBeenCalledTimes(1);
		expect(harness.setText).toHaveBeenCalledWith("");
	});

	it("shows top-level interactive selector with all 5 panels for /setup when showHookSelector is available", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["← Exit"],
		});

		const handled = await executeBuiltinSlashCommand("/setup", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector).toHaveBeenCalledTimes(1);
		const [title, items] = harness.showHookSelector.mock.calls[0] as [string, Array<{ label: string }>];
		expect(title).toContain("Setup");
		expect(items.some(i => i.label.includes("providers"))).toBe(true);
		expect(items.some(i => i.label.includes("add"))).toBe(true);
		expect(items.some(i => i.label.includes("reverse"))).toBe(true);
		expect(items.some(i => i.label.includes("python"))).toBe(true);
		expect(items.some(i => i.label.includes("speech"))).toBe(true);
		expect(items.some(i => i.label.includes("Exit") || i.label.includes("退出"))).toBe(true);
	});

	it("keeps /providers as direct providers alias even when showHookSelector is available", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["← Exit"],
		});

		const handled = await executeBuiltinSlashCommand("/providers", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector).not.toHaveBeenCalled();
		expect(harness.showProviderSetup).toHaveBeenCalledTimes(1);
	});

	it("dispatches to providers when chosen from interactive setup menu", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["🌐 Model Providers (providers)"],
		});

		const handled = await executeBuiltinSlashCommand("/setup", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showProviderSetup).toHaveBeenCalledTimes(1);
	});

	it("dispatches to add provider when chosen from interactive setup menu", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["➕ Add Custom Provider (add)"],
		});

		const handled = await executeBuiltinSlashCommand("/setup", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showCustomProviderWizard).toHaveBeenCalledTimes(1);
	});

	it("dispatches to reverse toolchain when chosen from interactive setup menu", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["🛠️ Reverse Engineering Toolchain (reverse)", "← Exit"],
		});

		const handled = await executeBuiltinSlashCommand("/setup", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector).toHaveBeenCalledTimes(2);
		const secondTitle = harness.showHookSelector.mock.calls[1]?.[0] as string;
		expect(secondTitle.includes("Reverse") || secondTitle.includes("逆向")).toBe(true);
	});

	it("dispatches to python environment when chosen from interactive setup menu", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["🐍 Python Execution Environment (python)", "← Back to Setup Menu"],
		});

		const handled = await executeBuiltinSlashCommand("/setup", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector).toHaveBeenCalledTimes(2);
		const secondTitle = harness.showHookSelector.mock.calls[1]?.[0] as string;
		expect(secondTitle.includes("Python") || secondTitle.includes("执行环境")).toBe(true);
	});

	it("dispatches to speech when chosen from interactive setup menu", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["🎙️ Speech Recognition & Synthesis (speech)", "← Back to Setup Menu"],
		});

		const handled = await executeBuiltinSlashCommand("/setup", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector).toHaveBeenCalledTimes(2);
		const secondTitle = harness.showHookSelector.mock.calls[1]?.[0] as string;
		expect(secondTitle.includes("Speech") || secondTitle.includes("语音")).toBe(true);
	});

	it("routes direct /setup python subcommand in non-interactive mode", async () => {
		const harness = createRuntime();

		const handled = await executeBuiltinSlashCommand("/setup python", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showCommandReport).toHaveBeenCalledTimes(1);
		const reportCall = harness.showCommandReport.mock.calls[0]?.[0];
		expect(reportCall.title).toContain("Python");
	});

	it("routes direct /setup speech subcommand in non-interactive mode", async () => {
		const harness = createRuntime();

		const handled = await executeBuiltinSlashCommand("/setup speech", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showCommandReport).toHaveBeenCalledTimes(1);
	});
	it("opens custom provider wizard for /setup add", async () => {
		const harness = createRuntime();

		const handled = await executeBuiltinSlashCommand("/setup add", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showCustomProviderWizard).toHaveBeenCalledTimes(1);
		expect(harness.showWarning).not.toHaveBeenCalled();
		expect(harness.setText).toHaveBeenCalledWith("");
	});

	it("opens reverse toolchain report panel for /setup reverse", async () => {
		const harness = createRuntime();

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showCommandReport).toHaveBeenCalledTimes(1);
		const reportCall = harness.showCommandReport.mock.calls[0]?.[0];
		expect(reportCall).toBeDefined();
		expect(reportCall.title).toBeDefined();
		expect(reportCall.body).toBeDefined();
		expect(harness.showWarning).not.toHaveBeenCalled();
		expect(harness.setText).toHaveBeenCalledWith("");
	});

	it("opens reverse toolchain report panel for /setup reverse <tool>", async () => {
		const harness = createRuntime();

		const handled = await executeBuiltinSlashCommand("/setup reverse jadx", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showCommandReport).toHaveBeenCalledTimes(1);
		const reportCall = harness.showCommandReport.mock.calls[0]?.[0];
		expect(reportCall).toBeDefined();
		expect(reportCall.title).toContain("jadx");
		expect(reportCall.body).toBeDefined();
		expect(harness.showWarning).not.toHaveBeenCalled();
		expect(harness.setText).toHaveBeenCalledWith("");
	});

	it("opens interactive selector for /setup reverse when showHookSelector is available", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["← Exit"],
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector).toHaveBeenCalledTimes(1);
		const [, items] = harness.showHookSelector.mock.calls[0] as [string, Array<{ label: string }>];
		expect(items.some(item => item.label.includes("[CLI]"))).toBe(true);
		expect(items.some(item => item.label.includes("[MCP]"))).toBe(true);
		expect(harness.showWarning).not.toHaveBeenCalled();
		expect(harness.setText).toHaveBeenCalledWith("");
	});

	it("supports category filtering in the interactive selector", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["○ Filter: Missing only (0)", "← Exit"],
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector.mock.calls.length).toBeGreaterThanOrEqual(2);
	});

	it("supports category filtering and preserves basket selection across filter switches", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["(jadx)", "Missing only", "Exit"],
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector).toHaveBeenCalled();
		const hasBasketCall = harness.showHookSelector.mock.calls.some(call => {
			const items = call[1] as Array<{ label?: string }> | undefined;
			return items?.some(i => i.label?.includes("1"));
		});
		expect(hasBasketCall).toBe(true);
	});

	it("cancels batch install when user declines confirmation", async () => {
		const installSpy = vi.fn(async () => ({ success: true }));
		const harness = createInteractiveRuntime({
			selectorChoices: ["(jadx)", "Install selected", "Exit"],
			confirmResult: false,
			installCallback: installSpy,
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookConfirm).toHaveBeenCalledTimes(1);
		expect(installSpy).not.toHaveBeenCalled();
		expect(harness.showStatus).toHaveBeenCalled();
	});

	it("executes install callback upon batch confirmation for selected tools", async () => {
		const installSpy = vi.fn(async (_item: unknown) => ({ success: true, message: "Installed jadx successfully" }));
		const harness = createInteractiveRuntime({
			selectorChoices: ["(jadx)", "Install selected", "Exit"],
			confirmResult: true,
			installCallback: installSpy,
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookConfirm).toHaveBeenCalledTimes(1);
		expect(installSpy).toHaveBeenCalledTimes(1);
		expect(harness.showStatus).toHaveBeenCalled();
	});

	it("reports error when install callback returns failure during batch install", async () => {
		const installSpy = vi.fn(async () => ({ success: false, message: "Failed: permission denied" }));
		const harness = createInteractiveRuntime({
			selectorChoices: ["(jadx)", "Install selected", "Exit"],
			confirmResult: true,
			installCallback: installSpy,
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(installSpy).toHaveBeenCalledTimes(1);
		expect(harness.showError).toHaveBeenCalledTimes(1);
		const errCall = harness.showError.mock.calls[0]?.[0] as string;
		expect(errCall).toContain("permission denied");
	});

	it("supports installing all missing supported tools with single batch confirmation", async () => {
		const installSpy = vi.fn(async () => ({ success: true, message: "Installed successfully" }));
		const harness = createInteractiveRuntime({
			selectorChoices: ["Install all missing supported", "Exit"],
			confirmResult: true,
			installCallback: installSpy,
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookConfirm).toHaveBeenCalledTimes(1);
		expect(installSpy).toHaveBeenCalled();
	});

	it("supports selecting multiple tools into basket and installing with single confirmation", async () => {
		const installSpy = vi.fn(async () => ({ success: true, message: "Installed successfully" }));
		const harness = createInteractiveRuntime({
			selectorChoices: ["(jadx)", "(apktool)", "Install selected", "Exit"],
			confirmResult: true,
			installCallback: installSpy,
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookConfirm).toHaveBeenCalledTimes(1);
		expect(installSpy).toHaveBeenCalledTimes(2);
		expect(harness.showStatus).toHaveBeenCalled();
	});

	it("warns and avoids pretending success when no executor/callback is available", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["(jadx)", "Install selected", "Exit"],
			confirmResult: true,
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showWarning).toHaveBeenCalledTimes(1);
	});

	it("opens detail directly for /setup reverse <tool> with primary install and secondary guide", async () => {
		const installSpy = vi.fn(async (_item: unknown) => ({ success: true, message: "Installed jadx successfully" }));
		const harness = createInteractiveRuntime({
			selectorChoices: ["brew install jadx", "Back"],
			confirmResult: true,
			installCallback: installSpy,
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse jadx", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector).toHaveBeenCalled();
		const [title, options] = harness.showHookSelector.mock.calls[0] as [string, Array<{ label: string }>];
		expect(title.toLowerCase()).toContain("jadx");
		expect(options[0]?.label).toBeDefined();
		expect(options.length).toBeGreaterThanOrEqual(2);
		expect(installSpy).toHaveBeenCalledTimes(1);
	});

	it("shows manual install limitation for manual-only tools directly", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["Back"],
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse ida", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector).toHaveBeenCalled();
		const [title, options] = harness.showHookSelector.mock.calls[0] as [string, Array<{ label: string }>];
		expect(title.toLowerCase()).toContain("ida");
		expect(options.some(o => o.label.includes("Manual Install Only") || o.label.includes("仅支持手动安装"))).toBe(
			true,
		);
	});

	it("shows MCP config snippet when requested for an MCP service", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["Show MCP Config Snippet", "Back"],
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse r2mcp", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showCommandReport).toHaveBeenCalledTimes(1);
		const reportCall = harness.showCommandReport.mock.calls[0]?.[0];
		expect(reportCall.title).toBeDefined();
	});

	it("opens tool detail through secondary guide picker from main menu", async () => {
		const harness = createInteractiveRuntime({
			selectorChoices: ["details & guides", "(jadx)", "Back", "Back", "Exit"],
		});

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector.mock.calls.length).toBeGreaterThanOrEqual(2);
	});
	it("falls back to command report without blocking in non-TTY environment", async () => {
		const harness = createInteractiveRuntime();
		harness.runtime.ctx.isTTY = false;

		const handled = await executeBuiltinSlashCommand("/setup reverse", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showHookSelector).not.toHaveBeenCalled();
		expect(harness.showCommandReport).toHaveBeenCalledTimes(1);
	});

	it("rejects untrusted installation argv in executeSafeCatalogCommand", async () => {
		const fakeItem = {
			kind: "cli" as const,
			id: "jadx",
			name: "JADX",
			category: "binary" as const,
			description: "",
			optional: true,
			systemTool: false,
			status: "missing" as const,
			foundPath: null,
			packageManager: "brew",
			installCommand: "malicious && rm -rf /",
			installArgv: ["sh", "-c", "malicious"],
			riskNote: null,
			manualUrl: "",
			manualInstructions: "",
		};

		const result = await executeSafeCatalogCommand(fakeItem, { allowNonTTY: true });
		expect(result.exitCode).toBe(1);
		expect(result.stderr).toContain("Untrusted installation command");
	});

	it("refuses execution in non-TTY environments unless allowed", async () => {
		const jadx = SKILL_TOOL_CATALOG.jadx;
		const toolItem = {
			kind: "cli" as const,
			id: "jadx",
			name: jadx?.name ?? "JADX",
			category: jadx?.category ?? ("binary" as const),
			description: jadx?.description ?? "",
			optional: true,
			systemTool: false,
			status: "missing" as const,
			foundPath: null,
			packageManager: "brew",
			installCommand: "brew install jadx",
			installArgv: ["brew", "install", "jadx"],
			riskNote: null,
			manualUrl: "",
			manualInstructions: "",
		};

		const result = await executeSafeCatalogCommand(toolItem, { isTTY: false });
		expect(result.exitCode).toBe(1);
		expect(result.stderr).toContain("requires an interactive TTY");
	});

	it("shows usage for unsupported setup scenes", async () => {
		const harness = createRuntime();

		const handled = await executeBuiltinSlashCommand("/setup theme", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showProviderSetup).not.toHaveBeenCalled();
		expect(harness.showWarning).toHaveBeenCalledWith("Usage: /setup [providers|add|reverse|python|speech]");
		expect(harness.setText).toHaveBeenCalledWith("");
	});

	it("always opens provider setup directly through the /providers alias", async () => {
		const harness = createRuntime();

		const handled = await executeBuiltinSlashCommand("/providers theme", harness.runtime);

		expect(handled).toBe(true);
		expect(harness.showProviderSetup).toHaveBeenCalledTimes(1);
		expect(harness.showWarning).not.toHaveBeenCalled();
		expect(harness.setText).toHaveBeenCalledWith("");
	});
});
