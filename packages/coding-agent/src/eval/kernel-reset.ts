import type { EvalStatusEvent } from "@reverse/tui/tools/eval";

export type KernelLanguage = "python" | "js";

export type KernelResetReason =
	| "timeout"
	| "kernel_killed"
	| "kernel_died"
	| "kernel_loss"
	| "reset"
	| "process_exit"
	| "worker_error";

export interface KernelStateResetNotice {
	op: "kernel_reset";
	language: KernelLanguage;
	generation: number;
	nextGeneration?: number;
	previousGeneration?: number;
	kernelKilled?: boolean;
	recreated?: boolean;
	reason: KernelResetReason;
	action: "reimport_dependencies";
	message: string;
}

export function formatKernelLossNotice(options: {
	language: KernelLanguage;
	generation: number;
	nextGeneration?: number;
	kernelKilled?: boolean;
	reason?: KernelResetReason;
}): string {
	const lang = options.language === "js" ? "JavaScript worker" : "Python kernel";
	const nextGen = options.nextGeneration ?? options.generation + 1;
	return `[eval kernel reset: ${lang} was terminated (generation ${options.generation} lost). All previous memory variables, imports, and state were wiped. The next call will start fresh kernel generation ${nextGen}; explicitly re-import dependencies and verify side effects before referencing them.]`;
}

export function formatKernelRecreatedNotice(options: {
	language: KernelLanguage;
	generation: number;
	previousGeneration?: number;
	reason?: KernelResetReason;
}): string {
	const lang = options.language === "js" ? "JavaScript worker" : "Python kernel";
	if (options.reason === "reset") {
		return `[eval kernel notice: ${lang} reset (generation ${options.generation}). Memory namespace cleared; explicitly re-import dependencies before use.]`;
	}
	const prevClause = options.previousGeneration
		? ` following previous generation ${options.previousGeneration} termination`
		: "";
	return `[eval kernel notice: ${lang} generation ${options.generation} initialized with clean namespace${prevClause}. Previous variables and imports were wiped; explicitly re-import dependencies before referencing them.]`;
}

export function createKernelResetStatusEvent(
	options:
		| {
				type: "loss";
				language: KernelLanguage;
				generation: number;
				nextGeneration?: number;
				kernelKilled?: boolean;
				reason?: KernelResetReason;
		  }
		| {
				type: "recreated";
				language: KernelLanguage;
				generation: number;
				previousGeneration?: number;
				reason?: KernelResetReason;
		  },
): KernelStateResetNotice & EvalStatusEvent {
	if (options.type === "loss") {
		const nextGen = options.nextGeneration ?? options.generation + 1;
		const reason = options.reason ?? "kernel_loss";
		const message = formatKernelLossNotice({ ...options, reason: reason as KernelResetReason });
		return {
			op: "kernel_reset",
			language: options.language,
			generation: options.generation,
			nextGeneration: nextGen,
			kernelKilled: options.kernelKilled ?? true,
			reason: reason as KernelResetReason,
			action: "reimport_dependencies",
			message,
		};
	}
	const reason = options.reason ?? "kernel_died";
	const message = formatKernelRecreatedNotice({ ...options, reason: reason as KernelResetReason });
	return {
		op: "kernel_reset",
		language: options.language,
		generation: options.generation,
		previousGeneration: options.previousGeneration,
		recreated: true,
		reason: reason as KernelResetReason,
		action: "reimport_dependencies",
		message,
	};
}
