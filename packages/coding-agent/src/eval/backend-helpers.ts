/**
 * Helpers shared by the per-language eval backend definitions (js/py
 * index modules): session-id namespacing and projection of
 * executor results into the ExecutorBackend result shape.
 */
import type { OutputArtifactError } from "@reverse/tui/tools/streaming-output";
import type { ExecutorBackendResult } from "./backend";
import type { EvalDisplayOutput } from "./types";

export function namespaceSessionId(sessionId: string, prefix: string): string {
	return sessionId.startsWith(prefix) ? sessionId : `${prefix}${sessionId}`;
}

export function toExecutorBackendResult(result: {
	output: string;
	exitCode: number | undefined;
	cancelled: boolean;
	truncated: boolean;
	artifactId?: string | undefined;
	artifactBytes?: number;
	artifactElidedBytes?: number;
	artifactMaxBytes?: number;
	artifactBudgetExhausted?: boolean;
	artifactError?: OutputArtifactError;
	totalLines: number;
	totalBytes: number;
	outputLines: number;
	outputBytes: number;
	displayOutputs: EvalDisplayOutput[];
	definedNames?: string[];
	definedNamesOmitted?: number;
	missingNames?: string[];
	recoveryGuidance?: string;
}): ExecutorBackendResult {
	return {
		output: result.output,
		exitCode: result.exitCode,
		cancelled: result.cancelled,
		truncated: result.truncated,
		artifactId: result.artifactId,
		artifactBytes: result.artifactBytes,
		artifactElidedBytes: result.artifactElidedBytes,
		artifactMaxBytes: result.artifactMaxBytes,
		artifactBudgetExhausted: result.artifactBudgetExhausted,
		artifactError: result.artifactError,
		totalLines: result.totalLines,
		totalBytes: result.totalBytes,
		outputLines: result.outputLines,
		outputBytes: result.outputBytes,
		displayOutputs: result.displayOutputs,
		...(result.definedNames !== undefined ? { definedNames: result.definedNames } : {}),
		...(result.definedNamesOmitted !== undefined ? { definedNamesOmitted: result.definedNamesOmitted } : {}),
		...(result.missingNames && result.missingNames.length > 0 ? { missingNames: result.missingNames } : {}),
		...(result.recoveryGuidance ? { recoveryGuidance: result.recoveryGuidance } : {}),
	};
}
