import * as fs from "node:fs/promises";
import * as path from "node:path";
import { getEvidenceProjectDir, isEnoent } from "@reverse/utils";
import { withFileLock } from "@reverse/utils/file-lock";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { replaceFileAtomically } from "../utils/atomic-file";
import {
	type AddFactInput,
	type AddHypothesisInput,
	type AddUnknownInput,
	type ConclusionEvidence,
	type EvidenceDriftStatus,
	type EvidenceListFilter,
	type EvidenceListResult,
	type EvidenceRecord,
	type FactEvidence,
	type HypothesisEvidence,
	type UnknownEvidence,
	type VerifyHypothesisInput,
	type EvidenceAssuranceLevel,
	type ExecutionBinding,
	type CommandStageResult,
	type NegativeSearchScope,
	type QuantitativeRatio,
	type ObservationContext,
	DEFAULT_LIST_LIMIT,
	MAX_EXCERPT_LENGTH,
	MAX_FIELD_LENGTH,
	MAX_LIST_LIMIT,
	MAX_LOCATOR_LENGTH,
	MAX_NOTES_LENGTH,
	MAX_SOURCE_TOOL_LENGTH,
	MAX_TAGS_COUNT,
	MAX_TAG_LENGTH,
	MAX_TARGET_LENGTH,
	MAX_TITLE_LENGTH,
	EVIDENCE_ASSURANCE_LEVELS,
	ASSURANCE_LEVEL_RANK,
	createEvidenceId,
	encodeEvidenceProjectKey,
	redactEvidenceText,
} from "./contracts";
import {
	type CanonicalEvidenceValidity,
	type EvidenceRequirements,
	type EvidenceSupportEvaluation,
	resolveEvidenceLedgerValidity,
	evaluateEvidenceSupport,
} from "./validity";

const PRIVATE_DIR_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;

/** In-process write serializer per project directory */
const EVIDENCE_STORE_WRITE_CHAINS = new Map<string, Promise<unknown>>();

async function withEvidenceStoreWrite<T>(
	projectDirectory: string,
	lockTarget: string,
	operation: () => Promise<T>,
): Promise<T> {
	await fs.mkdir(projectDirectory, { recursive: true, mode: PRIVATE_DIR_MODE });
	if (process.platform !== "win32") {
		await fs.chmod(projectDirectory, PRIVATE_DIR_MODE).catch(() => undefined);
	}
	const run = (EVIDENCE_STORE_WRITE_CHAINS.get(projectDirectory) ?? Promise.resolve()).then(() =>
		withFileLock(lockTarget, operation, { retries: 200, retryDelayMs: 50 }),
	);
	const guarded = run.catch(() => undefined);
	EVIDENCE_STORE_WRITE_CHAINS.set(projectDirectory, guarded);
	try {
		return await run;
	} finally {
		if (EVIDENCE_STORE_WRITE_CHAINS.get(projectDirectory) === guarded) {
			EVIDENCE_STORE_WRITE_CHAINS.delete(projectDirectory);
		}
	}
}

export interface EvidenceStoreOptions {
	repositoryRoot: string;
	stateRoot?: string;
	signal?: AbortSignal;
}

export class EvidenceStore {
	readonly repositoryRoot: string;
	readonly projectKey: string;
	readonly projectDirectory: string;
	readonly ledgerPath: string;
	readonly lockPath: string;

	constructor(options: EvidenceStoreOptions) {
		this.repositoryRoot = path.resolve(options.repositoryRoot);
		this.projectKey = encodeEvidenceProjectKey(this.repositoryRoot);
		this.projectDirectory = options.stateRoot
			? path.join(path.resolve(options.stateRoot), this.projectKey)
			: getEvidenceProjectDir(this.projectKey);
		this.ledgerPath = path.join(this.projectDirectory, "ledger.jsonl");
		this.lockPath = path.join(this.projectDirectory, "ledger.lock");
	}

	static forSession(cwd: string, stateRoot?: string): EvidenceStore {
		return new EvidenceStore({ repositoryRoot: cwd, stateRoot });
	}

	private async ensureDirectory(): Promise<void> {
		await fs.mkdir(this.projectDirectory, { recursive: true, mode: PRIVATE_DIR_MODE });
		if (process.platform !== "win32") {
			await fs.chmod(this.projectDirectory, PRIVATE_DIR_MODE).catch(() => undefined);
		}
	}

	private async readAllRecordsUnlocked(): Promise<EvidenceRecord[]> {
		try {
			const content = await fs.readFile(this.ledgerPath, "utf-8");
			const lines = content.split("\n");
			const records: EvidenceRecord[] = [];
			for (const line of lines) {
				const trimmed = line.trim();
				if (!trimmed) continue;
				try {
					const parsed = JSON.parse(trimmed) as EvidenceRecord;
					if (parsed && typeof parsed.id === "string" && typeof parsed.kind === "string") {
						records.push(parsed);
					}
				} catch {
					// Ignore corrupted or partial lines in append-only history
				}
			}
			return records;
		} catch (error) {
			if (isEnoent(error)) return [];
			throw error;
		}
	}

	private linkHypotheses(records: EvidenceRecord[]): EvidenceRecord[] {
		const verifiedMap = new Map<string, string>();
		for (const record of records) {
			if (record.kind === "conclusion") {
				verifiedMap.set(record.hypothesisId, record.id);
			}
		}
		return records.map(record => {
			if (record.kind === "hypothesis" && verifiedMap.has(record.id)) {
				return { ...record, verifiedBy: verifiedMap.get(record.id) };
			}
			return record;
		});
	}

	private async resolveTargetFile(
		targetPath: string,
	): Promise<{ absolutePath: string; exists: boolean; sha256?: string }> {
		const resolved = path.resolve(this.repositoryRoot, targetPath);
		try {
			const stat = await fs.stat(resolved);
			if (!stat.isFile()) {
				return { absolutePath: resolved, exists: false };
			}
			const file = Bun.file(resolved);
			const buffer = await file.arrayBuffer();
			const sha256 = Bun.SHA256.hash(buffer, "hex");
			return { absolutePath: resolved, exists: true, sha256 };
		} catch {
			return { absolutePath: resolved, exists: false };
		}
	}

	private validateStringField(name: string, value: string, maxLen: number, required = true): string {
		const trimmed = value?.trim() ?? "";
		if (required && trimmed.length === 0) {
			throw new ToolError(`Field '${name}' is required and cannot be empty`);
		}
		if (trimmed.length > maxLen) {
			throw new ToolError(
				`Field '${name}' length (${trimmed.length}) exceeds maximum limit of ${maxLen} characters`,
			);
		}
		return trimmed;
	}

	private validateOptionalString(name: string, value: string | undefined, maxLen: number): string | undefined {
		if (value === undefined || value === null) return undefined;
		const trimmed = value.trim();
		if (trimmed.length === 0) return undefined;
		if (trimmed.length > maxLen) {
			throw new ToolError(
				`Field '${name}' length (${trimmed.length}) exceeds maximum limit of ${maxLen} characters`,
			);
		}
		return trimmed;
	}

	private sanitizeTags(tags: string[] | undefined): string[] | undefined {
		if (!tags || !Array.isArray(tags)) return undefined;
		const sanitized: string[] = [];
		for (const tag of tags.slice(0, MAX_TAGS_COUNT)) {
			if (typeof tag !== "string") continue;
			const trimmed = tag.trim().slice(0, MAX_TAG_LENGTH);
			if (trimmed.length > 0 && !sanitized.includes(trimmed)) {
				sanitized.push(trimmed);
			}
		}
		return sanitized.length > 0 ? sanitized : undefined;
	}
	private sanitizeObservationContext(input: {
		context?: ObservationContext;
		subject?: string;
		assurance?: EvidenceAssuranceLevel;
		executionBinding?: ExecutionBinding;
		compoundStages?: CommandStageResult[];
		negativeScope?: NegativeSearchScope;
		completionRatio?: QuantitativeRatio;
		claimScope?: "bounded" | "universal";
	}): { subject?: string; context?: ObservationContext } {
		const rawContext = input.context ?? {};
		const rawSubject = input.subject ?? rawContext.subject;
		const subject = this.validateOptionalString("subject", rawSubject, 256);

		const rawAssurance = input.assurance ?? rawContext.assurance;
		let assurance: EvidenceAssuranceLevel | undefined;
		if (rawAssurance) {
			if (!EVIDENCE_ASSURANCE_LEVELS.includes(rawAssurance)) {
				throw new ToolError(
					`Invalid assurance tier '${rawAssurance}'. Permitted: ${EVIDENCE_ASSURANCE_LEVELS.join(", ")}`,
				);
			}
			assurance = rawAssurance;
		}

		let executionBinding: ExecutionBinding | undefined;
		const rawEb = input.executionBinding ?? rawContext.executionBinding;
		if (rawEb) {
			const artifactSha256 = this.validateOptionalString("artifactSha256", rawEb.artifactSha256, 128);
			const deviceAbi = this.validateOptionalString("deviceAbi", rawEb.deviceAbi, 64);
			const os = this.validateOptionalString("os", rawEb.os, 64);
			let pid: number | undefined;
			if (rawEb.pid !== undefined && rawEb.pid !== null) {
				if (typeof rawEb.pid !== "number" || !Number.isInteger(rawEb.pid) || rawEb.pid < 0) {
					throw new ToolError("Field 'pid' must be a non-negative integer");
				}
				pid = rawEb.pid;
			}
			let window: { startedAt?: string; endedAt?: string } | undefined;
			if (rawEb.window) {
				const startedAt = this.validateOptionalString("startedAt", rawEb.window.startedAt, 64);
				const endedAt = this.validateOptionalString("endedAt", rawEb.window.endedAt, 64);
				if (startedAt || endedAt) {
					window = { ...(startedAt ? { startedAt } : {}), ...(endedAt ? { endedAt } : {}) };
				}
			}
			if (artifactSha256 || deviceAbi || os || pid !== undefined || window) {
				executionBinding = {
					...(artifactSha256 ? { artifactSha256 } : {}),
					...(deviceAbi ? { deviceAbi } : {}),
					...(os ? { os } : {}),
					...(pid !== undefined ? { pid } : {}),
					...(window ? { window } : {}),
				};
			}
		}

		let compoundStages: CommandStageResult[] | undefined;
		const rawStages = input.compoundStages ?? rawContext.compoundStages;
		if (rawStages && Array.isArray(rawStages) && rawStages.length > 0) {
			compoundStages = [];
			for (let i = 0; i < rawStages.length; i++) {
				const stageItem = rawStages[i];
				if (!stageItem || typeof stageItem !== "object") continue;
				const stageName = this.validateStringField(`compoundStages[${i}].stage`, stageItem.stage, 128);
				if (typeof stageItem.exitCode !== "number" || !Number.isInteger(stageItem.exitCode)) {
					throw new ToolError(`Field 'compoundStages[${i}].exitCode' must be an integer`);
				}
				const cmd = this.validateOptionalString(
					`compoundStages[${i}].command`,
					stageItem.command,
					MAX_FIELD_LENGTH,
				);
				const stdout = this.validateOptionalString(
					`compoundStages[${i}].stdout`,
					stageItem.stdout,
					MAX_FIELD_LENGTH,
				);
				const stderr = this.validateOptionalString(
					`compoundStages[${i}].stderr`,
					stageItem.stderr,
					MAX_FIELD_LENGTH,
				);
				const status = stageItem.status === "failed" || stageItem.exitCode !== 0 ? "failed" : "success";
				compoundStages.push({
					stage: redactEvidenceText(stageName),
					exitCode: stageItem.exitCode,
					status,
					...(cmd ? { command: redactEvidenceText(cmd) } : {}),
					...(stdout ? { stdout: redactEvidenceText(stdout) } : {}),
					...(stderr ? { stderr: redactEvidenceText(stderr) } : {}),
				});
			}
			if (compoundStages.length === 0) compoundStages = undefined;
		}

		let negativeScope: NegativeSearchScope | undefined;
		const rawNeg = input.negativeScope ?? rawContext.negativeScope;
		if (rawNeg) {
			const searchTarget = this.validateStringField("negativeScope.searchTarget", rawNeg.searchTarget, 256);
			const query = this.validateStringField("negativeScope.query", rawNeg.query, 256);
			const scopeBoundary = this.validateOptionalString("negativeScope.scopeBoundary", rawNeg.scopeBoundary, 64);
			const details = this.validateOptionalString("negativeScope.details", rawNeg.details, MAX_FIELD_LENGTH);
			let sampleCount: number | undefined;
			if (rawNeg.sampleCount !== undefined && rawNeg.sampleCount !== null) {
				if (
					typeof rawNeg.sampleCount !== "number" ||
					!Number.isInteger(rawNeg.sampleCount) ||
					rawNeg.sampleCount < 0
				) {
					throw new ToolError("Field 'negativeScope.sampleCount' must be a non-negative integer");
				}
				sampleCount = rawNeg.sampleCount;
			}
			negativeScope = {
				searchTarget: redactEvidenceText(searchTarget),
				query: redactEvidenceText(query),
				isExhaustive: Boolean(rawNeg.isExhaustive),
				...(scopeBoundary ? { scopeBoundary } : {}),
				...(sampleCount !== undefined ? { sampleCount } : {}),
				...(details ? { details: redactEvidenceText(details) } : {}),
			};
		}

		let completionRatio: QuantitativeRatio | undefined;
		const rawRatio = input.completionRatio ?? rawContext.completionRatio;
		if (rawRatio) {
			if (
				typeof rawRatio.totalRequiredUnits !== "number" ||
				!Number.isInteger(rawRatio.totalRequiredUnits) ||
				rawRatio.totalRequiredUnits <= 0
			) {
				throw new ToolError(
					"Field 'completionRatio.totalRequiredUnits' must be a positive integer > 0 (denominator must be positive)",
				);
			}
			if (
				typeof rawRatio.verifiedUnits !== "number" ||
				!Number.isInteger(rawRatio.verifiedUnits) ||
				rawRatio.verifiedUnits < 0
			) {
				throw new ToolError("Field 'completionRatio.verifiedUnits' must be a non-negative integer >= 0");
			}
			if (rawRatio.verifiedUnits > rawRatio.totalRequiredUnits) {
				throw new ToolError(
					`Field 'completionRatio.verifiedUnits' (${rawRatio.verifiedUnits}) cannot exceed 'totalRequiredUnits' (${rawRatio.totalRequiredUnits})`,
				);
			}
			const unitDesc = this.validateOptionalString("completionRatio.unitDescription", rawRatio.unitDescription, 128);
			completionRatio = {
				verifiedUnits: rawRatio.verifiedUnits,
				totalRequiredUnits: rawRatio.totalRequiredUnits,
				...(unitDesc ? { unitDescription: redactEvidenceText(unitDesc) } : {}),
			};
		}
		const rawClaimScope = input.claimScope ?? rawContext.claimScope ?? rawNeg?.claimScope;
		let claimScope: "bounded" | "universal" | undefined;
		if (rawClaimScope) {
			if (rawClaimScope !== "bounded" && rawClaimScope !== "universal") {
				throw new ToolError("Field 'claimScope' must be 'bounded' or 'universal'");
			}
			claimScope = rawClaimScope;
		}

		if (negativeScope && claimScope) {
			negativeScope.claimScope = claimScope;
		}

		const hasContext =
			subject || assurance || executionBinding || compoundStages || negativeScope || completionRatio || claimScope;
		const context: ObservationContext | undefined = hasContext
			? {
					...(subject ? { subject } : {}),
					...(assurance ? { assurance } : {}),
					...(executionBinding ? { executionBinding } : {}),
					...(compoundStages ? { compoundStages } : {}),
					...(negativeScope ? { negativeScope } : {}),
					...(completionRatio ? { completionRatio } : {}),
					...(claimScope ? { claimScope } : {}),
				}
			: undefined;

		return { subject, context };
	}

	async addFact(input: AddFactInput): Promise<FactEvidence> {
		const sourceTool = this.validateStringField("sourceTool", input.sourceTool, MAX_SOURCE_TOOL_LENGTH);
		const locator = this.validateStringField("locator", input.locator, MAX_LOCATOR_LENGTH);
		const content = this.validateStringField("content", input.content, MAX_FIELD_LENGTH);
		const target = this.validateOptionalString("target", input.target, MAX_TARGET_LENGTH);
		const excerpt = this.validateOptionalString("excerpt", input.excerpt, MAX_EXCERPT_LENGTH);
		const title =
			this.validateOptionalString("title", input.title, MAX_TITLE_LENGTH) ?? `[Fact] ${sourceTool} @ ${locator}`;
		const classification = this.validateOptionalString("classification", input.classification, 128);
		const tags = this.sanitizeTags(input.tags);
		const { subject, context } = this.sanitizeObservationContext(input);

		let targetSha256: string | undefined;
		if (target) {
			const targetInfo = await this.resolveTargetFile(target);
			if (targetInfo.exists && targetInfo.sha256) {
				targetSha256 = targetInfo.sha256;
			}
		}

		// Finding 4: Reject conflicting target file hash vs execution artifact hash
		const ebHash = context?.executionBinding?.artifactSha256;
		if (targetSha256 && ebHash && targetSha256.toLowerCase() !== ebHash.toLowerCase()) {
			throw new ToolError(
				`Conflicting target file hash ('${targetSha256}') and execution artifact SHA-256 ('${ebHash}')`,
			);
		}

		let excerptHash: string | undefined;
		if (excerpt) {
			excerptHash = Bun.SHA256.hash(excerpt, "hex");
		}

		const fact: FactEvidence = {
			id: createEvidenceId("fact"),
			kind: "fact",
			title: redactEvidenceText(title),
			createdAt: new Date().toISOString(),
			sourceTool: redactEvidenceText(sourceTool),
			locator: redactEvidenceText(locator),
			content: redactEvidenceText(content),
			...(target ? { target } : {}),
			...(targetSha256 ? { targetSha256 } : {}),
			...(excerpt ? { excerpt: redactEvidenceText(excerpt) } : {}),
			...(excerptHash ? { excerptHash } : {}),
			...(classification ? { classification } : {}),
			...(tags ? { tags } : {}),
			...(subject ? { subject } : {}),
			...(context ? { context } : {}),
		};

		await this.appendRecord(fact);
		return fact;
	}

	async addHypothesis(input: AddHypothesisInput): Promise<HypothesisEvidence> {
		const claim = this.validateStringField("claim", input.claim, MAX_FIELD_LENGTH);
		const verificationPlan = this.validateStringField("verificationPlan", input.verificationPlan, MAX_FIELD_LENGTH);
		const target = this.validateOptionalString("target", input.target, MAX_TARGET_LENGTH);
		const content = this.validateOptionalString("content", input.content, MAX_FIELD_LENGTH);
		const title =
			this.validateOptionalString("title", input.title, MAX_TITLE_LENGTH) ?? `[Hypothesis] ${claim.slice(0, 60)}`;
		const classification = this.validateOptionalString("classification", input.classification, 128);
		const tags = this.sanitizeTags(input.tags);
		const { subject, context } = this.sanitizeObservationContext(input);

		let targetSha256: string | undefined;
		if (target) {
			const targetInfo = await this.resolveTargetFile(target);
			if (targetInfo.exists && targetInfo.sha256) {
				targetSha256 = targetInfo.sha256;
			}
		}
		// Finding 4: Reject conflicting target file hash vs execution artifact hash
		const hypEbHash = context?.executionBinding?.artifactSha256;
		if (targetSha256 && hypEbHash && targetSha256.toLowerCase() !== hypEbHash.toLowerCase()) {
			throw new ToolError(
				`Conflicting target file hash ('${targetSha256}') and execution artifact SHA-256 ('${hypEbHash}')`,
			);
		}

		const validFacts = Array.isArray(input.facts)
			? input.facts.filter(f => typeof f === "string" && f.trim().length > 0).map(f => f.trim())
			: undefined;

		const hypothesis: HypothesisEvidence = {
			id: createEvidenceId("hypothesis"),
			kind: "hypothesis",
			title: redactEvidenceText(title),
			createdAt: new Date().toISOString(),
			claim: redactEvidenceText(claim),
			verificationPlan: redactEvidenceText(verificationPlan),
			...(target ? { target } : {}),
			...(targetSha256 ? { targetSha256 } : {}),
			...(content ? { content: redactEvidenceText(content) } : {}),
			...(validFacts && validFacts.length > 0 ? { facts: validFacts } : {}),
			...(classification ? { classification } : {}),
			...(tags ? { tags } : {}),
			...(subject ? { subject } : {}),
			...(context ? { context } : {}),
		};

		await this.appendRecord(hypothesis);
		return hypothesis;
	}

	async addUnknown(input: AddUnknownInput): Promise<UnknownEvidence> {
		const question = this.validateStringField("question", input.question, MAX_FIELD_LENGTH);
		const notes = this.validateOptionalString("notes", input.notes, MAX_NOTES_LENGTH);
		const content = this.validateOptionalString("content", input.content, MAX_FIELD_LENGTH);
		const target = this.validateOptionalString("target", input.target, MAX_TARGET_LENGTH);
		const title =
			this.validateOptionalString("title", input.title, MAX_TITLE_LENGTH) ?? `[Unknown] ${question.slice(0, 60)}`;
		const classification = this.validateOptionalString("classification", input.classification, 128);
		const tags = this.sanitizeTags(input.tags);
		const { subject, context } = this.sanitizeObservationContext(input);

		let targetSha256: string | undefined;
		if (target) {
			const targetInfo = await this.resolveTargetFile(target);
			if (targetInfo.exists && targetInfo.sha256) {
				targetSha256 = targetInfo.sha256;
			}
		}

		const unknownRecord: UnknownEvidence = {
			id: createEvidenceId("unknown"),
			kind: "unknown",
			title: redactEvidenceText(title),
			createdAt: new Date().toISOString(),
			question: redactEvidenceText(question),
			...(notes ? { notes: redactEvidenceText(notes) } : {}),
			...(content ? { content: redactEvidenceText(content) } : {}),
			...(target ? { target } : {}),
			...(targetSha256 ? { targetSha256 } : {}),
			...(classification ? { classification } : {}),
			...(tags ? { tags } : {}),
			...(subject ? { subject } : {}),
			...(context ? { context } : {}),
		};

		await this.appendRecord(unknownRecord);
		return unknownRecord;
	}

	async verifyHypothesis(input: VerifyHypothesisInput): Promise<ConclusionEvidence> {
		const hypothesisId = this.validateStringField("hypothesisId", input.hypothesisId, 128);
		const method = this.validateStringField("method", input.method, MAX_FIELD_LENGTH);
		const command = this.validateStringField("command", input.command, MAX_FIELD_LENGTH);
		const result = this.validateStringField("result", input.result, MAX_FIELD_LENGTH);
		const conclusionText = this.validateStringField("conclusion", input.conclusion, MAX_FIELD_LENGTH);
		const reproducibility =
			this.validateOptionalString("reproducibility", input.reproducibility, 256) ?? "not specified";
		const status = input.status === "refuted" ? "refuted" : "verified";
		const { subject: conclusionSubject, context: conclusionContext } = this.sanitizeObservationContext(input);

		let invalidatesConclusions: string[] | undefined;
		if (input.invalidatesConclusions && Array.isArray(input.invalidatesConclusions)) {
			const sanitized = input.invalidatesConclusions
				.filter(id => typeof id === "string" && id.trim().length > 0)
				.map(id => id.trim());
			if (sanitized.length > 0) {
				invalidatesConclusions = sanitized;
			}
		}

		return await withEvidenceStoreWrite(this.projectDirectory, this.lockPath, async () => {
			await this.ensureDirectory();
			const existingRecords = await this.readAllRecordsUnlocked();
			const hypothesis = existingRecords.find(r => r.id === hypothesisId);
			if (!hypothesis) {
				throw new ToolError(`Hypothesis '${hypothesisId}' not found in evidence ledger`);
			}
			if (hypothesis.kind !== "hypothesis") {
				throw new ToolError(
					`Target evidence '${hypothesisId}' is of kind '${hypothesis.kind}', not 'hypothesis'. Only hypotheses can be verified.`,
				);
			}

			// Finding 4: Reject conflicting target file hash vs execution artifact hash in verify call
			const concTargetSha = input.targetSha256;
			const concEbHash = conclusionContext?.executionBinding?.artifactSha256;
			if (concTargetSha && concEbHash && concTargetSha.toLowerCase() !== concEbHash.toLowerCase()) {
				throw new ToolError(
					`Conflicting target file hash ('${concTargetSha}') and execution artifact SHA-256 ('${concEbHash}')`,
				);
			}

			// Finding 7: Reject rebinding hypothesis subject or hash during verification
			const hypSubject = hypothesis.subject ?? hypothesis.context?.subject;
			if (hypSubject && conclusionSubject && hypSubject !== conclusionSubject) {
				throw new ToolError(
					`Cannot rebind hypothesis subject from '${hypSubject}' to '${conclusionSubject}' during verification`,
				);
			}

			const hypHash = hypothesis.targetSha256 ?? hypothesis.context?.executionBinding?.artifactSha256;
			const concEffectiveHash = concTargetSha ?? concEbHash;
			if (hypHash && concEffectiveHash && hypHash.toLowerCase() !== concEffectiveHash.toLowerCase()) {
				throw new ToolError(
					`Cannot rebind hypothesis target SHA-256 from '${hypHash}' to '${concEffectiveHash}' during verification`,
				);
			}

			// When establishing a verified conclusion, enforce evidentiary rigor
			if (status === "verified") {
				// 1. Reject nonzero stage in compound commands (conclusion context AND hypothesis context - Finding 10)
				if (conclusionContext?.compoundStages && conclusionContext.compoundStages.length > 0) {
					const failedStage = conclusionContext.compoundStages.find(
						s => s.exitCode !== 0 || s.status === "failed",
					);
					if (failedStage) {
						throw new ToolError(
							`Cannot establish verified conclusion: compound command stage '${failedStage.stage}' failed with exit code ${failedStage.exitCode}`,
						);
					}
				}

				if (hypothesis.context?.compoundStages && hypothesis.context.compoundStages.length > 0) {
					const hypFailed = hypothesis.context.compoundStages.find(s => s.exitCode !== 0 || s.status === "failed");
					if (hypFailed) {
						throw new ToolError(
							`Cannot establish verified conclusion: hypothesis context compound command stage '${hypFailed.stage}' failed with exit code ${hypFailed.exitCode}`,
						);
					}
				}

				// 2. Reject non-exhaustive negative scope ONLY when claiming universal absence
				const isUniversalAbsence =
					input.requireExhaustiveNegative === true ||
					input.claimScope === "universal" ||
					conclusionContext?.claimScope === "universal" ||
					conclusionContext?.negativeScope?.claimScope === "universal" ||
					hypothesis.context?.claimScope === "universal" ||
					hypothesis.context?.negativeScope?.claimScope === "universal";

				if (isUniversalAbsence) {
					const neg = conclusionContext?.negativeScope ?? hypothesis.context?.negativeScope;
					if (!neg || !neg.isExhaustive) {
						throw new ToolError(
							`Cannot establish verified conclusion claiming universal absence: negative search scope on '${neg?.searchTarget ?? "target"}' must be exhaustive`,
						);
					}
				}
				// 3. Supporting facts validation
				const supportingFactIds = Array.from(new Set([...(hypothesis.facts ?? []), ...(input.facts ?? [])]));

				// High assurance (dynamic_call_observation, algorithm_recovery, independent_reproduction)
				// requires supporting evidence facts; cannot be established out of thin air
				if (
					conclusionContext?.assurance &&
					ASSURANCE_LEVEL_RANK[conclusionContext.assurance] >= 2 &&
					supportingFactIds.length === 0
				) {
					throw new ToolError(
						`Cannot establish verified conclusion with assurance tier '${conclusionContext.assurance}' without supporting evidence facts`,
					);
				}

				if (supportingFactIds.length > 0) {
					const effectiveTargetSha =
						input.targetSha256 ??
						conclusionContext?.executionBinding?.artifactSha256 ??
						hypothesis.targetSha256 ??
						hypothesis.context?.executionBinding?.artifactSha256;

					const effectiveSubject = conclusionSubject ?? hypothesis.subject ?? hypothesis.context?.subject;

					const minAssurance = conclusionContext?.assurance;

					const evalResult = await evaluateEvidenceSupport(existingRecords, supportingFactIds, {
						requiredSubject: effectiveSubject,
						requiredTargetSha256: effectiveTargetSha,
						minAssurance,
						requireZeroExitStages: true,
						requireExhaustiveNegative: isUniversalAbsence,
					});

					if (!evalResult.valid) {
						throw new ToolError(
							`Cannot establish verified conclusion: supporting evidence failed verification: ${evalResult.reason ?? "invalid evidence"}`,
						);
					}
				}
			}

			const title =
				this.validateOptionalString("title", input.title, MAX_TITLE_LENGTH) ??
				`[Conclusion] ${conclusionText.slice(0, 60)}`;

			const conclusion: ConclusionEvidence = {
				id: createEvidenceId("conclusion"),
				kind: "conclusion",
				title: redactEvidenceText(title),
				createdAt: new Date().toISOString(),
				hypothesisId: hypothesis.id,
				method: redactEvidenceText(method),
				command: redactEvidenceText(command),
				result: redactEvidenceText(result),
				conclusion: redactEvidenceText(conclusionText),
				reproducibility: redactEvidenceText(reproducibility),
				status,
				verifiedAt: new Date().toISOString(),
				...((input.target ?? hypothesis.target) ? { target: input.target ?? hypothesis.target } : {}),
				...((input.targetSha256 ?? hypothesis.targetSha256)
					? { targetSha256: input.targetSha256 ?? hypothesis.targetSha256 }
					: {}),
				...(hypothesis.classification ? { classification: hypothesis.classification } : {}),
				...(hypothesis.tags ? { tags: hypothesis.tags } : {}),
				...(conclusionSubject
					? { subject: conclusionSubject }
					: hypothesis.subject
						? { subject: hypothesis.subject }
						: {}),
				...(conclusionContext ? { context: conclusionContext } : {}),
				...(invalidatesConclusions && invalidatesConclusions.length > 0 ? { invalidatesConclusions } : {}),
			};

			const updatedHypothesis: HypothesisEvidence = {
				...hypothesis,
				...(input.facts && input.facts.length > 0
					? { facts: Array.from(new Set([...(hypothesis.facts ?? []), ...input.facts])) }
					: {}),
			};

			const updated = existingRecords.map(r => (r.id === hypothesisId ? updatedHypothesis : r));
			updated.push(conclusion);
			const jsonlContent = updated.map(r => JSON.stringify(r)).join("\n") + "\n";
			const tempFile = `${this.ledgerPath}.${process.pid}.${Bun.randomUUIDv7()}.tmp`;
			await fs.writeFile(tempFile, jsonlContent, { encoding: "utf-8", mode: PRIVATE_FILE_MODE });
			await replaceFileAtomically(tempFile, this.ledgerPath);

			return conclusion;
		});
	}

	private async appendRecord(record: EvidenceRecord): Promise<void> {
		await withEvidenceStoreWrite(this.projectDirectory, this.lockPath, async () => {
			await this.ensureDirectory();
			const existingRecords = await this.readAllRecordsUnlocked();
			const updated = [...existingRecords, record];
			const jsonlContent = updated.map(r => JSON.stringify(r)).join("\n") + "\n";
			const tempFile = `${this.ledgerPath}.${process.pid}.${Bun.randomUUIDv7()}.tmp`;
			await fs.writeFile(tempFile, jsonlContent, { encoding: "utf-8", mode: PRIVATE_FILE_MODE });
			await replaceFileAtomically(tempFile, this.ledgerPath);
		});
	}

	async getRecord(id: string): Promise<EvidenceRecord | null> {
		const records = await this.readAllRecordsUnlocked();
		const linked = this.linkHypotheses(records);
		return linked.find(r => r.id === id) ?? null;
	}

	async listRecords(filter: EvidenceListFilter = {}): Promise<EvidenceListResult> {
		const records = await this.readAllRecordsUnlocked();
		const linked = this.linkHypotheses(records);

		let filtered = linked;

		if (filter.kind) {
			filtered = filtered.filter(r => r.kind === filter.kind);
		}

		if (filter.target) {
			const targetLower = filter.target.toLowerCase();
			filtered = filtered.filter(r => r.target && r.target.toLowerCase().includes(targetLower));
		}

		if (filter.query) {
			const q = filter.query.toLowerCase();
			filtered = filtered.filter(r => {
				const titleMatch = r.title.toLowerCase().includes(q);
				const targetMatch = r.target?.toLowerCase().includes(q) ?? false;
				const tagsMatch = r.tags?.some(t => t.toLowerCase().includes(q)) ?? false;
				let contentMatch = false;
				if (r.kind === "fact") {
					contentMatch = r.content.toLowerCase().includes(q) || r.locator.toLowerCase().includes(q);
				} else if (r.kind === "hypothesis") {
					contentMatch = r.claim.toLowerCase().includes(q) || r.verificationPlan.toLowerCase().includes(q);
				} else if (r.kind === "unknown") {
					contentMatch = r.question.toLowerCase().includes(q) || (r.notes?.toLowerCase().includes(q) ?? false);
				} else if (r.kind === "conclusion") {
					contentMatch =
						r.conclusion.toLowerCase().includes(q) ||
						r.result.toLowerCase().includes(q) ||
						r.method.toLowerCase().includes(q);
				}
				return titleMatch || targetMatch || tagsMatch || contentMatch;
			});
		}

		const total = filtered.length;
		const offset = Math.max(0, filter.offset ?? 0);
		const limit = Math.min(MAX_LIST_LIMIT, Math.max(1, filter.limit ?? DEFAULT_LIST_LIMIT));
		const items = filtered.slice(offset, offset + limit);

		return { items, total, limit, offset };
	}

	async checkDrift(record: EvidenceRecord): Promise<EvidenceDriftStatus> {
		const warnings: string[] = [];
		const status: EvidenceDriftStatus = {
			recordId: record.id,
			target: record.target,
			warnings,
		};

		if (!record.target) {
			return status;
		}

		const targetInfo = await this.resolveTargetFile(record.target);
		if (!targetInfo.exists) {
			status.targetMissing = true;
			warnings.push(`Target file '${record.target}' does not exist on disk.`);
			return status;
		}

		status.currentTargetSha256 = targetInfo.sha256;
		status.originalTargetSha256 = record.targetSha256;

		if (record.targetSha256 && targetInfo.sha256 && record.targetSha256 !== targetInfo.sha256) {
			status.targetDrift = true;
			warnings.push(
				`Target file '${record.target}' has changed since evidence was recorded (original SHA-256: ${record.targetSha256}, current SHA-256: ${targetInfo.sha256}).`,
			);
		}

		if (record.kind === "fact" && record.excerpt) {
			status.originalExcerptHash = record.excerptHash;
			try {
				const file = Bun.file(targetInfo.absolutePath);
				// Only inspect excerpt existence if file size <= 16 MiB
				if (file.size <= 16 * 1024 * 1024) {
					const text = await file.text();
					if (!text.includes(record.excerpt)) {
						status.excerptDrift = true;
						warnings.push(
							`Excerpt text is no longer found in '${record.target}'. Target content may have drifted or been refactored.`,
						);
					}
				}
			} catch {
				// Non-text file or unreadable as text
			}
		}

		return status;
	}
	async getAllRecords(): Promise<EvidenceRecord[]> {
		const records = await this.readAllRecordsUnlocked();
		return this.linkHypotheses(records);
	}

	async resolveValidity(): Promise<Map<string, CanonicalEvidenceValidity>> {
		const records = await this.getAllRecords();
		return resolveEvidenceLedgerValidity(records);
	}

	async evaluateSupport(ids: string[], requirements?: EvidenceRequirements): Promise<EvidenceSupportEvaluation> {
		return await evaluateEvidenceSupport(this, ids, requirements);
	}
}
