import { redactMemorySecrets } from "../memory-backend/redact";

export type EvidenceKind = "fact" | "hypothesis" | "unknown" | "conclusion";

export const EVIDENCE_ASSURANCE_LEVELS = [
	"static_candidate",
	"dynamic_call_observation",
	"algorithm_recovery",
	"independent_reproduction",
] as const;
export type EvidenceAssuranceLevel = (typeof EVIDENCE_ASSURANCE_LEVELS)[number];

export const ASSURANCE_LEVEL_RANK: Record<EvidenceAssuranceLevel, number> = {
	static_candidate: 1,
	dynamic_call_observation: 2,
	algorithm_recovery: 3,
	independent_reproduction: 4,
};

export interface ExecutionObservationWindow {
	startedAt?: string;
	endedAt?: string;
}

export interface ExecutionBinding {
	artifactSha256?: string;
	deviceAbi?: string;
	os?: string;
	pid?: number;
	window?: ExecutionObservationWindow;
}

export interface CommandStageResult {
	stage: string;
	command?: string;
	exitCode: number;
	status?: "success" | "failed";
	stdout?: string;
	stderr?: string;
}

export interface NegativeSearchScope {
	searchTarget: string;
	query: string;
	scopeBoundary?: string;
	sampleCount?: number;
	isExhaustive: boolean;
	claimScope?: "bounded" | "universal";
	details?: string;
}

export interface QuantitativeRatio {
	verifiedUnits: number;
	totalRequiredUnits: number;
	unitDescription?: string;
}

export interface ObservationContext {
	subject?: string;
	assurance?: EvidenceAssuranceLevel;
	executionBinding?: ExecutionBinding;
	compoundStages?: CommandStageResult[];
	negativeScope?: NegativeSearchScope;
	completionRatio?: QuantitativeRatio;
	claimScope?: "bounded" | "universal";
}

export const MAX_TITLE_LENGTH = 256;
export const MAX_TARGET_LENGTH = 512;
export const MAX_LOCATOR_LENGTH = 512;
export const MAX_SOURCE_TOOL_LENGTH = 64;
export const MAX_FIELD_LENGTH = 32768; // 32 KiB
export const MAX_EXCERPT_LENGTH = 16384; // 16 KiB
export const MAX_NOTES_LENGTH = 8192; // 8 KiB
export const MAX_TAGS_COUNT = 20;
export const MAX_TAG_LENGTH = 64;
export const DEFAULT_LIST_LIMIT = 20;
export const MAX_LIST_LIMIT = 100;
export const MAX_INLINE_CHARS = 4000;

export interface BaseEvidenceRecord {
	id: string;
	kind: EvidenceKind;
	title: string;
	createdAt: string;
	target?: string;
	targetSha256?: string;
	classification?: string;
	tags?: string[];
	subject?: string;
	context?: ObservationContext;
}

export interface FactEvidence extends BaseEvidenceRecord {
	kind: "fact";
	sourceTool: string;
	locator: string;
	content: string;
	excerpt?: string;
	excerptHash?: string;
}

export interface HypothesisEvidence extends BaseEvidenceRecord {
	kind: "hypothesis";
	claim: string;
	verificationPlan: string;
	facts?: string[];
	verifiedBy?: string;
	content?: string;
}

export interface UnknownEvidence extends BaseEvidenceRecord {
	kind: "unknown";
	question: string;
	notes?: string;
	content?: string;
}

export interface ConclusionEvidence extends BaseEvidenceRecord {
	kind: "conclusion";
	hypothesisId: string;
	method: string;
	command: string;
	result: string;
	conclusion: string;
	reproducibility: string;
	status: "verified" | "refuted";
	verifiedAt: string;
	invalidatesConclusions?: string[];
}

export type EvidenceRecord = FactEvidence | HypothesisEvidence | UnknownEvidence | ConclusionEvidence;

export interface AddFactInput {
	kind: "fact";
	title?: string;
	target?: string;
	sourceTool: string;
	locator: string;
	content: string;
	excerpt?: string;
	classification?: string;
	tags?: string[];
	subject?: string;
	assurance?: EvidenceAssuranceLevel;
	executionBinding?: ExecutionBinding;
	compoundStages?: CommandStageResult[];
	negativeScope?: NegativeSearchScope;
	completionRatio?: QuantitativeRatio;
	context?: ObservationContext;
}

export interface AddHypothesisInput {
	kind: "hypothesis";
	title?: string;
	target?: string;
	claim: string;
	verificationPlan: string;
	facts?: string[];
	content?: string;
	classification?: string;
	tags?: string[];
	subject?: string;
	assurance?: EvidenceAssuranceLevel;
	executionBinding?: ExecutionBinding;
	negativeScope?: NegativeSearchScope;
	context?: ObservationContext;
}

export interface AddUnknownInput {
	kind: "unknown";
	title?: string;
	target?: string;
	question: string;
	notes?: string;
	content?: string;
	classification?: string;
	tags?: string[];
	subject?: string;
	context?: ObservationContext;
}

export type AddEvidenceInput = AddFactInput | AddHypothesisInput | AddUnknownInput;

export interface VerifyHypothesisInput {
	hypothesisId: string;
	method: string;
	command: string;
	result: string;
	conclusion: string;
	reproducibility?: string;
	status?: "verified" | "refuted";
	title?: string;
	facts?: string[];
	target?: string;
	targetSha256?: string;
	subject?: string;
	assurance?: EvidenceAssuranceLevel;
	executionBinding?: ExecutionBinding;
	compoundStages?: CommandStageResult[];
	negativeScope?: NegativeSearchScope;
	completionRatio?: QuantitativeRatio;
	invalidatesConclusions?: string[];
	context?: ObservationContext;
	claimScope?: "bounded" | "universal";
	requireExhaustiveNegative?: boolean;
}

export interface EvidenceListFilter {
	kind?: EvidenceKind;
	target?: string;
	query?: string;
	limit?: number;
	offset?: number;
}

export interface EvidenceListResult {
	items: EvidenceRecord[];
	total: number;
	limit: number;
	offset: number;
}

export interface EvidenceDriftStatus {
	recordId: string;
	target?: string;
	targetMissing?: boolean;
	targetDrift?: boolean;
	originalTargetSha256?: string;
	currentTargetSha256?: string;
	excerptDrift?: boolean;
	originalExcerptHash?: string;
	currentExcerptHash?: string;
	warnings: string[];
}

export function createEvidenceId(kind: EvidenceKind): string {
	const shortKind =
		kind === "hypothesis" ? "hyp" : kind === "conclusion" ? "conc" : kind === "unknown" ? "unk" : "fact";
	return `ev_${shortKind}_${Bun.randomUUIDv7()}`;
}

export function encodeEvidenceProjectKey(repositoryRoot: string): string {
	const normalized = repositoryRoot.replaceAll("\\", "/").replace(/\/$/, "");
	const readable = normalized
		.replace(/^\//, "")
		.replace(/[^a-zA-Z0-9._-]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(-80);
	return `${readable || "project"}-${Bun.SHA256.hash(normalized, "hex").slice(0, 12)}`;
}

const EMBEDDED_URL_CREDS_RE = /https?:\/\/[^/:]+:[^/@]+@/g;

export function redactEvidenceText(input: string): string {
	if (!input) return input;
	const scrubbedUrls = input.replace(EMBEDDED_URL_CREDS_RE, "https://[REDACTED]@");
	return redactMemorySecrets(scrubbedUrls);
}

export const DYNAMIC_LOCATOR_REGEX = /^session:([a-zA-Z0-9_.-]+):seq:(\d+)$/;

export function isDynamicLocator(locator: string): boolean {
	return Boolean(locator && DYNAMIC_LOCATOR_REGEX.test(locator.trim()));
}
