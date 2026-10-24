import { ToolError } from "@reverse/tui/tools/tool-errors";
import type { EvidenceRecord } from "../evidence/contracts";
import { EVIDENCE_ASSURANCE_LEVELS, type EvidenceAssuranceLevel } from "../evidence/contracts";
import type { EvidenceStore } from "../evidence/store";
import { evaluateEvidenceSupport } from "../evidence/validity";
import type {
	AcceptanceCriterion,
	AcceptanceCriterionStatus,
	ProgressionAuditEntry,
	ReverseWorkflowRecord,
	TargetDeviceConstraints,
	WorkflowDependencyRecord,
} from "./contracts";

/** Reserved typed metadata key for acceptance criteria keyed by stable step_id */
export const WORKFLOW_METADATA_ACCEPTANCE_KEY = "acceptance";

/** Reserved typed metadata key for active verifying proof IDs supporting completed steps */
export const WORKFLOW_METADATA_ACTIVE_PROOF_KEY = "active_proof";

/** Reserved typed metadata key for target device constraints */
export const WORKFLOW_METADATA_CONSTRAINTS_KEY = "target_device_constraints";

/** Reserved typed metadata key for workflow dependencies */
export const WORKFLOW_METADATA_DEPENDENCIES_KEY = "dependencies";

const MAX_ID_LENGTH = 64;
const MAX_TITLE_LENGTH = 256;
const MAX_SUBJECT_LENGTH = 256;
const MAX_ENVIRONMENT_LENGTH = 128;
const MAX_NOTES_LENGTH = 2048;
const MAX_ARRAY_ITEMS = 50;

/**
 * Normalizes an acceptance criterion input into a typed AcceptanceCriterion.
 * Validates strictly: rejects malformed constraints, validates type/length bounds, and enforces canonical fields.
 * On initial creation, status must be "pending"; caller cannot claim initial satisfaction/waiver.
 */
export function normalizeAcceptanceCriterion(
	input: unknown,
	defaultStepId?: string,
	options: { isInitialCreation?: boolean } = {},
): AcceptanceCriterion {
	if (!input || typeof input !== "object" || Array.isArray(input)) {
		throw new ToolError("Invalid acceptance criterion: expected an object.");
	}
	const obj = input as Record<string, unknown>;

	if (typeof obj.id !== "string" || !obj.id.trim() || obj.id.trim().length > MAX_ID_LENGTH) {
		throw new ToolError(`Acceptance criterion requires a non-empty 'id' string (max ${MAX_ID_LENGTH} characters).`);
	}
	const id = obj.id.trim();

	const rawStepId = typeof obj.step_id === "string" && obj.step_id.trim() ? obj.step_id.trim() : defaultStepId?.trim();
	if (!rawStepId || rawStepId.length > MAX_ID_LENGTH) {
		throw new ToolError(`Acceptance criterion '${id}' requires a valid 'step_id' (max ${MAX_ID_LENGTH} characters).`);
	}
	const stepId = rawStepId;

	const title = typeof obj.title === "string" && obj.title.trim() ? obj.title.trim().slice(0, MAX_TITLE_LENGTH) : id;

	// Canonical subject field: required, immutable target subject string
	if (typeof obj.subject !== "string" || !obj.subject.trim() || obj.subject.trim().length > MAX_SUBJECT_LENGTH) {
		throw new ToolError(
			`Acceptance criterion '${id}' requires a non-empty canonical 'subject' string (max ${MAX_SUBJECT_LENGTH} characters).`,
		);
	}
	const subject = obj.subject.trim();

	let minAssurance: EvidenceAssuranceLevel | undefined;
	if (obj.min_assurance !== undefined && obj.min_assurance !== null) {
		if (typeof obj.min_assurance !== "string") {
			throw new ToolError(`min_assurance on criterion '${id}' must be a string.`);
		}
		const rawAssurance = obj.min_assurance.trim() as EvidenceAssuranceLevel;
		if (!EVIDENCE_ASSURANCE_LEVELS.includes(rawAssurance)) {
			throw new ToolError(
				`Invalid min_assurance '${obj.min_assurance}' on criterion '${id}'. Must be one of: ${EVIDENCE_ASSURANCE_LEVELS.join(", ")}`,
			);
		}
		minAssurance = rawAssurance;
	}

	let requiredEvidenceTypes: string[] | undefined;
	if (obj.required_evidence_types !== undefined && obj.required_evidence_types !== null) {
		if (!Array.isArray(obj.required_evidence_types)) {
			throw new ToolError(`Acceptance criterion '${id}' 'required_evidence_types' must be an array of strings.`);
		}
		if (obj.required_evidence_types.length > MAX_ARRAY_ITEMS) {
			throw new ToolError(`required_evidence_types on criterion '${id}' cannot exceed ${MAX_ARRAY_ITEMS} items.`);
		}
		requiredEvidenceTypes = obj.required_evidence_types.map(t => {
			if (typeof t !== "string" || !t.trim() || t.trim().length > MAX_ID_LENGTH) {
				throw new ToolError(`Acceptance criterion '${id}' contains empty or invalid evidence type.`);
			}
			return t.trim();
		});
	}

	let status: AcceptanceCriterionStatus = "pending";
	if (options.isInitialCreation) {
		if (obj.status !== undefined && obj.status !== null && obj.status !== "pending") {
			throw new ToolError(
				`Initial acceptance criterion '${id}' status must be 'pending'. Initial satisfaction or waiver cannot be claimed by caller.`,
			);
		}
		status = "pending";
	} else if (typeof obj.status === "string") {
		const rawStatus = obj.status.trim() as AcceptanceCriterionStatus;
		if (
			rawStatus === "pending" ||
			rawStatus === "satisfied" ||
			rawStatus === "waived" ||
			rawStatus === "proxy_verified"
		) {
			status = rawStatus;
		} else {
			throw new ToolError(
				`Invalid status '${obj.status}' for acceptance criterion '${id}'. Must be one of: pending, satisfied, waived, proxy_verified.`,
			);
		}
	} else if (obj.status !== undefined && obj.status !== null) {
		throw new ToolError(`Acceptance criterion '${id}' status must be a string.`);
	}

	return {
		id,
		step_id: stepId,
		title,
		subject,
		...(requiredEvidenceTypes && requiredEvidenceTypes.length > 0
			? { required_evidence_types: requiredEvidenceTypes }
			: {}),
		...(minAssurance ? { min_assurance: minAssurance } : {}),
		status,
		satisfied_by_evidence_ids: Array.isArray(obj.satisfied_by_evidence_ids)
			? (obj.satisfied_by_evidence_ids as string[]).map(String)
			: undefined,
		is_proxy: typeof obj.is_proxy === "boolean" ? obj.is_proxy : false,
		proxy_for_criterion_id: typeof obj.proxy_for_criterion_id === "string" ? obj.proxy_for_criterion_id : undefined,
		proxy_evidence_ids: Array.isArray(obj.proxy_evidence_ids)
			? (obj.proxy_evidence_ids as string[]).map(String)
			: undefined,
		waiver_reason: typeof obj.waiver_reason === "string" ? obj.waiver_reason : undefined,
		waiver_timestamp: typeof obj.waiver_timestamp === "string" ? obj.waiver_timestamp : undefined,
		waived_by_decision: typeof obj.waived_by_decision === "string" ? obj.waived_by_decision : undefined,
		created_at: typeof obj.created_at === "string" ? obj.created_at : undefined,
		updated_at: typeof obj.updated_at === "string" ? obj.updated_at : undefined,
	};
}

/**
 * Retrieves acceptance criteria from the workflow's single reserved metadata key:
 * workflow.metadata.acceptance (Record<step_id, AcceptanceCriterion[]>).
 */
export function getWorkflowAcceptanceCriteria(workflow: ReverseWorkflowRecord, stepId?: string): AcceptanceCriterion[] {
	const metadata = workflow.metadata;
	if (!metadata || !metadata[WORKFLOW_METADATA_ACCEPTANCE_KEY]) {
		return [];
	}

	const acceptance = metadata[WORKFLOW_METADATA_ACCEPTANCE_KEY];
	if (Array.isArray(acceptance)) {
		const list = acceptance as AcceptanceCriterion[];
		return stepId ? list.filter(c => c.step_id === stepId) : list;
	}

	if (typeof acceptance === "object" && acceptance !== null) {
		const table = acceptance as Record<string, AcceptanceCriterion[]>;
		if (stepId) {
			return table[stepId] ?? [];
		}
		const all: AcceptanceCriterion[] = [];
		for (const group of Object.values(table)) {
			if (Array.isArray(group)) {
				all.push(...group);
			}
		}
		return all;
	}

	return [];
}

/**
 * Updates or appends an acceptance criterion in the workflow's single reserved metadata key.
 * Strictly verifies that criterion.step_id exists in workflow.steps.
 */
export function updateAcceptanceCriterion(workflow: ReverseWorkflowRecord, criterion: AcceptanceCriterion): void {
	if (!workflow.steps.some(s => s.id === criterion.step_id)) {
		throw new ToolError(
			`Cannot update acceptance criterion '${criterion.id}': step '${criterion.step_id}' does not exist in workflow '${workflow.id}'.`,
		);
	}

	if (!workflow.metadata) {
		workflow.metadata = {};
	}

	let table: Record<string, AcceptanceCriterion[]>;
	const raw = workflow.metadata[WORKFLOW_METADATA_ACCEPTANCE_KEY];
	if (raw && typeof raw === "object" && !Array.isArray(raw)) {
		table = raw as Record<string, AcceptanceCriterion[]>;
	} else {
		table = {};
		if (Array.isArray(raw)) {
			for (const c of raw as AcceptanceCriterion[]) {
				if (c && typeof c.step_id === "string") {
					table[c.step_id] = table[c.step_id] ?? [];
					table[c.step_id]!.push(c);
				}
			}
		}
		workflow.metadata[WORKFLOW_METADATA_ACCEPTANCE_KEY] = table;
	}

	const stepId = criterion.step_id;
	const list = table[stepId] ?? [];
	const idx = list.findIndex(c => c.id === criterion.id);
	if (idx >= 0) {
		list[idx] = criterion;
	} else {
		list.push(criterion);
	}
	table[stepId] = list;
}

/**
 * Stores a full set of initial or updated acceptance criteria in workflow.metadata.acceptance.
 * Strictly verifies that all criterion step_ids exist in workflow.steps and rejects duplicate IDs.
 */
export function setWorkflowAcceptanceCriteria(workflow: ReverseWorkflowRecord, criteria: AcceptanceCriterion[]): void {
	const validStepIds = new Set(workflow.steps.map(s => s.id));
	const seenIds = new Set<string>();
	const table: Record<string, AcceptanceCriterion[]> = {};

	for (const c of criteria) {
		if (seenIds.has(c.id)) {
			throw new ToolError(`Duplicate acceptance criterion ID: '${c.id}'. Each criterion ID must be unique.`);
		}
		seenIds.add(c.id);

		if (!validStepIds.has(c.step_id)) {
			throw new ToolError(
				`Acceptance criterion '${c.id}' references unknown step '${c.step_id}'. Must reference an existing step in workflow '${workflow.id}'.`,
			);
		}

		table[c.step_id] = table[c.step_id] ?? [];
		table[c.step_id]!.push(c);
	}

	if (!workflow.metadata) {
		workflow.metadata = {};
	}
	workflow.metadata[WORKFLOW_METADATA_ACCEPTANCE_KEY] = table;
}

/**
 * Evaluates whether evidence records satisfy an acceptance criterion.
 * Consumes canonical evaluateEvidenceSupport with criterion requirements.
 * Mismatched subjects are classified as proxy observations and cannot satisfy the criterion.
 */
export async function evaluateAcceptanceSatisfaction(
	criterion: AcceptanceCriterion,
	evidenceRecords: EvidenceRecord[],
	evidenceStore?: EvidenceStore,
): Promise<{
	status: AcceptanceCriterionStatus;
	isProxy: boolean;
	proxyReason?: string;
	matchingEvidenceIds: string[];
	unmetReason?: string;
}> {
	if (criterion.status === "waived") {
		return {
			status: "waived",
			isProxy: false,
			matchingEvidenceIds: criterion.satisfied_by_evidence_ids ?? [],
		};
	}

	if (!evidenceRecords || evidenceRecords.length === 0) {
		return {
			status: "pending",
			isProxy: false,
			matchingEvidenceIds: [],
			unmetReason: `No supporting evidence records provided for criterion '${criterion.id}'.`,
		};
	}

	const evidenceIds = evidenceRecords.map(r => r.id);
	const resolver = evidenceStore ?? evidenceRecords;

	// 1. Evaluate with canonical evaluator against the required subject and minAssurance
	const evalResult = await evaluateEvidenceSupport(resolver, evidenceIds, {
		requiredSubject: criterion.subject,
		minAssurance: criterion.min_assurance,
		requiredKinds: ["fact", "conclusion"],
	});

	// Check if any evidence is a proxy (recorded under a different subject)
	if (evalResult.mismatchedSubjectIds.length > 0) {
		const proxyIds = evalResult.mismatchedSubjectIds;
		const sampleProxy = evidenceRecords.find(r => r.id === proxyIds[0]);
		const proxySubject = sampleProxy?.subject ?? sampleProxy?.context?.subject ?? "unspecified";
		const proxyReason = `Evidence '${proxyIds.join(", ")}' records subject '${proxySubject}', which differs from required acceptance subject '${criterion.subject}'. Proxy observations cannot close original acceptance criteria without explicit user waiver.`;

		return {
			status: "proxy_verified",
			isProxy: true,
			proxyReason,
			matchingEvidenceIds: proxyIds,
			unmetReason: proxyReason,
		};
	}

	// 2. Validate overall canonical validity
	if (!evalResult.valid) {
		return {
			status: "pending",
			isProxy: false,
			matchingEvidenceIds: [],
			unmetReason: evalResult.reason ?? `Evidence does not satisfy criterion '${criterion.id}' requirements.`,
		};
	}

	// 3. Verify required_evidence_types if specified
	let matchingRecords = evalResult.records;
	if (criterion.required_evidence_types && criterion.required_evidence_types.length > 0) {
		const filtered: EvidenceRecord[] = [];
		for (const record of matchingRecords) {
			const evidenceTags = new Set<string>();
			if (Array.isArray(record.tags)) {
				for (const t of record.tags) evidenceTags.add(t.toLowerCase());
			}
			evidenceTags.add(record.kind.toLowerCase());
			if (record.kind === "fact") {
				if (record.sourceTool) evidenceTags.add(record.sourceTool.toLowerCase());
				if (record.target) evidenceTags.add(record.target.toLowerCase());
				if (record.locator) evidenceTags.add(record.locator.toLowerCase());
			}
			const matchesType = criterion.required_evidence_types.some(req => {
				const lower = req.toLowerCase();
				return evidenceTags.has(lower) || Array.from(evidenceTags).some(t => t.includes(lower));
			});
			if (matchesType) {
				filtered.push(record);
			}
		}
		if (filtered.length === 0) {
			return {
				status: "pending",
				isProxy: false,
				matchingEvidenceIds: [],
				unmetReason: `Evidence does not match required evidence types: ${criterion.required_evidence_types.join(", ")}.`,
			};
		}
		matchingRecords = filtered;
	}

	return {
		status: "satisfied",
		isProxy: false,
		matchingEvidenceIds: matchingRecords.map(r => r.id),
	};
}

/**
 * Normalizes and validates target device constraints from input.
 * Rejects malformed values strictly: validates booleans with typeof, enforces bounds, never silently drops.
 */
export function normalizeTargetDeviceConstraints(input: unknown): TargetDeviceConstraints | undefined {
	if (input === undefined || input === null) return undefined;
	if (typeof input !== "object" || Array.isArray(input)) {
		throw new ToolError("Target device constraints must be an object.");
	}
	const obj = input as Record<string, unknown>;

	let targetEnvironment: string | undefined;
	if (obj.target_environment !== undefined && obj.target_environment !== null) {
		if (
			typeof obj.target_environment !== "string" ||
			!obj.target_environment.trim() ||
			obj.target_environment.length > MAX_ENVIRONMENT_LENGTH
		) {
			throw new ToolError(`target_environment must be a non-empty string <= ${MAX_ENVIRONMENT_LENGTH} characters.`);
		}
		targetEnvironment = obj.target_environment.trim();
	}

	let requiresStandalone = false;
	if (obj.requires_standalone !== undefined && obj.requires_standalone !== null) {
		if (typeof obj.requires_standalone !== "boolean") {
			throw new ToolError("requires_standalone must be a strict boolean (true or false).");
		}
		requiresStandalone = obj.requires_standalone;
	}

	let disallowed: string[] | undefined;
	if (obj.disallowed_dependencies !== undefined && obj.disallowed_dependencies !== null) {
		if (!Array.isArray(obj.disallowed_dependencies)) {
			throw new ToolError("disallowed_dependencies must be an array of strings.");
		}
		if (obj.disallowed_dependencies.length > MAX_ARRAY_ITEMS) {
			throw new ToolError(`disallowed_dependencies cannot exceed ${MAX_ARRAY_ITEMS} items.`);
		}
		disallowed = obj.disallowed_dependencies.map(d => {
			if (typeof d !== "string" || !d.trim() || d.trim().length > MAX_ID_LENGTH) {
				throw new ToolError("disallowed_dependencies contains an empty or invalid entry.");
			}
			return d.trim();
		});
	}

	let allowedModes: string[] | undefined;
	if (obj.allowed_delivery_modes !== undefined && obj.allowed_delivery_modes !== null) {
		if (!Array.isArray(obj.allowed_delivery_modes)) {
			throw new ToolError("allowed_delivery_modes must be an array of strings.");
		}
		if (obj.allowed_delivery_modes.length > MAX_ARRAY_ITEMS) {
			throw new ToolError(`allowed_delivery_modes cannot exceed ${MAX_ARRAY_ITEMS} items.`);
		}
		allowedModes = obj.allowed_delivery_modes.map(m => {
			if (typeof m !== "string" || !m.trim() || m.trim().length > MAX_ID_LENGTH) {
				throw new ToolError("allowed_delivery_modes contains an empty or invalid entry.");
			}
			return m.trim();
		});
	}

	let notes: string | undefined;
	if (obj.notes !== undefined && obj.notes !== null) {
		if (typeof obj.notes !== "string" || obj.notes.length > MAX_NOTES_LENGTH) {
			throw new ToolError(`notes must be a string <= ${MAX_NOTES_LENGTH} characters.`);
		}
		notes = obj.notes.trim();
	}

	return {
		target_environment: targetEnvironment,
		disallowed_dependencies: disallowed,
		allowed_delivery_modes: allowedModes,
		requires_standalone: requiresStandalone,
		notes,
	};
}

/**
 * Normalizes and validates workflow dependencies.
 * Rejects malformed values strictly: validates booleans with typeof, requires explicit scope, rejects duplicates.
 * On initial creation, approved_for_delivery=true is rejected (cannot bypass UI).
 */
export function normalizeWorkflowDependencies(
	input: unknown,
	options: { isInitialCreation?: boolean } = {},
): WorkflowDependencyRecord[] | undefined {
	if (input === undefined || input === null) return undefined;
	if (!Array.isArray(input)) {
		throw new ToolError("dependencies must be an array of dependency objects.");
	}
	if (input.length > MAX_ARRAY_ITEMS) {
		throw new ToolError(`dependencies cannot exceed ${MAX_ARRAY_ITEMS} items.`);
	}

	const seenIds = new Set<string>();

	return input.map(item => {
		if (!item || typeof item !== "object" || Array.isArray(item)) {
			throw new ToolError("Each dependency item must be an object.");
		}
		const obj = item as Record<string, unknown>;

		if (typeof obj.id !== "string" || !obj.id.trim() || obj.id.trim().length > MAX_ID_LENGTH) {
			throw new ToolError(`Dependency item requires a non-empty 'id' string <= ${MAX_ID_LENGTH} characters.`);
		}
		const id = obj.id.trim();

		if (seenIds.has(id)) {
			throw new ToolError(`Duplicate dependency ID: '${id}'. Each dependency ID must be unique.`);
		}
		seenIds.add(id);

		const name = typeof obj.name === "string" && obj.name.trim() ? obj.name.trim().slice(0, MAX_TITLE_LENGTH) : id;
		const kind =
			typeof obj.kind === "string" && obj.kind.trim() ? obj.kind.trim().slice(0, MAX_ID_LENGTH) : "runtime_library";

		// Strict scope enum validation: no silent fallback on typos
		if (obj.scope === undefined || obj.scope === null) {
			throw new ToolError(`Dependency '${id}' requires an explicit 'scope' ('experiment' or 'delivery').`);
		}
		const rawScope = String(obj.scope).trim();
		if (rawScope !== "experiment" && rawScope !== "delivery") {
			throw new ToolError(
				`Dependency '${id}' scope must be strictly 'experiment' or 'delivery'. Got: '${String(obj.scope)}'.`,
			);
		}
		const scope: "experiment" | "delivery" = rawScope;

		let approvedForExp = false;
		if (obj.approved_for_experiment !== undefined && obj.approved_for_experiment !== null) {
			if (typeof obj.approved_for_experiment !== "boolean") {
				throw new ToolError(`Dependency '${id}' approved_for_experiment must be a strict boolean.`);
			}
			approvedForExp = obj.approved_for_experiment;
		}

		let approvedForDel = false;
		if (options.isInitialCreation) {
			if (obj.approved_for_delivery === true) {
				throw new ToolError(
					`Dependency '${id}' cannot be created with approved_for_delivery=true. Delivery authorization requires explicit interactive user confirmation via 'approve_dependency'.`,
				);
			}
		} else if (obj.approved_for_delivery !== undefined && obj.approved_for_delivery !== null) {
			if (typeof obj.approved_for_delivery !== "boolean") {
				throw new ToolError(`Dependency '${id}' approved_for_delivery must be a strict boolean.`);
			}
			approvedForDel = obj.approved_for_delivery;
		}

		return {
			id,
			name,
			kind,
			scope,
			target_host:
				typeof obj.target_host === "string" && obj.target_host.trim()
					? obj.target_host.trim().slice(0, MAX_ID_LENGTH)
					: undefined,
			approved_for_experiment: approvedForExp,
			approved_for_delivery: approvedForDel,
			approval_notes:
				typeof obj.approval_notes === "string" ? obj.approval_notes.trim().slice(0, MAX_NOTES_LENGTH) : undefined,
			approved_at: typeof obj.approved_at === "string" ? obj.approved_at.trim() : undefined,
			decision_id: typeof obj.decision_id === "string" ? obj.decision_id.trim() : undefined,
		};
	});
}

/**
 * Validates deployment dependencies against target device constraints.
 * Ensures experimental dependencies or disallowed packages never leak into delivery builds.
 * Preserves lab experimental approval: standalone constraints apply ONLY when targetScope === 'delivery'.
 */
export function validateDeploymentConstraints(
	constraints: TargetDeviceConstraints | undefined,
	dependencies: WorkflowDependencyRecord[] | undefined,
	targetScope: "experiment" | "delivery" = "delivery",
	deliveryMode?: string,
): { valid: boolean; violation?: string; violationCode?: string } {
	const requiresStandalone = constraints?.requires_standalone === true;
	const isDelivery = targetScope === "delivery";

	// 0. Strict delivery mode validation:
	// When delivery modes are constrained on the target device, delivery builds MUST specify a valid allowed mode.
	if (isDelivery && constraints?.allowed_delivery_modes && constraints.allowed_delivery_modes.length > 0) {
		const allowedSet = new Set(constraints.allowed_delivery_modes.map(m => m.trim().toLowerCase()));
		const normalizedMode = (deliveryMode ?? "").trim().toLowerCase();
		if (!normalizedMode || !allowedSet.has(normalizedMode)) {
			return {
				valid: false,
				violationCode: "VIOLATION_UNALLOWED_DELIVERY_MODE",
				violation: `Delivery packaging mode '${deliveryMode ?? "unspecified"}' is not permitted for target environment '${constraints.target_environment ?? "target"}'. Allowed delivery modes: ${constraints.allowed_delivery_modes.join(", ")}.`,
			};
		}
	}

	if (!dependencies || dependencies.length === 0) {
		return { valid: true };
	}

	const disallowedSet = new Set((constraints?.disallowed_dependencies ?? []).map(d => d.trim().toLowerCase()));

	for (const dep of dependencies) {
		const depId = dep.id.trim().toLowerCase();
		const depName = dep.name.trim().toLowerCase();

		// 1. Experimental dependency in delivery build
		if (isDelivery && dep.scope === "experiment" && !dep.approved_for_delivery) {
			return {
				valid: false,
				violationCode: "VIOLATION_EXPERIMENTAL_DEPENDENCY_IN_DELIVERY",
				violation: `Experimental dependency '${dep.name}' (${dep.id}) is not approved for delivery build. Lab experimental approval does not imply delivery authorization.`,
			};
		}
		// 2. Disallowed dependencies for target environment in delivery build (exact match; delivery approval cannot override explicit target constraint)
		const isDisallowed = disallowedSet.has(depId) || disallowedSet.has(depName);
		if (isDelivery && isDisallowed) {
			return {
				valid: false,
				violationCode: "VIOLATION_DISALLOWED_DEPENDENCY",
				violation: `Dependency '${dep.name}' (${dep.id}) is explicitly disallowed for target environment '${constraints?.target_environment ?? "target"}'. Target device constraints must be explicitly revised to allow this dependency.`,
			};
		}

		// 3. Standalone constraint violations in delivery build:
		// An external runtime dependency or non-target host cannot be included in a standalone delivery build,
		// regardless of delivery approval (approval does not alter target standalone requirements).
		if (isDelivery && requiresStandalone) {
			const targetEnv = (constraints?.target_environment ?? "target_device").trim().toLowerCase();
			const depHost = (dep.target_host ?? "").trim().toLowerCase();
			const isNonTargetHost = depHost.length > 0 && depHost !== targetEnv && depHost !== "target_device";
			const isExternalService = dep.kind === "external_service";

			if (isNonTargetHost || isExternalService) {
				return {
					valid: false,
					violationCode: "VIOLATION_NON_STANDALONE_DEPENDENCY",
					violation: `Target environment requires standalone delivery. External runtime dependency '${dep.name}' (${dep.id}, kind: '${dep.kind}', host: '${dep.target_host ?? "external"}') cannot be included in delivery. Target device constraints must be explicitly revised to permit non-standalone external dependencies.`,
				};
			}
		}
	}

	return { valid: true };
}

/**
 * Cascades evidence refutations through a workflow.
 * Checks active supporting proof IDs (not superseded historical attempts) so re-verification with B
 * stably completes the step even if prior attempt A was refuted.
 * Reopens step or criterion to preserve honest status, recording a progression audit.
 * Does NOT delete or destroy historical records.
 */
export async function cascadeEvidenceRefutation(
	workflow: ReverseWorkflowRecord,
	evidenceStore: EvidenceStore,
): Promise<{ invalidatedSteps: string[]; invalidatedCriteria: string[]; invalidatedBuilds: string[] }> {
	const invalidatedSteps: string[] = [];
	const invalidatedCriteria: string[] = [];
	const invalidatedBuilds: string[] = [];
	const now = new Date().toISOString();

	// Check completed steps
	for (const step of workflow.steps) {
		if (step.status !== "completed") continue;

		// Track active proof IDs for this step, not all historical attempts
		const activeProofTable = workflow.metadata?.active_proof as Record<string, string[]> | undefined;
		const activeProofIds = activeProofTable?.[step.id];

		const stepCriteria = getWorkflowAcceptanceCriteria(workflow, step.id);
		const criteriaProofIds = stepCriteria.flatMap(c => c.satisfied_by_evidence_ids ?? []);

		const idsToCheck =
			activeProofIds && activeProofIds.length > 0
				? activeProofIds
				: criteriaProofIds.length > 0
					? criteriaProofIds
					: (step.evidence_ids ?? []);

		if (idsToCheck.length === 0) continue;

		const evalResult = await evaluateEvidenceSupport(evidenceStore, idsToCheck).catch(() => null);
		if (!evalResult) continue;

		if (evalResult.refutedIds.length > 0 || evalResult.staleIds.length > 0) {
			const badIds = [...evalResult.refutedIds, ...evalResult.staleIds];
			invalidatedSteps.push(step.id);

			step.status = "pending";
			step.progression_status = "held_pending_decision";
			step.decision = "invalidated_by_evidence";
			step.decision_reason = `Active supporting evidence was refuted or became stale: ${badIds.join(", ")}. Step reopened pending verification.`;
			step.updated_at = now;

			// Clear active proof for this step
			if (workflow.metadata && workflow.metadata.active_proof) {
				delete (workflow.metadata.active_proof as Record<string, string[]>)[step.id];
			}

			const audit: ProgressionAuditEntry = {
				step_id: step.id,
				step_title: step.title,
				tool: step.tool,
				gate: step.gate,
				action: "advance",
				status: "held_pending_decision",
				decision: step.decision,
				reason: step.decision_reason,
				is_low_risk: false,
				timestamp: now,
				params_summary: step.params_summary,
			};
			workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];
		}
	}

	// Check criteria in single metadata key
	const allCriteria = getWorkflowAcceptanceCriteria(workflow);
	for (const crit of allCriteria) {
		if (crit.status !== "satisfied") continue;
		if (!crit.satisfied_by_evidence_ids || crit.satisfied_by_evidence_ids.length === 0) continue;

		const evalResult = await evaluateEvidenceSupport(evidenceStore, crit.satisfied_by_evidence_ids).catch(() => null);
		if (!evalResult) continue;

		if (evalResult.refutedIds.length > 0 || evalResult.staleIds.length > 0) {
			invalidatedCriteria.push(crit.id);
			crit.status = "pending";
			crit.satisfied_by_evidence_ids = undefined;
			crit.updated_at = now;
			updateAcceptanceCriterion(workflow, crit);
		}
	}
	// Check build lineage runtime evidence
	if (workflow.build_lineage && workflow.build_lineage.length > 0) {
		for (const build of workflow.build_lineage) {
			if (build.verification_result.runtime_status !== "verified") continue;
			if (!build.runtime_evidence_ids || build.runtime_evidence_ids.length === 0) continue;

			const evalResult = await evaluateEvidenceSupport(evidenceStore, build.runtime_evidence_ids, {
				requiredTargetSha256: build.output_sha256,
			}).catch(() => null);
			if (!evalResult) continue;

			if (!evalResult.valid || evalResult.refutedIds.length > 0 || evalResult.staleIds.length > 0) {
				const badIds = [...evalResult.refutedIds, ...evalResult.staleIds];
				invalidatedBuilds.push(build.build_id);
				build.verification_result.runtime_status = "failed";
				build.verification_result.status = "failed";
				build.verification_result.failure_reason = `Runtime verification evidence was refuted or became stale: ${badIds.join(", ")}. Prior revision runtime evidence cannot be inherited.`;
				build.updated_at = now;
			}
		}
	}

	if (invalidatedSteps.length > 0) {
		if (workflow.status === "completed") {
			workflow.status = "active";
		}
		workflow.updated_at = now;
	}

	return { invalidatedSteps, invalidatedCriteria, invalidatedBuilds };
}
