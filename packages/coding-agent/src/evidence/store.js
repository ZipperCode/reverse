import * as fs from "node:fs/promises";
import * as path from "node:path";
import { getEvidenceProjectDir, isEnoent } from "@rva/utils";
import { withFileLock } from "@rva/utils/file-lock";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { replaceFileAtomically } from "../utils/atomic-file";
import { DEFAULT_LIST_LIMIT, MAX_EXCERPT_LENGTH, MAX_FIELD_LENGTH, MAX_LIST_LIMIT, MAX_LOCATOR_LENGTH, MAX_NOTES_LENGTH, MAX_SOURCE_TOOL_LENGTH, MAX_TAGS_COUNT, MAX_TAG_LENGTH, MAX_TARGET_LENGTH, MAX_TITLE_LENGTH, createEvidenceId, encodeEvidenceProjectKey, redactEvidenceText, } from "./contracts";
const PRIVATE_DIR_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
/** In-process write serializer per project directory */
const EVIDENCE_STORE_WRITE_CHAINS = new Map();
async function withEvidenceStoreWrite(projectDirectory, lockTarget, operation) {
    await fs.mkdir(projectDirectory, { recursive: true, mode: PRIVATE_DIR_MODE });
    if (process.platform !== "win32") {
        await fs.chmod(projectDirectory, PRIVATE_DIR_MODE).catch(() => undefined);
    }
    const run = (EVIDENCE_STORE_WRITE_CHAINS.get(projectDirectory) ?? Promise.resolve()).then(() => withFileLock(lockTarget, operation, { retries: 200, retryDelayMs: 50 }));
    const guarded = run.catch(() => undefined);
    EVIDENCE_STORE_WRITE_CHAINS.set(projectDirectory, guarded);
    try {
        return await run;
    }
    finally {
        if (EVIDENCE_STORE_WRITE_CHAINS.get(projectDirectory) === guarded) {
            EVIDENCE_STORE_WRITE_CHAINS.delete(projectDirectory);
        }
    }
}
export class EvidenceStore {
    repositoryRoot;
    projectKey;
    projectDirectory;
    ledgerPath;
    lockPath;
    constructor(options) {
        this.repositoryRoot = path.resolve(options.repositoryRoot);
        this.projectKey = encodeEvidenceProjectKey(this.repositoryRoot);
        this.projectDirectory = options.stateRoot
            ? path.join(path.resolve(options.stateRoot), this.projectKey)
            : getEvidenceProjectDir(this.projectKey);
        this.ledgerPath = path.join(this.projectDirectory, "ledger.jsonl");
        this.lockPath = path.join(this.projectDirectory, "ledger.lock");
    }
    static forSession(cwd, stateRoot) {
        return new EvidenceStore({ repositoryRoot: cwd, stateRoot });
    }
    async ensureDirectory() {
        await fs.mkdir(this.projectDirectory, { recursive: true, mode: PRIVATE_DIR_MODE });
        if (process.platform !== "win32") {
            await fs.chmod(this.projectDirectory, PRIVATE_DIR_MODE).catch(() => undefined);
        }
    }
    async readAllRecordsUnlocked() {
        try {
            const content = await fs.readFile(this.ledgerPath, "utf-8");
            const lines = content.split("\n");
            const records = [];
            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed)
                    continue;
                try {
                    const parsed = JSON.parse(trimmed);
                    if (parsed && typeof parsed.id === "string" && typeof parsed.kind === "string") {
                        records.push(parsed);
                    }
                }
                catch {
                    // Ignore corrupted or partial lines in append-only history
                }
            }
            return records;
        }
        catch (error) {
            if (isEnoent(error))
                return [];
            throw error;
        }
    }
    linkHypotheses(records) {
        const verifiedMap = new Map();
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
    async resolveTargetFile(targetPath) {
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
        }
        catch {
            return { absolutePath: resolved, exists: false };
        }
    }
    validateStringField(name, value, maxLen, required = true) {
        const trimmed = value?.trim() ?? "";
        if (required && trimmed.length === 0) {
            throw new ToolError(`Field '${name}' is required and cannot be empty`);
        }
        if (trimmed.length > maxLen) {
            throw new ToolError(`Field '${name}' length (${trimmed.length}) exceeds maximum limit of ${maxLen} characters`);
        }
        return trimmed;
    }
    validateOptionalString(name, value, maxLen) {
        if (value === undefined || value === null)
            return undefined;
        const trimmed = value.trim();
        if (trimmed.length === 0)
            return undefined;
        if (trimmed.length > maxLen) {
            throw new ToolError(`Field '${name}' length (${trimmed.length}) exceeds maximum limit of ${maxLen} characters`);
        }
        return trimmed;
    }
    sanitizeTags(tags) {
        if (!tags || !Array.isArray(tags))
            return undefined;
        const sanitized = [];
        for (const tag of tags.slice(0, MAX_TAGS_COUNT)) {
            if (typeof tag !== "string")
                continue;
            const trimmed = tag.trim().slice(0, MAX_TAG_LENGTH);
            if (trimmed.length > 0 && !sanitized.includes(trimmed)) {
                sanitized.push(trimmed);
            }
        }
        return sanitized.length > 0 ? sanitized : undefined;
    }
    async addFact(input) {
        const sourceTool = this.validateStringField("sourceTool", input.sourceTool, MAX_SOURCE_TOOL_LENGTH);
        const locator = this.validateStringField("locator", input.locator, MAX_LOCATOR_LENGTH);
        const content = this.validateStringField("content", input.content, MAX_FIELD_LENGTH);
        const target = this.validateOptionalString("target", input.target, MAX_TARGET_LENGTH);
        const excerpt = this.validateOptionalString("excerpt", input.excerpt, MAX_EXCERPT_LENGTH);
        const title = this.validateOptionalString("title", input.title, MAX_TITLE_LENGTH) ?? `[Fact] ${sourceTool} @ ${locator}`;
        const classification = this.validateOptionalString("classification", input.classification, 128);
        const tags = this.sanitizeTags(input.tags);
        let targetSha256;
        if (target) {
            const targetInfo = await this.resolveTargetFile(target);
            if (targetInfo.exists && targetInfo.sha256) {
                targetSha256 = targetInfo.sha256;
            }
        }
        let excerptHash;
        if (excerpt) {
            excerptHash = Bun.SHA256.hash(excerpt, "hex");
        }
        const fact = {
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
        };
        await this.appendRecord(fact);
        return fact;
    }
    async addHypothesis(input) {
        const claim = this.validateStringField("claim", input.claim, MAX_FIELD_LENGTH);
        const verificationPlan = this.validateStringField("verificationPlan", input.verificationPlan, MAX_FIELD_LENGTH);
        const target = this.validateOptionalString("target", input.target, MAX_TARGET_LENGTH);
        const content = this.validateOptionalString("content", input.content, MAX_FIELD_LENGTH);
        const title = this.validateOptionalString("title", input.title, MAX_TITLE_LENGTH) ?? `[Hypothesis] ${claim.slice(0, 60)}`;
        const classification = this.validateOptionalString("classification", input.classification, 128);
        const tags = this.sanitizeTags(input.tags);
        let targetSha256;
        if (target) {
            const targetInfo = await this.resolveTargetFile(target);
            if (targetInfo.exists && targetInfo.sha256) {
                targetSha256 = targetInfo.sha256;
            }
        }
        const validFacts = Array.isArray(input.facts)
            ? input.facts.filter(f => typeof f === "string" && f.trim().length > 0).map(f => f.trim())
            : undefined;
        const hypothesis = {
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
        };
        await this.appendRecord(hypothesis);
        return hypothesis;
    }
    async addUnknown(input) {
        const question = this.validateStringField("question", input.question, MAX_FIELD_LENGTH);
        const notes = this.validateOptionalString("notes", input.notes, MAX_NOTES_LENGTH);
        const content = this.validateOptionalString("content", input.content, MAX_FIELD_LENGTH);
        const target = this.validateOptionalString("target", input.target, MAX_TARGET_LENGTH);
        const title = this.validateOptionalString("title", input.title, MAX_TITLE_LENGTH) ?? `[Unknown] ${question.slice(0, 60)}`;
        const classification = this.validateOptionalString("classification", input.classification, 128);
        const tags = this.sanitizeTags(input.tags);
        let targetSha256;
        if (target) {
            const targetInfo = await this.resolveTargetFile(target);
            if (targetInfo.exists && targetInfo.sha256) {
                targetSha256 = targetInfo.sha256;
            }
        }
        const unknownRecord = {
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
        };
        await this.appendRecord(unknownRecord);
        return unknownRecord;
    }
    async verifyHypothesis(input) {
        const hypothesisId = this.validateStringField("hypothesisId", input.hypothesisId, 128);
        const method = this.validateStringField("method", input.method, MAX_FIELD_LENGTH);
        const command = this.validateStringField("command", input.command, MAX_FIELD_LENGTH);
        const result = this.validateStringField("result", input.result, MAX_FIELD_LENGTH);
        const conclusionText = this.validateStringField("conclusion", input.conclusion, MAX_FIELD_LENGTH);
        const reproducibility = this.validateOptionalString("reproducibility", input.reproducibility, 256) ?? "100%";
        const status = input.status === "refuted" ? "refuted" : "verified";
        return await withEvidenceStoreWrite(this.projectDirectory, this.lockPath, async () => {
            await this.ensureDirectory();
            const existingRecords = await this.readAllRecordsUnlocked();
            const hypothesis = existingRecords.find(r => r.id === hypothesisId);
            if (!hypothesis) {
                throw new ToolError(`Hypothesis '${hypothesisId}' not found in evidence ledger`);
            }
            if (hypothesis.kind !== "hypothesis") {
                throw new ToolError(`Target evidence '${hypothesisId}' is of kind '${hypothesis.kind}', not 'hypothesis'. Only hypotheses can be verified.`);
            }
            const title = this.validateOptionalString("title", input.title, MAX_TITLE_LENGTH) ??
                `[Conclusion] ${conclusionText.slice(0, 60)}`;
            const conclusion = {
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
                ...(hypothesis.target ? { target: hypothesis.target } : {}),
                ...(hypothesis.targetSha256 ? { targetSha256: hypothesis.targetSha256 } : {}),
                ...(hypothesis.classification ? { classification: hypothesis.classification } : {}),
                ...(hypothesis.tags ? { tags: hypothesis.tags } : {}),
            };
            const updated = [...existingRecords, conclusion];
            const jsonlContent = updated.map(r => JSON.stringify(r)).join("\n") + "\n";
            const tempFile = `${this.ledgerPath}.${process.pid}.${Bun.randomUUIDv7()}.tmp`;
            await fs.writeFile(tempFile, jsonlContent, { encoding: "utf-8", mode: PRIVATE_FILE_MODE });
            await replaceFileAtomically(tempFile, this.ledgerPath);
            return conclusion;
        });
    }
    async appendRecord(record) {
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
    async getRecord(id) {
        const records = await this.readAllRecordsUnlocked();
        const linked = this.linkHypotheses(records);
        return linked.find(r => r.id === id) ?? null;
    }
    async listRecords(filter = {}) {
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
                }
                else if (r.kind === "hypothesis") {
                    contentMatch = r.claim.toLowerCase().includes(q) || r.verificationPlan.toLowerCase().includes(q);
                }
                else if (r.kind === "unknown") {
                    contentMatch = r.question.toLowerCase().includes(q) || (r.notes?.toLowerCase().includes(q) ?? false);
                }
                else if (r.kind === "conclusion") {
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
    async checkDrift(record) {
        const warnings = [];
        const status = {
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
            warnings.push(`Target file '${record.target}' has changed since evidence was recorded (original SHA-256: ${record.targetSha256}, current SHA-256: ${targetInfo.sha256}).`);
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
                        warnings.push(`Excerpt text is no longer found in '${record.target}'. Target content may have drifted or been refactored.`);
                    }
                }
            }
            catch {
                // Non-text file or unreadable as text
            }
        }
        return status;
    }
}
