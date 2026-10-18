import * as fs from "node:fs/promises";
import * as path from "node:path";
import { createSecurityEvidenceId, createSecurityFindingFingerprint, createSecurityFindingId, createSecurityOccurrenceId, createSecurityScanId, encodeSecurityProjectKey, parseSecurityScanBundle, } from "../contracts";
async function readJson(filePath) {
    return JSON.parse(await Bun.file(filePath).text());
}
function stringArray(value) {
    return Array.isArray(value) ? value.filter((item) => typeof item === "string") : [];
}
function importedLocationPath(value) {
    const normalized = value.replaceAll("\\", "/").replace(/^\.\//, "");
    if (!normalized ||
        normalized.startsWith("/") ||
        /^[a-zA-Z]:\//.test(normalized) ||
        normalized.split("/").includes("..")) {
        throw new Error(`Codex Security bundle locations must be repository-relative: ${value}`);
    }
    return normalized;
}
function locationsForFinding(finding) {
    const locations = [];
    for (const location of finding.locations ?? []) {
        if (typeof location.path !== "string" || typeof location.startLine !== "number")
            continue;
        const normalized = {
            path: importedLocationPath(location.path),
            startLine: location.startLine,
        };
        if (location.endLine !== undefined)
            normalized.endLine = location.endLine;
        if (location.role !== undefined)
            normalized.role = location.role;
        locations.push(normalized);
    }
    return locations.length > 0 ? locations : [{ path: "unknown", startLine: 1, role: "unknown" }];
}
const canonicalValidationStatuses = {
    unvalidated: true,
    validated: true,
    rejected: true,
    partial: true,
    error: true,
};
function validationStatus(validation) {
    const status = validation?.status;
    return typeof status === "string" && canonicalValidationStatuses[status] === true
        ? status
        : "unvalidated";
}
function mapCoverage(document) {
    const allowedModes = new Set(["repository", "scoped_path", "diff", "working_tree", "deep_repository"]);
    const mode = allowedModes.has(document.mode ?? "")
        ? document.mode
        : document.mode === "commit" || document.mode === "branch_diff"
            ? "diff"
            : "imported";
    const completeness = ["complete", "partial", "unknown"].includes(document.completeness ?? "")
        ? document.completeness
        : "unknown";
    const inventoryStrategy = ["repository", "scoped_path", "diff", "directory", "custom"].includes(document.inventoryStrategy ?? "")
        ? document.inventoryStrategy
        : "imported";
    const coverage = {
        mode,
        completeness,
        inventoryStrategy,
        includePaths: stringArray(document.includePaths),
        excludePaths: stringArray(document.excludePaths),
        surfaces: Array.isArray(document.surfaces) ? document.surfaces : [],
        explicitExclusions: Array.isArray(document.explicitExclusions)
            ? document.explicitExclusions
            : [],
        deferred: Array.isArray(document.deferred) ? document.deferred : [],
    };
    if (Array.isArray(document.openQuestions)) {
        coverage.openQuestions = document.openQuestions;
    }
    return coverage;
}
export async function importCodexSecurityBundle(bundleDirectory, options) {
    const root = path.resolve(bundleDirectory);
    const manifest = await readJson(path.join(root, "scan-manifest.json"));
    const findingsDocument = await readJson(path.join(root, "findings.json"));
    const coverageDocument = await readJson(path.join(root, "coverage.json"));
    if (manifest.documentType !== "codex-security.scan-manifest" || manifest.schemaVersion !== "1.0") {
        throw new Error("Unsupported Codex Security scan manifest");
    }
    if (findingsDocument.documentType !== "codex-security.findings" || findingsDocument.schemaVersion !== "1.0") {
        throw new Error("Unsupported Codex Security findings document");
    }
    if (coverageDocument.documentType !== "codex-security.coverage" || coverageDocument.schemaVersion !== "1.0") {
        throw new Error("Unsupported Codex Security coverage document");
    }
    if (!manifest.scan?.id ||
        findingsDocument.scanId !== manifest.scan.id ||
        coverageDocument.scanId !== manifest.scan.id) {
        throw new Error("Codex Security bundle scan IDs do not agree");
    }
    const fixtureProvenance = await readJson(path.join(root, "PROVENANCE.json")).catch(() => ({}));
    const scanId = options.createScanId?.() ?? createSecurityScanId();
    const createdAt = options.createdAt ?? manifest.scan.startedAt ?? new Date().toISOString();
    const canonicalRoot = await fs.realpath(path.resolve(options.repositoryRoot));
    const producer = {
        kind: "codex-security-bundle",
        name: manifest.scan.producer?.name || "codex-security",
        vendor: "openai",
    };
    if (manifest.scan.producer?.version !== undefined)
        producer.version = manifest.scan.producer.version;
    if (fixtureProvenance.revision !== undefined)
        producer.revision = fixtureProvenance.revision;
    if (fixtureProvenance.pluginVersion !== undefined)
        producer.pluginVersion = fixtureProvenance.pluginVersion;
    const upstream = {};
    if (fixtureProvenance.repository !== undefined)
        upstream.repository = fixtureProvenance.repository;
    if (fixtureProvenance.revision !== undefined)
        upstream.revision = fixtureProvenance.revision;
    if (fixtureProvenance.packageVersion !== undefined)
        upstream.packageVersion = fixtureProvenance.packageVersion;
    if (fixtureProvenance.pluginVersion !== undefined)
        upstream.pluginVersion = fixtureProvenance.pluginVersion;
    if (fixtureProvenance.archiveSha256 !== undefined)
        upstream.archiveSha256 = fixtureProvenance.archiveSha256;
    const findings = [];
    for (const source of findingsDocument.findings ?? []) {
        const ruleId = source.ruleId || "codex-security.unknown";
        const category = source.taxonomy?.category || ruleId.split(/[./-]/)[0] || "security";
        const hasSourceLocations = (source.locations ?? []).some(location => typeof location.path === "string" && typeof location.startLine === "number");
        const locations = locationsForFinding(source);
        const anchor = source.identity?.anchor ||
            source.fingerprints?.primary ||
            (!hasSourceLocations ? source.findingId : undefined);
        const fingerprint = createSecurityFindingFingerprint({
            ruleId,
            category,
            anchor,
            locations,
        });
        const evidence = (source.codeEvidence ?? []).map((item, index) => {
            const entry = {
                id: createSecurityEvidenceId(fingerprint, item.label || item.id || "code evidence", index),
                kind: "code",
                label: item.label || item.id || `Evidence ${index + 1}`,
                explanation: item.explanation || "",
            };
            if (typeof item.path === "string" && typeof item.startLine === "number") {
                const location = { path: importedLocationPath(item.path), startLine: item.startLine };
                if (item.endLine !== undefined)
                    location.endLine = item.endLine;
                if (item.role !== undefined)
                    location.role = item.role;
                entry.location = location;
            }
            if (item.code !== undefined)
                entry.excerpt = item.code;
            return entry;
        });
        const provenance = {
            producer,
            createdAt,
            importedAt: new Date().toISOString(),
            sourceIds: {
                scanId: manifest.scan.id,
                ...(source.findingId ? { findingId: source.findingId } : {}),
                ...(source.occurrenceId ? { occurrenceId: source.occurrenceId } : {}),
            },
            upstream,
        };
        if (source.fingerprints?.primary) {
            provenance.vendorFingerprints = {
                [source.fingerprints.algorithm || "codex-security/v1"]: source.fingerprints.primary,
            };
        }
        if (source.provenance !== undefined)
            provenance.metadata = source.provenance;
        const finding = {
            id: createSecurityFindingId(fingerprint),
            scanId,
            fingerprint,
            ruleId,
            title: source.title || ruleId,
            summary: source.summary || "",
            severity: {
                level: ["critical", "high", "medium", "low", "informational"].includes(source.severity?.level ?? "")
                    ? source.severity?.level
                    : "informational",
            },
            confidence: {
                level: ["high", "medium", "low"].includes(source.confidence?.level ?? "")
                    ? source.confidence?.level
                    : "medium",
            },
            taxonomy: { category, cwe: stringArray(source.taxonomy?.cwe) },
            occurrences: [
                {
                    id: createSecurityOccurrenceId(fingerprint, locations),
                    locations,
                    evidenceIds: evidence.map(item => item.id),
                },
            ],
            evidence,
            validation: {
                status: validationStatus(source.validation),
                evidenceIds: [],
            },
            disposition: { status: "open" },
            provenance,
        };
        if (anchor !== undefined)
            finding.anchor = anchor;
        if (source.severity?.score !== undefined)
            finding.severity.score = source.severity.score;
        if (source.severity?.scoringSystem !== undefined)
            finding.severity.scoringSystem = source.severity.scoringSystem;
        if (source.severity?.vector !== undefined)
            finding.severity.vector = source.severity.vector;
        if (source.severity?.rationale !== undefined)
            finding.severity.rationale = source.severity.rationale;
        if (source.confidence?.rationale !== undefined)
            finding.confidence.rationale = source.confidence.rationale;
        if (source.remediation !== undefined)
            finding.remediation = source.remediation;
        if (source.validation)
            finding.validation.summary = JSON.stringify(source.validation);
        if (source.extensions !== undefined)
            finding.extensions = source.extensions;
        findings.push(finding);
    }
    const target = manifest.scan.target ?? {};
    const sourceKind = String(target.kind ?? "");
    const targetKind = sourceKind === "git_diff" ? "ref_diff" : sourceKind === "git_worktree" ? "working_tree" : "imported";
    const reportPath = path.join(root, "report.md");
    const sarifPath = path.join(root, "exports", "results.sarif");
    const report = await Bun.file(reportPath)
        .text()
        .catch(() => undefined);
    const sarifText = await Bun.file(sarifPath)
        .text()
        .catch(() => undefined);
    const scanProvenance = {
        producer,
        createdAt,
        importedAt: new Date().toISOString(),
        sourceIds: { scanId: manifest.scan.id },
        upstream,
        metadata: { bundleDirectory: root },
    };
    const canonicalTarget = {
        kind: targetKind,
        repositoryRoot: canonicalRoot,
        displayName: String(target.displayName ?? path.basename(canonicalRoot)),
        includePaths: stringArray(manifest.scan.scope?.includePaths),
        excludePaths: stringArray(manifest.scan.scope?.excludePaths),
        treeDigest: typeof target.snapshotDigest === "string"
            ? target.snapshotDigest
            : Bun.SHA256.hash(JSON.stringify({ manifest, findingsDocument, coverageDocument }), "hex"),
    };
    if (typeof target.revision === "string")
        canonicalTarget.revision = target.revision;
    if (typeof target.baseRevision === "string")
        canonicalTarget.baseRevision = target.baseRevision;
    if (typeof target.headRevision === "string")
        canonicalTarget.headRevision = target.headRevision;
    const scan = {
        documentType: "omp-security.scan",
        schemaVersion: "1.0",
        id: scanId,
        projectKey: encodeSecurityProjectKey(canonicalRoot),
        status: "completed",
        createdAt,
        completedAt: manifest.scan.completedAt ?? createdAt,
        target: canonicalTarget,
        producer,
        provenance: scanProvenance,
        findingIds: findings.map(finding => finding.id),
        coverage: mapCoverage(coverageDocument),
    };
    if (manifest.scan.startedAt !== undefined)
        scan.startedAt = manifest.scan.startedAt;
    if (scan.startedAt !== undefined) {
        const runtimeMs = new Date(scan.completedAt ?? createdAt).getTime() - new Date(scan.startedAt).getTime();
        if (Number.isFinite(runtimeMs) && runtimeMs >= 0)
            scan.metrics = { runtimeMs };
    }
    if (report !== undefined)
        scan.reportRef = "report.md";
    if (sarifText !== undefined)
        scan.sarifRef = "results.sarif";
    const bundle = { scan, findings };
    if (report !== undefined)
        bundle.report = report;
    if (sarifText !== undefined)
        bundle.sarif = JSON.parse(sarifText);
    return parseSecurityScanBundle(bundle);
}
