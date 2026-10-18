function normalizedPrimaryLocation(finding) {
    const location = finding.occurrences.flatMap(occurrence => occurrence.locations)[0];
    if (!location)
        return undefined;
    return `${location.path.replaceAll("\\", "/").replace(/^\.\//, "").toLowerCase()}:${location.startLine}`;
}
function fallbackKey(finding) {
    const location = normalizedPrimaryLocation(finding);
    if (!location)
        return undefined;
    return `${finding.ruleId.trim().toLowerCase()}\u0000${location}`;
}
function normalizedPath(value) {
    return value.replaceAll("\\", "/").replace(/^\.\//, "").toLowerCase();
}
function findingLocations(finding) {
    return finding.occurrences.flatMap(occurrence => occurrence.locations);
}
function taxonomyLocationMatch(reference, candidate) {
    const referenceCwes = new Set(reference.taxonomy.cwe.map(value => value.trim().toUpperCase()));
    if (referenceCwes.size === 0 ||
        !candidate.taxonomy.cwe.some(value => referenceCwes.has(value.trim().toUpperCase()))) {
        return false;
    }
    for (const referenceLocation of findingLocations(reference)) {
        for (const candidateLocation of findingLocations(candidate)) {
            if (normalizedPath(referenceLocation.path) !== normalizedPath(candidateLocation.path))
                continue;
            const referenceEnd = referenceLocation.endLine ?? referenceLocation.startLine;
            const candidateEnd = candidateLocation.endLine ?? candidateLocation.startLine;
            if (Math.max(referenceLocation.startLine, candidateLocation.startLine) <=
                Math.min(referenceEnd, candidateEnd) ||
                Math.abs(referenceLocation.startLine - candidateLocation.startLine) <= 3) {
                return true;
            }
        }
    }
    return false;
}
function findingSummary(finding) {
    const location = finding.occurrences.flatMap(occurrence => occurrence.locations)[0];
    return {
        findingId: finding.id,
        ruleId: finding.ruleId,
        title: finding.title,
        severity: finding.severity.level,
        confidence: finding.confidence.level,
        validationStatus: finding.validation.status,
        dispositionStatus: finding.disposition.status,
        ...(location ? { primaryLocation: { path: location.path, startLine: location.startLine } } : {}),
    };
}
function scanSummary(bundle) {
    return {
        scanId: bundle.scan.id,
        producer: bundle.scan.producer,
        status: bundle.scan.status,
        findingCount: bundle.findings.length,
        actionableFindingCount: bundle.findings.filter(finding => finding.disposition.status === "open").length,
        validatedFindingCount: bundle.findings.filter(finding => finding.validation.status === "validated").length,
        rejectedFindingCount: bundle.findings.filter(finding => finding.validation.status === "rejected").length,
        coverage: bundle.scan.coverage,
        ...(bundle.scan.metrics ? { metrics: bundle.scan.metrics } : {}),
    };
}
function ratio(numerator, denominator) {
    return denominator === 0 ? (numerator === 0 ? 1 : 0) : numerator / denominator;
}
export function compareSecurityProducers(reference, candidate) {
    const candidateByFingerprint = new Map(candidate.findings.map(finding => [finding.fingerprint, finding]));
    const candidateByFallback = new Map();
    for (const finding of candidate.findings) {
        const key = fallbackKey(finding);
        if (!key)
            continue;
        const bucket = candidateByFallback.get(key) ?? [];
        bucket.push(finding);
        candidateByFallback.set(key, bucket);
    }
    const usedCandidateIds = new Set();
    const matchedReferenceIds = new Set();
    const matches = [];
    const addMatch = (referenceFinding, candidateFinding, basis) => {
        matchedReferenceIds.add(referenceFinding.id);
        usedCandidateIds.add(candidateFinding.id);
        matches.push({
            referenceFindingId: referenceFinding.id,
            candidateFindingId: candidateFinding.id,
            basis,
        });
    };
    for (const referenceFinding of reference.findings) {
        const exact = candidateByFingerprint.get(referenceFinding.fingerprint);
        if (exact && !usedCandidateIds.has(exact.id))
            addMatch(referenceFinding, exact, "fingerprint");
    }
    for (const referenceFinding of reference.findings) {
        if (matchedReferenceIds.has(referenceFinding.id))
            continue;
        const key = fallbackKey(referenceFinding);
        const fallback = key
            ? candidateByFallback.get(key)?.find(finding => !usedCandidateIds.has(finding.id))
            : undefined;
        if (fallback)
            addMatch(referenceFinding, fallback, "rule_location");
    }
    const unmatchedReferences = reference.findings.filter(finding => !matchedReferenceIds.has(finding.id));
    for (const referenceFinding of unmatchedReferences) {
        const compatibleCandidates = candidate.findings.filter(finding => !usedCandidateIds.has(finding.id) && taxonomyLocationMatch(referenceFinding, finding));
        if (compatibleCandidates.length !== 1)
            continue;
        const compatibleCandidate = compatibleCandidates[0];
        const compatibleReferences = unmatchedReferences.filter(finding => !matchedReferenceIds.has(finding.id) && taxonomyLocationMatch(finding, compatibleCandidate));
        if (compatibleReferences.length !== 1)
            continue;
        addMatch(referenceFinding, compatibleCandidate, "taxonomy_location");
    }
    const referenceOnlyFindingIds = reference.findings
        .filter(finding => !matchedReferenceIds.has(finding.id))
        .map(finding => finding.id);
    const candidateOnlyFindingIds = candidate.findings
        .filter(finding => !usedCandidateIds.has(finding.id))
        .map(finding => finding.id);
    const unionSize = reference.findings.length + candidate.findings.length - matches.length;
    return {
        referenceScanId: reference.scan.id,
        candidateScanId: candidate.scan.id,
        matches,
        referenceOnlyFindingIds,
        reference: scanSummary(reference),
        candidate: scanSummary(candidate),
        referenceOnlyFindings: referenceOnlyFindingIds.map(findingId => findingSummary(reference.findings.find(finding => finding.id === findingId))),
        candidateOnlyFindings: candidateOnlyFindingIds.map(findingId => findingSummary(candidate.findings.find(finding => finding.id === findingId))),
        candidateOnlyFindingIds,
        referenceFindingCount: reference.findings.length,
        candidateFindingCount: candidate.findings.length,
        matchedFindingCount: matches.length,
        recallAgainstReference: ratio(matches.length, reference.findings.length),
        precisionAgainstReference: ratio(matches.length, candidate.findings.length),
        jaccardOverlap: ratio(matches.length, unionSize),
    };
}
export function compareSecurityLineage(before, after) {
    // An incomplete after-scan proves nothing about unmatched earlier findings;
    // claiming them "resolved" against a cancelled/partial/failed run would be a lie.
    if (after.scan.status !== "completed") {
        throw new Error(`Security lineage comparison requires a completed after-scan; ${after.scan.id} is ${after.scan.status}`);
    }
    const differential = compareSecurityProducers(before, after);
    const beforeById = new Map(before.findings.map(finding => [finding.id, finding]));
    const afterById = new Map(after.findings.map(finding => [finding.id, finding]));
    const matches = differential.matches.map(match => {
        const beforeFinding = beforeById.get(match.referenceFindingId);
        const afterFinding = afterById.get(match.candidateFindingId);
        if (!beforeFinding || !afterFinding)
            throw new Error("Security comparison produced an invalid finding reference");
        return {
            beforeFindingId: beforeFinding.id,
            afterFindingId: afterFinding.id,
            fingerprint: beforeFinding.fingerprint,
            status: "unchanged",
            matchBasis: match.basis,
        };
    });
    for (const findingId of differential.referenceOnlyFindingIds) {
        const finding = beforeById.get(findingId);
        if (!finding)
            continue;
        matches.push({ beforeFindingId: finding.id, fingerprint: finding.fingerprint, status: "resolved" });
    }
    for (const findingId of differential.candidateOnlyFindingIds) {
        const finding = afterById.get(findingId);
        if (!finding)
            continue;
        matches.push({ afterFindingId: finding.id, fingerprint: finding.fingerprint, status: "new" });
    }
    matches.sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
    return {
        beforeScanId: before.scan.id,
        afterScanId: after.scan.id,
        matches,
        unchanged: matches.filter(match => match.status === "unchanged").length,
        introduced: matches.filter(match => match.status === "new").length,
        resolved: matches.filter(match => match.status === "resolved").length,
    };
}
