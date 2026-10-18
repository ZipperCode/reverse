/**
 * Shared output-schema validation for subagent yield + executor finalization.
 *
 * Both the in-process `yield` tool (subagent side) and the executor's post-mortem
 * finalize path (parent side) need to validate yield payloads against the agent's
 * declared output schema. This module is the single source of truth for that
 * pipeline — keeping the two callsites in lockstep so a schema accepted in-tool
 * cannot be rejected post-mortem (or vice versa).
 */
import { dereferenceJsonSchema, isValidJsonSchema, validateJsonSchemaValue, } from "@rva/ai/utils/schema";
import { isRecord } from "@rva/utils";
import { LRUCache } from "@rva/utils/lru";
import { jtdToJsonSchema, normalizeSchema } from "./jtd-to-json-schema";
/**
 * Builds keyed by the declaration's content (JSON strings verbatim, objects by
 * their serialization), so a reused schema object that was edited in place
 * gets a fresh validator.
 */
const schemaResults = new LRUCache({ max: 32 });
/**
 * Build the canonical validator for a JTD-or-JSON-Schema output declaration.
 *
 * Returns:
 * - `{ validator, jsonSchema, normalized }` for constraining schemas — both callers use this path.
 * - `{ normalized: true }` for an intentionally unconstrained schema (the JSON Schema literal `true`).
 *   No validator, but distinguishable from "no schema provided".
 * - `{}` for an absent schema (`undefined`).
 * - `{ error, normalized? }` when the schema cannot be honored (invalid syntax, `false`, malformed JTD).
 *
 * Results are memoized per schema content and shared across calls: the
 * validator holds no per-call state, and callers MUST NOT mutate the returned result.
 */
export function buildOutputValidator(schema) {
    let key;
    if (typeof schema === "string")
        key = `s${schema}`;
    else if (schema !== null && typeof schema === "object") {
        try {
            key = `o${JSON.stringify(schema)}`;
        }
        catch {
            // Unserializable (cyclic) declarations are rejected by the build itself.
        }
    }
    if (key === undefined)
        return buildOutputValidatorUncached(schema);
    let cached = schemaResults.get(key);
    if (!cached) {
        // Build from a private copy: the cached result must not alias an object the caller may edit later.
        cached = buildOutputValidatorUncached(typeof schema === "string" ? schema : JSON.parse(key.slice(1)));
        schemaResults.set(key, cached);
    }
    return cached;
}
function buildOutputValidatorUncached(schema) {
    const { normalized, error: normalizeError } = normalizeSchema(schema);
    if (normalizeError)
        return { error: normalizeError, normalized };
    if (normalized === undefined)
        return {};
    if (normalized === false)
        return { error: "boolean false schema rejects all outputs", normalized };
    if (normalized === true)
        return { normalized };
    const jsonSchema = jtdToJsonSchema(normalized);
    if (jsonSchema === undefined)
        return { normalized };
    if (jsonSchema === false)
        return { error: "boolean false schema rejects all outputs", normalized };
    if (jsonSchema === true)
        return { normalized };
    if (typeof jsonSchema !== "object" || Array.isArray(jsonSchema)) {
        return { error: "invalid JSON schema", normalized };
    }
    if (!isValidJsonSchema(jsonSchema))
        return { error: "invalid JSON schema", normalized };
    const jsonSchemaRecord = jsonSchema;
    // Resolve a root `$ref` (e.g. caller schemas exported as `{ $ref: "#/$defs/Closed", $defs: ... }`)
    // before deriving incremental-label metadata. AJV-style validation chases the ref at runtime, so
    // `validate()` accepts the resolved object — but `properties` and `additionalProperties` live on
    // the inlined node, not the wrapper. Without this, unknown labels slipped past the yield gate and
    // only fired as parent-side schema_violations.
    const dereferenced = dereferenceJsonSchema(jsonSchemaRecord);
    const labelSchema = dereferenced && typeof dereferenced === "object" && !Array.isArray(dereferenced)
        ? dereferenced
        : jsonSchemaRecord;
    const required = extractRequiredFields(labelSchema);
    const sectionLabels = buildSectionLabelMetadata(labelSchema);
    const sectionSchemas = buildSectionSchemas(labelSchema);
    const sectionValidators = new Map();
    for (const [label, sectionSchema] of sectionSchemas) {
        sectionValidators.set(label, value => validateJsonSchemaValue(sectionSchema, value));
    }
    return {
        normalized,
        jsonSchema: jsonSchemaRecord,
        validator: {
            requiredFields: required,
            validate: value => validateJsonSchemaValue(jsonSchemaRecord, value),
            normalize: value => normalizeStrictOutput(value, labelSchema),
            normalizeSection: (label, value) => normalizeStrictOutput(value, sectionSchemas.get(label)),
            validateSection: sectionValidators,
            rejectUnknownSections: sectionLabels.rejectUnknownSections,
            knownSectionLabels: sectionLabels.labels,
            isKnownSection: sectionLabels.isKnown,
        },
    };
}
/** Derive the schema for each incremental section, selecting array items when the section submits one element. */
function buildSectionSchemas(jsonSchema) {
    const schemas = new Map();
    const properties = jsonSchema.properties;
    if (!isRecord(properties))
        return schemas;
    for (const label in properties) {
        const raw = properties[label];
        const propRecord = isRecord(raw) ? raw : undefined;
        schemas.set(label, propRecord?.type === "array" && propRecord.items !== undefined && propRecord.items !== null
            ? propRecord.items
            : raw);
    }
    return schemas;
}
// Remove provider-injected nulls only when the declared property schema rejects null.
function normalizeStrictOutput(value, schema) {
    if (!isRecord(schema))
        return value;
    if (Array.isArray(schema.anyOf) && schema.anyOf.length === 2) {
        const [first, second] = schema.anyOf;
        if (isRecord(first) && first.type === "null")
            return normalizeStrictOutput(value, second);
        if (isRecord(second) && second.type === "null")
            return normalizeStrictOutput(value, first);
    }
    if (Array.isArray(schema.allOf)) {
        for (const branch of schema.allOf)
            value = normalizeStrictOutput(value, branch);
    }
    // For unions, accept a candidate only when it satisfies the entire original schema.
    for (const keyword of ["oneOf", "anyOf"]) {
        const branches = schema[keyword];
        if (!Array.isArray(branches))
            continue;
        if (validateJsonSchemaValue(schema, value).success)
            return value;
        for (const branch of branches) {
            const candidate = normalizeStrictOutput(value, branch);
            if (candidate !== value && validateJsonSchemaValue(schema, candidate).success)
                return candidate;
        }
    }
    const prefixItems = Array.isArray(schema.prefixItems) ? schema.prefixItems : undefined;
    if (Array.isArray(value) && (prefixItems !== undefined || schema.items !== undefined)) {
        let normalized;
        for (let index = 0; index < value.length; index++) {
            const itemSchema = prefixItems && index < prefixItems.length ? prefixItems[index] : schema.items;
            const item = normalizeStrictOutput(value[index], itemSchema);
            if (item === value[index])
                continue;
            normalized ??= value.slice();
            normalized[index] = item;
        }
        return normalized ?? value;
    }
    if (!isRecord(value) || !isRecord(schema.properties))
        return value;
    let normalized;
    for (const key in schema.properties) {
        if (!Object.hasOwn(value, key))
            continue;
        const propertySchema = schema.properties[key];
        if (value[key] === null &&
            !(Array.isArray(schema.required) && schema.required.includes(key)) &&
            !validateJsonSchemaValue(propertySchema, null).success) {
            normalized ??= { ...value };
            delete normalized[key];
            continue;
        }
        const property = normalizeStrictOutput(value[key], propertySchema);
        if (property === value[key])
            continue;
        normalized ??= { ...value };
        normalized[key] = property;
    }
    return normalized ?? value;
}
/**
 * Derive incremental-label metadata from top-level schema closure.
 *
 * The unknown-label gate (`rejectUnknownSections`) engages when the schema constrains top-level
 * property names anywhere: a closed conjunct (root or recursive `allOf` child with
 * `additionalProperties: false`) or a `oneOf`/`anyOf` union whose EVERY variant is closed. A label
 * is known iff every closed conjunct accepts it AND, per closed union, at least one variant
 * accepts it (union semantics are disjunctive — the assembled output only has to match one
 * variant). Unions containing any open variant never gate: the open variant accepts arbitrary
 * labels, so rejection would be a false positive.
 */
function buildSectionLabelMetadata(jsonSchema) {
    const closedConjuncts = collectClosedTopLevelSchemas(jsonSchema);
    const closedUnions = collectClosedTopLevelUnions(jsonSchema);
    const closed = closedConjuncts.length > 0 || closedUnions.length > 0;
    const acceptedByAll = (conjuncts, label) => conjuncts.every(schema => schemaAcceptsSectionLabel(schema, label));
    const labels = [
        ...new Set([
            ...closedConjuncts.flatMap(schema => declaredPropertyLabels(schema)),
            ...closedUnions.flatMap(variants => variants.flatMap(conjuncts => conjuncts.flatMap(schema => declaredPropertyLabels(schema)))),
        ]),
    ];
    return {
        labels,
        rejectUnknownSections: closed,
        isKnown: label => !closed ||
            (acceptedByAll(closedConjuncts, label) &&
                closedUnions.every(variants => variants.some(conjuncts => acceptedByAll(conjuncts, label)))),
    };
}
function collectClosedTopLevelSchemas(jsonSchema) {
    const schemas = [];
    if (jsonSchema.additionalProperties === false)
        schemas.push(jsonSchema);
    const allOf = jsonSchema.allOf;
    if (Array.isArray(allOf)) {
        for (const raw of allOf) {
            if (raw !== null && typeof raw === "object" && !Array.isArray(raw)) {
                schemas.push(...collectClosedTopLevelSchemas(raw));
            }
        }
    }
    return schemas;
}
/**
 * Collect top-level `oneOf`/`anyOf` unions in which EVERY variant is closed — i.e. each variant
 * (or one of its `allOf` conjuncts, resolved via `collectClosedTopLevelSchemas`) carries
 * `additionalProperties: false`. JTD discriminator output schemas compile to exactly this shape:
 * a root `oneOf` of closed object variants. Unions with any open (or non-object) variant are
 * skipped entirely so the unknown-label gate cannot fire false rejections. Unions nested under
 * `allOf` conjuncts gate identically (intersection semantics).
 */
function collectClosedTopLevelUnions(jsonSchema) {
    const unions = [];
    for (const key of ["oneOf", "anyOf"]) {
        const rawVariants = jsonSchema[key];
        if (!Array.isArray(rawVariants) || rawVariants.length === 0)
            continue;
        const variants = [];
        let allClosed = true;
        for (const raw of rawVariants) {
            const conjuncts = isRecord(raw) ? collectClosedTopLevelSchemas(raw) : [];
            if (conjuncts.length === 0) {
                allClosed = false;
                break;
            }
            variants.push(conjuncts);
        }
        if (allClosed)
            unions.push(variants);
    }
    const allOf = jsonSchema.allOf;
    if (Array.isArray(allOf)) {
        for (const raw of allOf) {
            if (isRecord(raw))
                unions.push(...collectClosedTopLevelUnions(raw));
        }
    }
    return unions;
}
function declaredPropertyLabels(jsonSchema) {
    const properties = jsonSchema.properties;
    if (properties === null || typeof properties !== "object" || Array.isArray(properties))
        return [];
    const labels = [];
    for (const label in properties)
        labels.push(label);
    return labels;
}
function schemaAcceptsSectionLabel(jsonSchema, label) {
    const properties = jsonSchema.properties;
    if (properties !== null && typeof properties === "object" && !Array.isArray(properties) && label in properties) {
        return true;
    }
    const patternProperties = jsonSchema.patternProperties;
    if (patternProperties !== null && typeof patternProperties === "object" && !Array.isArray(patternProperties)) {
        for (const pattern in patternProperties) {
            try {
                if (new RegExp(pattern).test(label))
                    return true;
            }
            catch {
                // `isValidJsonSchema` already rejected malformed regexes; ignore any unexpected runtime mismatch.
            }
        }
    }
    return jsonSchema.additionalProperties !== false;
}
/** Produce the executor's headline+missing-required summary from a failed validation. */
export function summarizeValidationFailure(result, value, requiredFields) {
    if (result.success)
        return { message: "", missingRequired: [] };
    const missing = computeMissingRequired(requiredFields, value);
    const message = formatValidationIssueHeadline(result.issues[0]) ?? "schema validation failed";
    return { message, missingRequired: missing };
}
export function extractRequiredFields(jsonSchema) {
    if (!jsonSchema || typeof jsonSchema !== "object")
        return [];
    const required = jsonSchema.required;
    return Array.isArray(required) ? required.filter((k) => typeof k === "string") : [];
}
export function computeMissingRequired(required, value) {
    if (required.length === 0)
        return [];
    if (value === null || value === undefined)
        return [...required];
    if (typeof value !== "object" || Array.isArray(value))
        return [];
    const record = value;
    return required.filter(key => !(key in record) || record[key] === undefined);
}
/**
 * Format a single validation issue as `path.with.dots: message`.
 *
 * Used by the executor's post-mortem `schema_violation` headline — one line, dot-separated path,
 * since the executor's error format already lists missing-required fields separately.
 */
export function formatValidationIssueHeadline(issue) {
    if (!issue)
        return undefined;
    const path = issue.path.length > 0 ? issue.path.map(String).join(".") : "(root)";
    return `${path}: ${issue.message}`;
}
/**
 * Format every validation issue as `path/with/slashes: message; ...`.
 *
 * Used by the yield tool's model-facing retry feedback — the model gets every problem at once so it
 * can fix the entire output in one retry instead of iterating issue-by-issue. The slash separator
 * mirrors JSON Pointer convention and disambiguates against fields whose names contain dots.
 */
export function formatAllValidationIssues(issues) {
    if (!issues || issues.length === 0)
        return "Unknown schema validation error.";
    return issues
        .map(issue => {
        const path = issue.path.length === 0 ? "" : `${issue.path.map(seg => String(seg)).join("/")}: `;
        return `${path}${issue.message}`;
    })
        .join("; ");
}
