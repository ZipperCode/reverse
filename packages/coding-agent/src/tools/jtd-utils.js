/**
 * JSON Type Definition (JTD) utility types and guards.
 *
 * Shared type definitions and type guard functions for JTD schema validation.
 *
 * @see https://jsontypedef.com/
 * @see https://datatracker.ietf.org/doc/html/rfc8927
 */
// Type guards
export function isJTDType(schema) {
    return typeof schema === "object" && schema !== null && "type" in schema;
}
export function isJTDEnum(schema) {
    return typeof schema === "object" && schema !== null && "enum" in schema && Array.isArray(schema.enum);
}
export function isJTDElements(schema) {
    return typeof schema === "object" && schema !== null && "elements" in schema;
}
export function isJTDValues(schema) {
    return typeof schema === "object" && schema !== null && "values" in schema;
}
export function isJTDProperties(schema) {
    return typeof schema === "object" && schema !== null && ("properties" in schema || "optionalProperties" in schema);
}
export function isJTDDiscriminator(schema) {
    return (typeof schema === "object" &&
        schema !== null &&
        "discriminator" in schema &&
        "mapping" in schema &&
        typeof schema.discriminator === "string" &&
        typeof schema.mapping === "object" &&
        schema.mapping !== null &&
        !Array.isArray(schema.mapping));
}
export function isJTDRef(schema) {
    return typeof schema === "object" && schema !== null && "ref" in schema;
}
