/** Build the per-batch output schema used to assemble one yield per item. */
export function buildWorkPoolOutputSchema(items) {
    return {
        type: "object",
        properties: Object.fromEntries(items.map(item => [item.id, {}])),
        required: items.map(item => item.id),
        additionalProperties: false,
    };
}
