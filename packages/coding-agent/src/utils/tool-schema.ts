import { schemaDefinesProperty } from "@rva/ai/utils/schema";
import { INTENT_FIELD } from "@rva/wire";

/** Whether a wire schema owns `i` as a tool parameter rather than harness intent. */
export function schemaDeclaresIntentField(schema: unknown): boolean {
	return schemaDefinesProperty(schema, INTENT_FIELD);
}
