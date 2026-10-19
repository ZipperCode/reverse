import { schemaDefinesProperty } from "@reverse/ai/utils/schema";
import { INTENT_FIELD } from "@reverse/wire";

/** Whether a wire schema owns `i` as a tool parameter rather than harness intent. */
export function schemaDeclaresIntentField(schema: unknown): boolean {
	return schemaDefinesProperty(schema, INTENT_FIELD);
}
