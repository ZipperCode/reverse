import { type } from "@rva/omptype";
export const replaceEditSchema = type({
    path: "string",
    old_string: "string",
    new_string: "string",
    "replace_all?": "boolean",
});
export const patchEditEntrySchema = type({
    "op?": "'create' | 'delete' | 'update'",
    "rename?": "string",
    "diff?": "string",
});
export const patchEditSchema = type({
    path: "string",
    edits: patchEditEntrySchema.array(),
});
export const applyPatchSchema = type({
    input: "string",
});
export const hashlineEditParamsSchema = type({
    input: "string",
});
export const sloppyEditSchema = type({
    input: "string",
});
