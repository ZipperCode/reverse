import { type } from "@rva/omptype";
import { TOOL_TIMEOUTS } from "../tools/tool-timeouts";
// =============================================================================
// Tool Schema
// =============================================================================
export const lspSchema = type({
    action: "'diagnostics' | 'definition' | 'references' | 'hover' | 'symbols' | 'rename' | 'rename_file' | 'code_actions' | 'type_definition' | 'implementation' | 'status' | 'reload' | 'capabilities' | 'request'",
    file: "string?",
    line: "number?",
    symbol: "string?",
    query: "string?",
    new_name: "string?",
    apply: "boolean?",
    "timeout?": type.number
        .atLeast(TOOL_TIMEOUTS.lsp.min)
        .atMost(TOOL_TIMEOUTS.lsp.max)
        .describe("Timeout in seconds; raises or lowers the default (range 5–300)."),
    payload: "string?",
});
export const SYMBOL_KIND_NAMES = {
    1: "File",
    2: "Module",
    3: "Namespace",
    4: "Package",
    5: "Class",
    6: "Method",
    7: "Property",
    8: "Field",
    9: "Constructor",
    10: "Enum",
    11: "Interface",
    12: "Function",
    13: "Variable",
    14: "Constant",
    15: "String",
    16: "Number",
    17: "Boolean",
    18: "Array",
    19: "Object",
    20: "Key",
    21: "Null",
    22: "EnumMember",
    23: "Struct",
    24: "Event",
    25: "Operator",
    26: "TypeParameter",
};
