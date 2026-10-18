import { ToolError } from "@rva/tui/tools/tool-errors";
/** Normalize explicit distribution requirements without accepting package-manager flags. */
export function normalizePackageRequirements(requirements) {
    const normalized = new Set();
    for (const requirement of requirements) {
        if (typeof requirement !== "string") {
            throw new ToolError("Eval packages must be distribution requirement strings.");
        }
        const value = requirement.trim();
        if (!value || value.startsWith("-") || /[\r\n\0]/.test(value)) {
            throw new ToolError("Eval packages must be nonempty distribution requirements, not installer flags or control characters.");
        }
        normalized.add(value);
    }
    return [...normalized];
}
