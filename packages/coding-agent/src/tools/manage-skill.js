import * as path from "node:path";
import { type } from "@rva/omptype";
import { deleteManagedSkill, getManagedSkillsDir, sanitizeSkillName, writeManagedSkill, } from "../autolearn/managed-skills";
import { isNameClaimedByAuthoredSkill } from "../extensibility/skills";
import manageSkillDescription from "../prompts/tools/manage-skill.md" with { type: "text" };
import { cfgAutolearnEnabled } from "../autolearn/settings";
const manageSkillSchema = type({
    action: "'create' | 'update' | 'delete'",
    name: type("string").describe("kebab-case skill name"),
    "description?": type("string").describe("one-line description of when to use the skill (required for create/update)"),
    "body?": type("string").describe("the SKILL.md body in markdown, no frontmatter (required for create/update)"),
}).narrow((p, ctx) => p.action === "delete" ||
    (p.description !== undefined && p.body !== undefined) ||
    // Enforce the action/field contract at validation time rather than only in
    // execute. Kept as a cross-field narrow (not a discriminated union) so the
    // wire schema stays a single root object — strict structured-output mode and
    // the Anthropic tool-schema builder both require that.
    ctx.mustBe('used with both "description" and "body" for "create" and "update"'));
/**
 * Direct create/update/delete of isolated managed skills. Gated behind
 * `autolearn.enabled`; backend-independent (the skill side is standalone).
 */
export class ManageSkillTool {
    refreshSkills;
    name = "manage_skill";
    approval = "write";
    label = "Manage Skill";
    description = manageSkillDescription;
    parameters = manageSkillSchema;
    strict = true;
    loadMode = "essential";
    summary = "Create, update, or delete an isolated managed skill";
    constructor(refreshSkills) {
        this.refreshSkills = refreshSkills;
    }
    static createIf(session) {
        if (!cfgAutolearnEnabled.get(session.settings))
            return null;
        return new ManageSkillTool(session.refreshSkills);
    }
    async execute(_id, params) {
        if (params.action === "delete") {
            await deleteManagedSkill(params.name);
            await this.refreshSkills?.();
            return {
                content: [{ type: "text", text: `Deleted managed skill "${params.name}".` }],
                details: { action: "delete", name: params.name },
            };
        }
        // Defensive narrowing: the schema refine already rejects create/update
        // without both fields, so this is unreachable for valid input — it only
        // proves the strings are present to `writeManagedSkill`'s typed contract.
        if (!params.description || !params.body) {
            throw new Error(`"${params.action}" requires both "description" and "body".`);
        }
        // A managed skill resolves below any authored skill of the same name
        // (authored always wins in discovery), so creating one under a name an
        // authored skill already claims writes a file that never surfaces. Refuse
        // up front rather than report a false "Created". `sanitizeSkillName`
        // normalizes to the on-disk name the discovery scan compares against.
        if (params.action === "create" && isNameClaimedByAuthoredSkill(sanitizeSkillName(params.name))) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Cannot create managed skill "${params.name}": an authored skill of that name already exists, and managed skills cannot override authored ones. Choose a different name.`,
                    },
                ],
                isError: true,
                details: { action: "create", name: params.name, shadowed: true },
            };
        }
        const { path: skillPath } = await writeManagedSkill({
            action: params.action,
            name: params.name,
            description: params.description,
            body: params.body,
        });
        await this.refreshSkills?.();
        const relativePath = path.relative(getManagedSkillsDir(), skillPath);
        const verb = params.action === "create" ? "Created" : "Updated";
        return {
            content: [{ type: "text", text: `${verb} managed skill "${params.name}" (managed-skills/${relativePath}).` }],
            details: { action: params.action, name: params.name },
        };
    }
}
