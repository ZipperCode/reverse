import { checkToolRequirements, } from "../extensibility/skill-requirements";
import { resolveSkillTarget, runSkillsCommand, toTerminalSafe } from "./skill-list";
export async function runSkillCheckCommand(options = {}) {
    const listing = await runSkillsCommand({ cwd: options.cwd, skillsSettings: options.skillsSettings });
    const skills = listing.skills.map(skill => {
        const requirements = checkToolRequirements(skill.requirements, options.deps);
        return {
            name: skill.name,
            filePath: skill.filePath,
            requirements,
            missingRequired: requirements
                .filter(status => !status.optional && (status.foundPath === null || (status.secondaryMissing?.length ?? 0) > 0))
                .map(status => status.id),
        };
    });
    return {
        ok: skills.every(skill => skill.missingRequired.length === 0),
        skills,
        warnings: listing.warnings,
    };
}
function formatStatus(status) {
    const optional = status.optional ? " (optional)" : "";
    if (status.foundPath === null) {
        const hint = status.hint ? `; install: ${status.hint}` : "";
        return `  missing${optional} ${status.id}${hint}`;
    }
    if ((status.secondaryMissing?.length ?? 0) > 0) {
        const hint = status.hint ? `; install: ${status.hint}` : "";
        return `  missing${optional} ${status.secondaryMissing?.join(", ")} (needed by ${status.id})${hint}`;
    }
    return `  ok${optional} ${status.id}: ${status.foundPath}`;
}
/**
 * `rva skill check [dir] [--json]`: check declared tool dependencies for the
 * skills a session in `dir` would resolve. Returns 1 when a required tool is
 * missing; discovery warnings go to stderr in text mode.
 */
export async function handleSkillCheck(args, cwd, json) {
    const target = await resolveSkillTarget(args, cwd, "usage: omp skill check [dir] [--json]");
    const result = await runSkillCheckCommand({ cwd: target });
    if (json) {
        process.stdout.write(`${JSON.stringify(result)}\n`);
        return result.ok ? 0 : 1;
    }
    let checked = 0;
    for (const skill of result.skills) {
        if (skill.requirements.length === 0)
            continue;
        checked++;
        process.stdout.write(`${toTerminalSafe(skill.name)}\n`);
        for (const status of skill.requirements) {
            process.stdout.write(`${toTerminalSafe(formatStatus(status))}\n`);
        }
    }
    if (checked === 0)
        process.stdout.write("No tool dependencies declared.\n");
    for (const warning of result.warnings) {
        process.stderr.write(`warning: ${toTerminalSafe(warning.message)}\n`);
    }
    return result.ok ? 0 : 1;
}
