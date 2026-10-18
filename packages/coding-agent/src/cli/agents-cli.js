/**
 * Agents CLI command handlers.
 *
 * Handles `omp agents unpack` for writing bundled agent definitions to disk.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { getAgentDir, getProjectAgentDir, getProjectDir, isEnoent } from "@rva/utils";
import chalk from "@rva/utils/chalk";
import { YAML } from "bun";
import { theme } from "@rva/tui/theme";
import { loadBundledAgents } from "../task/agents";
function writeStdout(line) {
    process.stdout.write(`${line}\n`);
}
function resolveTargetDir(flags) {
    if (flags.dir && flags.dir.trim().length > 0) {
        return path.resolve(getProjectDir(), flags.dir.trim());
    }
    if (flags.user && flags.project) {
        throw new Error("Choose either --user or --project, not both.");
    }
    if (flags.project) {
        return path.join(getProjectAgentDir(getProjectDir()), "agents");
    }
    return path.join(getAgentDir(), "agents");
}
function toFrontmatter(agent) {
    const frontmatter = {
        name: agent.name,
        description: agent.description,
    };
    if (agent.tools !== undefined)
        frontmatter.tools = agent.tools;
    if (agent.spawns !== undefined)
        frontmatter.spawns = agent.spawns;
    if (agent.model && agent.model.length > 0)
        frontmatter.model = agent.model;
    if (agent.thinkingLevel)
        frontmatter.thinkingLevel = agent.thinkingLevel;
    if (agent.output !== undefined)
        frontmatter.output = agent.output;
    if (agent.blocking)
        frontmatter.blocking = true;
    if (agent.structured)
        frontmatter.structured = true;
    return frontmatter;
}
function serializeAgent(agent) {
    const frontmatter = YAML.stringify(toFrontmatter(agent), null, 2).trimEnd();
    const body = agent.systemPrompt.trim();
    return `---\n${frontmatter}\n---\n\n${body}\n`;
}
async function unpackBundledAgents(flags) {
    const targetDir = resolveTargetDir(flags);
    await fs.mkdir(targetDir, { recursive: true });
    const bundledAgents = [...loadBundledAgents()].sort((a, b) => a.name.localeCompare(b.name));
    const written = [];
    const skipped = [];
    for (const agent of bundledAgents) {
        const filePath = path.join(targetDir, `${agent.name}.md`);
        if (!flags.force) {
            try {
                await fs.stat(filePath);
                skipped.push(filePath);
                continue;
            }
            catch (error) {
                if (!isEnoent(error))
                    throw error;
            }
        }
        await Bun.write(filePath, serializeAgent(agent));
        written.push(filePath);
    }
    return {
        targetDir,
        total: bundledAgents.length,
        written,
        skipped,
    };
}
export async function runAgentsCommand(cmd) {
    switch (cmd.action) {
        case "unpack": {
            const result = await unpackBundledAgents(cmd.flags);
            if (cmd.flags.json) {
                writeStdout(JSON.stringify(result, null, 2));
                return;
            }
            writeStdout(chalk.bold(`Bundled agents: ${result.total}`));
            writeStdout(chalk.dim(`Target directory: ${result.targetDir}`));
            writeStdout(chalk.green(`${theme.status.success} Written: ${result.written.length}`));
            if (result.skipped.length > 0) {
                writeStdout(chalk.yellow(`${theme.status.warning} Skipped existing: ${result.skipped.length} (use --force to overwrite)`));
            }
            for (const filePath of result.written) {
                writeStdout(chalk.dim(`  + ${filePath}`));
            }
            for (const filePath of result.skipped) {
                writeStdout(chalk.dim(`  = ${filePath}`));
            }
            return;
        }
    }
}
