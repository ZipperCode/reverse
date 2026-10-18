/**
 * Custom command loader - loads TypeScript command modules using native Bun import.
 *
 * Dependencies (the arktype validation and pi-coding-agent) are injected via the
 * CustomCommandAPI to avoid import resolution issues with custom commands loaded from user directories.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { type } from "@rva/omptype";
import * as zod from "@rva/omptype/zod";
import { getAgentDir, getProjectDir, isEnoent, logger } from "@rva/utils";
import { getConfigDirs } from "../../config";
import { execCommand } from "../../exec/exec";
// Runtime self-reference: dereference this namespace only inside loader functions to keep the index.ts cycle safe.
import * as PiCodingAgent from "../../index";
import * as typebox from "../legacy-typebox";
import { GreenCommand } from "./bundled/ci-green";
import { AnnotateCommand } from "./bundled/annotate";
import { ReviewCommand } from "./bundled/review";
const arktype = Object.assign(Function.prototype.bind.call(type, undefined), type, { type });
/**
 * Load a single command module using native Bun import.
 */
async function loadCommandModule(commandPath, _cwd, sharedApi) {
    try {
        const module = await import(commandPath);
        const factory = (module.default ?? module);
        if (typeof factory !== "function") {
            return { commands: null, error: "Command must export a default function" };
        }
        const result = await factory(sharedApi);
        const commands = Array.isArray(result) ? result : [result];
        // Validate commands
        for (const cmd of commands) {
            if (!cmd.name || typeof cmd.name !== "string") {
                return { commands: null, error: "Command must have a name" };
            }
            if (!cmd.description || typeof cmd.description !== "string") {
                return { commands: null, error: `Command "${cmd.name}" must have a description` };
            }
            if (typeof cmd.execute !== "function") {
                return { commands: null, error: `Command "${cmd.name}" must have an execute function` };
            }
        }
        return { commands, error: null };
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { commands: null, error: `Failed to load command: ${message}` };
    }
}
/**
 * Discover custom command modules (TypeScript slash commands).
 * Markdown slash commands are handled by core/slash-commands.ts.
 */
export async function discoverCustomCommands(options = {}) {
    const cwd = options.cwd ?? getProjectDir();
    const agentDir = options.agentDir ?? getAgentDir();
    const paths = [];
    const seen = new Set();
    const addPath = (commandPath, source) => {
        const resolved = path.resolve(commandPath);
        if (seen.has(resolved))
            return;
        seen.add(resolved);
        paths.push({ path: resolved, source });
    };
    const commandDirs = [];
    if (agentDir) {
        const userCommandsDir = path.join(agentDir, "commands");
        if (fs.existsSync(userCommandsDir)) {
            commandDirs.push({ path: userCommandsDir, source: "user" });
        }
    }
    for (const entry of getConfigDirs("commands", { cwd, existingOnly: true })) {
        const source = entry.level === "user" ? "user" : "project";
        if (!commandDirs.some(d => d.path === entry.path)) {
            commandDirs.push({ path: entry.path, source });
        }
    }
    const indexCandidates = ["index.ts", "index.js", "index.mjs", "index.cjs"];
    for (const { path: commandsDir, source } of commandDirs) {
        let entries;
        try {
            entries = await fs.promises.readdir(commandsDir, { withFileTypes: true });
        }
        catch (error) {
            if (!isEnoent(error)) {
                logger.warn("Failed to read custom commands directory", { path: commandsDir, error: String(error) });
            }
            continue;
        }
        for (const entry of entries) {
            if (!entry.isDirectory() || entry.name.startsWith("."))
                continue;
            const commandDir = path.join(commandsDir, entry.name);
            for (const filename of indexCandidates) {
                const candidate = path.join(commandDir, filename);
                if (fs.existsSync(candidate)) {
                    addPath(candidate, source);
                    break;
                }
            }
        }
    }
    return { paths };
}
/**
 * Load bundled commands (shipped with pi-coding-agent).
 */
function loadBundledCommands(sharedApi) {
    const bundled = [];
    // Add bundled commands here
    bundled.push({
        path: "bundled:green",
        resolvedPath: "bundled:green",
        command: new GreenCommand(sharedApi),
        source: "bundled",
    });
    bundled.push({
        path: "bundled:review",
        resolvedPath: "bundled:review",
        command: new ReviewCommand(sharedApi),
        source: "bundled",
    });
    bundled.push({
        path: "bundled:annotate",
        resolvedPath: "bundled:annotate",
        command: new AnnotateCommand(sharedApi),
        source: "bundled",
    });
    return bundled;
}
/**
 * Discover and load custom commands from standard locations.
 */
export async function loadCustomCommands(options = {}) {
    const cwd = options.cwd ?? getProjectDir();
    const agentDir = options.agentDir ?? getAgentDir();
    const { paths } = await discoverCustomCommands({ cwd, agentDir });
    const commands = [];
    const errors = [];
    const seenNames = new Set();
    // Shared API object - all commands get the same instance
    const sharedApi = {
        cwd,
        exec: (command, args, execOptions) => execCommand(command, args, execOptions?.cwd ?? cwd, execOptions),
        typebox,
        arktype,
        zod,
        pi: PiCodingAgent,
    };
    // 1. Load bundled commands first (lowest priority - can be overridden)
    for (const loaded of loadBundledCommands(sharedApi)) {
        seenNames.add(loaded.command.name);
        commands.push(loaded);
    }
    // 2. Load user/project commands (can override bundled)
    for (const { path: commandPath, source } of paths) {
        const { commands: loadedCommands, error } = await loadCommandModule(commandPath, cwd, sharedApi);
        if (error) {
            errors.push({ path: commandPath, error });
            continue;
        }
        if (loadedCommands) {
            for (const command of loadedCommands) {
                // Allow overriding bundled commands, but not user/project conflicts
                const existingIdx = commands.findIndex(c => c.command.name === command.name);
                if (existingIdx !== -1) {
                    const existing = commands[existingIdx];
                    if (existing.source === "bundled") {
                        // Override bundled command
                        commands.splice(existingIdx, 1);
                        seenNames.delete(command.name);
                    }
                    else {
                        // Conflict between user/project commands
                        errors.push({
                            path: commandPath,
                            error: `Command name "${command.name}" conflicts with existing command`,
                        });
                        continue;
                    }
                }
                seenNames.add(command.name);
                commands.push({
                    path: commandPath,
                    resolvedPath: path.resolve(commandPath),
                    command,
                    source,
                });
            }
        }
    }
    return { commands, errors };
}
