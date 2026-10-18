import { type } from "@rva/omptype";
import { prompt } from "@rva/utils";
import checkpointDescription from "../prompts/tools/checkpoint.md" with { type: "text" };
import rewindDescription from "../prompts/tools/rewind.md" with { type: "text" };
import { ToolError } from "@rva/tui/tools/tool-errors";
import { toolResult } from "./tool-result";
const checkpointSchema = type({
    goal: type("string").describe("investigation goal"),
});
const rewindSchema = type({
    report: type("string").describe("investigation findings"),
});
export class CheckpointTool {
    session;
    name = "checkpoint";
    approval = "read";
    label = "Checkpoint";
    summary = "Create a git-based checkpoint to save and restore session state";
    description;
    parameters = checkpointSchema;
    strict = true;
    loadMode = "discoverable";
    intent = (args) => (args.goal ? `checkpointing: ${args.goal}` : "checkpointing");
    constructor(session) {
        this.session = session;
        this.description = prompt.render(checkpointDescription);
    }
    static createIf(session) {
        return new CheckpointTool(session);
    }
    async execute(_toolCallId, params, _signal, _onUpdate, _context) {
        if (this.session.getCheckpointState?.()) {
            throw new ToolError("Checkpoint already active.");
        }
        const startedAt = new Date().toISOString();
        return toolResult({ goal: params.goal, startedAt })
            .text([`Checkpoint: ${params.goal}`, "Finish exploration and formulate findings."].join("\n"))
            .done();
    }
}
export class RewindTool {
    session;
    name = "rewind";
    approval = "read";
    label = "Rewind";
    summary = "Rewind to a previously created checkpoint";
    description;
    parameters = rewindSchema;
    strict = true;
    loadMode = "discoverable";
    intent = () => "rewinding";
    constructor(session) {
        this.session = session;
        this.description = prompt.render(rewindDescription);
    }
    static createIf(session) {
        return new RewindTool(session);
    }
    async execute(_toolCallId, params, _signal, _onUpdate, _context) {
        if (!this.session.getCheckpointState?.()) {
            if (this.session.getLastCompletedRewind?.()) {
                throw new ToolError("Checkpoint already completed; continue from the retained rewind report instead of calling rewind again.");
            }
            throw new ToolError("No active checkpoint. Create a checkpoint before calling rewind.");
        }
        const report = params.report.trim();
        if (report.length === 0) {
            throw new ToolError("Report cannot be empty.");
        }
        return toolResult({ report, rewound: true })
            .text(["Rewind requested.", "Report captured for context replacement."].join("\n"))
            .done();
    }
}
