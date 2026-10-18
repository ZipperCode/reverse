import { buildSkillPromptMessage, getSkillSlashCommandName, parseSkillInvocation } from "../extensibility/skills";
import { SKILL_PROMPT_MESSAGE_TYPE } from "../session/messages";
/** Return true when `text` invokes a registered `/skill:<name>` command. */
export function isKnownSkillCommand(ctx, text) {
    const parsed = parseSkillInvocation(text);
    if (!parsed)
        return false;
    return ctx.skillCommands.has(getSkillSlashCommandName({ name: parsed.name }));
}
/** Build the user-attributed custom message for a registered `/skill:<name>` command. */
export async function buildSkillCommandPrompt(ctx, text, streamingBehavior, images) {
    const parsed = parseSkillInvocation(text);
    if (!parsed)
        return undefined;
    const skill = ctx.skillCommands.get(getSkillSlashCommandName({ name: parsed.name }));
    if (!skill)
        return undefined;
    const built = await buildSkillPromptMessage(skill, parsed, "user");
    const textBlock = { type: "text", text: built.message };
    const promptContent = images && images.length > 0 ? [textBlock, ...images] : built.message;
    return {
        message: {
            customType: SKILL_PROMPT_MESSAGE_TYPE,
            content: promptContent,
            display: true,
            details: built.details,
            attribution: "user",
        },
        options: { streamingBehavior, queueChipText: text },
    };
}
/** Invoke a registered `/skill:<name>` command as a user-attributed custom message. */
export async function invokeSkillCommandFromText(ctx, text, streamingBehavior, options) {
    let optimistic = false;
    try {
        const built = await buildSkillCommandPrompt(ctx, text, streamingBehavior, options?.images);
        if (!built)
            return false;
        const promptOptions = options?.queueOnly ? { ...built.options, queueOnly: true } : built.options;
        optimistic = options?.optimistic === true && !options?.queueOnly && !ctx.session.isStreaming;
        if (optimistic) {
            ctx.renderOptimisticSkillMessage({ role: "custom", ...built.message, timestamp: Date.now() }, { imageLinks: options?.imageLinks });
        }
        await ctx.session.promptCustomMessage(built.message, promptOptions);
        return true;
    }
    catch (err) {
        if (optimistic)
            ctx.clearOptimisticSkillMessage();
        if (options?.propagateErrors) {
            throw err;
        }
        ctx.showError(`Failed to load skill: ${err instanceof Error ? err.message : String(err)}`);
        return true;
    }
    finally {
        if (optimistic && ctx.optimisticSkillMessagePending) {
            // Dispatch resolved without a canonical skill message_start (aborted
            // preflight, or a streaming-race requeue): drop the pending row.
            ctx.clearOptimisticSkillMessage();
        }
    }
}
