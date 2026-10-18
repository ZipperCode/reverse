import { isRecord, prompt } from "@rva/utils";
import { formatModelString } from "../config/model-resolver";
import modelMentionDescription from "../prompts/agents/model-mention.md" with { type: "text" };
import { getBundledAgent } from "../task/agents";
import { MODEL_MENTION_RE, modelMentionDisplayName, modelMentionTag, } from "@rva/tui/prompt/model-mention-syntax";
/** Journal entry identifying a model the user authorized for delegation. */
export const MODEL_MENTION_ENTRY_TYPE = "model_mention";
/** Replay valid branch entries, keeping the first occurrence of each agent and selector. */
export function readModelMentions(entries) {
    const mentions = [];
    const agents = new Set();
    const selectors = new Set();
    for (const entry of entries) {
        if (entry.type !== "custom" || entry.customType !== MODEL_MENTION_ENTRY_TYPE || !isRecord(entry.data))
            continue;
        const { agent, selector, name } = entry.data;
        if (typeof agent !== "string" ||
            !/^m\d+$/.test(agent) ||
            typeof selector !== "string" ||
            typeof name !== "string")
            continue;
        if (agents.has(agent) || selectors.has(selector))
            continue;
        agents.add(agent);
        selectors.add(selector);
        mentions.push({ agent, selector, name });
    }
    return mentions;
}
/** Owns branch-local pseudonyms for models explicitly tagged by the user. */
export class ModelMentionRegistry {
    #host;
    #inheritedAgents;
    #mentions = [];
    #bySelector = new Map();
    #agents = new Set();
    constructor(host) {
        this.#host = host;
        this.#inheritedAgents = host.inheritedAgents ?? [];
    }
    /** Rebuild pseudonyms after resume, rewind, or a session switch. */
    syncFromBranch() {
        this.#mentions = readModelMentions(this.#host.sessionManager.getBranch());
        this.#bySelector.clear();
        this.#agents.clear();
        for (const agent of this.#inheritedAgents) {
            this.#agents.add(agent.name);
        }
        for (const mention of this.#mentions) {
            this.#bySelector.set(mention.selector, mention);
            this.#agents.add(mention.agent);
        }
    }
    /** User-authorized model pseudonyms in first-mention order. */
    get mentions() {
        return this.#mentions;
    }
    /** Resolve an exact selector within the same model scope as the session picker. */
    findMentionable(selector) {
        const scoped = this.#host.scopedModels();
        const models = scoped.length > 0 ? scoped : this.#host.modelRegistry.getAvailable();
        return models.find(model => formatModelString(model) === selector);
    }
    /** Register user-tagged models and replace their tokens with persisted agent tags. */
    expandMentions(text) {
        if (!text.includes("^"))
            return text;
        return text.replace(MODEL_MENTION_RE, (token, delimiter, selector) => {
            let mention = this.#bySelector.get(selector);
            if (!mention) {
                const model = this.findMentionable(selector);
                if (!model)
                    return token;
                let next = 1;
                while (this.#agents.has(`m${next}`))
                    next++;
                mention = { agent: `m${next}`, selector, name: modelMentionDisplayName(model) };
                this.#host.sessionManager.appendCustomEntry(MODEL_MENTION_ENTRY_TYPE, mention);
                this.#mentions.push(mention);
                this.#bySelector.set(selector, mention);
                this.#agents.add(mention.agent);
            }
            return `${delimiter}${modelMentionTag(mention)}`;
        });
    }
    /** Expose inherited and session-tagged models as general-purpose task agents. */
    sessionAgents() {
        const task = getBundledAgent("task");
        if (!task)
            throw new Error("Bundled task agent is unavailable");
        const inheritedNames = new Set(this.#inheritedAgents.map(agent => agent.name));
        return [
            ...this.#inheritedAgents,
            ...this.#mentions
                .filter(mention => !inheritedNames.has(mention.agent))
                .map(mention => ({
                ...task,
                name: mention.agent,
                description: prompt.render(modelMentionDescription, { name: mention.name, selector: mention.selector }),
                model: [mention.selector],
                filePath: undefined,
            })),
        ];
    }
}
