const GENERATION_STATEMENT = /{%-?\s*(?:endgeneration|generation)\s*-?%}/g;
/**
 * Render a text chat after removing generation-mask statements unsupported by
 * the Transformers.js CommonJS template parser.
 */
export function renderTextChatTemplate(tokenizer, messages, options) {
    const source = tokenizer.get_chat_template();
    const chatTemplate = typeof source === "string" ? source.replace(GENERATION_STATEMENT, "") : undefined;
    const templateOptions = {
        ...(chatTemplate === undefined ? {} : { chat_template: chatTemplate }),
        add_generation_prompt: options.addGenerationPrompt,
        tokenize: false,
        enable_thinking: options.enableThinking,
    };
    return tokenizer.apply_chat_template([...messages], templateOptions);
}
