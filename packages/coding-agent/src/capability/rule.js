/**
 * Rules Capability
 *
 * Project-specific rules from Cursor (.mdc), Windsurf (.md), and Cline formats.
 * Translated to a canonical shape regardless of source format.
 */
import { defineCapability } from ".";
const CONDITION_GLOB_SCOPE_TOOLS = ["edit", "write"];
/**
 * Provider id for the bundled default rules shipped with the agent.
 * Lowest priority, so any user/project/tool rule of the same name overrides
 * a bundled default. Also used to gate the whole bundled set via
 * `ttsr.builtinRules`.
 */
export const BUILTIN_DEFAULTS_PROVIDER_ID = "builtin-defaults";
function normalizeRuleField(value) {
    if (typeof value === "string") {
        const token = value.trim();
        return token.length > 0 ? [token] : undefined;
    }
    if (!Array.isArray(value)) {
        return undefined;
    }
    const tokens = value
        .filter((item) => typeof item === "string")
        .map(item => item.trim())
        .filter(item => item.length > 0);
    if (tokens.length === 0) {
        return undefined;
    }
    return Array.from(new Set(tokens));
}
function splitScopeTokens(value) {
    const tokens = [];
    let current = "";
    let parenDepth = 0;
    let bracketDepth = 0;
    let braceDepth = 0;
    let quote;
    for (let i = 0; i < value.length; i++) {
        const char = value[i];
        if (quote) {
            current += char;
            if (char === quote && value[i - 1] !== "\\") {
                quote = undefined;
            }
            continue;
        }
        if (char === '"' || char === "'") {
            quote = char;
            current += char;
            continue;
        }
        if (char === "(") {
            parenDepth++;
            current += char;
            continue;
        }
        if (char === ")") {
            parenDepth = Math.max(0, parenDepth - 1);
            current += char;
            continue;
        }
        if (char === "[") {
            bracketDepth++;
            current += char;
            continue;
        }
        if (char === "]") {
            bracketDepth = Math.max(0, bracketDepth - 1);
            current += char;
            continue;
        }
        if (char === "{") {
            braceDepth++;
            current += char;
            continue;
        }
        if (char === "}") {
            braceDepth = Math.max(0, braceDepth - 1);
            current += char;
            continue;
        }
        if (char === "," && parenDepth === 0 && bracketDepth === 0 && braceDepth === 0) {
            const token = current.trim();
            if (token.length > 0) {
                tokens.push(token);
            }
            current = "";
            continue;
        }
        current += char;
    }
    const tail = current.trim();
    if (tail.length > 0) {
        tokens.push(tail);
    }
    return tokens;
}
function normalizeScopeField(value) {
    const normalized = normalizeRuleField(value);
    if (!normalized) {
        return undefined;
    }
    const tokens = normalized
        .flatMap(splitScopeTokens)
        .map(token => {
        // Tolerate malformed frontmatter (e.g. `scope: "text","thinking"`) whose
        // YAML-fallback parse leaves per-token quotes intact (issue #4796).
        const quote = token[0];
        if (token.length >= 2 && (quote === '"' || quote === "'") && token[token.length - 1] === quote) {
            return token.slice(1, -1).trim();
        }
        return token;
    })
        .filter(item => item.length > 0);
    if (tokens.length === 0) {
        return undefined;
    }
    return Array.from(new Set(tokens));
}
/**
 * Parse the `agents` frontmatter field into lowercased agent-name glob patterns.
 * Reuses the scope tokenizer for comma-separated spellings; `{a,b}` groups survive.
 */
export function parseRuleAgents(value) {
    const tokens = normalizeScopeField(value);
    if (!tokens) {
        return undefined;
    }
    return Array.from(new Set(tokens.map(token => token.replace(/\s*,\s*/g, ",").toLowerCase())));
}
/** Agent name used for the top-level (non-sub) session when evaluating `agents`. */
export const MAIN_AGENT_RULE_NAME = "main";
/** Fallback agent name used for a subagent session with no explicit `agentName` (see sdk.ts). */
export const SUB_AGENT_RULE_NAME = "sub";
/**
 * Whether a rule's `agents` scope admits `agentName`. A rule without `agents`
 * applies everywhere; `agentName === undefined` disables scoping entirely
 * (used by CLI inventory listings that must show every rule).
 */
export function ruleAppliesToAgent(rule, agentName) {
    const patterns = rule.agents;
    if (!patterns || patterns.length === 0 || agentName === undefined) {
        return true;
    }
    const name = agentName.trim().toLowerCase();
    return patterns.some(pattern => {
        if (pattern === name) {
            return true;
        }
        return new Bun.Glob(pattern).match(name);
    });
}
/**
 * Heuristic for condition shorthand that looks like a file glob (for example `*.rs`).
 */
function isLikelyFileGlob(value) {
    const token = value.trim();
    if (token.length === 0) {
        return false;
    }
    if (/[\\^$+|()]/.test(token)) {
        return false;
    }
    if (!/[?*[\]{}]/.test(token)) {
        return false;
    }
    if (token.includes("/")) {
        return true;
    }
    return /^\*\.[^\s/]+$/.test(token);
}
/**
 * Parse the TTSR trigger fields (`condition`, `astCondition`, `question`) and `scope` from rule frontmatter.
 *
 * - `condition` accepts string or string[]
 * - `scope` accepts string or string[]
 * - legacy `ttsr_trigger` / `ttsrTrigger` are accepted as a `condition` fallback
 * - condition tokens that look like file globs become scope shorthands:
 *   `*.rs` => `tool:edit(*.rs)`, `tool:write(*.rs)` and a catch-all condition `.*`
 * - `astCondition` holds ast-grep patterns and is kept verbatim (no glob inference)
 * - `question` accepts a single non-empty string
 */
export function parseRuleConditionAndScope(frontmatter) {
    const rawCondition = frontmatter.condition ?? frontmatter.ttsr_trigger ?? frontmatter.ttsrTrigger;
    const parsedCondition = normalizeRuleField(rawCondition);
    const astCondition = normalizeRuleField(frontmatter.astCondition);
    const parsedScope = normalizeScopeField(frontmatter.scope);
    const inferredScope = [];
    const condition = [];
    for (const token of parsedCondition ?? []) {
        if (isLikelyFileGlob(token)) {
            for (const toolName of CONDITION_GLOB_SCOPE_TOOLS) {
                inferredScope.push(`tool:${toolName}(${token})`);
            }
            continue;
        }
        condition.push(token);
    }
    if (condition.length === 0 && inferredScope.length > 0) {
        condition.push(".*");
    }
    const scope = [...(parsedScope ?? []), ...inferredScope];
    return {
        condition: condition.length > 0 ? Array.from(new Set(condition)) : undefined,
        astCondition,
        question: typeof frontmatter.question === "string" ? frontmatter.question.trim() || undefined : undefined,
        scope: scope.length > 0 ? Array.from(new Set(scope)) : undefined,
    };
}
/** Leading PCRE-style inline flag group, e.g. `(?i)` or `(?ims)`. */
const INLINE_FLAG_PREFIX = /^\(\?([a-z]+)\)/;
/** Inline flags that map cleanly onto native `RegExp` flags. */
const TRANSLATABLE_INLINE_FLAGS = /^[ims]+$/;
/**
 * A sequence of positive lookaheads whose bodies all begin with greedy `[\s\S]*`
 * has the same result at index zero as it does at any later index. Each body
 * can consume the prefix itself before testing its predicate, so asking the
 * RegExp engine to retry the sequence at every character only repeats work.
 * Lazy `[\s\S]*?` prefixes are excluded because captures chosen by one
 * lookahead can make a later backreference depend on the starting position.
 */
function canMatchWholeBufferFromStart(source) {
    let offset = 0;
    let lookaheads = 0;
    const prefix = "(?=[\\s\\S]*";
    while (source.startsWith(prefix, offset) && source[offset + prefix.length] !== "?") {
        let depth = 1;
        let inCharacterClass = false;
        let end = -1;
        for (let index = offset + 3; index < source.length; index++) {
            const char = source[index];
            if (char === "\\") {
                index++;
                continue;
            }
            if (inCharacterClass) {
                if (char === "]")
                    inCharacterClass = false;
                continue;
            }
            if (char === "[") {
                inCharacterClass = true;
                continue;
            }
            if (char === "(") {
                depth++;
                continue;
            }
            if (char !== ")")
                continue;
            depth--;
            if (depth === 0) {
                end = index + 1;
                break;
            }
        }
        if (end === -1)
            return false;
        offset = end;
        lookaheads++;
    }
    return lookaheads > 0 && offset === source.length;
}
function optimizeRuleCondition(condition) {
    if (condition.sticky || !canMatchWholeBufferFromStart(condition.source))
        return condition;
    return new RegExp(condition.source, `${condition.flags}y`);
}
/**
 * Compile a rule `condition` into a `RegExp`, translating a leading PCRE-style
 * inline flag group into native `RegExp` flags.
 *
 * JS/Bun `RegExp` rejects inline flag prefixes such as `(?i)`, so a rule written
 * `condition: "(?i)pre.existing"` would otherwise throw at compile time and be
 * silently dropped (see issue #4796). Only a *leading* group of `i`/`m`/`s`
 * flags is translated; anything else — mid-pattern groups, unsupported flags —
 * is passed through verbatim so the native error still surfaces for genuinely
 * invalid patterns.
 */
export function compileRuleCondition(pattern) {
    const match = INLINE_FLAG_PREFIX.exec(pattern);
    if (match && TRANSLATABLE_INLINE_FLAGS.test(match[1])) {
        const flags = Array.from(new Set(match[1])).join("");
        return optimizeRuleCondition(new RegExp(pattern.slice(match[0].length), flags));
    }
    return optimizeRuleCondition(new RegExp(pattern));
}
let activeRules = [];
/**
 * Process-global snapshot of rules the active session loaded.
 * Read by internal URL protocol handlers (rule://).
 */
export function getActiveRules() {
    return activeRules;
}
/** Replace the active rule snapshot. Called once per top-level session. */
export function setActiveRules(value) {
    activeRules = value;
}
/** Reset the active rule snapshot. Test-only. */
export function resetActiveRulesForTests() {
    activeRules = [];
}
export const ruleCapability = defineCapability({
    id: "rules",
    displayName: "Rules",
    description: "Project-specific rules and constraints (Cursor MDC, Windsurf, Cline formats)",
    key: rule => rule.name,
    toExtensionId: rule => `rule:${rule.name}`,
    validate: rule => {
        if (!rule.name)
            return "Missing rule name";
        if (!rule.path)
            return "Missing rule path";
        if (!rule.content || typeof rule.content !== "string")
            return "Rule must have content";
        return undefined;
    },
});
