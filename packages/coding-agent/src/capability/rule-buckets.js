import { BUILTIN_DEFAULTS_PROVIDER_ID, ruleAppliesToAgent } from "./rule";
/**
 * Filter and bucket rules, registering TTSR rules on `ttsrManager` as a side
 * effect. Disabled rules are dropped before any bucket assignment, so a
 * disabled rule is neither matched as TTSR nor surfaced via `rule://`.
 */
export function bucketRules(rules, ttsrManager, options = {}) {
    const includeBuiltin = options.builtinRules !== false;
    const disabled = new Set();
    for (const raw of options.disabledRules ?? []) {
        const name = raw.trim();
        if (name.length > 0)
            disabled.add(name);
    }
    const includedRules = [];
    for (const rule of rules) {
        if (disabled.has(rule.name))
            continue;
        if (!includeBuiltin && rule._source?.provider === BUILTIN_DEFAULTS_PROVIDER_ID)
            continue;
        if (!ruleAppliesToAgent(rule, options.agentName))
            continue;
        includedRules.push(rule);
    }
    const replacedTtsrNames = options.replaceTtsrRules ? ttsrManager.replaceRules(includedRules) : undefined;
    const rulebookRules = [];
    const alwaysApplyRules = [];
    for (const rule of includedRules) {
        const hasTtsrCondition = (rule.condition && rule.condition.length > 0) ||
            (rule.astCondition && rule.astCondition.length > 0) ||
            rule.question !== undefined;
        const isTtsrRule = hasTtsrCondition ? (replacedTtsrNames?.has(rule.name) ?? ttsrManager.addRule(rule)) : false;
        if (isTtsrRule)
            continue;
        if (rule.alwaysApply === true) {
            alwaysApplyRules.push(rule);
            continue;
        }
        if (rule.description) {
            rulebookRules.push(rule);
        }
    }
    return { rulebookRules, alwaysApplyRules };
}
