var __addDisposableResource = (this && this.__addDisposableResource) || function (env, value, async) {
    if (value !== null && value !== void 0) {
        if (typeof value !== "object" && typeof value !== "function") throw new TypeError("Object expected.");
        var dispose, inner;
        if (async) {
            if (!Symbol.asyncDispose) throw new TypeError("Symbol.asyncDispose is not defined.");
            dispose = value[Symbol.asyncDispose];
        }
        if (dispose === void 0) {
            if (!Symbol.dispose) throw new TypeError("Symbol.dispose is not defined.");
            dispose = value[Symbol.dispose];
            if (async) inner = dispose;
        }
        if (typeof dispose !== "function") throw new TypeError("Object not disposable.");
        if (inner) dispose = function() { try { inner.call(this); } catch (e) { return Promise.reject(e); } };
        env.stack.push({ value: value, dispose: dispose, async: async });
    }
    else if (async) {
        env.stack.push({ async: true });
    }
    return value;
};
var __disposeResources = (this && this.__disposeResources) || (function (SuppressedError) {
    return function (env) {
        function fail(e) {
            env.error = env.hasError ? new SuppressedError(e, env.error, "An error was suppressed during disposal.") : e;
            env.hasError = true;
        }
        var r, s = 0;
        function next() {
            while (r = env.stack.pop()) {
                try {
                    if (!r.async && s === 1) return s = 0, env.stack.push(r), Promise.resolve().then(next);
                    if (r.dispose) {
                        var result = r.dispose.call(r.value);
                        if (r.async) return s |= 2, Promise.resolve(result).then(next, function(e) { fail(e); return next(); });
                    }
                    else s |= 1;
                }
                catch (e) {
                    fail(e);
                }
            }
            if (s === 1) return env.hasError ? Promise.reject(env.error) : Promise.resolve();
            if (env.hasError) throw env.error;
        }
        return next();
    };
})(typeof SuppressedError === "function" ? SuppressedError : function (error, suppressed, message) {
    var e = new Error(message);
    return e.name = "SuppressedError", e.error = error, e.suppressed = suppressed, e;
});
import { Database } from "bun:sqlite";
import * as fs from "node:fs";
import * as path from "node:path";
import { getMemoriesDir, logger, withLoopPhase } from "@rva/utils";
import { cfgMnemopiAutoRecall, cfgMnemopiAutoRetain, cfgMnemopiBank, cfgMnemopiDbPath, cfgMnemopiDebug, cfgMnemopiEmbeddingApiKey, cfgMnemopiEmbeddingApiUrl, cfgMnemopiEmbeddingModel, cfgMnemopiEmbeddingVariant, cfgMnemopiEnhancedRecall, cfgMnemopiInjectionTokenLimit, cfgMnemopiLlmApiKey, cfgMnemopiLlmBaseUrl, cfgMnemopiLlmMode, cfgMnemopiLlmModel, cfgMnemopiNoEmbeddings, cfgMnemopiPolyphonicRecall, cfgMnemopiProactiveLinking, cfgMnemopiRecallContextTurns, cfgMnemopiRecallLimit, cfgMnemopiRecallMaxQueryChars, cfgMnemopiRetainEveryNTurns, cfgMnemopiScoping, } from "./settings";
export function loadMnemopiConfig(settings, agentDir) {
    const configuredDbPath = cfgMnemopiDbPath.get(settings);
    const cwd = settings.getCwd();
    const scoping = cfgMnemopiScoping.get(settings);
    const dbPath = configuredDbPath?.trim()
        ? configuredDbPath
        : path.join(getMemoriesDir(agentDir), "mnemopi", "mnemopi.db");
    const scope = computeMnemopiBankScope(cfgMnemopiBank.get(settings), cwd, scoping);
    const recallBanks = scoping === "global" ? scope.recallBanks : extendRecallWithLegacyBanks(scope.recallBanks, dbPath, cwd);
    const llmMode = cfgMnemopiLlmMode.get(settings);
    const embeddingOverride = cfgMnemopiEmbeddingModel.get(settings);
    const embeddingVariant = cfgMnemopiEmbeddingVariant.get(settings);
    // Map the variant explicitly rather than indexing an object with the raw config
    // value (which could resolve an inherited property like `__proto__`); any value
    // other than the multilingual variant falls back to the English default.
    const variantModel = embeddingVariant === "multilingual" ? "intfloat/multilingual-e5-large" : "BAAI/bge-base-en-v1.5";
    const embeddingModel = embeddingOverride?.trim() || variantModel;
    return {
        dbPath,
        baseBank: scope.baseBank,
        bank: scope.bank,
        globalBank: scope.globalBank,
        retainBank: scope.retainBank,
        recallBanks,
        scoping,
        autoRecall: cfgMnemopiAutoRecall.get(settings),
        autoRetain: cfgMnemopiAutoRetain.get(settings),
        polyphonicRecall: cfgMnemopiPolyphonicRecall.get(settings),
        enhancedRecall: cfgMnemopiEnhancedRecall.get(settings),
        proactiveLinking: cfgMnemopiProactiveLinking.get(settings),
        retainEveryNTurns: Math.max(1, Math.floor(cfgMnemopiRetainEveryNTurns.get(settings))),
        recallLimit: Math.max(1, Math.floor(cfgMnemopiRecallLimit.get(settings))),
        recallContextTurns: Math.max(1, Math.floor(cfgMnemopiRecallContextTurns.get(settings))),
        recallMaxQueryChars: Math.max(256, Math.floor(cfgMnemopiRecallMaxQueryChars.get(settings))),
        injectionTokenLimit: Math.max(256, Math.floor(cfgMnemopiInjectionTokenLimit.get(settings))),
        debug: cfgMnemopiDebug.get(settings),
        providerOptions: {
            noEmbeddings: cfgMnemopiNoEmbeddings.get(settings),
            debug: cfgMnemopiDebug.get(settings),
            embeddingModel,
            embeddingApiUrl: cfgMnemopiEmbeddingApiUrl.get(settings),
            embeddingApiKey: cfgMnemopiEmbeddingApiKey.get(settings),
            llm: llmMode === "remote"
                ? {
                    baseUrl: cfgMnemopiLlmBaseUrl.get(settings),
                    apiKey: cfgMnemopiLlmApiKey.get(settings),
                    model: cfgMnemopiLlmModel.get(settings),
                }
                : false,
        },
        llmMode,
        llmBaseUrl: cfgMnemopiLlmBaseUrl.get(settings),
        llmApiKey: cfgMnemopiLlmApiKey.get(settings),
        llmModel: cfgMnemopiLlmModel.get(settings),
    };
}
const DEFAULT_SHARED_BANK = "default";
// Cap legacy-bank scanning at session start so a pathological banks/
// directory cannot dominate startup latency.
const LEGACY_BANK_SCAN_LIMIT = 64;
/**
 * Resolve write/recall banks for a session.
 *
 * Mnemopi has no tag-filtered recall, so `per-project-tagged` maps to a
 * project-local write bank plus a shared recall-visible bank. The project
 * bank is derived purely from {@link cwd} — see {@link projectBank} for the
 * stability contract.
 */
export function computeMnemopiBankScope(configured, cwd, scoping) {
    const project = projectBank(configured, cwd);
    const globalBank = sharedBank(configured);
    switch (scoping) {
        case "global":
            return {
                baseBank: globalBank,
                bank: globalBank,
                globalBank,
                retainBank: globalBank,
                recallBanks: [globalBank],
            };
        case "per-project":
            return {
                baseBank: globalBank,
                bank: project,
                globalBank,
                retainBank: project,
                recallBanks: [project],
            };
        case "per-project-tagged":
            return {
                baseBank: globalBank,
                bank: project,
                globalBank,
                retainBank: project,
                recallBanks: project === globalBank ? [project] : [project, globalBank],
            };
    }
}
function sharedBank(configured) {
    return sanitizeBankName(configured) ?? DEFAULT_SHARED_BANK;
}
/**
 * Derive the per-project bank id from `cwd` alone.
 *
 * Earlier versions resolved the enclosing git root before hashing, which
 * made the bank id unstable: removing or adding a `.git` anywhere above the
 * cwd repointed the same conversation directory to a different bank and
 * fragmented memories (#2412). The git lookup is gone here; the rescue path
 * for already-fragmented installs lives in {@link extendRecallWithLegacyBanks}.
 */
function projectBank(configured, cwd) {
    const projectRoot = path.resolve(cwd || ".");
    const project = projectBankSegment(projectRoot);
    const base = sanitizeBankName(configured);
    return limitBankName(base ? `${base}-${project}` : project);
}
/**
 * Stable project-identity segment derived from an absolute project root:
 * `<sanitized-basename>-<Bun.hash(projectRoot).toString(36)>`, clamped to the
 * bank-name limit. Shared by mnemopi bank scoping and the sharpshooter
 * project store so both subsystems key the same directory identically.
 */
export function projectBankSegment(projectRoot) {
    const project = sanitizeBankName(path.basename(projectRoot)) ?? "default";
    return limitBankName(`${project}-${Bun.hash(projectRoot).toString(36)}`);
}
/**
 * Discover sibling banks under `<dbDir>/banks/` whose `working_memory` rows
 * all carry the active `cwd` in `metadata_json.$.cwd`, and add those safe
 * single-cwd banks to the recall set. This rescues memories stranded by a
 * previous, less-stable bank derivation (#2412) without recalling mixed-cwd
 * legacy banks wholesale under per-project isolation.
 *
 * Robust by design: a missing banks directory, unreadable bank dir, or
 * corrupt SQLite file is silently skipped. Scanning is capped at
 * {@link LEGACY_BANK_SCAN_LIMIT} to bound startup cost.
 */
export function extendRecallWithLegacyBanks(resolved, dbPath, cwd) {
    return withLoopPhase("mnemopi.open", () => {
        const banksDir = path.join(path.dirname(dbPath), "banks");
        const cwdAbs = path.resolve(cwd || ".");
        let entries;
        try {
            entries = fs.readdirSync(banksDir, { withFileTypes: true });
        }
        catch {
            return resolved;
        }
        const have = new Set(resolved);
        const extras = [];
        let scanned = 0;
        for (const entry of entries) {
            if (!entry.isDirectory() || have.has(entry.name))
                continue;
            if (scanned >= LEGACY_BANK_SCAN_LIMIT)
                break;
            scanned++;
            const candidate = path.join(banksDir, entry.name, "mnemopi.db");
            if (bankOnlyHasCwd(candidate, cwdAbs))
                extras.push(entry.name);
        }
        return extras.length === 0 ? resolved : [...resolved, ...extras];
    });
}
function bankOnlyHasCwd(dbPath, cwd) {
    let db;
    try {
        const env_1 = { stack: [], error: void 0, hasError: false };
        try {
            db = new Database(dbPath, { readonly: true });
            // "Safe" = no row with a different/missing cwd AND at least one matching row. Both probes stop at
            // the first hit, and CASE skips the matching probe once an unsafe row disqualifies the bank.
            const statement = __addDisposableResource(env_1, db.prepare(`
				SELECT CASE
					WHEN EXISTS(SELECT 1 FROM working_memory WHERE json_extract(metadata_json, '$.cwd') IS NOT ?1) THEN 0
					ELSE EXISTS(SELECT 1 FROM working_memory WHERE json_extract(metadata_json, '$.cwd') = ?1)
				END AS safe
		`), false);
            const row = statement.get(cwd);
            return row?.safe === 1;
        }
        catch (e_1) {
            env_1.error = e_1;
            env_1.hasError = true;
        }
        finally {
            __disposeResources(env_1);
        }
    }
    catch (error) {
        logger.debug("Mnemopi: legacy bank probe failed", { dbPath, error: String(error) });
        return false;
    }
    finally {
        try {
            db?.close();
        }
        catch {
            // nothing to do — read-only handle.
        }
    }
}
function sanitizeBankName(value) {
    const raw = value?.trim();
    if (!raw)
        return undefined;
    const sanitized = raw.replace(/[^a-zA-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
    return sanitized ? limitBankName(sanitized) : undefined;
}
function limitBankName(name) {
    if (name.length <= 64)
        return name;
    const hash = Bun.hash(name).toString(36);
    const prefixLength = Math.max(1, 63 - hash.length);
    const prefix = name.slice(0, prefixLength).replace(/-+$/g, "") || "bank";
    return `${prefix}-${hash}`;
}
export function truncateApproxTokens(text, tokenLimit) {
    const maxChars = Math.max(0, tokenLimit * 4);
    if (text.length <= maxChars)
        return text;
    return `${text.slice(0, Math.max(0, maxChars - 1)).trimEnd()}…`;
}
