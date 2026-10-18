import * as fs from "node:fs";
import * as path from "node:path";
import { OmpErrors } from "@rva/omptype";
import { getAgentDir, isEnoent, logger, stringifyYamlConfig } from "@rva/utils";
import { JSONC, YAML } from "bun";
/**
 * Module-private cache of JSON → YAML migrations this process already ran.
 * Prevents `ConfigFile.relocate()` / repeated `tryLoad()` calls from re-running
 * the migration over and over on the boot path.
 */
const migratedPaths = new Set();
function migrationKey(jsonPath, ymlPath) {
    return `${jsonPath}\u0000${ymlPath}`;
}
/**
 * Synchronous JSON → YAML migration kept for callers that still want the
 * eager path (settings init, tests that observe migration completion).
 * Idempotent — re-running is a no-op.
 */
function migrateJsonToYml(jsonPath, ymlPath) {
    const key = migrationKey(jsonPath, ymlPath);
    if (migratedPaths.has(key))
        return;
    try {
        if (fs.existsSync(ymlPath)) {
            migratedPaths.add(key);
            return;
        }
        if (!fs.existsSync(jsonPath)) {
            migratedPaths.add(key);
            return;
        }
        const content = fs.readFileSync(jsonPath, "utf-8");
        const parsed = JSONC.parse(content);
        if (!parsed) {
            logger.warn("migrateJsonToYml: invalid json structure", { path: jsonPath });
            migratedPaths.add(key);
            return;
        }
        fs.writeFileSync(ymlPath, stringifyYamlConfig(parsed));
        migratedPaths.add(key);
    }
    catch (error) {
        logger.warn("migrateJsonToYml: migration failed", { error: String(error) });
    }
}
export class ConfigError extends Error {
    id;
    schemaErrors;
    other;
    #message;
    constructor(id, schemaErrors, other) {
        let messages;
        let cause;
        let klass;
        if (schemaErrors) {
            klass = "Schema";
            messages = schemaErrors.map(e => `${e.instancePath || "root"}: ${e.message}`);
        }
        else if (other) {
            klass = other.stage;
            if (other.err instanceof Error) {
                messages = [other.err.message];
                cause = other.err;
            }
            else {
                messages = [String(other.err)];
            }
        }
        else {
            klass = "Unknown";
        }
        const title = `Failed to load config file ${id}, ${klass} error:`;
        let message;
        switch (messages?.length ?? 0) {
            case 0:
                message = title.slice(0, -1);
                break;
            case 1:
                message = `${title} ${messages[0]}`;
                break;
            default:
                message = `${title}\n${messages.map(m => `  - ${m}`).join("\n")}`;
        }
        super(message, { cause });
        this.id = id;
        this.schemaErrors = schemaErrors;
        this.other = other;
        this.name = "LoadError";
        this.#message = message;
    }
    get message() {
        return this.#message;
    }
    toString() {
        return this.message;
    }
}
export class ConfigFile {
    id;
    #basePath;
    #yamlFallbackPath;
    #jsonMigrationPath;
    #schemaSource;
    #resolvedSchema;
    #cache;
    #auxValidate;
    constructor(id, schema, configPath = path.join(getAgentDir(), `${id}.yml`)) {
        this.id = id;
        this.#schemaSource = typeof schema === "function" ? { kind: "eager", schema } : schema;
        this.#basePath = configPath;
        if (configPath.endsWith(".yml")) {
            this.#yamlFallbackPath = `${configPath.slice(0, -4)}.yaml`;
            this.#jsonMigrationPath = `${configPath.slice(0, -4)}.json`;
        }
        else if (configPath.endsWith(".yaml")) {
            this.#yamlFallbackPath = null;
            this.#jsonMigrationPath = `${configPath.slice(0, -5)}.json`;
        }
        else if (configPath.endsWith(".json") || configPath.endsWith(".jsonc")) {
            this.#yamlFallbackPath = null;
            // JSON configs are still supported without migration.
            this.#jsonMigrationPath = null;
        }
        else {
            this.#yamlFallbackPath = null;
            throw new Error(`Invalid config file path: ${configPath}`);
        }
    }
    get schema() {
        if (this.#schemaSource.kind === "eager")
            return this.#schemaSource.schema;
        if (!this.#resolvedSchema)
            this.#resolvedSchema = this.#schemaSource.resolve();
        return this.#resolvedSchema;
    }
    /**
     * Run the JSON → YAML migration synchronously, if applicable. Idempotent.
     * Sync callers (tests, settings init) hit this implicitly via {@link tryLoad}.
     */
    #ensureMigrated() {
        if (!this.#jsonMigrationPath)
            return;
        if (this.#yamlFallbackPath && !fs.existsSync(this.#basePath) && fs.existsSync(this.#yamlFallbackPath)) {
            return;
        }
        migrateJsonToYml(this.#jsonMigrationPath, this.#basePath);
    }
    relocate(configPath) {
        if (!configPath || configPath === this.#basePath)
            return this;
        const result = new ConfigFile(this.id, this.#schemaSource, configPath);
        result.#auxValidate = this.#auxValidate;
        result.#resolvedSchema = this.#resolvedSchema;
        result.#ensureMigrated();
        return result;
    }
    #resolveReadPath() {
        if (fs.existsSync(this.#basePath)) {
            return this.#basePath;
        }
        if (this.#yamlFallbackPath && fs.existsSync(this.#yamlFallbackPath)) {
            return this.#yamlFallbackPath;
        }
        return this.#basePath;
    }
    getMtimeMs() {
        try {
            return fs.statSync(this.#resolveReadPath()).mtimeMs;
        }
        catch (err) {
            if (isEnoent(err))
                return null;
            throw err;
        }
    }
    withValidation(name, validate) {
        const prev = this.#auxValidate;
        this.#auxValidate = (value) => {
            prev?.(value);
            try {
                validate(value);
            }
            catch (error) {
                throw new ConfigError(this.id, undefined, { err: error, stage: `Validate(${name})` });
            }
        };
        return this;
    }
    createDefault() {
        const parsed = this.schema({});
        if (!(parsed instanceof Error))
            return parsed;
        const fallback = this.schema(undefined);
        if (!(fallback instanceof Error))
            return fallback;
        throw new ConfigError(this.id, undefined, {
            err: new Error("Schema produced no default value"),
            stage: "createDefault",
        });
    }
    #storeCache(result) {
        this.#cache = result;
        return result;
    }
    #parseContent(content) {
        try {
            let parsed;
            const readPath = this.#resolveReadPath();
            if (readPath.endsWith(".json") || readPath.endsWith(".jsonc")) {
                parsed = JSONC.parse(content);
            }
            else if (readPath.endsWith(".yml") || readPath.endsWith(".yaml")) {
                parsed = YAML.parse(content);
            }
            else {
                throw new Error(`Invalid config file path: ${readPath}`);
            }
            const checked = this.schema(parsed);
            if (checked instanceof OmpErrors) {
                const schemaErrors = checked.map(error => ({
                    instancePath: error.path.length === 0 ? "root" : error.path.join("."),
                    message: error.problem,
                }));
                const error = new ConfigError(this.id, schemaErrors);
                logger.warn("Failed to parse config file", { path: this.path(), error });
                return this.#storeCache({ error, status: "error" });
            }
            const value = checked;
            try {
                this.#auxValidate?.(value);
            }
            catch (error) {
                const wrapped = error instanceof ConfigError
                    ? error
                    : new ConfigError(this.id, undefined, { err: error, stage: "AuxValidate" });
                return this.#storeCache({ error: wrapped, status: "error" });
            }
            return this.#storeCache({ value, status: "ok" });
        }
        catch (error) {
            logger.warn("Failed to parse config file", { path: this.path(), error });
            return this.#storeCache({
                error: new ConfigError(this.id, undefined, { err: error, stage: "Unexpected" }),
                status: "error",
            });
        }
    }
    tryLoad() {
        if (this.#cache)
            return this.#cache;
        this.#ensureMigrated();
        let content;
        try {
            content = fs.readFileSync(this.#resolveReadPath(), "utf-8").trim();
        }
        catch (error) {
            if (isEnoent(error)) {
                return this.#storeCache({ status: "not-found" });
            }
            logger.warn("Failed to read config file", { path: this.path(), error });
            return this.#storeCache({
                error: new ConfigError(this.id, undefined, { err: error, stage: "Read" }),
                status: "error",
            });
        }
        return this.#parseContent(content);
    }
    load() {
        return this.tryLoad().value ?? null;
    }
    loadOrDefault() {
        return this.tryLoad().value ?? this.createDefault();
    }
    path() {
        return this.#resolveReadPath();
    }
    invalidate() {
        this.#cache = undefined;
    }
}
