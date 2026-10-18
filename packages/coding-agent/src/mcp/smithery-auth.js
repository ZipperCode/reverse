import * as fs from "node:fs/promises";
import * as path from "node:path";
import { isEnoent, logger } from "@rva/utils";
import { getAgentDir } from "@rva/utils/dirs";
import { withTimeoutSignal } from "../utils/fetch-timeout";
const SMITHERY_AUTH_FILENAME = "smithery.json";
const SMITHERY_URL = process.env.SMITHERY_URL || "https://smithery.ai";
const SMITHERY_AUTH_TIMEOUT_MS = 10000;
const SMITHERY_POLL_TIMEOUT_MS = 30000;
function getSmitheryAuthPath() {
    return path.join(getAgentDir(), SMITHERY_AUTH_FILENAME);
}
function normalizeApiKey(value) {
    if (!value)
        return undefined;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
}
export function getSmitheryLoginUrl() {
    return SMITHERY_URL;
}
export async function createSmitheryCliAuthSession() {
    const response = await fetch(`${SMITHERY_URL}/api/auth/cli/session`, {
        method: "POST",
        signal: withTimeoutSignal(SMITHERY_AUTH_TIMEOUT_MS),
    });
    if (!response.ok) {
        throw new Error(`Failed to create Smithery auth session: ${response.status} ${response.statusText}`);
    }
    return (await response.json());
}
export async function pollSmitheryCliAuthSession(sessionId, signal) {
    const response = await fetch(`${SMITHERY_URL}/api/auth/cli/poll/${sessionId}`, {
        signal: withTimeoutSignal(SMITHERY_POLL_TIMEOUT_MS, signal),
    });
    if (!response.ok) {
        if (response.status === 404 || response.status === 410) {
            throw new Error("Smithery login session expired. Please try again.");
        }
        throw new Error(`Smithery auth polling failed: ${response.status} ${response.statusText}`);
    }
    return (await response.json());
}
export async function getSmitheryApiKey() {
    const envKey = normalizeApiKey(process.env.SMITHERY_API_KEY);
    if (envKey)
        return envKey;
    const authPath = getSmitheryAuthPath();
    try {
        const payload = (await Bun.file(authPath).json());
        return normalizeApiKey(payload.apiKey);
    }
    catch (error) {
        if (isEnoent(error))
            return undefined;
        logger.warn("Failed to read Smithery auth file, treating as missing", { path: authPath, error });
        return undefined;
    }
}
export async function saveSmitheryApiKey(apiKey) {
    const normalized = normalizeApiKey(apiKey);
    if (!normalized) {
        throw new Error("Smithery API key cannot be empty.");
    }
    const authPath = getSmitheryAuthPath();
    const payload = { apiKey: normalized };
    await Bun.write(authPath, `${JSON.stringify(payload, null, 2)}\n`);
    try {
        await fs.chmod(authPath, 0o600);
    }
    catch (error) {
        logger.warn("Could not set restrictive permissions on Smithery auth file", { path: authPath, error });
    }
}
export async function clearSmitheryApiKey() {
    const authPath = getSmitheryAuthPath();
    try {
        await fs.rm(authPath);
        return true;
    }
    catch (error) {
        if (isEnoent(error))
            return false;
        throw error;
    }
}
