import { redactMemorySecrets } from "../memory-backend/redact";
export const MAX_TITLE_LENGTH = 256;
export const MAX_TARGET_LENGTH = 512;
export const MAX_LOCATOR_LENGTH = 512;
export const MAX_SOURCE_TOOL_LENGTH = 64;
export const MAX_FIELD_LENGTH = 32768; // 32 KiB
export const MAX_EXCERPT_LENGTH = 16384; // 16 KiB
export const MAX_NOTES_LENGTH = 8192; // 8 KiB
export const MAX_TAGS_COUNT = 20;
export const MAX_TAG_LENGTH = 64;
export const DEFAULT_LIST_LIMIT = 20;
export const MAX_LIST_LIMIT = 100;
export const MAX_INLINE_CHARS = 4000;
export function createEvidenceId(kind) {
    const shortKind = kind === "hypothesis" ? "hyp" : kind === "conclusion" ? "conc" : kind === "unknown" ? "unk" : "fact";
    return `ev_${shortKind}_${Bun.randomUUIDv7()}`;
}
export function encodeEvidenceProjectKey(repositoryRoot) {
    const normalized = repositoryRoot.replaceAll("\\", "/").replace(/\/$/, "");
    const readable = normalized
        .replace(/^\//, "")
        .replace(/[^a-zA-Z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(-80);
    return `${readable || "project"}-${Bun.SHA256.hash(normalized, "hex").slice(0, 12)}`;
}
const EMBEDDED_URL_CREDS_RE = /https?:\/\/[^/:]+:[^/@]+@/g;
export function redactEvidenceText(input) {
    if (!input)
        return input;
    const scrubbedUrls = input.replace(EMBEDDED_URL_CREDS_RE, "https://[REDACTED]@");
    return redactMemorySecrets(scrubbedUrls);
}
