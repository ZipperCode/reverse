import { isRecord } from "@rva/utils/type-guards";
/** Image metadata accepted at the untyped JS/Python display boundary. */
export function evalImageMetadata(value) {
    const metadata = {};
    if (!isRecord(value))
        return metadata;
    if (value.detail === "auto" || value.detail === "low" || value.detail === "high" || value.detail === "original") {
        metadata.detail = value.detail;
    }
    if (typeof value.url === "string")
        metadata.url = value.url;
    const file = value.providerFile;
    if (isRecord(file) && (file.provider === "openai" || file.provider === "anthropic" || file.provider === "google")) {
        metadata.providerFile = { provider: file.provider };
        if (typeof file.id === "string")
            metadata.providerFile.id = file.id;
        if (typeof file.uri === "string")
            metadata.providerFile.uri = file.uri;
        if (typeof file.expiresAt === "number" && Number.isFinite(file.expiresAt)) {
            metadata.providerFile.expiresAt = file.expiresAt;
        }
    }
    return metadata;
}
