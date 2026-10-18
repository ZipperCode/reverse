import { expectOk, fetchFor, fileNameFor, multipartFile, optionString, publication, requireCredential, } from "./uploader-runtime";
const DISCORD_API_ORIGIN = "https://discord.com";
const FALLBACK_LIFETIME_MS = 24 * 60 * 60 * 1000;
function parseWebhook(value) {
    let url;
    try {
        url = new URL(value);
    }
    catch {
        throw new Error("Discord webhook credential is not a valid URL");
    }
    if (url.protocol !== "https:") {
        throw new Error("Discord webhook credential must use HTTPS");
    }
    const segments = url.pathname.split("/").filter(Boolean);
    const webhooksIndex = segments.indexOf("webhooks");
    const id = webhooksIndex >= 0 ? segments[webhooksIndex + 1] : undefined;
    const token = webhooksIndex >= 0 ? segments[webhooksIndex + 2] : undefined;
    if (!id || !token || !/^\d+$/.test(id)) {
        throw new Error("Discord webhook credential does not contain a webhook ID and token");
    }
    return { id, token };
}
function webhookEndpoint(webhook, suffix) {
    const base = `${DISCORD_API_ORIGIN}/api/v10/webhooks/${encodeURIComponent(webhook.id)}/${encodeURIComponent(webhook.token)}`;
    return new URL(suffix ? `${base}/${suffix}` : base);
}
function parseMessage(value) {
    if (!value || typeof value !== "object")
        throw new Error("Discord returned an invalid message response");
    const message = value;
    if (typeof message.id !== "string")
        throw new Error("Discord response did not include a message ID");
    if (!Array.isArray(message.attachments))
        throw new Error("Discord response did not include an attachment");
    const first = message.attachments[0];
    if (!first || typeof first !== "object")
        throw new Error("Discord response did not include an attachment");
    const attachmentUrl = first.url;
    if (typeof attachmentUrl !== "string")
        throw new Error("Discord attachment did not include a URL");
    try {
        const parsed = new URL(attachmentUrl);
        if (parsed.protocol !== "https:")
            throw new Error();
    }
    catch {
        throw new Error("Discord attachment URL is invalid");
    }
    return { id: message.id, attachmentUrl };
}
function attachmentExpiry(url, now) {
    const signedExpiry = new URL(url).searchParams.get("ex");
    if (signedExpiry && /^[0-9a-f]+$/i.test(signedExpiry)) {
        const seconds = Number.parseInt(signedExpiry, 16);
        const expiresAt = seconds * 1000;
        if (Number.isSafeInteger(expiresAt) && expiresAt > 0)
            return expiresAt;
    }
    return now + FALLBACK_LIFETIME_MS;
}
/** Create the built-in Discord webhook uploader, or `null` for another destination. */
export function createDiscordUploader(destination, config) {
    if (destination !== "discord")
        return null;
    const webhook = parseWebhook(requireCredential(config, "webhookUrl"));
    const content = optionString(config, "content");
    const threadId = optionString(config, "threadId");
    const executeUrl = webhookEndpoint(webhook);
    executeUrl.searchParams.set("wait", "true");
    if (threadId)
        executeUrl.searchParams.set("thread_id", threadId);
    return {
        destination,
        async upload(request) {
            const filename = fileNameFor(request);
            const payload = {
                attachments: [{ id: 0, filename }],
            };
            if (content !== undefined)
                payload.content = content;
            const body = multipartFile(request, "files[0]", {
                payload_json: JSON.stringify(payload),
            });
            const response = await fetchFor(config)(executeUrl, { method: "POST", body });
            await expectOk(response, destination);
            const message = parseMessage(await response.json());
            const deleteUrl = webhookEndpoint(webhook, `messages/${encodeURIComponent(message.id)}`);
            if (threadId)
                deleteUrl.searchParams.set("thread_id", threadId);
            return publication(destination, request, message.attachmentUrl, {
                expiresAt: attachmentExpiry(message.attachmentUrl, Date.now()),
                delete: { method: "DELETE", url: deleteUrl.href },
                remoteId: message.id,
            });
        },
    };
}
