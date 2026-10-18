import { summarizeDiagnosticMessages } from "./utils";
const DIAGNOSTIC_LOCATION_PREFIX_RE = /^.*?:\d+:\d+\s+/;
export function diagnosticIdentity(message) {
    return message.replace(DIAGNOSTIC_LOCATION_PREFIX_RE, "");
}
export class DiagnosticsLedger {
    #seen = new Map();
    reduce(absPath, result) {
        const previous = this.#seen.get(absPath);
        const currentIdentities = new Set();
        const fresh = [];
        for (const message of result.messages) {
            const identity = diagnosticIdentity(message);
            currentIdentities.add(identity);
            if (!previous?.has(identity)) {
                fresh.push(message);
            }
        }
        if (currentIdentities.size === 0) {
            this.#seen.delete(absPath);
        }
        else {
            this.#seen.set(absPath, currentIdentities);
        }
        if (fresh.length === result.messages.length) {
            return result;
        }
        return {
            ...result,
            messages: fresh,
            ...summarizeDiagnosticMessages(fresh),
        };
    }
}
export function getDiagnosticsLedger(owner) {
    owner.diagnosticsLedger ??= new DiagnosticsLedger();
    return owner.diagnosticsLedger;
}
