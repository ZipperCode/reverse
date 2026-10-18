/**
 * Sharpshooter storage layout.
 *
 * Everything lives home-scoped under `<agentDir>/memories/sharpshooter/<bank>/`
 * (mnemopi-style project bank id, never the project working tree):
 *
 * - `architecture.md` / `product.md` / `style.md` — the memory files
 * - `queue/<sessionId>/<ts36>-<nonce>.json`        — one queued delta per file
 * - `state.json`                                   — consolidation bookkeeping
 * - `consolidate.lock`                             — cross-process single-writer lock
 */
import * as path from "node:path";
import { getMemoriesDir } from "@rva/utils";
import { projectBankSegment } from "../mnemopi/config";
/** Root for every sharpshooter bank. */
export function sharpshooterRoot(agentDir) {
    return path.join(getMemoriesDir(agentDir), "sharpshooter");
}
/** Stable per-project bank id derived from `cwd` alone (see {@link projectBankSegment}). */
export function sharpshooterBankId(cwd) {
    return projectBankSegment(path.resolve(cwd || "."));
}
/** Bank directory for a project. */
export function sharpshooterBankDir(agentDir, cwd) {
    return path.join(sharpshooterRoot(agentDir), sharpshooterBankId(cwd));
}
/** Queue root of a bank; one subdirectory per session. */
export function sharpshooterQueueDir(agentDir, cwd) {
    return path.join(sharpshooterBankDir(agentDir, cwd), "queue");
}
/** Path of one memory file inside a bank. */
export function sharpshooterMemoryFilePath(agentDir, cwd, file) {
    return path.join(sharpshooterBankDir(agentDir, cwd), file);
}
/** Advisory lock path guarding consolidation for a bank. */
// withFileLock appends ".lock" itself, so this is the bare stem.
export function sharpshooterLockPath(agentDir, cwd) {
    return path.join(sharpshooterBankDir(agentDir, cwd), "consolidate");
}
/** Read a bank's consolidation state; a missing or corrupt file yields the epoch state. */
export async function readSharpshooterState(agentDir, cwd) {
    try {
        const parsed = (await Bun.file(path.join(sharpshooterBankDir(agentDir, cwd), "state.json")).json());
        if (parsed && typeof parsed === "object" && parsed.v === 1)
            return parsed;
    }
    catch {
        // Missing or corrupt state only delays the next consolidation window; start fresh.
    }
    return { v: 1, lastConsolidatedAt: 0 };
}
/** Persist a bank's consolidation state (parent directories auto-created). */
export async function writeSharpshooterState(agentDir, cwd, state) {
    await Bun.write(path.join(sharpshooterBankDir(agentDir, cwd), "state.json"), `${JSON.stringify(state, null, "\t")}\n`);
}
