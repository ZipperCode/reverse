/**
 * Git data model for the `omp git` fullscreen TUI.
 *
 * Owns porcelain status parsing into staged/unstaged file lists, HEAD commit
 * metadata for the clean-tree view, per-file old/new content resolution for
 * the split diff pane, and the staging/commit actions the sidebar triggers.
 */
import * as path from "node:path";
import { DiffSide, DiffStream, rasterizeSvg } from "@rva/natives";
import * as vcs from "@rva/natives/vcs";
import { BINARY_SNIFF_BYTES, isEnoent, isProbablyBinaryHeader } from "@rva/utils";
import { DIFF_CONTEXT_LINES, } from "@rva/tui/apps/git/state";
/** SHA of git's canonical empty tree: diff base for a root commit. */
const EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
/** Files larger than this render as a placeholder instead of a diff. */
const MAX_FILE_BYTES = 4 * 1024 * 1024;
/** Maximum canonical Git LFS pointer size. */
const LFS_POINTER_MAX_BYTES = 1024;
/** Pixel bounds for a terminal SVG preview. */
const SVG_PREVIEW_MAX_PX = 2048;
/** Decode guard for raster images before terminal handoff. */
const MAX_IMAGE_PIXELS = 16 * 1024 * 1024;
const LFS_VERSION = "version https://git-lfs.github.com/spec/v1";
const LFS_VERSION_BYTES = new TextEncoder().encode(LFS_VERSION);
const IMAGE_EXTENSIONS = {
    ".avif": true,
    ".bmp": true,
    ".gif": true,
    ".heic": true,
    ".heif": true,
    ".jpeg": true,
    ".jpg": true,
    ".png": true,
    ".svg": true,
    ".svgz": true,
    ".tif": true,
    ".tiff": true,
    ".webp": true,
};
function concatChunks(chunks, byteLength) {
    const first = chunks[0];
    if (first && first.byteLength >= byteLength)
        return first.subarray(0, byteLength);
    const bytes = new Uint8Array(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
        const take = Math.min(chunk.byteLength, byteLength - offset);
        bytes.set(chunk.subarray(0, take), offset);
        offset += take;
        if (offset === byteLength)
            break;
    }
    return bytes;
}
function pathLooksLikeImage(filePath) {
    return IMAGE_EXTENSIONS[path.extname(filePath).toLowerCase()] === true;
}
function couldBeLfsPointer(bytes) {
    if (bytes.byteLength > LFS_POINTER_MAX_BYTES)
        return false;
    const compared = Math.min(bytes.byteLength, LFS_VERSION_BYTES.byteLength);
    for (let index = 0; index < compared; index++) {
        if (bytes[index] !== LFS_VERSION_BYTES[index])
            return false;
    }
    return true;
}
function parseLfsPointer(bytes) {
    if (bytes.byteLength > LFS_POINTER_MAX_BYTES)
        return null;
    let text;
    try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    }
    catch {
        return null;
    }
    const lines = text.split(/\r?\n/);
    if (lines[0] !== LFS_VERSION)
        return null;
    let oid;
    let size;
    for (const line of lines.slice(1)) {
        const oidMatch = /^oid sha256:([0-9a-f]{64})$/.exec(line);
        if (oidMatch) {
            oid = oidMatch[1];
            continue;
        }
        const sizeMatch = /^size ([0-9]+)$/.exec(line);
        if (sizeMatch)
            size = Number(sizeMatch[1]);
    }
    return oid && Number.isSafeInteger(size) ? { oid, size: size ?? 0 } : null;
}
function looksLikeSvg(bytes, filePath) {
    const extension = path.extname(filePath).toLowerCase();
    if (extension === ".svg" || extension === ".svgz")
        return true;
    if (isProbablyBinaryHeader(bytes))
        return false;
    try {
        return /<svg(?:\\s|>)/i.test(new TextDecoder("utf-8", { fatal: true }).decode(bytes, { stream: true }));
    }
    catch {
        return false;
    }
}
function imageMimeType(format) {
    switch (format) {
        case "jpeg":
            return "image/jpeg";
        case "png":
            return "image/png";
        case "webp":
            return "image/webp";
        case "heic":
            return "image/heic";
        case "avif":
            return "image/avif";
        case "bmp":
            return "image/bmp";
        case "tiff":
            return "image/tiff";
        case "gif":
            return "image/gif";
    }
}
function bytesToBase64(bytes) {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64");
}
async function decodeReviewImage(bytes, options) {
    const key = options.lfsOid ?? Bun.hash.xxHash64(bytes).toString(16);
    if (looksLikeSvg(bytes.subarray(0, BINARY_SNIFF_BYTES), options.filePath)) {
        try {
            const png = await rasterizeSvg(bytes, SVG_PREVIEW_MAX_PX, SVG_PREVIEW_MAX_PX);
            const metadata = await new Bun.Image(png, { maxPixels: MAX_IMAGE_PIXELS }).metadata();
            return {
                data: bytesToBase64(png),
                mimeType: "image/png",
                sourceMimeType: "image/svg+xml",
                widthPx: metadata.width,
                heightPx: metadata.height,
                byteLength: bytes.byteLength,
                key,
                lfsOid: options.lfsOid,
            };
        }
        catch {
            return null;
        }
    }
    try {
        const image = new Bun.Image(bytes, { maxPixels: MAX_IMAGE_PIXELS });
        const metadata = await image.metadata();
        return {
            data: metadata.format === "png" ? bytesToBase64(bytes) : await image.png().toBase64(),
            mimeType: "image/png",
            sourceMimeType: imageMimeType(metadata.format),
            widthPx: metadata.width,
            heightPx: metadata.height,
            byteLength: bytes.byteLength,
            key,
            lfsOid: options.lfsOid,
        };
    }
    catch {
        return null;
    }
}
function kindFromLetter(letter) {
    switch (letter) {
        case "A":
            return "added";
        case "D":
            return "deleted";
        case "R":
        case "C":
            return "renamed";
        case "U":
            return "conflicted";
        default:
            return "modified";
    }
}
const CONFLICT_STATES = { DD: true, AU: true, UD: true, UA: true, DU: true, AA: true, UU: true };
function mapNumstat(entries) {
    return entries.map(entry => ({
        path: entry.path,
        additions: entry.added ?? 0,
        deletions: entry.removed ?? 0,
    }));
}
/**
 * Repository state backing the git TUI. `refresh()` re-reads everything and
 * returns whether the observable state changed since the previous refresh.
 */
export class GitModel {
    cwd;
    #repo;
    /** Resolved SHA when the TUI is pinned to one commit (`omp git <rev>`). */
    pinnedSha;
    branch = null;
    unstaged = [];
    staged = [];
    headCommit = null;
    #fingerprint = "";
    #statusStatsLoad = null;
    #headFilesLoad = null;
    #lfsMediaDir = null;
    constructor(cwd, options = {}) {
        this.cwd = cwd;
        this.#repo = vcs.requireGit(cwd);
        this.pinnedSha = options.pinnedSha ?? null;
    }
    /** True when the working tree and index carry no changes. */
    get clean() {
        return this.unstaged.length === 0 && this.staged.length === 0;
    }
    /** Re-read fast repository state; expensive numstats load separately. */
    async refresh() {
        if (this.pinnedSha) {
            if (this.#fingerprint === this.pinnedSha)
                return false;
            this.#fingerprint = this.pinnedSha;
            this.#headFilesLoad = null;
            this.headCommit = await this.#loadHeadMetadata(this.pinnedSha);
            return true;
        }
        const [statusText, branchName, headSha] = await Promise.all([
            this.#repo.statusPorcelain({ nulTerminated: true, untracked: "all" }).catch(() => null),
            this.#repo.currentBranch(),
            this.#repo.headSha(),
        ]);
        if (statusText === null)
            throw new Error("Not a git repository");
        const fingerprint = `${headSha ?? ""}\u0000${statusText}`;
        if (fingerprint === this.#fingerprint) {
            this.branch = branchName ?? null;
            return false;
        }
        this.#fingerprint = fingerprint;
        this.#statusStatsLoad = null;
        this.branch = branchName ?? null;
        this.#setChanges(statusText);
        if ((headSha ?? null) !== this.headCommit?.sha) {
            this.#headFilesLoad = null;
            this.headCommit = headSha ? await this.#loadHeadMetadata(headSha) : null;
        }
        return true;
    }
    /** Populate changed-line counts after the file list is already interactive. */
    async loadChangeStats() {
        if (this.clean)
            return false;
        if (this.#statusStatsLoad)
            return await this.#statusStatsLoad;
        const fingerprint = this.#fingerprint;
        const load = (async () => {
            const [unstagedStat, stagedStat] = await Promise.all([
                this.#repo
                    .numstat({})
                    .then(mapNumstat)
                    .catch(() => []),
                this.#repo
                    .numstat({ cached: true })
                    .then(mapNumstat)
                    .catch(() => []),
            ]);
            if (fingerprint !== this.#fingerprint)
                return false;
            const unstagedCounts = new Map(unstagedStat.map(entry => [entry.path, entry]));
            const stagedCounts = new Map(stagedStat.map(entry => [entry.path, entry]));
            this.unstaged = this.#withCounts(this.unstaged, unstagedCounts);
            this.staged = this.#withCounts(this.staged, stagedCounts);
            return true;
        })();
        this.#statusStatsLoad = load;
        try {
            return await load;
        }
        finally {
            if (this.#statusStatsLoad === load)
                this.#statusStatsLoad = null;
        }
    }
    /** Load changed-file details for the clean commit view without delaying initial paint. */
    async loadHeadFiles() {
        const head = this.headCommit;
        if (!head || !this.clean || head.filesLoaded)
            return false;
        if (this.#headFilesLoad)
            return await this.#headFilesLoad;
        const load = (async () => {
            const base = head.parents[0] ?? EMPTY_TREE;
            const numstat = await this.#repo
                .numstat({ base, head: head.sha })
                .then(mapNumstat)
                .catch(() => []);
            if (this.headCommit?.sha !== head.sha)
                return false;
            this.headCommit = {
                ...head,
                files: numstat.map(entry => ({
                    path: entry.path,
                    kind: entry.additions > 0 && entry.deletions === 0 ? "added" : "modified",
                    area: "commit",
                    additions: entry.additions,
                    deletions: entry.deletions,
                })),
                filesLoaded: true,
            };
            return true;
        })();
        this.#headFilesLoad = load;
        try {
            return await load;
        }
        finally {
            if (this.#headFilesLoad === load)
                this.#headFilesLoad = null;
        }
    }
    #setChanges(statusText) {
        const unstaged = [];
        const staged = [];
        const tokens = statusText.split("\0");
        for (let i = 0; i < tokens.length; i++) {
            const record = tokens[i];
            if (record.length < 4)
                continue;
            const x = record[0];
            const y = record[1];
            const filePath = record.slice(3);
            // In `-z` output a rename/copy record is followed by the original path
            // as its own NUL-separated token.
            const origPath = x === "R" || x === "C" ? tokens[++i] : undefined;
            if (x === "?" && y === "?") {
                unstaged.push({ path: filePath, kind: "untracked", area: "unstaged" });
                continue;
            }
            if (CONFLICT_STATES[`${x}${y}`]) {
                unstaged.push({ path: filePath, kind: "conflicted", area: "unstaged" });
                continue;
            }
            if (x !== " ")
                staged.push({ path: filePath, origPath, kind: kindFromLetter(x), area: "staged" });
            if (y !== " ")
                unstaged.push({ path: filePath, kind: kindFromLetter(y), area: "unstaged" });
        }
        this.unstaged = unstaged;
        this.staged = staged;
    }
    #withCounts(files, counts) {
        return files.map(file => {
            const count = counts.get(file.path);
            return count ? { ...file, additions: count.additions, deletions: count.deletions } : file;
        });
    }
    async #loadHeadMetadata(sha) {
        try {
            const details = await this.#repo.commitDetails(sha);
            const [subject = "", ...bodyLines] = details.message.split("\n");
            return {
                sha,
                shortSha: sha.slice(0, 8),
                subject,
                body: bodyLines.join("\n").trim(),
                authorName: details.author.name,
                authorEmail: details.author.email,
                authorDate: details.author.date ?? "",
                parents: details.parents,
                files: [],
                filesLoaded: false,
            };
        }
        catch {
            return null;
        }
    }
    /** Stream old/new sources concurrently, emitting complete lines as they arrive. */
    async streamContents(file, onProgress, signal) {
        const stream = new DiffStream();
        let oldLineOffset = 0;
        let newLineOffset = 0;
        let lastProgress = null;
        const emit = () => {
            const progress = stream.progress();
            const oldLines = stream.lines(DiffSide.Old, oldLineOffset, progress.oldLines - oldLineOffset);
            const newLines = stream.lines(DiffSide.New, newLineOffset, progress.newLines - newLineOffset);
            const stateChanged = lastProgress === null ||
                progress.stableCommonLines !== lastProgress.stableCommonLines ||
                progress.oldDone !== lastProgress.oldDone ||
                progress.newDone !== lastProgress.newDone ||
                progress.binary !== lastProgress.binary ||
                progress.tooLarge !== lastProgress.tooLarge;
            if (oldLines.length > 0 || newLines.length > 0 || stateChanged) {
                onProgress({ oldLineOffset, oldLines, newLineOffset, newLines, progress });
            }
            oldLineOffset = progress.oldLines;
            newLineOffset = progress.newLines;
            lastProgress = progress;
        };
        const empty = (side) => {
            stream.finishSide(side);
            emit();
            return Promise.resolve({ kind: "empty" });
        };
        const filePath = path.join(this.cwd, file.path);
        const oldPath = path.join(this.cwd, file.origPath ?? file.path);
        let oldSource;
        let newSource;
        let oldRef;
        let newRef;
        switch (file.area) {
            case "unstaged":
                oldSource =
                    file.kind === "untracked"
                        ? empty(DiffSide.Old)
                        : this.#streamGitSide(stream, DiffSide.Old, `:0:${file.path}`, file.path, emit, signal);
                if (file.kind !== "untracked")
                    oldRef = { path: filePath, rev: ":0" };
                newSource =
                    file.kind === "deleted"
                        ? empty(DiffSide.New)
                        : this.#streamFileSide(stream, DiffSide.New, filePath, file.path, emit, signal);
                if (file.kind !== "deleted")
                    newRef = { path: filePath };
                break;
            case "staged":
                oldSource = this.#streamGitSide(stream, DiffSide.Old, `HEAD:${file.origPath ?? file.path}`, file.origPath ?? file.path, emit, signal);
                newSource = this.#streamGitSide(stream, DiffSide.New, `:0:${file.path}`, file.path, emit, signal);
                oldRef = { path: oldPath, rev: "HEAD" };
                newRef = { path: filePath, rev: ":0" };
                break;
            case "commit": {
                const head = this.headCommit;
                const base = head?.parents[0];
                oldSource = base
                    ? this.#streamGitSide(stream, DiffSide.Old, `${base}:${file.origPath ?? file.path}`, file.origPath ?? file.path, emit, signal)
                    : empty(DiffSide.Old);
                newSource = head
                    ? this.#streamGitSide(stream, DiffSide.New, `${head.sha}:${file.path}`, file.path, emit, signal)
                    : empty(DiffSide.New);
                if (base)
                    oldRef = { path: oldPath, rev: base };
                if (head)
                    newRef = { path: filePath, rev: head.sha };
                break;
            }
        }
        const [oldSide, newSide] = await Promise.all([oldSource, newSource]);
        const oldDiffable = oldSide.kind === "empty" || oldSide.kind === "text";
        const newDiffable = newSide.kind === "empty" || newSide.kind === "text";
        if (oldDiffable && newDiffable) {
            return {
                kind: "text",
                oldText: stream.text(DiffSide.Old),
                newText: stream.text(DiffSide.New),
                streamResult: await stream.finish(DIFF_CONTEXT_LINES),
            };
        }
        return {
            kind: "asset",
            old: oldSide,
            new: newSide,
            oldRef: oldSide.kind === "empty" ? undefined : oldRef,
            newRef: newSide.kind === "empty" ? undefined : newRef,
        };
    }
    async #streamGitSide(stream, side, spec, filePath, emit, signal) {
        const chunks = [];
        let byteLength = 0;
        let streaming = false;
        try {
            const result = await this.#repo.showBlob(spec, MAX_FILE_BYTES, signal);
            if (result.truncated) {
                stream.markTooLarge(side);
                emit();
                return { kind: "tooLarge" };
            }
            for (const chunk of [result.data]) {
                byteLength += chunk.byteLength;
                if (streaming) {
                    const progress = stream.pushBytes(side, chunk);
                    emit();
                    if (progress.binary) {
                        stream.finishSide(side);
                        emit();
                        return { kind: "binary" };
                    }
                    continue;
                }
                chunks.push(chunk);
                const header = concatChunks(chunks, Math.min(byteLength, BINARY_SNIFF_BYTES));
                const keepBuffered = pathLooksLikeImage(filePath) ||
                    couldBeLfsPointer(header) ||
                    looksLikeSvg(header, filePath) ||
                    isProbablyBinaryHeader(header);
                if (keepBuffered || byteLength < BINARY_SNIFF_BYTES)
                    continue;
                streaming = true;
                for (const buffered of chunks)
                    stream.pushBytes(side, buffered);
                chunks.length = 0;
                emit();
            }
            if (!streaming) {
                return await this.#finishBufferedSide(stream, side, concatChunks(chunks, byteLength), filePath, emit, signal);
            }
            stream.finishSide(side);
            emit();
            return { kind: "text", byteLength };
        }
        catch (error) {
            if (signal?.aborted)
                throw error;
            if (vcs.isVcsError(error)) {
                stream.finishSide(side);
                emit();
                return { kind: "empty" };
            }
            throw error;
        }
    }
    async #streamFileSide(stream, side, filePath, displayPath, emit, signal) {
        signal?.throwIfAborted();
        const file = Bun.file(filePath);
        const byteLength = file.size;
        if (byteLength > MAX_FILE_BYTES) {
            stream.markTooLarge(side);
            emit();
            return { kind: "tooLarge", byteLength };
        }
        const header = await file.slice(0, BINARY_SNIFF_BYTES).bytes();
        signal?.throwIfAborted();
        if (pathLooksLikeImage(displayPath) ||
            couldBeLfsPointer(header) ||
            looksLikeSvg(header, displayPath) ||
            isProbablyBinaryHeader(header)) {
            const bytes = header.byteLength === byteLength ? header : await file.bytes();
            signal?.throwIfAborted();
            if (bytes.byteLength > MAX_FILE_BYTES) {
                stream.markTooLarge(side);
                emit();
                return { kind: "tooLarge", byteLength: bytes.byteLength };
            }
            return await this.#finishBufferedSide(stream, side, bytes, displayPath, emit, signal);
        }
        let done = false;
        const reading = stream.openFile(side, filePath, MAX_FILE_BYTES, signal);
        reading.then(() => {
            done = true;
        }, () => {
            done = true;
        });
        while (!done) {
            await Bun.sleep(4);
            emit();
        }
        const progress = await reading;
        emit();
        return progress.binary ? { kind: "binary", byteLength } : { kind: "text", byteLength };
    }
    async #finishBufferedSide(stream, side, bytes, filePath, emit, signal, lfsOid) {
        signal?.throwIfAborted();
        if (!lfsOid) {
            const pointer = parseLfsPointer(bytes);
            if (pointer) {
                const object = await this.#loadLfsObject(pointer, signal);
                if (object.kind !== "loaded") {
                    stream.finishSide(side);
                    emit();
                    return object;
                }
                return await this.#finishBufferedSide(stream, side, object.bytes, filePath, emit, signal, pointer.oid);
            }
        }
        const header = bytes.subarray(0, BINARY_SNIFF_BYTES);
        if (pathLooksLikeImage(filePath) || looksLikeSvg(header, filePath) || isProbablyBinaryHeader(header)) {
            const image = await decodeReviewImage(bytes, { filePath, lfsOid });
            signal?.throwIfAborted();
            if (image) {
                stream.finishSide(side);
                emit();
                return { kind: "image", image };
            }
        }
        if (isProbablyBinaryHeader(header)) {
            stream.finishSide(side);
            emit();
            return { kind: "binary", byteLength: bytes.byteLength, lfsOid };
        }
        const progress = stream.pushBytes(side, bytes);
        stream.finishSide(side);
        emit();
        return progress.binary
            ? { kind: "binary", byteLength: bytes.byteLength, lfsOid }
            : { kind: "text", byteLength: bytes.byteLength, lfsOid };
    }
    async #loadLfsObject(pointer, signal) {
        if (pointer.size > MAX_FILE_BYTES) {
            return { kind: "tooLarge", byteLength: pointer.size, lfsOid: pointer.oid };
        }
        this.#lfsMediaDir ??= this.#repo
            .lfsMediaDir()
            .then(mediaDir => mediaDir ?? null)
            .catch(() => null);
        const mediaDir = await this.#lfsMediaDir;
        if (!mediaDir)
            return { kind: "lfsMissing", oid: pointer.oid, byteLength: pointer.size };
        const objectPath = path.join(mediaDir, pointer.oid.slice(0, 2), pointer.oid.slice(2, 4), pointer.oid);
        try {
            const bytes = await Bun.file(objectPath).bytes();
            signal?.throwIfAborted();
            if (bytes.byteLength !== pointer.size) {
                return { kind: "lfsMissing", oid: pointer.oid, byteLength: pointer.size };
            }
            return { kind: "loaded", bytes };
        }
        catch (error) {
            if (!isEnoent(error))
                throw error;
            return { kind: "lfsMissing", oid: pointer.oid, byteLength: pointer.size };
        }
    }
    /** Stage the given files (or everything when omitted). */
    async stage(files) {
        await this.#repo.stageFiles(files?.map(file => file.path) ?? []);
    }
    /** Unstage the given files (or everything when omitted). */
    async unstage(files) {
        await this.#repo.unstage(files?.map(file => file.path) ?? []);
    }
    /**
     * Throw away the given files' changes. Unstaged entries revert the
     * worktree to the index (untracked files are deleted); staged entries
     * reset both index and worktree to HEAD, which also drops any unstaged
     * edits on the same path. Conflicted entries are skipped.
     */
    async discard(files) {
        const worktree = [];
        const untracked = [];
        const staged = [];
        const stagedNew = [];
        for (const file of files) {
            if (file.kind === "conflicted")
                continue;
            if (file.area === "unstaged") {
                (file.kind === "untracked" ? untracked : worktree).push(file.path);
            }
            else if (file.area === "staged") {
                staged.push(file.path);
                if (file.origPath)
                    staged.push(file.origPath);
                // Paths absent from HEAD stay on disk after the index reset; clean them like untracked files.
                if (file.kind === "added" || file.kind === "renamed")
                    stagedNew.push(file.path);
            }
        }
        if (worktree.length > 0)
            await this.#repo.restore({ files: worktree, worktree: true });
        if (staged.length > 0)
            await this.#repo.restore({ files: staged, source: "HEAD", staged: true, worktree: true });
        const toClean = [...untracked, ...stagedNew];
        if (toClean.length > 0)
            await this.#repo.clean({ paths: toClean });
    }
    /** Create (or amend) a commit from the staged changes. */
    async commit(message, options = {}) {
        await this.#repo.commitCreate(message, { amend: options.amend });
    }
    /** Apply a patch to the index (`cached`) and/or worktree; `reverse` undoes it. */
    async applyPatch(patchText, options = {}) {
        if (!patchText.trim())
            return;
        await this.#repo.applyPatch(patchText, options);
    }
}
