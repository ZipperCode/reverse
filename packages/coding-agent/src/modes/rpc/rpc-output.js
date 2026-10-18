import * as fs from "node:fs";
import { logger, openCloexecSync, TempDir } from "@rva/utils";
const READ_BYTES = 64 * 1024;
/** Synchronous event producers spill to disk while the RPC reader applies backpressure. */
export class RpcOutputWriter {
    sink;
    onFailure;
    #spool;
    #blocked = false;
    #pumping = false;
    #pendingWrites = 0;
    #failure;
    #closing = false;
    #completion;
    constructor(sink, onFailure) {
        this.sink = sink;
        this.onFailure = onFailure;
        sink.on("drain", this.#onDrain);
        sink.on("error", this.#onError);
        sink.on("close", this.#onClose);
        process.once("exit", this.#onExit);
    }
    write(frames) {
        if (this.#failure || this.#closing)
            return;
        try {
            for (const line of frames) {
                if (this.#blocked || this.#pumping || this.#spool)
                    this.#append(line);
                else
                    this.#write(line);
            }
        }
        catch (error) {
            this.#fail(error);
        }
    }
    async close() {
        this.#closing = true;
        if (this.#failure)
            throw this.#failure;
        if (this.#pendingWrites || this.#spool || this.#pumping) {
            this.#completion ??= Promise.withResolvers();
            await this.#completion.promise;
        }
        this.sink.off("drain", this.#onDrain);
        this.sink.off("error", this.#onError);
        this.sink.off("close", this.#onClose);
        process.off("exit", this.#onExit);
    }
    #write(bytes) {
        this.#pendingWrites++;
        this.#blocked = !this.sink.write(bytes, error => {
            this.#pendingWrites--;
            if (error)
                this.#fail(error);
            else
                this.#settle();
        });
    }
    #append(line) {
        if (!this.#spool) {
            const dir = TempDir.createSync("@omp-rpc-output-");
            try {
                const file = dir.join("output");
                const handle = Bun.file(file);
                const fd = openCloexecSync(file, fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
                this.#spool = { dir, file: handle, fd, read: 0, written: 0 };
            }
            catch (error) {
                dir.removeSync();
                throw error;
            }
        }
        const spool = this.#spool;
        const bytes = Buffer.from(line);
        let offset = 0;
        // Event callbacks cannot await a disk write without retaining an unbounded queue.
        while (offset < bytes.length) {
            const written = fs.writeSync(spool.fd, bytes, offset, bytes.length - offset, spool.written);
            if (written === 0)
                throw new Error("RPC output spool write made no progress");
            offset += written;
            spool.written += written;
        }
    }
    #onDrain = () => {
        this.#blocked = false;
        void this.#pump();
    };
    #onError = (error) => this.#fail(error);
    #onClose = () => this.#fail(new Error("RPC output closed before delivery completed"));
    #onExit = () => {
        try {
            this.#removeSpool();
        }
        catch (error) {
            logger.warn("RPC output spool cleanup failed", { error: String(error) });
        }
    };
    async #pump() {
        if (this.#pumping || this.#failure)
            return;
        this.#pumping = true;
        try {
            while (this.#spool && !this.#blocked && !this.#failure) {
                const spool = this.#spool;
                const end = Math.min(spool.written, spool.read + READ_BYTES);
                const bytes = await spool.file.slice(spool.read, end).bytes();
                if (this.#failure)
                    break;
                if (bytes.length !== end - spool.read)
                    throw new Error("RPC output spool ended before delivery completed");
                spool.read = end;
                this.#write(bytes);
                if (spool.read === spool.written)
                    this.#removeSpool();
            }
        }
        catch (error) {
            this.#fail(error);
        }
        finally {
            this.#pumping = false;
            this.#settle();
        }
    }
    #removeSpool() {
        const spool = this.#spool;
        if (!spool)
            return;
        this.#spool = undefined;
        try {
            fs.closeSync(spool.fd);
        }
        finally {
            spool.dir.removeSync();
        }
    }
    #settle() {
        if (!this.#pendingWrites && !this.#spool && !this.#pumping && !this.#failure)
            this.#completion?.resolve();
    }
    #fail(error) {
        if (this.#failure)
            return;
        this.#failure = error instanceof Error ? error : new Error(String(error));
        try {
            this.#removeSpool();
        }
        catch (cleanupError) {
            this.#failure = new AggregateError([this.#failure, cleanupError], "RPC output failed and spool cleanup failed");
        }
        this.#completion?.reject(this.#failure);
        process.off("exit", this.#onExit);
        this.onFailure(this.#failure);
    }
}
