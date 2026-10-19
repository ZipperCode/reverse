import type { Subprocess } from "bun";
import { logger } from "@reverse/utils";
import { stageRunnerScript } from "../eval/runner-cache";
import FRIDA_WORKER_SCRIPT from "./frida-worker.py" with { type: "text" };
import type { FridaSessionTarget } from "./frida-session";

export interface FridaLiveInitResult {
	status: "ok";
	pid?: number;
	device?: string;
}

export interface FridaLiveLoadResult {
	status: "ok";
	exports: string[];
}

export interface FridaLiveRpcResult {
	status: "ok";
	result: unknown;
}

export interface FridaLiveStatusResult {
	status: "ok";
	alive: boolean;
	detached: boolean;
	detachReason?: string;
	hasScript: boolean;
	exports: string[];
	pid?: number;
}

export interface FridaLiveEventFrame {
	type: "event";
	kind: "message" | "stdout" | "stderr" | "error" | "lifecycle";
	channel?: string;
	payload: unknown;
	raw?: string;
	metadata?: Record<string, unknown>;
	timestamp: string;
}

interface PendingRequest {
	resolve: (value: unknown) => void;
	reject: (reason: unknown) => void;
	timer?: NodeJS.Timeout;
}

export class FridaLiveClient {
	private child?: Subprocess<"pipe", "pipe", "pipe">;
	private pendingRequests = new Map<string, PendingRequest>();
	private eventListener?: (event: FridaLiveEventFrame) => void;
	private isExited = false;
	private exitCode?: number;
	private stderrLines: string[] = [];

	constructor(
		private readonly options: {
			pythonPath: string;
			cwd: string;
		},
	) {}

	get pid(): number | undefined {
		return this.child?.pid;
	}

	get exited(): boolean {
		return this.isExited;
	}

	onEvent(listener?: (event: FridaLiveEventFrame) => void): void {
		this.eventListener = listener;
	}

	async start(): Promise<void> {
		const stagedWorkerPath = await stageRunnerScript("frida-worker", "py", FRIDA_WORKER_SCRIPT);

		const child = Bun.spawn([this.options.pythonPath, "-u", stagedWorkerPath], {
			cwd: this.options.cwd,
			stdin: "pipe",
			stdout: "pipe",
			stderr: "pipe",
		});
		this.child = child;

		child.exited
			.then(code => {
				this.exitCode = code;
				this.handleProcessTermination(`Worker process exited with code ${code}`);
			})
			.catch(() => {});

		this.readStdoutLoop(child.stdout);
		this.readStderrLoop(child.stderr);
	}

	private async readStdoutLoop(stdout: ReadableStream<Uint8Array>): Promise<void> {
		const reader = stdout.getReader();
		const decoder = new TextDecoder();
		let buffer = "";
		const MAX_FRAME_BYTES = 1024 * 1024;
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				buffer += decoder.decode(value, { stream: true });

				let newlineIdx = buffer.indexOf("\n");
				while (newlineIdx !== -1) {
					const line = buffer.slice(0, newlineIdx).trim();
					buffer = buffer.slice(newlineIdx + 1);
					if (line.length > 0) {
						if (line.length > MAX_FRAME_BYTES) {
							this.handleProcessTermination("Line exceeded maximum frame limit of 1MiB");
							this.destroy();
							return;
						}
						try {
							const parsed = JSON.parse(line);
							this.handleIncomingFrame(parsed);
						} catch (err) {
							// Malformed IPC fails safely without logging raw payload (to avoid leaking secrets)
							logger.warn("Malformed NDJSON frame received from Frida worker", { error: String(err) });
						}
					}
					newlineIdx = buffer.indexOf("\n");
				}

				if (buffer.length > MAX_FRAME_BYTES) {
					this.handleProcessTermination("Incomplete frame line exceeded maximum allowed size of 1MiB");
					this.destroy();
					return;
				}
			}
		} catch {
			// Stream finished or closed
		} finally {
			this.handleProcessTermination("Worker stdout stream closed");
		}
	}

	private async readStderrLoop(stderr: ReadableStream<Uint8Array>): Promise<void> {
		const reader = stderr.getReader();
		const decoder = new TextDecoder();
		let buffer = "";
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				buffer += decoder.decode(value, { stream: true });
				let newlineIdx = buffer.indexOf("\n");
				while (newlineIdx !== -1) {
					const line = buffer.slice(0, newlineIdx);
					buffer = buffer.slice(newlineIdx + 1);
					this.stderrLines.push(line);
					if (this.stderrLines.length > 100) {
						this.stderrLines.shift();
					}
					newlineIdx = buffer.indexOf("\n");
				}
			}
		} catch {
			// Ignore stderr reader close
		}
	}

	private handleIncomingFrame(parsed: unknown): void {
		if (!parsed || typeof parsed !== "object") return;
		const frameObj = parsed as Record<string, unknown>;
		if (frameObj.type === "event") {
			try {
				this.eventListener?.(frameObj as unknown as FridaLiveEventFrame);
			} catch (err) {
				logger.warn("Error inside Frida live event listener callback", { error: String(err) });
			}
			return;
		}

		const reqId = frameObj.id;
		if (typeof reqId === "string") {
			const pending = this.pendingRequests.get(reqId);
			if (pending) {
				this.pendingRequests.delete(reqId);
				clearTimeout(pending.timer);

				if (frameObj.type === "error") {
					const errMsg = typeof frameObj.error === "string" ? frameObj.error : "Frida worker error";
					pending.reject(new Error(errMsg));
				} else {
					pending.resolve(frameObj);
				}
			}
		}
	}

	private handleProcessTermination(reason: string): void {
		if (this.isExited) return;
		this.isExited = true;

		for (const [, pending] of this.pendingRequests) {
			clearTimeout(pending.timer);
			pending.reject(new Error(`${reason} (stderr: ${this.stderrLines.slice(-5).join("; ")})`));
		}
		this.pendingRequests.clear();
	}

	async sendRequest<T = Record<string, unknown>>(
		req: Record<string, unknown>,
		options: { timeoutMs?: number; signal?: AbortSignal } = {},
	): Promise<T> {
		if (this.isExited || !this.child) {
			throw new Error(`Cannot send request to stopped Frida worker (exitCode: ${this.exitCode})`);
		}

		if (options.signal?.aborted) {
			throw new Error("Request aborted");
		}

		const id = Bun.randomUUIDv7();
		const timeoutMs = options.timeoutMs ?? 30_000;
		const { promise, resolve, reject } = Promise.withResolvers<T>();

		let timer: NodeJS.Timeout | undefined;
		if (timeoutMs > 0) {
			timer = setTimeout(() => {
				this.pendingRequests.delete(id);
				this.destroy();
				reject(
					new Error(
						`Frida worker request timed out after ${timeoutMs}ms; worker terminated to prevent pipeline stall`,
					),
				);
			}, timeoutMs);
		}

		const onAbort = () => {
			this.pendingRequests.delete(id);
			clearTimeout(timer);
			this.destroy();
			reject(new Error("Request aborted by caller signal; worker terminated to prevent pipeline stall"));
		};

		if (options.signal) {
			options.signal.addEventListener("abort", onAbort, { once: true });
		}

		this.pendingRequests.set(id, {
			resolve: val => {
				if (options.signal) options.signal.removeEventListener("abort", onAbort);
				resolve(val as T);
			},
			reject: err => {
				if (options.signal) options.signal.removeEventListener("abort", onAbort);
				reject(err);
			},
			timer,
		});

		try {
			const line = JSON.stringify({ id, ...req }) + "\n";
			this.child!.stdin.write(line);
		} catch (err) {
			this.pendingRequests.delete(id);
			clearTimeout(timer);
			if (options.signal) options.signal.removeEventListener("abort", onAbort);
			reject(err);
		}

		return promise;
	}

	async init(target: FridaSessionTarget, timeoutMs = 30_000, signal?: AbortSignal): Promise<FridaLiveInitResult> {
		return this.sendRequest<FridaLiveInitResult>({ type: "init", target }, { timeoutMs, signal });
	}

	async load(script: string, name?: string, timeoutMs = 30_000, signal?: AbortSignal): Promise<FridaLiveLoadResult> {
		return this.sendRequest<FridaLiveLoadResult>({ type: "load", script, name }, { timeoutMs, signal });
	}

	async unload(timeoutMs = 10_000, signal?: AbortSignal): Promise<{ status: "ok" }> {
		return this.sendRequest<{ status: "ok" }>({ type: "unload" }, { timeoutMs, signal });
	}

	async rpc(method: string, args?: unknown, timeoutMs = 30_000, signal?: AbortSignal): Promise<FridaLiveRpcResult> {
		return this.sendRequest<FridaLiveRpcResult>({ type: "rpc", method, args }, { timeoutMs, signal });
	}

	async status(timeoutMs = 10_000, signal?: AbortSignal): Promise<FridaLiveStatusResult> {
		return this.sendRequest<FridaLiveStatusResult>({ type: "status" }, { timeoutMs, signal });
	}

	async resume(timeoutMs = 10_000, signal?: AbortSignal): Promise<{ status: "ok"; pid?: number }> {
		return this.sendRequest<{ status: "ok"; pid?: number }>({ type: "resume" }, { timeoutMs, signal });
	}
	async stop(timeoutMs = 5_000): Promise<void> {
		if (this.isExited || !this.child) return;
		try {
			await this.sendRequest({ type: "stop" }, { timeoutMs });
		} catch {
			// Best effort stop request
		}
		this.destroy();
	}

	destroy(): void {
		const child = this.child;
		if (child) {
			try {
				child.kill("SIGTERM");
				setTimeout(() => {
					try {
						child.kill("SIGKILL");
					} catch {}
				}, 1000);
			} catch {}
		}
		this.handleProcessTermination("FridaLiveClient destroyed");
	}
}
