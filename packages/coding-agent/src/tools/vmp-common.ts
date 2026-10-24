import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { filterEnv } from "../eval/py/runtime";
import { ToolError } from "@reverse/tui/tools/tool-errors";

// ============================================================================
// PE64 解析与校验 (VMP x64 目标校验)
// ============================================================================

export interface Pe64Section {
	name: string;
	virtualAddress: bigint;
	virtualSize: bigint;
	rawDataOffset: bigint;
	rawDataSize: bigint;
	characteristics: number;
	isExecutable: boolean;
}
export interface Pe64Info {
	magic: number; // 0x20b (PE32+)
	machine: number; // 0x8664 (AMD64)
	characteristics: number; // File header characteristics (e.g. 0x0001 RELOCS_STRIPPED)
	imageBase: bigint;
	sizeOfImage: bigint;
	entryPointRva: bigint;
	entryPointVa: bigint;
	numSections: number;
	sections: Pe64Section[];
}

const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;
const PE32_PLUS_MAGIC = 0x020b;
const PE32_MAGIC = 0x010b;
const MIN_OPTIONAL_HEADER_SIZE_PE64 = 112; // PE32+ Optional Header 基础大小（不含数据目录）
const MAX_TARGET_BYTES = 500 * 1024 * 1024; // 单个静态输入最大 500MB

/**
 * 校验目标二进制为合法的 x64 PE (PE32+ / AMD64)，并提取 ImageBase/RVA/Section 等元数据。
 * 拒绝符号链接、超大文件以及格式畸变输入。
 */
export async function parseAndValidatePe64(filePath: string): Promise<Pe64Info> {
	let lstat: fs.Stats;
	try {
		lstat = await fs.promises.lstat(filePath);
	} catch (err: unknown) {
		const msg = err instanceof Error ? err.message : String(err);
		throw new ToolError(`无法访问目标文件: ${filePath} (${msg})`);
	}

	if (lstat.isSymbolicLink()) {
		throw new ToolError(`拒绝符号链接输入以防路径逃逸: ${filePath}`);
	}

	if (!lstat.isFile()) {
		throw new ToolError(`目标路径不是常规文件: ${filePath}`);
	}

	if (lstat.size < 512) {
		throw new ToolError(`文件过小，非有效 PE 文件 (${lstat.size} 字节): ${filePath}`);
	}

	if (lstat.size > MAX_TARGET_BYTES) {
		throw new ToolError(`文件超出最大允许体积 500MB (${lstat.size} 字节): ${filePath}`);
	}

	let fd: fs.promises.FileHandle | null = null;
	let buffer: Buffer;
	try {
		fd = await fs.promises.open(filePath, "r");
		const initialReadSize = Math.min(lstat.size, 4096);
		buffer = Buffer.alloc(initialReadSize);
		await fd.read(buffer, 0, initialReadSize, 0);

		// 验证 DOS 签名 "MZ"
		if (buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
			throw new ToolError(
				`非有效 PE 文件: 偏移 0 缺少 MZ 签名 (找到 0x${buffer[0].toString(16)} 0x${buffer[1].toString(16)}): ${filePath}`,
			);
		}

		// 读取 0x3C 处的 e_lfanew
		const eLfanew = buffer.readUInt32LE(0x3c);
		if (eLfanew < 64 || eLfanew + 24 > lstat.size) {
			throw new ToolError(
				`DOS 头畸变: e_lfanew (0x${eLfanew.toString(16)}) 超出合法范围 (文件大小: ${lstat.size} 字节)`,
			);
		}

		// 确保 NT 头在已读缓冲区内
		if (eLfanew + 24 > buffer.length) {
			const expandedSize = Math.min(lstat.size, eLfanew + 4096);
			buffer = Buffer.alloc(expandedSize);
			await fd.read(buffer, 0, expandedSize, 0);
		}

		// 验证 NT 签名 "PE\0\0"
		if (
			buffer[eLfanew] !== 0x50 ||
			buffer[eLfanew + 1] !== 0x45 ||
			buffer[eLfanew + 2] !== 0x00 ||
			buffer[eLfanew + 3] !== 0x00
		) {
			throw new ToolError(`非有效 PE 文件: 偏移 0x${eLfanew.toString(16)} 缺少 PE 签名: ${filePath}`);
		}

		// 读取 Machine 架构 (uint16 LE)
		const machine = buffer.readUInt16LE(eLfanew + 4);
		if (machine !== IMAGE_FILE_MACHINE_AMD64) {
			let archName = `0x${machine.toString(16)}`;
			if (machine === IMAGE_FILE_MACHINE_I386) archName = "x86 32位 (0x14c)";
			else if (machine === IMAGE_FILE_MACHINE_ARM64) archName = "ARM64 (0xaa64)";

			throw new ToolError(
				`不支持的 PE 架构: ${archName}。VMP x64 工具链严格要求 AMD64 / x64 PE 文件 (0x8664): ${filePath}`,
			);
		}
		const numSections = buffer.readUInt16LE(eLfanew + 6);
		const sizeOfOptionalHeader = buffer.readUInt16LE(eLfanew + 20);
		const characteristics = buffer.readUInt16LE(eLfanew + 22);

		if (sizeOfOptionalHeader < MIN_OPTIONAL_HEADER_SIZE_PE64) {
			throw new ToolError(
				`PE Optional Header 尺寸过小 (${sizeOfOptionalHeader} 字节, 至少需 ${MIN_OPTIONAL_HEADER_SIZE_PE64} 字节)`,
			);
		}

		const secTablePos = eLfanew + 24 + sizeOfOptionalHeader;
		const sectionEntrySize = 40;
		const secTableEnd = secTablePos + numSections * sectionEntrySize;

		if (secTableEnd > lstat.size) {
			throw new ToolError(
				`节区表超出文件边界: 需要 ${secTableEnd} 字节，实际文件大小 ${lstat.size} 字节: ${filePath}`,
			);
		}

		// 确保整个 Optional Header 和 节区表 全部读入缓冲区
		if (secTableEnd > buffer.length) {
			buffer = Buffer.alloc(secTableEnd);
			await fd.read(buffer, 0, secTableEnd, 0);
		}

		// 验证 Optional Header Magic (uint16 LE)
		const magic = buffer.readUInt16LE(eLfanew + 24);
		if (magic !== PE32_PLUS_MAGIC) {
			let magicName = `0x${magic.toString(16)}`;
			if (magic === PE32_MAGIC) magicName = "PE32 32位 (0x10b)";

			throw new ToolError(`不支持的 PE Optional Header 格式: ${magicName}。必须为 PE32+ 64位 (0x20b): ${filePath}`);
		}

		// 提取 64位 Optional Header 字段
		const entryPointRva = BigInt(buffer.readUInt32LE(eLfanew + 40));
		const imageBase = buffer.readBigUInt64LE(eLfanew + 48);
		const sizeOfImage = BigInt(buffer.readUInt32LE(eLfanew + 80));
		const entryPointVa = imageBase + entryPointRva;

		const sections: Pe64Section[] = [];
		for (let i = 0; i < numSections; i++) {
			const pos = secTablePos + i * sectionEntrySize;
			let name = "";
			for (let n = 0; n < 8; n++) {
				const b = buffer[pos + n];
				if (b === 0) break;
				name += String.fromCharCode(b);
			}
			const virtualSize = BigInt(buffer.readUInt32LE(pos + 8));
			const virtualAddress = BigInt(buffer.readUInt32LE(pos + 12));
			const rawDataSize = BigInt(buffer.readUInt32LE(pos + 16));
			const rawDataOffset = BigInt(buffer.readUInt32LE(pos + 20));
			const characteristics = buffer.readUInt32LE(pos + 36);
			const isExecutable = (characteristics & 0x20000000) !== 0;

			if (rawDataOffset + rawDataSize > BigInt(lstat.size)) {
				throw new ToolError(
					`节区 '${name}' 文件偏移超界 (0x${rawDataOffset.toString(16)} + 0x${rawDataSize.toString(16)} > ${lstat.size} 字节): ${filePath}`,
				);
			}
			const virtualSpan = virtualSize > rawDataSize ? virtualSize : rawDataSize;
			if (virtualAddress + virtualSpan > sizeOfImage) {
				throw new ToolError(
					`节区 '${name}' 虚拟地址超界 (0x${virtualAddress.toString(16)} + 0x${virtualSpan.toString(16)} > 0x${sizeOfImage.toString(16)}): ${filePath}`,
				);
			}

			sections.push({
				name,
				virtualAddress,
				virtualSize,
				rawDataOffset,
				rawDataSize,
				characteristics,
				isExecutable,
			});
		}

		return {
			magic,
			machine,
			characteristics,
			imageBase,
			sizeOfImage,
			entryPointRva,
			entryPointVa,
			numSections,
			sections,
		};
	} finally {
		if (fd) await fd.close();
	}
}

export function parseAddress(addr: string | number | bigint, paramName: string): bigint {
	let val: bigint;
	if (typeof addr === "bigint") {
		val = addr;
	} else if (typeof addr === "number") {
		if (!Number.isSafeInteger(addr) || addr < 0) {
			throw new ToolError(`Parameter '${paramName}' must be a non-negative safe integer (got ${addr})`);
		}
		val = BigInt(addr);
	} else if (typeof addr === "string") {
		const trimmed = addr.trim();
		if (!trimmed) {
			throw new ToolError(`Parameter '${paramName}' cannot be empty`);
		}
		if (trimmed.startsWith("-")) {
			throw new ToolError(`Parameter '${paramName}' must be non-negative (got '${addr}')`);
		}
		try {
			if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
				val = BigInt(trimmed);
			} else if (/[a-fA-F]/.test(trimmed)) {
				val = BigInt(`0x${trimmed}`);
			} else {
				val = BigInt(trimmed);
			}
		} catch {
			try {
				val = BigInt(`0x${trimmed}`);
			} catch {
				throw new ToolError(`Failed to parse address parameter '${paramName}': '${addr}'`);
			}
		}
	} else {
		throw new ToolError(`Parameter '${paramName}' must be a string, number, or bigint`);
	}

	if (val < 0n) {
		throw new ToolError(`Address '${paramName}' must be non-negative (got ${val})`);
	}
	if (val > 0xffffffffffffffffn) {
		throw new ToolError(`Address '${paramName}' exceeds 64-bit integer range (0xFFFFFFFFFFFFFFFF)`);
	}
	return val;
}
/**
 * 格式化 BigInt/number 地址为规范的 0x 前缀小写十六进制字符串。
 */
export function formatHexAddress(addr: bigint | number): string {
	const b = typeof addr === "bigint" ? addr : BigInt(addr);
	return `0x${b.toString(16).toLowerCase()}`;
}

/**
 * 校验 Mergen 的 start_address 必须为有效的虚拟地址 (VA >= ImageBase)。
 * 严禁猜测或隐式转换 RVA，若输入为 RVA 则明确抛出换算指引。
 */
export function validateMergenStartVa(addrInput: string | number | bigint, pe: Pe64Info): bigint {
	const addr = parseAddress(addrInput, "start_address");
	if (addr < pe.imageBase) {
		const suggestedVa = pe.imageBase + addr;
		throw new ToolError(
			`Mergen 严格要求函数起始虚拟地址 (VA >= ImageBase)。输入地址 ${formatHexAddress(addr)} 低于镜像基址 ${formatHexAddress(pe.imageBase)}。若您传入的是 RVA，请提供其 VA: ${formatHexAddress(suggestedVa)} (ImageBase + RVA)。`,
		);
	}
	const rva = addr - pe.imageBase;
	if (rva >= pe.sizeOfImage) {
		throw new ToolError(
			`起始虚拟地址 ${formatHexAddress(addr)} 超出 PE 镜像范围 ${formatHexAddress(pe.sizeOfImage)} (ImageBase: ${formatHexAddress(pe.imageBase)})。`,
		);
	}
	return addr;
}

/**
 * 校验 NoVmp 的 VM 入口地址必须为相对虚拟地址 (RVA < SizeOfImage 且不含 ImageBase)。
 * 严禁传入 VA，若输入为 VA 则明确抛出换算指引。
 */
export function validateNoVmpRva(addrInput: string | number | bigint, pe: Pe64Info, paramName: string): bigint {
	const addr = parseAddress(addrInput, paramName);
	if (addr >= pe.imageBase) {
		const suggestedRva = addr - pe.imageBase;
		throw new ToolError(
			`NoVmp ${paramName} 要求相对虚拟地址 (RVA)。输入地址 ${formatHexAddress(addr)} 大于等于镜像基址 ${formatHexAddress(pe.imageBase)}。请提供其 RVA: ${formatHexAddress(suggestedRva)} (VA - ImageBase)。`,
		);
	}
	if (addr >= pe.sizeOfImage) {
		throw new ToolError(
			`相对虚拟地址 ${formatHexAddress(addr)} 超出 PE 镜像范围 ${formatHexAddress(pe.sizeOfImage)}。`,
		);
	}
	return addr;
}

// ============================================================================
// 安全子进程树执行与流式限额
// ============================================================================

export interface SafeSubprocessOptions {
	binary: string;
	args: string[];
	cwd?: string;
	env?: Record<string, string | undefined>;
	stdinInput?: string | Uint8Array;
	timeoutMs?: number;
	maxBytes?: number;
	signal?: AbortSignal;
}

export interface SafeSubprocessResult {
	exitCode: number | null;
	stdout: string;
	stderr: string;
	stdoutBytes: number;
	stderrBytes: number;
	timedOut: boolean;
	killedOnOverflow: boolean;
	durationMs: number;
}

/**
 * 终止进程树（Windows 使用 taskkill /F /T，Unix 使用负 PID 发送信号到进程组）。
 */
export function killProcessTree(pid: number, signal: NodeJS.Signals | number = "SIGKILL"): void {
	if (!pid || pid <= 0) return;
	if (process.platform === "win32") {
		try {
			Bun.spawnSync(["taskkill", "/F", "/T", "/PID", String(pid)]);
		} catch {
			try {
				process.kill(pid, signal);
			} catch {}
		}
	} else {
		try {
			process.kill(-pid, signal);
		} catch {
			try {
				process.kill(pid, signal);
			} catch {}
		}
	}
}

/**
 * 流式读取并在超过 maxBytes 时立即中止，避免一次性分配无界内存。
 */
async function readBoundedStream(
	stream: ReadableStream<Uint8Array>,
	maxBytes: number,
	onOverflow: () => void,
): Promise<{ text: string; overflowed: boolean; bytes: number }> {
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let totalBytes = 0;
	let overflowed = false;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (value) {
				totalBytes += value.byteLength;
				if (totalBytes > maxBytes) {
					overflowed = true;
					onOverflow();
					break;
				}
				chunks.push(value);
			}
		}
	} finally {
		reader.releaseLock();
	}

	const merged = new Uint8Array(chunks.reduce((acc, c) => acc + c.byteLength, 0));
	let offset = 0;
	for (const c of chunks) {
		merged.set(c, offset);
		offset += c.byteLength;
	}
	return { text: new TextDecoder().decode(merged), overflowed, bytes: totalBytes };
}

interface BunSpawnChild {
	pid: number;
	stdout: ReadableStream<Uint8Array>;
	stderr: ReadableStream<Uint8Array>;
	exited: Promise<number>;
	kill(signal?: number): void;
}

/**
 * 执行原生二进制：
 * - 过滤敏感环境变量，防止密钥泄露
 * - 向 stdin 写入换行避免 NoVmp system("pause") 挂起
 * - 流式限额捕获 stdout/stderr，超限立即杀进程树
 * - 进程组树杀机制保证超时或中止时无孤儿进程
 */
export async function runSafeSubprocess(opts: SafeSubprocessOptions): Promise<SafeSubprocessResult> {
	const timeoutMs = Math.max(1000, opts.timeoutMs ?? 60_000);
	const maxBytes = opts.maxBytes ?? 1_048_576; // 默认 1MB 上限
	const startTime = Date.now();

	if (opts.signal?.aborted) {
		throw new ToolError("执行在子进程启动前已中止");
	}

	const cleanEnv: Record<string, string | undefined> = filterEnv({
		...process.env,
		...opts.env,
	});

	const stdinData =
		opts.stdinInput !== undefined
			? typeof opts.stdinInput === "string"
				? Buffer.from(opts.stdinInput)
				: opts.stdinInput
			: Buffer.from("\n");

	let proc: BunSpawnChild;
	try {
		proc = Bun.spawn([opts.binary, ...opts.args], {
			cwd: opts.cwd,
			env: cleanEnv,
			stdin: stdinData,
			stdout: "pipe",
			stderr: "pipe",
			detached: process.platform !== "win32",
		});
	} catch (err: unknown) {
		const msg = err instanceof Error ? err.message : String(err);
		throw new ToolError(`启动二进制 '${opts.binary}' 失败: ${msg}`);
	}

	let timedOut = false;
	let killedOnOverflow = false;
	let aborted = false;

	const timer = setTimeout(() => {
		timedOut = true;
		killProcessTree(proc.pid);
	}, timeoutMs);

	const onAbort = () => {
		aborted = true;
		killProcessTree(proc.pid);
	};
	opts.signal?.addEventListener("abort", onAbort, { once: true });

	try {
		const [stdoutRes, stderrRes, exitCode] = await Promise.all([
			readBoundedStream(proc.stdout, maxBytes, () => {
				killedOnOverflow = true;
				killProcessTree(proc.pid);
			}),
			readBoundedStream(proc.stderr, maxBytes, () => {
				killedOnOverflow = true;
				killProcessTree(proc.pid);
			}),
			proc.exited,
		]);

		clearTimeout(timer);
		if (opts.signal) opts.signal.removeEventListener("abort", onAbort);

		if (aborted || opts.signal?.aborted) {
			throw new ToolError(`进程 '${opts.binary}' 执行被中止`);
		}
		if (timedOut) {
			throw new ToolError(`进程 '${opts.binary}' 运行超时 (${timeoutMs / 1000}秒)`);
		}
		if (killedOnOverflow) {
			throw new ToolError(`进程 '${opts.binary}' 输出超出 ${maxBytes} 字节限制已终止`);
		}

		return {
			exitCode,
			stdout: stdoutRes.text,
			stderr: stderrRes.text,
			stdoutBytes: stdoutRes.bytes,
			stderrBytes: stderrRes.bytes,
			timedOut: false,
			killedOnOverflow: false,
			durationMs: Date.now() - startTime,
		};
	} catch (err: unknown) {
		clearTimeout(timer);
		if (opts.signal) opts.signal.removeEventListener("abort", onAbort);
		killProcessTree(proc.pid);
		throw err;
	}
}

// ============================================================================
// 产物校验、流式哈希与安全复制
// ============================================================================

export interface ArtifactMetadata {
	path: string;
	bytes: number;
	sha256: string;
	mtimeMs: number;
}

/**
 * 流式计算文件 SHA-256 哈希，避免将整个大文件读入内存。
 */
export async function computeStreamingHash(
	filePath: string,
	maxBytes: number = MAX_TARGET_BYTES,
): Promise<{ sha256: string; bytes: number }> {
	const stream = fs.createReadStream(filePath);
	const hash = crypto.createHash("sha256");
	let bytes = 0;

	const { promise, resolve, reject } = Promise.withResolvers<{ sha256: string; bytes: number }>();

	stream.on("data", (chunk: Buffer | string) => {
		const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
		bytes += buf.length;
		if (bytes > maxBytes) {
			stream.destroy();
			reject(new ToolError(`文件大小超过允许上限 (${bytes} > ${maxBytes} 字节): ${filePath}`));
			return;
		}
		hash.update(buf);
	});

	stream.on("error", (err: Error) => {
		reject(new ToolError(`读取文件计算哈希失败: ${filePath} (${err.message})`));
	});

	stream.on("end", () => {
		resolve({ sha256: hash.digest("hex"), bytes });
	});

	return promise;
}

/**
 * 校验并获取生成产物的元数据。拒绝符号链接与空文件。
 */
export async function getFileMetadata(filePath: string): Promise<ArtifactMetadata | null> {
	try {
		const lstat = await fs.promises.lstat(filePath);
		if (lstat.isSymbolicLink() || !lstat.isFile() || lstat.size === 0) return null;
		if (lstat.size > MAX_TARGET_BYTES) return null;

		const { sha256, bytes } = await computeStreamingHash(filePath, MAX_TARGET_BYTES);
		return {
			path: path.resolve(filePath),
			bytes,
			sha256,
			mtimeMs: lstat.mtimeMs,
		};
	} catch {
		return null;
	}
}

/**
 * 安全复制产物：
 * - 拒绝目标已存在文件 (使用 COPYFILE_EXCL)，防止静默覆盖用户已有文件
 * - 拒绝目标通过符号链接或硬链接别名指向禁止的 inode (如原始输入样本)
 */
export async function safePublishArtifact(
	sourcePath: string,
	destPath: string,
	forbiddenInodes?: Set<string>,
): Promise<ArtifactMetadata> {
	const resolvedSource = path.resolve(sourcePath);
	const resolvedDest = path.resolve(destPath);

	const srcLstat = await fs.promises.lstat(resolvedSource).catch(() => null);
	if (!srcLstat || !srcLstat.isFile() || srcLstat.size === 0) {
		throw new ToolError(`源产物不存在或为空: ${resolvedSource}`);
	}

	const destLstat = await fs.promises.lstat(resolvedDest).catch(() => null);
	if (destLstat) {
		const destKey = `${destLstat.dev}:${destLstat.ino}`;
		if (forbiddenInodes && forbiddenInodes.has(destKey)) {
			throw new ToolError(`目标路径指向被保护的原始输入文件或链接: ${resolvedDest}`);
		}
		throw new ToolError(`目标路径已存在，拒绝静默覆盖: ${resolvedDest}`);
	}

	await fs.promises.mkdir(path.dirname(resolvedDest), { recursive: true });
	await fs.promises.copyFile(resolvedSource, resolvedDest, fs.constants.COPYFILE_EXCL);

	const postDestLstat = await fs.promises.lstat(resolvedDest);
	const postKey = `${postDestLstat.dev}:${postDestLstat.ino}`;
	if (forbiddenInodes && forbiddenInodes.has(postKey)) {
		throw new ToolError(`安全拦截: 目标文件与被保护文件共享同一 inode: ${resolvedDest}`);
	}

	const meta = await getFileMetadata(resolvedDest);
	if (!meta) {
		throw new ToolError(`复制后无法校验目标产物: ${resolvedDest}`);
	}
	return meta;
}

/**
 * 语法检查 Mergen 产出的 LLVM IR (.ll) 文件：必须包含 ModuleID 或 define 语句。
 */
export async function validateLlvmIr(filePath: string): Promise<void> {
	const stat = await fs.promises.lstat(filePath).catch(() => null);
	if (!stat || !stat.isFile() || stat.size === 0) {
		throw new ToolError(`LLVM IR 产物不存在或为空: ${filePath}`);
	}

	const fd = await fs.promises.open(filePath, "r");
	try {
		const readLen = Math.min(stat.size, 8192);
		const buf = Buffer.alloc(readLen);
		await fd.read(buf, 0, readLen, 0);
		const text = buf.toString("utf-8");

		const hasModule = text.includes("ModuleID") || text.includes("source_filename");
		const hasDefine = text.includes("define ");

		if (!hasModule && !hasDefine) {
			throw new ToolError(`生成的 .ll 文件缺少合法 LLVM IR 标记 (未找到 ModuleID 或 define 语句): ${filePath}`);
		}
	} finally {
		await fd.close();
	}
}
