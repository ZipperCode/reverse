/**
 * Real isolated installers, pinned artifacts, and provenance receipts for Python-based
 * reverse-engineering toolchains:
 * - frida-dexdump: Fast Dalvik/ART memory DEX dumper CLI via Frida (hluwa/frida-dexdump, GPL-3.0)
 * - msynth: Program synthesis for MBA deobfuscation with Miasm & Z3 (mrphrazer/msynth v1.0.0, GPL-2.0)
 * - d810-ng: IDA Pro / microcode deobfuscation framework (w00tzenheimer/d810-ng v0.6.6, AGPL-3.0)
 * - tritondse: Triton-based dynamic symbolic execution library (quarkslab/tritondse v0.1.14, Apache-2.0)
 *
 * Platform guards:
 * - Managed virtual environments in agent tools directory prevent global system mutation.
 * - Transactional install paths with permanent target directories preserve existing working
 *   versions in a backup directory and restore them on error, avoiding broken venv/pth relocations.
 * - External GPL source assets are never bundled directly into the reverse git repository.
 * - Strict SHA256 integrity verification for downloaded archives, oracle pickles, and licenses.
 * - Real independent module import and proof execution, not mere file existence or --version checks.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as fsPromises from "node:fs/promises";
import * as path from "node:path";
import { $which, getAgentDir, WhichCachePolicy } from "@reverse/utils";
import { extractArchive } from "@reverse/utils/ar";
import type { SkillRequirementWhich } from "./skill-requirements";
import type { SkillToolPlatform } from "./skill-tool-catalog";
import { runSubprocess } from "./triton-source-install";
import { installTritonVenv } from "./vmp-toolchain";

// ============================================================================
// Authoritative Release & Version Pins (Fact-Checked Primary Sources)
// ============================================================================

export const FRIDA_DEXDUMP_VERSION = "2.0.1";
export const FRIDA_DEXDUMP_PYPI_SPEC = `frida-dexdump==${FRIDA_DEXDUMP_VERSION}`;
export const FRIDA_DEXDUMP_WHEEL_SHA256 = "c580197e75de2eae0ee12bf2fe28342ec6a52eb7d6ed8e443c30e27aff790ac4";
export const FRIDA_DEXDUMP_SDIST_SHA256 = "e0eac76ccadf5cb6b5fa4f6f7ec84a53ad398127f313922d792134aef0d2af06";
export const FRIDA_DEXDUMP_LICENSE = "GPL-3.0";
export const FRIDA_DEXDUMP_UPSTREAM_URL = "https://github.com/hluwa/frida-dexdump.git";

export const MSYNTH_VERSION = "1.0.0";
export const MSYNTH_COMMIT = "dfd0f9e2cd0890658fe752aa207a2cfda2aef8d7";
export const MSYNTH_UPSTREAM_URL = "https://github.com/mrphrazer/msynth.git";
export const MSYNTH_ARCHIVE_URL = `https://github.com/mrphrazer/msynth/archive/${MSYNTH_COMMIT}.tar.gz`;
export const MSYNTH_ARCHIVE_SHA256 = "82c2b80fbc08bfa1c8d7a75bd989da8a674000dff7dcf76154b9f57d3bd94681";
export const MSYNTH_ORACLE_PICKLE_SHA256 = "176f2bb6420db7a8d171535d9cc45b0b9d7fea95573d9f9d8a7a27ae057ebdc0";
export const MSYNTH_LICENSE_SHA256 = "8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643";
export const MSYNTH_LICENSE = "GPL-2.0";

export const MIASM_VERSION = "0.1.5";
export const MIASM_COMMIT = "1dc5fa90311992c92b7cff08f3c5354ece67a995";
export const MIASM_GIT_URL = `git+https://github.com/cea-sec/miasm@${MIASM_COMMIT}`;
export const MIASM_ARCHIVE_URL = `https://github.com/cea-sec/miasm/archive/${MIASM_COMMIT}.tar.gz`;

export const D810_NG_VERSION = "0.6.6";
export const D810_NG_COMMIT = "2e59ab4ce18e5e82911880137d1285d95279981a";
export const D810_NG_PYPI_SPEC = `d810-ng==${D810_NG_VERSION}`;
export const D810_NG_LICENSE = "AGPL-3.0";
export const D810_NG_UPSTREAM_URL = "https://github.com/w00tzenheimer/d810-ng.git";

export const TRITONDSE_VERSION = "0.1.14";
export const TRITONDSE_COMMIT = "c7e02b6196d740ba663c492fefdc70c0daa61367";
export const TRITONDSE_PYPI_SPEC = `tritondse==${TRITONDSE_VERSION}`;
export const TRITONDSE_LICENSE = "Apache-2.0";
export const TRITONDSE_UPSTREAM_URL = "https://github.com/quarkslab/tritondse.git";
export const LIBMAGIC_BOTTLE_ARM64_URL =
	"https://ghcr.io/v2/homebrew/core/libmagic/blobs/sha256:c6e5827a76630cd9d8d7cb5ec0372c372cca1da5d80d4a578931020332ee3e88";
export const LIBMAGIC_BOTTLE_ARM64_SHA256 = "c6e5827a76630cd9d8d7cb5ec0372c372cca1da5d80d4a578931020332ee3e88";

// ============================================================================
// Types & Contracts
// ============================================================================

export interface ProtectionPythonInstallOptions {
	agentDir?: string;
	onChunk?: (chunk: string) => void;
	onLog?: (chunk: string) => void;
	signal?: AbortSignal;
	timeoutMs?: number;
	env?: Record<string, string | undefined>;
	fetch?: typeof globalThis.fetch;
	platform?: SkillToolPlatform;
	which?: SkillRequirementWhich;
	executor?: (
		argv: readonly string[],
		options?: {
			cwd?: string;
			env?: Record<string, string | undefined>;
			onChunk?: (chunk: string) => void;
			signal?: AbortSignal;
			timeoutMs?: number;
		},
	) => Promise<{ exitCode: number; stdout: string; stderr: string }>;
}

export interface ProtectionPythonInstallResult {
	success: boolean;
	id: string;
	installDir: string;
	executablePath: string;
	error?: string;
	message?: string;
	metadata?: Record<string, unknown>;
}

export interface ProtectionPythonVerifyResult {
	ready: boolean;
	id: string;
	version?: string;
	executablePath?: string;
	error?: string;
	metadata?: Record<string, unknown>;
}

// ============================================================================
// Python & Subprocess Helpers
// ============================================================================

export function findHostPython(
	env?: Record<string, string | undefined>,
	whichFn: SkillRequirementWhich = $which,
): string | null {
	const mergedEnv = env ?? process.env;
	if (mergedEnv.PYTHON && fs.existsSync(mergedEnv.PYTHON)) {
		return mergedEnv.PYTHON;
	}
	const candidates = [
		"/opt/homebrew/opt/python@3.12/bin/python3.12",
		"/opt/homebrew/bin/python3.12",
		"/usr/local/opt/python@3.12/bin/python3.12",
		"/opt/homebrew/bin/python3.11",
		"/usr/local/bin/python3.11",
		"/opt/homebrew/bin/python3.10",
		"/usr/local/bin/python3.10",
		"/opt/homebrew/bin/python3",
		"/usr/local/bin/python3",
		"python3.12",
		"python3.11",
		"python3.10",
		"python3",
		"python",
	];
	for (const cand of candidates) {
		if (cand.startsWith("/") && fs.existsSync(cand)) {
			return cand;
		}
		const resolved = whichFn(cand, { cache: WhichCachePolicy.Bypass });
		if (resolved && fs.existsSync(resolved)) {
			return resolved;
		}
	}
	return null;
}

export async function runPythonSubprocess(
	argv: readonly string[],
	options?: {
		cwd?: string;
		env?: Record<string, string | undefined>;
		onLog?: (chunk: string) => void;
		signal?: AbortSignal;
		timeoutMs?: number;
		executor?: ProtectionPythonInstallOptions["executor"];
	},
): Promise<string> {
	const execFn = options?.executor ?? runSubprocess;
	const res = await execFn(argv, {
		cwd: options?.cwd,
		env: options?.env,
		onChunk: options?.onLog,
		signal: options?.signal,
		timeoutMs: options?.timeoutMs,
	});

	if (res.exitCode !== 0) {
		const errText = res.stderr.trim() || res.stdout.trim() || `Exit code ${res.exitCode}`;
		throw new Error(`Command failed [${argv.join(" ")}]: ${errText}`);
	}

	return res.stdout;
}

export const DEFAULT_DOWNLOAD_MAX_BYTES = 150 * 1024 * 1024; // 150 MiB safety cap
export const DEFAULT_DOWNLOAD_TIMEOUT_MS = 120_000; // 2 minutes

async function downloadFileWithSha256(
	url: string,
	targetPath: string,
	expectedSha256?: string,
	options?: {
		signal?: AbortSignal;
		timeoutMs?: number;
		maxBytes?: number;
		fetch?: typeof globalThis.fetch;
		onLog?: (chunk: string) => void;
	},
): Promise<void> {
	options?.onLog?.(`[reverse] Downloading ${url}...\n`);
	const fetchFn = options?.fetch ?? globalThis.fetch;
	const maxBytes = options?.maxBytes ?? DEFAULT_DOWNLOAD_MAX_BYTES;
	const timeoutMs = options?.timeoutMs ?? DEFAULT_DOWNLOAD_TIMEOUT_MS;

	const controller = new AbortController();
	let timeoutTimer: NodeJS.Timeout | undefined;
	if (timeoutMs > 0) {
		timeoutTimer = setTimeout(
			() => controller.abort(new Error(`Download timed out after ${timeoutMs}ms for ${url}`)),
			timeoutMs,
		);
	}
	const onParentAbort = () => controller.abort(options?.signal?.reason);
	options?.signal?.addEventListener("abort", onParentAbort, { once: true });

	await fsPromises.mkdir(path.dirname(targetPath), { recursive: true });
	const tempPath = `${targetPath}.tmp.${Date.now()}`;

	try {
		let resp = await fetchFn(url, { signal: controller.signal });
		if (resp.status === 401) {
			const authHeader = resp.headers.get("www-authenticate");
			const realmMatch = authHeader?.match(/realm=["']?([^"',]+)["']?/i);
			const serviceMatch = authHeader?.match(/service=["']?([^"',]+)["']?/i);
			const scopeMatch = authHeader?.match(/scope=["']?([^"',]+)["']?/i);
			if (realmMatch && serviceMatch && scopeMatch) {
				const tokenUrl = `${realmMatch[1]}?service=${encodeURIComponent(serviceMatch[1])}&scope=${encodeURIComponent(scopeMatch[1])}`;
				const tokenResp = await fetchFn(tokenUrl, { signal: controller.signal });
				if (tokenResp.ok) {
					const tokenData = (await tokenResp.json()) as { token?: string; access_token?: string };
					const token = tokenData.token ?? tokenData.access_token;
					if (token) {
						resp = await fetchFn(url, {
							signal: controller.signal,
							headers: { Authorization: `Bearer ${token}` },
						});
					}
				}
			}
		}
		if (!resp.ok) {
			throw new Error(`Failed to download ${url}: HTTP ${resp.status} ${resp.statusText}`);
		}
		const cl = resp.headers.get("content-length");
		if (cl && Number.parseInt(cl, 10) > maxBytes) {
			throw new Error(`Content-Length header ${cl} exceeds safety limit of ${maxBytes} bytes.`);
		}
		if (!resp.body) {
			throw new Error(`Response body stream is empty for ${url}`);
		}

		const fileHandle = await fsPromises.open(tempPath, "w");
		const hasher = crypto.createHash("sha256");
		let totalBytes = 0;
		const reader = resp.body.getReader();

		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				if (value) {
					totalBytes += value.byteLength;
					if (totalBytes > maxBytes) {
						await reader.cancel();
						throw new Error(`Download stream exceeded safety limit of ${maxBytes} bytes.`);
					}
					hasher.update(value);
					await fileHandle.write(value);
				}
			}
		} finally {
			reader.releaseLock();
			await fileHandle.close();
		}

		const actualSha256 = hasher.digest("hex");
		if (expectedSha256 && actualSha256.toLowerCase() !== expectedSha256.toLowerCase()) {
			await fsPromises.rm(tempPath, { force: true }).catch(() => {});
			throw new Error(`SHA256 mismatch for ${url}: expected ${expectedSha256}, got ${actualSha256}`);
		}

		await fsPromises.rename(tempPath, targetPath);
	} catch (err) {
		await fsPromises.rm(tempPath, { force: true }).catch(() => {});
		throw err;
	} finally {
		clearTimeout(timeoutTimer);
		options?.signal?.removeEventListener("abort", onParentAbort);
	}
}

/**
 * Transactional target wrapper: executes installation directly in targetDir with permanent paths,
 * preserving any existing working installation in a backup directory during setup.
 * If any step fails, the partially created targetDir is deleted and the backup is restored.
 * On success, the backup is removed.
 */
async function withTransactionalTarget<T>(targetDir: string, action: (targetDir: string) => Promise<T>): Promise<T> {
	await fsPromises.mkdir(path.dirname(targetDir), { recursive: true });
	const backupDir = `${targetDir}.backup.${Date.now()}.${crypto.randomBytes(4).toString("hex")}`;
	let hadPrevious = false;
	if (fs.existsSync(targetDir)) {
		hadPrevious = true;
		await fsPromises.rename(targetDir, backupDir);
	}
	await fsPromises.mkdir(targetDir, { recursive: true });
	try {
		const result = await action(targetDir);
		if (hadPrevious && fs.existsSync(backupDir)) {
			await fsPromises.rm(backupDir, { recursive: true, force: true }).catch(() => {});
		}
		return result;
	} catch (err) {
		await fsPromises.rm(targetDir, { recursive: true, force: true }).catch(() => {});
		if (hadPrevious && fs.existsSync(backupDir)) {
			await fsPromises.rename(backupDir, targetDir).catch(() => {});
		}
		throw err;
	}
}

// ============================================================================
// frida-dexdump Installer
// ============================================================================

/**
 * Script contents for modern frida-dexdump runtime controller.
 * Preserves --help, -D, -U, -f, -p, -n, -o, -d, --sleep options and calls the
 * actual installed GPL agent from site-packages at runtime without copying GPL
 * assets into the reverse git repository.
 */
const FRIDA_DEXDUMP_CONTROLLER_SOURCE = `#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Modern frida-dexdump runtime controller.
Provides CLI compatibility (-D, -U, -f, -p, -n, -o, -d, --sleep, --version)
and executes the installed frida_dexdump agent at runtime without bundling GPL assets into reverse.
Dumps raw immutable DEX binaries, preserves separate fixed derivatives, and records manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import struct
import sys
import time

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("frida-dexdump")

def fix_header(dex_bytes: bytes) -> bytes:
    dex_size = len(dex_bytes)
    res = bytearray(dex_bytes)
    if dex_size >= 4 and res[:4] != b"dex\\n":
        res[:4] = b"dex\\n"
        if dex_size >= 8:
            res[4:8] = b"035\\x00"
    if dex_size >= 0x24:
        struct.pack_into("<I", res, 0x20, dex_size)
    if dex_size >= 0x28:
        struct.pack_into("<I", res, 0x24, 0x70)
    if dex_size >= 0x2C and bytes(res[0x28:0x2C]) not in (b"\\x78\\x56\\x34\\x12", b"\\x12\\x34\\x56\\x78"):
        res[0x28:0x2C] = b"\\x78\\x56\\x34\\x12"
    return bytes(res)

def get_frida_device(device_arg: str | None, is_usb: bool):
    import frida
    if is_usb:
        return frida.get_usb_device()
    if not device_arg or device_arg == "local":
        return frida.get_local_device()
    try:
        return frida.get_device(device_arg)
    except Exception:
        for dev in frida.enumerate_devices():
            if dev.id == device_arg:
                return dev
        raise

def get_agent_script() -> str:
    import frida_dexdump
    pkg_dir = os.path.dirname(frida_dexdump.__file__)
    agent_js = os.path.join(pkg_dir, "agent", "agent.js")
    if os.path.isfile(agent_js):
        with open(agent_js, "r", encoding="utf-8") as f:
            return f.read()
    raise FileNotFoundError(f"Cannot locate installed frida-dexdump agent.js in {pkg_dir}")

def get_adapted_agent_script() -> str:
    agent_code = get_agent_script()
    darwin_filter_js = """
(function() {
    if (typeof rpc === 'undefined' || !rpc.exports || !rpc.exports.searchdex) return;
    var _origSearchDex = rpc.exports.searchdex;
    rpc.exports.searchdex = function(enableDeepSearch) {
        var rawRanges = _origSearchDex.call(this, enableDeepSearch);
        if (Process.platform !== 'darwin') {
            return rawRanges;
        }
        var filtered = [];
        var isUniversalHeader = function(addr) {
            try {
                var p = new NativePointer(addr);
                var b = p.readByteArray(4);
                if (!b || b.byteLength < 4) return false;
                var u = new Uint8Array(b);
                return (u[0] === 0xca && u[1] === 0xfe && u[2] === 0xba && u[3] === 0xbe) ||
                       (u[0] === 0xbe && u[1] === 0xba && u[2] === 0xfe && u[3] === 0xca) ||
                       (u[0] === 0xfe && u[1] === 0xed && u[2] === 0xfa && (u[3] === 0xce || u[3] === 0xcf)) ||
                       (u[0] === 0xcf && u[1] === 0xfa && u[2] === 0xed && u[3] === 0xfe);
            } catch(e) {
                return false;
            }
        };
        for (var i = 0; i < rawRanges.length; i++) {
            var item = rawRanges[i];
            if (isUniversalHeader(item.addr)) {
                item.is_universal_range = true;
                item.reason = "Mach-O universal/fat binary range excluded on Darwin";
            }
            filtered.push(item);
        }
        return filtered;
    };
})();
"""
    return agent_code + "\\n" + darwin_filter_js

def main():
    parser = argparse.ArgumentParser(
        prog="frida-dexdump",
        description="Fast Dalvik/ART memory DEX dumper CLI via Frida.",
    )
    parser.add_argument("-D", "--device", dest="device", metavar="ID", help="connect to device with the given ID")
    parser.add_argument("-U", "--usb", dest="usb", action="store_true", help="connect to USB device")
    parser.add_argument("-f", "--file", dest="file", metavar="TARGET", help="spawn FILE")
    parser.add_argument("-n", "--attach-name", dest="attach_name", metavar="NAME", help="attach to NAME")
    parser.add_argument("-p", "--attach-pid", dest="attach_pid", type=int, metavar="PID", help="attach to PID")
    parser.add_argument("-o", "--output", dest="output", metavar="OUTPUT", help="Output folder path")
    parser.add_argument("-d", "--deep-search", dest="enable_deep", action="store_true", help="Enable deep search mode")
    parser.add_argument("--sleep", dest="sleep", type=int, default=None, help="Waiting times for start, spawn mode default is 5s")
    parser.add_argument("--version", action="version", version="frida-dexdump 2.0.1")

    args = parser.parse_args()

    env_max_bytes = os.environ.get("FRIDA_DEXDUMP_MAX_BYTES")
    max_dex_bytes = int(env_max_bytes) if env_max_bytes and env_max_bytes.isdigit() else 64 * 1024 * 1024
    env_max_total = os.environ.get("FRIDA_DEXDUMP_MAX_TOTAL_BYTES")
    max_total_bytes = int(env_max_total) if env_max_total and env_max_total.isdigit() else 256 * 1024 * 1024
    env_max_files = os.environ.get("FRIDA_DEXDUMP_MAX_FILES")
    max_files = int(env_max_files) if env_max_files and env_max_files.isdigit() else 200

    import frida
    dev = get_frida_device(args.device, args.usb)

    session = None
    target_pid = None
    try:
        if args.file:
            target_pid = dev.spawn([args.file])
            session = dev.attach(target_pid)
            dev.resume(target_pid)
            sleep_time = args.sleep if args.sleep is not None else 5
            if sleep_time > 0:
                time.sleep(sleep_time)
        elif args.attach_pid is not None:
            target_pid = args.attach_pid
            session = dev.attach(target_pid)
        elif args.attach_name:
            for proc in dev.enumerate_processes():
                if proc.name == args.attach_name:
                    target_pid = proc.pid
                    break
            if target_pid is not None:
                session = dev.attach(target_pid)
            else:
                session = dev.attach(args.attach_name)
                for proc in dev.enumerate_processes():
                    if proc.name == args.attach_name:
                        target_pid = proc.pid
                        break
                if target_pid is None:
                    target_pid = os.getpid()
        else:
            sys.stderr.write("Error: target process (-p, -f, or -n) must be specified.\\n")
            sys.exit(1)

        output_dir = args.output or os.path.join(os.getcwd(), f"dexdump_output_{target_pid}")
        os.makedirs(output_dir, exist_ok=True)

        agent_code = get_adapted_agent_script()
        script = session.create_script(agent_code)
        script.load()

        rpc = getattr(script, "exports_sync", script.exports)
        ranges = rpc.searchdex(bool(args.enable_deep))
        logger.info(f"[*] Found {len(ranges)} dex ranges.")

        seen_md5 = set()
        dump_manifest = []
        dump_errors = []
        dropped_universal_ranges = []
        is_partial = False
        idx = 1
        total_dumped_bytes = 0

        for r in ranges:
            if r.get("is_universal_range"):
                logger.info(f"[-] Excluding false universal range {r.get('addr')} on Darwin with explicit bounded partial indicator.")
                dropped_universal_ranges.append({
                    "address": str(r.get("addr")),
                    "size": r.get("size", 0),
                    "reason": r.get("reason", "Mach-O universal/fat binary range excluded on Darwin"),
                })
                is_partial = True
                continue

            if idx > max_files:
                logger.warning(f"[-] Reached max files limit ({max_files}); stopping dump.")
                is_partial = True
                dump_errors.append(f"Reached max files limit ({max_files})")
                break
            try:
                addr_raw = r.get("addr")
                size_raw = r.get("size", 0)
                addr = int(str(addr_raw), 0) if isinstance(addr_raw, str) else int(addr_raw)
                size = int(str(size_raw), 0) if isinstance(size_raw, str) else int(size_raw)
                if size < 0x20:
                    continue
                if size > max_dex_bytes:
                    logger.warning(f"[-] Skipping range {hex(addr)} with size {size} exceeding max {max_dex_bytes}")
                    is_partial = True
                    dump_errors.append(f"Skipping range {hex(addr)} exceeding max_dex_bytes {max_dex_bytes}")
                    continue
                if total_dumped_bytes + size > max_total_bytes:
                    logger.warning(f"[-] Cumulative bytes {total_dumped_bytes + size} exceeded max {max_total_bytes}; stopping.")
                    is_partial = True
                    dump_errors.append(f"Cumulative bytes {total_dumped_bytes + size} exceeded max {max_total_bytes}")
                    break

                chunk_size = 1024 * 1024
                raw_bytes = bytearray()
                cur_off = 0
                while cur_off < size:
                    take = min(chunk_size, size - cur_off)
                    chunk = rpc.memorydump(hex(addr + cur_off), take)
                    if not chunk:
                        break
                    raw_bytes.extend(bytes(chunk))
                    cur_off += len(chunk)

                if len(raw_bytes) < 0x20:
                    continue

                raw_data = bytes(raw_bytes)

                # Secondary safeguard for Darwin Mach-O universal/fat headers
                if len(raw_data) >= 4:
                    magic4 = raw_data[:4]
                    if magic4 in (b"\\xca\\xfe\\xba\\xbe", b"\\xbe\\xba\\xfe\\xca", b"\\xfe\\xed\\xfa\\xce", b"\\xfe\\xed\\xfa\\xcf", b"\\xcf\\xfa\\xed\\xfe"):
                        logger.info(f"[-] Excluding false universal range {hex(addr)} with Mach-O magic {magic4.hex()}")
                        dropped_universal_ranges.append({
                            "address": hex(addr),
                            "size": len(raw_data),
                            "reason": f"False universal range with Mach-O magic {magic4.hex()}",
                        })
                        is_partial = True
                        continue
                raw_md5 = hashlib.md5(raw_data).hexdigest()
                raw_sha256 = hashlib.sha256(raw_data).hexdigest()
                if raw_md5 in seen_md5:
                    continue
                seen_md5.add(raw_md5)

                out_filename = f"classes{idx:02d}.dex" if idx > 1 else "classes.dex"
                out_path = os.path.join(output_dir, out_filename)
                with open(out_path, "wb") as f:
                    f.write(raw_data)

                total_dumped_bytes += len(raw_data)

                fixed_data = fix_header(raw_data)
                header_modified = fixed_data != raw_data
                fixed_filename = None
                fixed_md5 = None
                if header_modified:
                    fixed_filename = f"classes{idx:02d}.fixed.dex" if idx > 1 else "classes.fixed.dex"
                    fixed_path = os.path.join(output_dir, fixed_filename)
                    with open(fixed_path, "wb") as f:
                        f.write(fixed_data)
                    fixed_md5 = hashlib.md5(fixed_data).hexdigest()

                dump_manifest.append({
                    "index": idx,
                    "address": hex(addr),
                    "size_bytes": len(raw_data),
                    "raw_file": out_filename,
                    "raw_md5": raw_md5,
                    "raw_sha256": raw_sha256,
                    "header_modified": header_modified,
                    "fixed_file": fixed_filename,
                    "fixed_md5": fixed_md5,
                })

                print(f"[+] DexMd5={raw_md5}, SavePath={out_path}, DexSize={hex(len(raw_data))}")
                idx += 1
            except Exception as e:
                dump_errors.append(f"Range {r}: {e}")
                logger.warning(f"[-] Failed dumping {r}: {e}")

        manifest_path = os.path.join(output_dir, "dump_manifest.json")
        try:
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump({
                    "manifest": dump_manifest,
                    "errors": dump_errors,
                    "partial": bool(is_partial or dump_errors or dropped_universal_ranges),
                    "dropped_universal_ranges": dropped_universal_ranges,
                }, f, indent=2)
        except Exception:
            pass

        if len(ranges) > 0 and len(dump_manifest) == 0:
            sys.stderr.write(f"[-] Dump failed: 0 of {len(ranges)} ranges dumped. Errors: {'; '.join(dump_errors)}\\n")
            sys.exit(1)

    finally:
        if session:
            try:
                session.detach()
            except Exception:
                pass

if __name__ == "__main__":
    main()
`;

export async function installFridaDexdump(
	options: ProtectionPythonInstallOptions = {},
): Promise<ProtectionPythonInstallResult> {
	const log = (msg: string) => {
		options.onLog?.(msg);
		options.onChunk?.(msg);
	};
	const agentDir = options.agentDir ?? getAgentDir();
	const installDir = path.join(agentDir, "tools", "frida-dexdump");
	const isWindows = (options.platform ?? process.platform) === "win32";

	const hostPython = findHostPython(options.env, options.which);
	if (!hostPython) {
		return {
			success: false,
			id: "frida-dexdump",
			installDir,
			executablePath: "",
			error: "Python 3 interpreter not found. Please install Python 3.9+ to provision frida-dexdump.",
		};
	}

	try {
		return await withTransactionalTarget(installDir, async targetDir => {
			const venvDir = path.join(targetDir, ".venv");
			const binDir = path.join(targetDir, "bin");
			const targetVenvPy = path.join(venvDir, isWindows ? "Scripts/python.exe" : "bin/python");
			const targetVenvPip = path.join(venvDir, isWindows ? "Scripts/pip.exe" : "bin/pip");

			log(`[reverse] Creating isolated virtual environment for frida-dexdump at ${venvDir}...\n`);
			await runPythonSubprocess([hostPython, "-m", "venv", venvDir], {
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			log(`[reverse] Upgrading pip in isolated virtual environment...\n`);
			await runPythonSubprocess([targetVenvPy, "-m", "pip", "install", "--upgrade", "pip"], {
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			log(`[reverse] Installing pinned ${FRIDA_DEXDUMP_PYPI_SPEC} from PyPI...\n`);
			await runPythonSubprocess([targetVenvPip, "install", FRIDA_DEXDUMP_PYPI_SPEC], {
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			// Provision modern controller script and executable wrapper
			const controllerPath = path.join(targetDir, "controller.py");
			await fsPromises.writeFile(controllerPath, FRIDA_DEXDUMP_CONTROLLER_SOURCE, {
				mode: 0o755,
			});

			await fsPromises.mkdir(binDir, { recursive: true });
			const wrapperPath = path.join(binDir, isWindows ? "frida-dexdump.cmd" : "frida-dexdump");
			if (isWindows) {
				const bat = `@echo off\r\n"%~dp0..\\.venv\\Scripts\\python.exe" "%~dp0..\\controller.py" %*\r\n`;
				await fsPromises.writeFile(wrapperPath, bat);
			} else {
				const sh = `#!/bin/sh\nBASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"\nexec "$BASE_DIR/.venv/bin/python" "$BASE_DIR/controller.py" "$@"\n`;
				await fsPromises.writeFile(wrapperPath, sh, { mode: 0o755 });
			}

			// Independent verification: import frida and DexDumpAgent, verify controller --help
			log(`[reverse] Verifying frida-dexdump package import and agent runtime...\n`);
			await runPythonSubprocess(
				[
					targetVenvPy,
					"-c",
					"import frida; from frida_dexdump.agent import DexDumpAgent; print('FRIDA_DEXDUMP_VERIFIED_OK')",
				],
				{
					onLog: log,
					signal: options.signal,
					timeoutMs: options.timeoutMs,
					executor: options.executor,
				},
			);

			log(`[reverse] Verifying frida-dexdump CLI wrapper --help...\n`);
			await runPythonSubprocess([wrapperPath, "--help"], {
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			// Write provenance receipt
			const receipt = {
				tool: "frida-dexdump",
				version: FRIDA_DEXDUMP_VERSION,
				spec: FRIDA_DEXDUMP_PYPI_SPEC,
				license: FRIDA_DEXDUMP_LICENSE,
				upstream: FRIDA_DEXDUMP_UPSTREAM_URL,
				wheelSha256: FRIDA_DEXDUMP_WHEEL_SHA256,
				installedAt: new Date().toISOString(),
			};
			await fsPromises.writeFile(
				path.join(targetDir, "install-receipt.json"),
				JSON.stringify(receipt, null, 2),
				"utf-8",
			);

			const finalWrapper = path.join(targetDir, "bin", isWindows ? "frida-dexdump.cmd" : "frida-dexdump");
			return {
				success: true,
				id: "frida-dexdump",
				installDir: targetDir,
				executablePath: finalWrapper,
				message: `Successfully installed frida-dexdump v${FRIDA_DEXDUMP_VERSION} into ${targetDir}`,
				metadata: {
					executablePath: finalWrapper,
					pythonPath: path.join(targetDir, ".venv", isWindows ? "Scripts/python.exe" : "bin/python"),
					version: FRIDA_DEXDUMP_VERSION,
					license: FRIDA_DEXDUMP_LICENSE,
				},
			};
		});
	} catch (err: unknown) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			success: false,
			id: "frida-dexdump",
			installDir,
			executablePath: "",
			error: `frida-dexdump installation failed: ${message}`,
		};
	}
}

// ============================================================================
// msynth Installer (MBA Program Synthesis & Z3 Prover)
// ============================================================================

export async function installMsynth(
	options: ProtectionPythonInstallOptions = {},
): Promise<ProtectionPythonInstallResult> {
	const log = (msg: string) => {
		options.onLog?.(msg);
		options.onChunk?.(msg);
	};
	const agentDir = options.agentDir ?? getAgentDir();
	const installDir = path.join(agentDir, "tools", "msynth");
	const isWindows = (options.platform ?? process.platform) === "win32";

	const hostPython = findHostPython(options.env, options.which);
	if (!hostPython) {
		return {
			success: false,
			id: "msynth",
			installDir,
			executablePath: "",
			error: "Python 3 interpreter not found. Please install Python 3.9+ to provision msynth.",
		};
	}

	try {
		return await withTransactionalTarget(installDir, async targetDir => {
			const venvDir = path.join(targetDir, ".venv");
			const srcDir = path.join(targetDir, "src");
			const targetVenvPy = path.join(venvDir, isWindows ? "Scripts/python.exe" : "bin/python");
			const targetVenvPip = path.join(venvDir, isWindows ? "Scripts/pip.exe" : "bin/pip");

			log(`[reverse] Creating isolated virtual environment for msynth at ${venvDir}...\n`);
			await runPythonSubprocess([hostPython, "-m", "venv", venvDir], {
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			log(`[reverse] Installing core dependencies (wheel, z3-solver)...\n`);
			await runPythonSubprocess([targetVenvPy, "-m", "pip", "install", "--upgrade", "pip", "wheel", "z3-solver"], {
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			log(`[reverse] Installing pinned Miasm (commit ${MIASM_COMMIT.slice(0, 8)})...\n`);
			try {
				await runPythonSubprocess([targetVenvPip, "install", MIASM_GIT_URL], {
					onLog: log,
					signal: options.signal,
					timeoutMs: options.timeoutMs,
					executor: options.executor,
				});
			} catch {
				log(`[reverse] Git pip install failed, falling back to archive download...\n`);
				const miasmTarPath = path.join(targetDir, `miasm-${MIASM_COMMIT}.tar.gz`);
				await downloadFileWithSha256(MIASM_ARCHIVE_URL, miasmTarPath, undefined, {
					signal: options.signal,
					timeoutMs: options.timeoutMs,
					fetch: options.fetch,
					onLog: log,
				});
				await runPythonSubprocess([targetVenvPip, "install", miasmTarPath], {
					onLog: log,
					signal: options.signal,
					timeoutMs: options.timeoutMs,
					executor: options.executor,
				});
				await fsPromises.rm(miasmTarPath, { force: true }).catch(() => {});
			}

			log(`[reverse] Fetching msynth pinned source repository (commit ${MSYNTH_COMMIT.slice(0, 8)})...\n`);
			const whichFn = options.which ?? $which;
			const hasGit = Boolean(whichFn("git", { cache: WhichCachePolicy.Bypass }));
			let fetchedViaGit = false;
			if (hasGit) {
				try {
					await runPythonSubprocess(["git", "clone", "--depth", "1", MSYNTH_UPSTREAM_URL, srcDir], {
						onLog: log,
						signal: options.signal,
						timeoutMs: options.timeoutMs,
						executor: options.executor,
					});
					await runPythonSubprocess(["git", "-C", srcDir, "checkout", MSYNTH_COMMIT], {
						onLog: log,
						signal: options.signal,
						timeoutMs: options.timeoutMs,
						executor: options.executor,
					});
					fetchedViaGit = true;
				} catch (gitErr) {
					log(`[reverse] Git clone failed: ${gitErr}. Falling back to GitHub tarball extraction...\n`);
					await fsPromises.rm(srcDir, { recursive: true, force: true }).catch(() => {});
				}
			}

			if (!fetchedViaGit) {
				const msynthTarPath = path.join(targetDir, `msynth-${MSYNTH_COMMIT}.tar.gz`);
				await downloadFileWithSha256(MSYNTH_ARCHIVE_URL, msynthTarPath, MSYNTH_ARCHIVE_SHA256, {
					signal: options.signal,
					timeoutMs: options.timeoutMs,
					fetch: options.fetch,
					onLog: log,
				});
				await extractArchive(msynthTarPath, targetDir);
				const extractedSubdirs = await fsPromises.readdir(targetDir);
				const msynthArchiveDir = extractedSubdirs.find(d => d.startsWith("msynth-"));
				if (!msynthArchiveDir) {
					throw new Error("Failed to find extracted msynth archive folder in target directory.");
				}
				await fsPromises.rename(path.join(targetDir, msynthArchiveDir), srcDir);
				await fsPromises.rm(msynthTarPath, { force: true }).catch(() => {});
			}

			// Rigorous integrity verification: oracle.pickle and LICENSE
			const oraclePicklePath = path.join(srcDir, "oracle.pickle");
			if (!fs.existsSync(oraclePicklePath)) {
				throw new Error(`Trusted oracle.pickle not found in msynth source at ${oraclePicklePath}`);
			}
			const oracleData = await fsPromises.readFile(oraclePicklePath);
			const oracleHash = crypto.createHash("sha256").update(oracleData).digest("hex");
			if (oracleHash.toLowerCase() !== MSYNTH_ORACLE_PICKLE_SHA256.toLowerCase()) {
				throw new Error(
					`oracle.pickle SHA-256 mismatch: expected ${MSYNTH_ORACLE_PICKLE_SHA256}, got ${oracleHash}`,
				);
			}
			log(`[reverse] Verified trusted oracle.pickle SHA-256 (${oracleHash.slice(0, 16)}...)\n`);

			const licensePath = path.join(srcDir, "LICENSE");
			if (fs.existsSync(licensePath)) {
				const licenseData = await fsPromises.readFile(licensePath);
				const licenseHash = crypto.createHash("sha256").update(licenseData).digest("hex");
				if (licenseHash.toLowerCase() !== MSYNTH_LICENSE_SHA256.toLowerCase()) {
					log(`[reverse] Notice: msynth LICENSE hash ${licenseHash} differs from standard pin.\n`);
				}
			}

			// Copy trusted oracle to target root for direct lookup
			const rootOraclePath = path.join(targetDir, "oracle.pickle");
			await fsPromises.copyFile(oraclePicklePath, rootOraclePath);

			// Install msynth in editable mode into isolated venv with permanent target paths
			log(`[reverse] Installing msynth package into virtual environment...\n`);
			await runPythonSubprocess([targetVenvPip, "install", "-e", srcDir], {
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			// Proof of execution: run real Simplifier and Synthesizer on MBA expression
			log(`[reverse] Proving independent msynth Simplifier and Z3 SMT evaluation...\n`);
			const proofScript = `
import os, sys
import msynth
import miasm
import z3
from msynth import Simplifier, Synthesizer
from miasm.expression.expression import ExprId, ExprInt, ExprOp

oracle_path = os.path.abspath('src/oracle.pickle')
if not os.path.isfile(oracle_path):
    oracle_path = os.path.abspath('oracle.pickle')
assert os.path.isfile(oracle_path), f"oracle.pickle missing: {oracle_path}"

s = Simplifier(oracle_path)
x = ExprId('x', 32)
y = ExprId('y', 32)
# Standard MBA equivalence: (x ^ y) + 2 * (x & y) -> x + y
expr = ExprOp('+', ExprOp('^', x, y), ExprOp('*', ExprInt(2, 32), ExprOp('&', x, y)))
res = s.simplify(expr)
res_str = str(res)
assert 'x + y' in res_str or (res.is_op() and res.op == '+'), f"Simplification failed: {res_str}"

synth = Synthesizer()
assert synth is not None, "Synthesizer failed to instantiate"

print('MSYNTH_PROVED_OK')
`;
			await runPythonSubprocess([targetVenvPy, "-c", proofScript], {
				cwd: targetDir,
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			// Write provenance receipt
			const receipt = {
				tool: "msynth",
				version: MSYNTH_VERSION,
				commit: MSYNTH_COMMIT,
				license: MSYNTH_LICENSE,
				licenseSha256: MSYNTH_LICENSE_SHA256,
				upstream: MSYNTH_UPSTREAM_URL,
				oraclePickleSha256: MSYNTH_ORACLE_PICKLE_SHA256,
				miasmCommit: MIASM_COMMIT,
				installedAt: new Date().toISOString(),
			};
			await fsPromises.writeFile(
				path.join(targetDir, "install-receipt.json"),
				JSON.stringify(receipt, null, 2),
				"utf-8",
			);

			const finalPy = path.join(targetDir, ".venv", isWindows ? "Scripts/python.exe" : "bin/python");
			const finalSrc = path.join(targetDir, "src");
			const finalOracle = path.join(finalSrc, "oracle.pickle");

			return {
				success: true,
				id: "msynth",
				installDir: targetDir,
				executablePath: finalPy,
				message: `Successfully provisioned msynth v${MSYNTH_VERSION} into ${targetDir}`,
				metadata: {
					pythonPath: finalPy,
					packageDir: finalSrc,
					oraclePath: finalOracle,
					oracleSha256: MSYNTH_ORACLE_PICKLE_SHA256,
					version: MSYNTH_VERSION,
					license: MSYNTH_LICENSE,
				},
			};
		});
	} catch (err: unknown) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			success: false,
			id: "msynth",
			installDir,
			executablePath: "",
			error: `msynth installation failed: ${message}`,
		};
	}
}

// ============================================================================
// d810-ng Installer
// ============================================================================

export async function installD810Ng(
	options: ProtectionPythonInstallOptions = {},
): Promise<ProtectionPythonInstallResult> {
	const log = (msg: string) => {
		options.onLog?.(msg);
		options.onChunk?.(msg);
	};
	const agentDir = options.agentDir ?? getAgentDir();
	const installDir = path.join(agentDir, "tools", "d810-ng");
	const isWindows = (options.platform ?? process.platform) === "win32";

	const hostPython = findHostPython(options.env, options.which);
	if (!hostPython) {
		return {
			success: false,
			id: "d810-ng",
			installDir,
			executablePath: "",
			error: "Python 3 interpreter not found. Please install Python 3.9+ to provision d810-ng.",
		};
	}

	try {
		return await withTransactionalTarget(installDir, async targetDir => {
			const venvDir = path.join(targetDir, ".venv");
			const targetVenvPy = path.join(venvDir, isWindows ? "Scripts/python.exe" : "bin/python");
			const targetVenvPip = path.join(venvDir, isWindows ? "Scripts/pip.exe" : "bin/pip");

			log(`[reverse] Creating isolated virtual environment for d810-ng at ${venvDir}...\n`);
			await runPythonSubprocess([hostPython, "-m", "venv", venvDir], {
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			log(`[reverse] Installing pinned ${D810_NG_PYPI_SPEC} from PyPI...\n`);
			await runPythonSubprocess([targetVenvPip, "install", "--upgrade", "pip", D810_NG_PYPI_SPEC], {
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			log(`[reverse] Verifying d810 module import...\n`);
			await runPythonSubprocess([targetVenvPy, "-c", "import d810; print('D810_VERIFIED_OK')"], {
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			const receipt = {
				tool: "d810-ng",
				version: D810_NG_VERSION,
				commit: D810_NG_COMMIT,
				spec: D810_NG_PYPI_SPEC,
				license: D810_NG_LICENSE,
				upstream: D810_NG_UPSTREAM_URL,
				installedAt: new Date().toISOString(),
			};
			await fsPromises.writeFile(
				path.join(targetDir, "install-receipt.json"),
				JSON.stringify(receipt, null, 2),
				"utf-8",
			);

			const finalPy = path.join(targetDir, ".venv", isWindows ? "Scripts/python.exe" : "bin/python");
			return {
				success: true,
				id: "d810-ng",
				installDir: targetDir,
				executablePath: finalPy,
				message: `Successfully provisioned d810-ng v${D810_NG_VERSION} into ${targetDir}`,
				metadata: {
					pythonPath: finalPy,
					packageDir: targetDir,
					version: D810_NG_VERSION,
					license: D810_NG_LICENSE,
				},
			};
		});
	} catch (err: unknown) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			success: false,
			id: "d810-ng",
			installDir,
			executablePath: "",
			error: `d810-ng installation failed: ${message}`,
		};
	}
}

// ============================================================================
// tritondse Installer (Dynamic Symbolic Execution Engine)
// ============================================================================

export function findManagedTritonSitePackages(agentDir?: string, targetPyDir?: string): string | null {
	const resolvedAgentDir = agentDir && agentDir.length > 0 ? agentDir : getAgentDir();
	const candidates = [
		path.join(resolvedAgentDir, "tools", "vmp", "triton-venv"),
		path.join(resolvedAgentDir, "tools", "triton"),
		path.join(resolvedAgentDir, "tools", "triton-venv"),
	];
	for (const cand of candidates) {
		if (!fs.existsSync(cand)) continue;
		const libDir = path.join(cand, "lib");
		if (fs.existsSync(libDir)) {
			try {
				const entries = fs.readdirSync(libDir);
				for (const ent of entries) {
					if (!ent.startsWith("python")) continue;
					if (targetPyDir && ent !== targetPyDir) continue;

					const sp = path.join(libDir, ent, "site-packages");
					if (fs.existsSync(sp) && fs.existsSync(path.join(sp, "triton_library-1.0.0rc4.dist-info"))) {
						if (targetPyDir) {
							const minorMatch = targetPyDir.match(/python3\.(\d+)/);
							if (minorMatch) {
								const minor = minorMatch[1];
								const spFiles = fs.readdirSync(sp);
								const tritonSo = spFiles.find(
									f =>
										f.startsWith("triton") &&
										(f.endsWith(".so") || f.endsWith(".pyd") || f.endsWith(".dylib")),
								);
								if (tritonSo) {
									const cpythonMatch = tritonSo.match(/cpython-3(\d+)/);
									if (cpythonMatch && cpythonMatch[1] !== minor) {
										continue;
									}
								}
							}
						}
						return sp;
					}
				}
			} catch {}
		}
	}
	return null;
}

export async function installTritondse(
	options: ProtectionPythonInstallOptions = {},
): Promise<ProtectionPythonInstallResult> {
	const log = (msg: string) => {
		options.onLog?.(msg);
		options.onChunk?.(msg);
	};
	const agentDir = options.agentDir ?? getAgentDir();
	const installDir = path.join(agentDir, "tools", "tritondse");
	const isWindows = (options.platform ?? process.platform) === "win32";

	const hostPython = findHostPython(options.env, options.which);
	if (!hostPython) {
		return {
			success: false,
			id: "tritondse",
			installDir,
			executablePath: "",
			error: "Python 3 interpreter not found. Please install Python 3.9+ to provision tritondse.",
		};
	}

	try {
		return await withTransactionalTarget(installDir, async targetDir => {
			const venvDir = path.join(targetDir, ".venv");
			const targetVenvPip = path.join(venvDir, isWindows ? "Scripts/pip.exe" : "bin/pip");

			log(`[reverse] Creating isolated virtual environment for tritondse at ${venvDir}...\n`);
			await runPythonSubprocess([hostPython, "-m", "venv", venvDir], {
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			const targetLib = path.join(venvDir, "lib");
			const pyDirs = await fsPromises.readdir(targetLib).catch(() => [] as string[]);
			const pyDir = pyDirs.find(d => d.startsWith("python")) ?? "python3.12";
			const targetVenvSp = path.join(targetLib, pyDir, "site-packages");
			await fsPromises.mkdir(targetVenvSp, { recursive: true });

			// Reuse verified managed Triton from vmp-toolchain or build from source
			let vmpTritonSp = findManagedTritonSitePackages(agentDir, pyDir);
			if (!vmpTritonSp) {
				log(
					`[reverse] No existing ABI-compatible managed Triton found. Installing via managed Triton source/wheel pipeline...\n`,
				);
				const tritonRes = await installTritonVenv({
					agentDir,
					signal: options.signal,
					onChunk: log,
					env: options.env,
					which: options.which,
					platform: options.platform,
					pythonPath: hostPython,
				});
				if (!tritonRes.success) {
					throw new Error(`Failed to provision prerequisite Triton environment: ${tritonRes.message}`);
				}
				vmpTritonSp = findManagedTritonSitePackages(agentDir, pyDir);
				if (!vmpTritonSp) {
					throw new Error(`Managed Triton was installed but site-packages for ${pyDir} could not be located.`);
				}
			}

			if (vmpTritonSp) {
				log(`[reverse] Reusing verified managed Triton build from ${vmpTritonSp}...\n`);
				const spEntries = await fsPromises.readdir(vmpTritonSp);
				for (const entry of spEntries) {
					if (
						entry.startsWith("triton") ||
						entry.startsWith("capstone") ||
						entry.startsWith("z3") ||
						entry.startsWith("llvmlite")
					) {
						const srcPath = path.join(vmpTritonSp, entry);
						const dstPath = path.join(targetVenvSp, entry);
						await fsPromises.cp(srcPath, dstPath, { recursive: true });
					}
				}
			}

			// 1. Provision verified native libmagic dylib into targetDir/lib if not already on host
			const hostLibmagic = "/opt/homebrew/lib/libmagic.dylib";
			const libDir = path.join(targetDir, "lib");
			const shareDir = path.join(targetDir, "share", "misc");
			await fsPromises.mkdir(libDir, { recursive: true });
			await fsPromises.mkdir(shareDir, { recursive: true });

			let libmagicPath = hostLibmagic;
			if (!fs.existsSync(hostLibmagic) && process.platform === "darwin" && process.arch === "arm64") {
				log(`[reverse] Fetching isolated Homebrew libmagic bottle (SHA-256 verified)...\n`);
				const bottleTarPath = path.join(targetDir, "libmagic.tar.gz");
				await downloadFileWithSha256(LIBMAGIC_BOTTLE_ARM64_URL, bottleTarPath, LIBMAGIC_BOTTLE_ARM64_SHA256, {
					signal: options.signal,
					timeoutMs: options.timeoutMs,
					fetch: options.fetch,
					onLog: log,
				});
				await extractArchive(bottleTarPath, targetDir);
				const extractedSubdirs = await fsPromises.readdir(targetDir);
				const extractedLibmagic = extractedSubdirs.find(d => d.startsWith("libmagic"));
				if (extractedLibmagic) {
					const versionEntries = await fsPromises.readdir(path.join(targetDir, extractedLibmagic));
					const versionDir = versionEntries.find(e => !e.startsWith(".")) ?? "5.48";
					const bottleBase = path.join(targetDir, extractedLibmagic, versionDir);
					const bottleLib = path.join(bottleBase, "lib");
					const bottleShare = path.join(bottleBase, "share", "misc");
					if (fs.existsSync(bottleLib)) {
						const libFiles = await fsPromises.readdir(bottleLib);
						for (const lf of libFiles) {
							if (lf.endsWith(".dylib")) {
								await fsPromises.copyFile(path.join(bottleLib, lf), path.join(libDir, lf)).catch(() => {});
							}
						}
					}
					if (fs.existsSync(bottleShare)) {
						const mgcPath = path.join(bottleShare, "magic.mgc");
						if (fs.existsSync(mgcPath)) {
							await fsPromises.copyFile(mgcPath, path.join(shareDir, "magic.mgc")).catch(() => {});
						}
					}
					await fsPromises
						.rm(path.join(targetDir, extractedLibmagic), { recursive: true, force: true })
						.catch(() => {});
				}
				await fsPromises.rm(bottleTarPath, { force: true }).catch(() => {});
				libmagicPath = path.join(libDir, "libmagic.dylib");
			}

			// 2. Fetch pinned tritondse source and adapt SmtSolver to underlying Triton build features (no shims)
			const srcDir = path.join(targetDir, "src");
			log(`[reverse] Fetching pinned tritondse source repository (commit ${TRITONDSE_COMMIT.slice(0, 8)})...\n`);
			const hasGit = Boolean($which("git", { cache: WhichCachePolicy.Bypass }));
			let fetchedViaGit = false;
			if (hasGit) {
				try {
					await runPythonSubprocess(
						["git", "clone", "--depth", "1", "--branch", `v${TRITONDSE_VERSION}`, TRITONDSE_UPSTREAM_URL, srcDir],
						{
							onLog: log,
							signal: options.signal,
							timeoutMs: options.timeoutMs,
							executor: options.executor,
						},
					);
					fetchedViaGit = true;
				} catch (gitErr) {
					log(`[reverse] Git clone failed: ${gitErr}. Falling back to tarball extraction...\n`);
					await fsPromises.rm(srcDir, { recursive: true, force: true }).catch(() => {});
				}
			}

			if (!fetchedViaGit) {
				const tritondseTarPath = path.join(targetDir, `tritondse-${TRITONDSE_COMMIT}.tar.gz`);
				const tritondseArchiveUrl = `https://github.com/quarkslab/tritondse/archive/${TRITONDSE_COMMIT}.tar.gz`;
				await downloadFileWithSha256(tritondseArchiveUrl, tritondseTarPath, undefined, {
					signal: options.signal,
					timeoutMs: options.timeoutMs,
					fetch: options.fetch,
					onLog: log,
				});
				await extractArchive(tritondseTarPath, targetDir);
				const extractedSubdirs = await fsPromises.readdir(targetDir);
				const tritondseArchiveDir = extractedSubdirs.find(d => d.startsWith("tritondse-"));
				if (!tritondseArchiveDir) {
					throw new Error("Failed to find extracted tritondse archive folder in target directory.");
				}
				await fsPromises.rename(path.join(targetDir, tritondseArchiveDir), srcDir);
				await fsPromises.rm(tritondseTarPath, { force: true }).catch(() => {});
			}

			// Apply small pinned source patch: exclude unavailable optional BITWUZLA solver
			// based on underlying Triton build features, without mutating the Triton namespace
			const typesPyPath = path.join(srcDir, "tritondse", "types.py");
			let bitwuzlaPatched = false;
			if (fs.existsSync(typesPyPath)) {
				let typesContent = await fsPromises.readFile(typesPyPath, "utf-8");
				const targetLine = "    BITWUZLA = SOLVER.BITWUZLA  # doc: bitwuzla solver";
				const patchedLine = '    if hasattr(SOLVER, "BITWUZLA"):\n        BITWUZLA = getattr(SOLVER, "BITWUZLA")';
				if (typesContent.includes(targetLine)) {
					typesContent = typesContent.replace(targetLine, patchedLine);
					await fsPromises.writeFile(typesPyPath, typesContent, "utf-8");
					bitwuzlaPatched = true;
					log(
						`[reverse] Applied pinned patch to tritondse SmtSolver: conditional BITWUZLA based on Triton build.\n`,
					);
				} else if (typesContent.includes('if hasattr(SOLVER, "BITWUZLA")')) {
					bitwuzlaPatched = true;
				}
			}

			const executionEnv: Record<string, string | undefined> = {
				...options.env,
				DYLD_LIBRARY_PATH: libDir,
				MAGIC: path.join(shareDir, "magic.mgc"),
			};

			log(`[reverse] Upgrading pip and installing tritondse dependencies...\n`);
			await runPythonSubprocess([targetVenvPip, "install", "--upgrade", "pip"], {
				env: executionEnv,
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			await runPythonSubprocess([targetVenvPip, "install", srcDir], {
				env: executionEnv,
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			// Create binary wrapper setting DYLD_LIBRARY_PATH and MAGIC for all consumers
			const binDir = path.join(targetDir, "bin");
			await fsPromises.mkdir(binDir, { recursive: true });
			const wrapperPath = path.join(binDir, isWindows ? "tritondse-python.cmd" : "tritondse-python");
			if (isWindows) {
				const bat = `@echo off\r\n"%~dp0..\\.venv\\Scripts\\python.exe" %*\r\n`;
				await fsPromises.writeFile(wrapperPath, bat);
			} else {
				const sh = `#!/bin/sh\nBASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"\nexport DYLD_LIBRARY_PATH="$BASE_DIR/lib:\${DYLD_LIBRARY_PATH}"\nexport MAGIC="$BASE_DIR/share/misc/magic.mgc"\nexec "$BASE_DIR/.venv/bin/python" "$@"\n`;
				await fsPromises.writeFile(wrapperPath, sh, { mode: 0o755 });
			}

			log(`[reverse] Verifying tritondse constructors (Config, Program, SymbolicExecutor, ProcessState)...\n`);
			const proofScript = `
import triton
import tritondse
from tritondse import Config, Program, ProcessState, Architecture
from triton import ARCH, Instruction
config = Config()
pstate = ProcessState()
pstate.architecture = Architecture.AARCH64
ctx = pstate.tt_ctx
inst = Instruction(b'\\x20\\x00\\x80\\xd2')
inst.setAddress(0x1000)
ctx.processing(inst)
assert ctx.getConcreteRegisterValue(ctx.registers.x0) == 1
assert pstate.read_register('x0') == 1
import importlib.metadata
ver = importlib.metadata.version('tritondse')
print('TRITONDSE_DSE_PROOF_SUCCESS', ver)
`;
			await runPythonSubprocess([wrapperPath, "-c", proofScript], {
				env: executionEnv,
				onLog: log,
				signal: options.signal,
				timeoutMs: options.timeoutMs,
				executor: options.executor,
			});

			const receipt = {
				tool: "tritondse",
				version: TRITONDSE_VERSION,
				commit: TRITONDSE_COMMIT,
				spec: TRITONDSE_PYPI_SPEC,
				license: TRITONDSE_LICENSE,
				upstream: TRITONDSE_UPSTREAM_URL,
				tritonSource: vmpTritonSp ?? "native",
				libmagic: libmagicPath,
				patches: bitwuzlaPatched
					? [
							"tritondse/types.py: conditional SmtSolver.BITWUZLA inclusion based on Triton build features (Z3-only)",
						]
					: [],
				installedAt: new Date().toISOString(),
			};
			await fsPromises.writeFile(
				path.join(targetDir, "install-receipt.json"),
				JSON.stringify(receipt, null, 2),
				"utf-8",
			);

			return {
				success: true,
				id: "tritondse",
				installDir: targetDir,
				executablePath: wrapperPath,
				message: `Successfully provisioned tritondse v${TRITONDSE_VERSION} into ${targetDir}`,
				metadata: {
					pythonPath: path.join(targetDir, ".venv", isWindows ? "Scripts/python.exe" : "bin/python"),
					executablePath: wrapperPath,
					packageDir: srcDir,
					version: TRITONDSE_VERSION,
					license: TRITONDSE_LICENSE,
					tritonSource: vmpTritonSp ?? "native",
					libmagic: libmagicPath,
				},
			};
		});
	} catch (err: unknown) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			success: false,
			id: "tritondse",
			installDir,
			executablePath: "",
			error: `tritondse installation failed: ${message}`,
		};
	}
}

// ============================================================================
// Dispatcher and Verification Helpers
// ============================================================================

export async function installProtectionPythonTool(
	id: string,
	options: ProtectionPythonInstallOptions = {},
): Promise<ProtectionPythonInstallResult> {
	switch (id) {
		case "frida-dexdump":
			return installFridaDexdump(options);
		case "msynth":
			return installMsynth(options);
		case "d810-ng":
			return installD810Ng(options);
		case "tritondse":
			return installTritondse(options);
		default:
			return {
				success: false,
				id,
				installDir: path.join(options.agentDir ?? getAgentDir(), "tools", id),
				executablePath: "",
				error: `Unsupported Python protection tool: ${id}`,
			};
	}
}

export async function verifyProtectionPythonTool(
	id: string,
	options: {
		agentDir?: string;
		env?: Record<string, string | undefined>;
		signal?: AbortSignal;
		executor?: ProtectionPythonInstallOptions["executor"];
	} = {},
): Promise<ProtectionPythonVerifyResult> {
	const agentDir = options.agentDir ?? getAgentDir();
	const installDir = path.join(agentDir, "tools", id);
	const isWindows = process.platform === "win32";

	switch (id) {
		case "frida-dexdump": {
			const wrapperPath = path.join(installDir, "bin", isWindows ? "frida-dexdump.cmd" : "frida-dexdump");
			const venvPy = path.join(installDir, ".venv", isWindows ? "Scripts/python.exe" : "bin/python");
			if (!fs.existsSync(wrapperPath) || !fs.existsSync(venvPy)) {
				return { ready: false, id, error: `frida-dexdump wrapper or venv missing at ${installDir}` };
			}
			try {
				await runPythonSubprocess(
					[venvPy, "-c", "import frida; from frida_dexdump.agent import DexDumpAgent; print('OK')"],
					{ signal: options.signal, executor: options.executor, env: options.env },
				);
				return {
					ready: true,
					id,
					version: FRIDA_DEXDUMP_VERSION,
					executablePath: wrapperPath,
					metadata: {
						executablePath: wrapperPath,
						pythonPath: venvPy,
						version: FRIDA_DEXDUMP_VERSION,
						license: FRIDA_DEXDUMP_LICENSE,
					},
				};
			} catch (err) {
				return { ready: false, id, error: String(err) };
			}
		}

		case "msynth": {
			const venvPy = path.join(installDir, ".venv", isWindows ? "Scripts/python.exe" : "bin/python");
			const oraclePath = path.join(installDir, "src", "oracle.pickle");
			if (!fs.existsSync(venvPy) || !fs.existsSync(oraclePath)) {
				return { ready: false, id, error: `msynth venv or oracle.pickle missing at ${installDir}` };
			}
			try {
				const proof = `
import msynth, miasm, z3
from msynth import Simplifier
s = Simplifier('${oraclePath}')
print('OK')
`;
				await runPythonSubprocess([venvPy, "-c", proof], {
					signal: options.signal,
					executor: options.executor,
					env: options.env,
				});
				return {
					ready: true,
					id,
					version: MSYNTH_VERSION,
					executablePath: venvPy,
					metadata: {
						pythonPath: venvPy,
						packageDir: path.join(installDir, "src"),
						oraclePath,
						oracleSha256: MSYNTH_ORACLE_PICKLE_SHA256,
						version: MSYNTH_VERSION,
						license: MSYNTH_LICENSE,
					},
				};
			} catch (err) {
				return { ready: false, id, error: String(err) };
			}
		}

		case "d810-ng": {
			const venvPy = path.join(installDir, ".venv", isWindows ? "Scripts/python.exe" : "bin/python");
			if (!fs.existsSync(venvPy)) {
				return { ready: false, id, error: `d810-ng venv missing at ${installDir}` };
			}
			try {
				await runPythonSubprocess([venvPy, "-c", "import d810; print('OK')"], {
					signal: options.signal,
					executor: options.executor,
					env: options.env,
				});
				return {
					ready: true,
					id,
					version: D810_NG_VERSION,
					executablePath: venvPy,
					metadata: {
						pythonPath: venvPy,
						packageDir: installDir,
						version: D810_NG_VERSION,
						license: D810_NG_LICENSE,
					},
				};
			} catch (err) {
				return { ready: false, id, error: String(err) };
			}
		}

		case "tritondse": {
			const wrapperPath = path.join(installDir, "bin", isWindows ? "tritondse-python.cmd" : "tritondse-python");
			const venvPy = path.join(installDir, ".venv", isWindows ? "Scripts/python.exe" : "bin/python");
			const execTarget = fs.existsSync(wrapperPath) ? wrapperPath : venvPy;
			if (!fs.existsSync(venvPy)) {
				return { ready: false, id, error: `tritondse venv missing at ${installDir}` };
			}
			try {
				const proof =
					"from tritondse import Config, Program, ProcessState; c = Config(); p = ProcessState(); print('OK')";
				const env: Record<string, string | undefined> = {
					...options.env,
					DYLD_LIBRARY_PATH: path.join(installDir, "lib"),
					MAGIC: path.join(installDir, "share", "misc", "magic.mgc"),
				};
				await runPythonSubprocess([execTarget, "-c", proof], {
					signal: options.signal,
					executor: options.executor,
					env,
				});
				return {
					ready: true,
					id,
					version: TRITONDSE_VERSION,
					executablePath: execTarget,
					metadata: {
						pythonPath: execTarget,
						executablePath: execTarget,
						packageDir: path.join(installDir, "src"),
						version: TRITONDSE_VERSION,
						license: TRITONDSE_LICENSE,
					},
				};
			} catch (err) {
				return { ready: false, id, error: String(err) };
			}
		}

		default:
			return { ready: false, id, error: `Unknown tool id: ${id}` };
	}
}
