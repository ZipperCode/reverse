import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as fsPromises from "node:fs/promises";
import * as path from "node:path";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { getAgentDir } from "@reverse/utils";
import { resolveProtectionTool } from "../extensibility/protection-toolchain";
import { stageRunnerScript } from "../eval/runner-cache";
import { probeFridaLiveDependency } from "./frida-live-env";
import { resolveFridaSessionTarget } from "./frida-session";

// ============================================================================
// Types & Contracts
// ============================================================================

export interface TargetEnvironment {
	platform: "android" | "linux" | "darwin" | "windows" | string;
	arch: "arm64" | "arm" | "x64" | "ia32" | string;
	pointerSize: 4 | 8 | number;
	tmpDir?: string;
}

export interface DeployQbdiOptions {
	pid?: number;
	process?: string;
	spawn?: string;
	device?: string; // -D <device> or ADB serial
	usb?: boolean; // -U
	host?: string; // -H <host:port>
	sessionId?: string;

	// Explicit caller overrides (respected verbatim, no host checks for remote)
	qbdiLibPath?: string;
	qbdiLibDir?: string;
	fridaBindingSource?: string;

	cwd: string;
	agentDir?: string;
	signal?: AbortSignal;
	timeoutMs?: number;
	chunkSize?: number;
}

export interface DeployedQbdiResult {
	targetLibPath: string;
	targetLibDir: string;
	fridaBindingSource: string;
	platform: string;
	arch: string;
	pointerSize: number;
	pid?: number;
	spawned?: boolean;
	deployed: boolean;
	ownedArtifactPath?: string;
	ownedArtifactDir?: string;
	resume?: () => Promise<void>;
	cleanup: () => Promise<void>;
}

export interface ValidateLibraryAbiResult {
	valid: boolean;
	expectedPlatform: string;
	expectedArch: string;
	detectedFormat?: string;
	detectedMachine?: number | string;
	error?: string;
}

export interface ManagedQbdiAssets {
	assetsDir: string;
	hostLib?: string;
	androidArm64Lib?: string;
	androidArmLib?: string;
	fridaBinding?: string;
	version: string;
}

// ============================================================================
// Injected Target Agent Script
// ============================================================================

export const QBDI_DEPLOY_AGENT_SCRIPT = `(function() {
function findExport(name) {
    if (typeof Module.findExportByName === "function") {
        try {
            var p = Module.findExportByName(null, name);
            if (p) return p;
        } catch (e) {}
    }
    if (typeof Module.findGlobalExportByName === "function") {
        try {
            var p = Module.findGlobalExportByName(name);
            if (p) return p;
        } catch (e) {}
    }
    return null;
}

var openPtr = findExport("open");
var writePtr = findExport("write");
var closePtr = findExport("close");
var mkdirPtr = findExport("mkdir");
var unlinkPtr = findExport("unlink");
var rmdirPtr = findExport("rmdir");
var chmodPtr = findExport("chmod");

var openFn = openPtr ? new NativeFunction(openPtr, "int", ["pointer", "int", "int"]) : null;
var writeFn = writePtr ? new NativeFunction(writePtr, "size_t", ["int", "pointer", "size_t"]) : null;
var closeFn = closePtr ? new NativeFunction(closePtr, "int", ["int"]) : null;
var mkdirFn = mkdirPtr ? new NativeFunction(mkdirPtr, "int", ["pointer", "int"]) : null;
var unlinkFn = unlinkPtr ? new NativeFunction(unlinkPtr, "int", ["pointer"]) : null;
var rmdirFn = rmdirPtr ? new NativeFunction(rmdirPtr, "int", ["pointer"]) : null;
var chmodFn = chmodPtr ? new NativeFunction(chmodPtr, "int", ["pointer", "int"]) : null;

function detectPlatform() {
    var raw = Process.platform;
    if (raw === "android") return "android";
    if (raw === "linux") {
        // Frida often reports Process.platform === "linux" on Android.
        // Discriminate Android Bionic vs generic glibc/musl Linux by checking
        // Bionic property exports, Java runtime, or ART/Android modules.
        var isBionic = Boolean(findExport("__system_property_get")) ||
            Boolean(findExport("__system_property_read")) ||
            (typeof Java !== "undefined" && Java.available);
        if (!isBionic && typeof Process.findModuleByName === "function") {
            isBionic = Boolean(Process.findModuleByName("libart.so") || Process.findModuleByName("libandroid_runtime.so"));
        }
        return isBionic ? "android" : "linux";
    }
    return raw;
}

function base64ToUint8Array(base64) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var lookup = new Uint8Array(256);
    for (var i = 0; i < chars.length; i++) lookup[chars.charCodeAt(i)] = i;
    var len = base64.length;
    var placeHolders = 0;
    if (base64.charAt(len - 1) === "=") placeHolders++;
    if (base64.charAt(len - 2) === "=") placeHolders++;
    var byteLength = Math.floor((len * 3) / 4) - placeHolders;
    var u8 = new Uint8Array(byteLength);
    var cur = 0;
    for (var j = 0; j < len; j += 4) {
        var a = lookup[base64.charCodeAt(j)];
        var b = lookup[base64.charCodeAt(j + 1)];
        var c = lookup[base64.charCodeAt(j + 2)];
        var d = lookup[base64.charCodeAt(j + 3)];
        u8[cur++] = (a << 2) | (b >> 4);
        if (cur < byteLength) u8[cur++] = ((b & 15) << 4) | (c >> 2);
        if (cur < byteLength) u8[cur++] = ((c & 3) << 6) | (d & 63);
    }
    return u8;
}

function getWritableTargetDirectory(plat) {
    if (plat === "android") {
        try {
            var probePath = "/data/local/tmp/.reverse_probe_" + Math.random().toString(36).substring(2, 10) + ".tmp";
            var f = new File(probePath, "wb");
            f.write("probe");
            f.flush();
            f.close();
            if (unlinkFn) unlinkFn(Memory.allocUtf8String(probePath));
            return "/data/local/tmp";
        } catch (e) {}

        if (typeof Java !== "undefined" && Java.available) {
            try {
                var ActivityThread = Java.use("android.app.ActivityThread");
                var app = ActivityThread.currentApplication();
                if (app) {
                    var ctx = app.getApplicationContext();
                    var codeCache = ctx.getCodeCacheDir();
                    if (codeCache) return codeCache.getAbsolutePath();
                }
            } catch (je) {}
        }
        return "/data/local/tmp";
    }

    if (plat === "darwin" || plat === "linux") {
        try {
            if (typeof Process.getTmpDir === "function") {
                var td = Process.getTmpDir();
                if (td) return td;
            }
        } catch (e) {}
        return "/tmp";
    }

    return "/tmp";
}

var activeFd = -1;
var activeChecksum = null;
var activeDir = null;
var activePath = null;
var writtenBytes = 0;
var firstChunkHeader = null;

rpc.exports = {
    probe: function() {
        var plat = detectPlatform();
        return {
            platform: plat,
            arch: Process.arch,
            pointerSize: Process.pointerSize,
            tmpDir: getWritableTargetDirectory(plat)
        };
    },
    openDestination: function(targetDir, targetFileName) {
        if (!openFn || !writeFn || !closeFn || !mkdirFn) {
            return { ok: false, error: "Required POSIX libc open/write/close exports missing on target" };
        }
        activeDir = targetDir;
        activePath = targetDir + "/" + targetFileName;
        writtenBytes = 0;
        firstChunkHeader = null;

        var dirPtr = Memory.allocUtf8String(targetDir);
        mkdirFn(dirPtr, 493); // 0755

        var filePtr = Memory.allocUtf8String(activePath);
        // O_WRONLY | O_CREAT | O_EXCL
        var flags = (Process.platform === "darwin") ? 2561 : 193;
        activeFd = openFn(filePtr, flags, 493);
        if (activeFd < 0) {
            return { ok: false, error: "open failed with O_EXCL (destination file already exists or permission denied)", fd: activeFd };
        }

        if (typeof Checksum === "undefined") {
            closeFn(activeFd);
            activeFd = -1;
            if (unlinkFn) unlinkFn(filePtr);
            if (rmdirFn) rmdirFn(dirPtr);
            return { ok: false, error: "Checksum utility not available on target runtime; failing closed" };
        }

        activeChecksum = new Checksum("sha256");
        return { ok: true, path: activePath, dir: activeDir };
    },
    writeChunk: function(b64) {
        if (activeFd < 0) return { ok: false, error: "No destination file open" };
        var u8 = base64ToUint8Array(b64);
        if (!firstChunkHeader && u8.length >= 24) {
            firstChunkHeader = Array.from(u8.subarray(0, 24));
        }
        var mem = Memory.alloc(u8.length);
        mem.writeByteArray(Array.from(u8));
        writeFn(activeFd, mem, u8.length);
        activeChecksum.update(u8.buffer);
        writtenBytes += u8.length;
        return { ok: true, writtenBytes: writtenBytes };
    },
    closeAndVerify: function(expectedSize, expectedSha256, expectedPlatform, expectedArch) {
        if (activeFd < 0) return { ok: false, error: "No active file to finalize" };
        closeFn(activeFd);
        activeFd = -1;

        var filePtr = Memory.allocUtf8String(activePath);
        var dirPtr = Memory.allocUtf8String(activeDir);

        if (chmodFn) chmodFn(filePtr, 493);

        if (!activeChecksum) {
            if (unlinkFn) unlinkFn(filePtr);
            if (rmdirFn) rmdirFn(dirPtr);
            return { ok: false, error: "Target Checksum context missing; failing closed" };
        }

        var actualSha256 = activeChecksum.getString();
        activeChecksum = null;

        var sizeMatch = (writtenBytes === expectedSize);
        var shaMatch = expectedSha256 ? (actualSha256.toLowerCase() === expectedSha256.toLowerCase()) : false;

        var abiValid = true;
        var abiError = null;

        if (firstChunkHeader && firstChunkHeader.length >= 24) {
            var h = firstChunkHeader;
            if (expectedPlatform === "android" || expectedPlatform === "linux") {
                if (h[0] !== 0x7f || h[1] !== 0x45 || h[2] !== 0x4c || h[3] !== 0x46) {
                    abiValid = false;
                    abiError = "Missing ELF magic in deployed library";
                } else {
                    var machine = (h[18] | (h[19] << 8)) >>> 0;
                    if ((expectedArch === "arm64" || expectedArch === "aarch64") && machine !== 0xb7) {
                        abiValid = false;
                        abiError = "ELF machine mismatch: expected EM_AARCH64 (0xb7), got 0x" + machine.toString(16);
                    } else if (expectedArch === "arm" && machine !== 0x28) {
                        abiValid = false;
                        abiError = "ELF machine mismatch: expected EM_ARM (0x28), got 0x" + machine.toString(16);
                    }
                }
            } else if (expectedPlatform === "darwin") {
                var magicLE = (h[0] | (h[1] << 8) | (h[2] << 16) | (h[3] << 24)) >>> 0;
                var isMachO64 = (magicLE === 0xfeedfacf);
                var isMachO32 = (magicLE === 0xfeedface);
                var isFat = (magicLE === 0xbebafeca || magicLE === 0xcafebabe);
                if (!isMachO64 && !isMachO32 && !isFat) {
                    abiValid = false;
                    abiError = "Missing Mach-O magic in deployed library (got 0x" + magicLE.toString(16) + ")";
                }
            }
        }

        if (!sizeMatch || !shaMatch || !abiValid) {
            if (unlinkFn) unlinkFn(filePtr);
            if (rmdirFn) rmdirFn(dirPtr);
            return {
                ok: false,
                error: abiError || "Integrity verification failed (sizeMatch=" + sizeMatch + ", shaMatch=" + shaMatch + ")",
                sizeMatch: sizeMatch,
                shaMatch: shaMatch,
                abiValid: abiValid,
                abiError: abiError,
                actualSize: writtenBytes,
                expectedSize: expectedSize,
                actualSha256: actualSha256,
                expectedSha256: expectedSha256
            };
        }

        return {
            ok: true,
            sizeMatch: true,
            shaMatch: true,
            abiValid: true,
            actualSize: writtenBytes,
            expectedSize: expectedSize,
            actualSha256: actualSha256,
            expectedSha256: expectedSha256
        };
    },
    cleanup: function(targetDir, targetFileName) {
        var filePath = targetDir + "/" + targetFileName;
        var filePtr = Memory.allocUtf8String(filePath);
        var dirPtr = Memory.allocUtf8String(targetDir);
        var fileUnlinked = unlinkFn ? (unlinkFn(filePtr) === 0) : false;
        var dirRmdired = rmdirFn ? (rmdirFn(dirPtr) === 0) : false;
        return { ok: fileUnlinked, fileUnlinked: fileUnlinked, dirRmdired: dirRmdired };
    }
};
})();`;

export const PYTHON_DEPLOY_RUNNER_SCRIPT = `"""Independent Frida QBDI library deployment runner."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

def main() -> None:
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            sys.stdout.write(json.dumps({"status": "error", "error": "Empty input"}) + "\\n")
            return
        req = json.loads(raw_input)
    except Exception as e:
        sys.stdout.write(json.dumps({"status": "error", "error": f"Invalid JSON request: {e}"}) + "\\n")
        return

    action = req.get("action", "deploy")
    target = req.get("target", {})
    agent_code = req.get("agentCode", "")

    import frida

    dev = None
    try:
        if target.get("usb"):
            dev = frida.get_usb_device()
        elif target.get("device") and str(target["device"]).strip() not in ("local", ""):
            dev = frida.get_device_manager().get_device(str(target["device"]).strip())
        elif target.get("host") and str(target["host"]).strip():
            dev = frida.get_device_manager().add_remote_device(str(target["host"]).strip())
        else:
            dev = frida.get_local_device()
    except Exception as e:
        sys.stdout.write(json.dumps({"status": "error", "error": f"Failed to connect to Frida device: {e}"}) + "\\n")
        return

    session = None
    pid = target.get("pid")
    process = target.get("process")
    spawn = target.get("spawn")

    if action == "cleanup":
        target_dir = req.get("targetDir")
        target_file_name = req.get("targetFileName")
        if not target_dir or not target_file_name:
            sys.stdout.write(json.dumps({"status": "error", "error": "Must specify targetDir and targetFileName for cleanup"}) + "\\n")
            return

        target_file = os.path.join(target_dir, target_file_name)
        is_local = not target.get("usb") and not target.get("host") and (not target.get("device") or str(target.get("device")).strip() in ("local", ""))

        if is_local:
            unlinked = False
            rmdired = False
            if os.path.exists(target_file):
                try:
                    os.unlink(target_file)
                    unlinked = True
                except Exception:
                    pass
            else:
                unlinked = True
            if os.path.exists(target_dir):
                try:
                    os.rmdir(target_dir)
                    rmdired = True
                except Exception:
                    pass
            else:
                rmdired = True
            sys.stdout.write(json.dumps({"status": "ok", "pid": pid, "cleanup": {"ok": unlinked and rmdired, "fileUnlinked": unlinked, "dirRmdired": rmdired}}) + "\\n")
            return

        # For remote target: try attaching to pid if still alive, or spawn minimal shell cleanup
        if dev and pid is not None:
            try:
                session = dev.attach(int(pid))
                script = session.create_script(agent_code)
                script.load()
                res = script.exports_sync.cleanup(target_dir, target_file_name)
                sys.stdout.write(json.dumps({"status": "ok", "pid": pid, "cleanup": res}) + "\\n")
                return
            except Exception:
                pass

        if dev:
            try:
                h_pid = dev.spawn(["/system/bin/sh", "-c", f"rm -rf '{target_dir}'"])
                dev.resume(h_pid)
                sys.stdout.write(json.dumps({"status": "ok", "pid": pid, "cleanup": {"ok": True, "helper": True}}) + "\\n")
                return
            except Exception as e:
                sys.stdout.write(json.dumps({"status": "error", "error": f"Remote cleanup failed: {e}"}) + "\\n")
                return

    try:
        if pid is not None:
            session = dev.attach(int(pid))
        elif process:
            session = dev.attach(str(process).strip())
        elif spawn:
            argv = spawn if isinstance(spawn, list) else [str(spawn).strip()]
            pid = dev.spawn(argv)
            session = dev.attach(pid)
        else:
            sys.stdout.write(json.dumps({"status": "error", "error": "Target must specify pid, process, or spawn"}) + "\\n")
            return
    except Exception as e:
        sys.stdout.write(json.dumps({"status": "error", "error": f"Failed to attach to target: {e}"}) + "\\n")
        return

    try:
        script = session.create_script(agent_code)
        script.load()

        if action == "probe":
            probe_res = script.exports_sync.probe()
            sys.stdout.write(json.dumps({"status": "ok", "pid": pid, "probe": probe_res}) + "\\n")
            return
        if action == "deploy":
            # Probe on the exact same attached session
            probe_info = script.exports_sync.probe()
            p_plat = probe_info.get("platform")
            p_arch = probe_info.get("arch")
            p_tmp = probe_info.get("tmpDir") or "/tmp"

            candidate_libs = req.get("candidateLibs", {})
            key = f"{p_plat}_{p_arch}"
            source_lib = req.get("sourceLib") or candidate_libs.get(key)
            if not source_lib or not os.path.exists(source_lib):
                sys.stdout.write(json.dumps({
                    "status": "error",
                    "error": f"No matching managed QBDI library for target {p_plat}-{p_arch}. Available candidates: {list(candidate_libs.keys())}",
                    "pid": pid,
                    "platform": p_plat,
                    "arch": p_arch,
                }) + "\\n")
                return

            expected_size = os.path.getsize(source_lib)
            with open(source_lib, "rb") as f:
                expected_sha256 = hashlib.sha256(f.read()).hexdigest()

            target_file_name = os.path.basename(source_lib)
            rand_tag = req.get("randTag") or "default"
            target_dir = f"{p_tmp}/reverse-qbdi-{rand_tag}"
            chunk_size = req.get("chunkSize", 65536)

            open_res = script.exports_sync.open_destination(target_dir, target_file_name)
            if not open_res.get("ok"):
                sys.stdout.write(json.dumps({"status": "error", "error": f"Failed to open exclusive destination on target: {open_res.get('error')}"}) + "\\n")
                return

            with open(source_lib, "rb") as fp:
                while True:
                    chunk = fp.read(chunk_size)
                    if not chunk:
                        break
                    b64 = base64.b64encode(chunk).decode("ascii")
                    script.exports_sync.write_chunk(b64)

            verify_res = script.exports_sync.close_and_verify(
                expected_size,
                expected_sha256,
                p_plat,
                p_arch,
            )

            if not verify_res.get("ok"):
                sys.stdout.write(json.dumps({
                    "status": "error",
                    "error": f"Target verification failed: {verify_res.get('error')}",
                    "details": verify_res,
                }) + "\\n")
                return

            target_lib_path = f"{target_dir}/{target_file_name}"
            sys.stdout.write(json.dumps({
                "status": "ok",
                "pid": pid,
                "spawned": bool(spawn and not req.get("target", {}).get("pid")),
                "targetLibPath": target_lib_path,
                "targetLibDir": target_dir,
                "platform": p_plat,
                "arch": p_arch,
                "pointerSize": probe_info.get("pointerSize"),
                "verification": verify_res,
            }) + "\n")
            return

        if action == "resume":
            if pid is None:
                sys.stdout.write(json.dumps({"status": "error", "error": "No pid to resume"}) + "\n")
                return
            try:
                dev.resume(int(pid))
                sys.stdout.write(json.dumps({"status": "ok", "pid": pid, "resumed": True}) + "\n")
            except Exception as e:
                sys.stdout.write(json.dumps({"status": "error", "error": f"Failed to resume pid {pid}: {e}"}) + "\n")
            return

        sys.stdout.write(json.dumps({"status": "error", "error": f"Unknown action: {action}"}) + "\\n")
    except Exception as e:
        sys.stdout.write(json.dumps({"status": "error", "error": f"Operation failed: {e}"}) + "\\n")
    finally:
        try:
            if session:
                session.detach()
        except Exception:
            pass

if __name__ == "__main__":
    main()
`;

// ============================================================================
// Process Execution Helper
// ============================================================================

async function readStreamBounded(stream: ReadableStream<Uint8Array>, maxBytes: number): Promise<string> {
	const reader = stream.getReader();
	const decoder = new TextDecoder();
	let result = "";
	let totalBytes = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (value) {
				totalBytes += value.byteLength;
				if (totalBytes > maxBytes) {
					result += decoder.decode(value.subarray(0, Math.max(0, maxBytes - (totalBytes - value.byteLength))));
					break;
				}
				result += decoder.decode(value, { stream: true });
			}
		}
		result += decoder.decode();
	} finally {
		reader.releaseLock();
	}
	return result;
}

async function runDeploymentWorker<T = Record<string, unknown>>(
	pythonPath: string,
	scriptPath: string,
	payload: unknown,
	options: {
		cwd: string;
		timeoutMs?: number;
		signal?: AbortSignal;
		maxBytes?: number;
	},
): Promise<T> {
	if (options.signal?.aborted) {
		throw new ToolError("Deployment cancelled before start");
	}

	const timeoutMs = options.timeoutMs ?? 30000;
	const maxBytes = options.maxBytes ?? 1024 * 1024;

	const child = Bun.spawn([pythonPath, "-u", scriptPath], {
		cwd: options.cwd,
		stdin: "pipe",
		stdout: "pipe",
		stderr: "pipe",
	});

	let timedOut = false;

	const abortHandler = () => {
		try {
			child.kill();
		} catch {}
	};
	options.signal?.addEventListener("abort", abortHandler, { once: true });

	const timeoutTimer = setTimeout(() => {
		timedOut = true;
		try {
			child.kill();
		} catch {}
	}, timeoutMs);

	try {
		child.stdin.write(JSON.stringify(payload));
		child.stdin.end();

		const [rawStdout, rawStderr] = await Promise.all([
			readStreamBounded(child.stdout, maxBytes),
			readStreamBounded(child.stderr, maxBytes),
		]);

		const exitCode = await child.exited;

		if (timedOut) {
			throw new ToolError(`Deployment worker timed out after ${timeoutMs}ms`);
		}
		if (options.signal?.aborted) {
			throw new ToolError("Deployment aborted by signal");
		}
		if (exitCode !== 0) {
			throw new ToolError(
				`Deployment worker exited with code ${exitCode}: ${rawStderr || rawStdout || "Unknown error"}`,
			);
		}

		const trimmed = rawStdout.trim();
		if (!trimmed) {
			throw new ToolError(`Deployment worker emitted empty output: ${rawStderr}`);
		}

		const parsed = JSON.parse(trimmed);
		if (parsed.status !== "ok") {
			throw new ToolError(`Deployment failed: ${parsed.error ?? "Unknown error"}`);
		}

		return parsed as T;
	} finally {
		clearTimeout(timeoutTimer);
		options.signal?.removeEventListener("abort", abortHandler);
	}
}

// ============================================================================
// ABI Validation Helpers
// ============================================================================

export function validateLibraryAbi(
	bufferOrPath: Buffer | string,
	platform: string,
	arch: string,
): ValidateLibraryAbiResult {
	try {
		let buf: Buffer;
		if (typeof bufferOrPath === "string") {
			if (!fs.existsSync(bufferOrPath)) {
				return {
					valid: false,
					expectedPlatform: platform,
					expectedArch: arch,
					error: `File not found: ${bufferOrPath}`,
				};
			}
			const fd = fs.openSync(bufferOrPath, "r");
			buf = Buffer.alloc(24);
			fs.readSync(fd, buf, 0, 24, 0);
			fs.closeSync(fd);
		} else {
			buf = bufferOrPath.subarray(0, 24);
		}

		if (buf.length < 20) {
			return { valid: false, expectedPlatform: platform, expectedArch: arch, error: "Header too short (<20 bytes)" };
		}

		if (platform === "android" || platform === "linux") {
			if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
				return {
					valid: false,
					expectedPlatform: platform,
					expectedArch: arch,
					detectedFormat: "non-elf",
					error: "Missing ELF magic bytes",
				};
			}
			const eiClass = buf[4];
			const machine = buf.readUInt16LE(18);

			if (arch === "arm64" || arch === "aarch64") {
				if (machine !== 0xb7 || eiClass !== 2) {
					return {
						valid: false,
						expectedPlatform: platform,
						expectedArch: arch,
						detectedFormat: "elf",
						detectedMachine: machine,
						error: `Expected ELF AArch64 (0xb7, 64-bit), got machine 0x${machine.toString(16)} class ${eiClass}`,
					};
				}
				return {
					valid: true,
					expectedPlatform: platform,
					expectedArch: arch,
					detectedFormat: "elf-arm64",
					detectedMachine: machine,
				};
			}

			if (arch === "arm" || arch === "armeabi" || arch === "armv7l") {
				if (machine !== 0x28 || eiClass !== 1) {
					return {
						valid: false,
						expectedPlatform: platform,
						expectedArch: arch,
						detectedFormat: "elf",
						detectedMachine: machine,
						error: `Expected ELF ARM32 (0x28, 32-bit), got machine 0x${machine.toString(16)} class ${eiClass}`,
					};
				}
				return {
					valid: true,
					expectedPlatform: platform,
					expectedArch: arch,
					detectedFormat: "elf-arm32",
					detectedMachine: machine,
				};
			}

			if (arch === "x64") {
				if (machine !== 0x3e || eiClass !== 2) {
					return {
						valid: false,
						expectedPlatform: platform,
						expectedArch: arch,
						detectedFormat: "elf",
						detectedMachine: machine,
						error: `Expected ELF x86_64 (0x3e, 64-bit), got machine 0x${machine.toString(16)} class ${eiClass}`,
					};
				}
				return {
					valid: true,
					expectedPlatform: platform,
					expectedArch: arch,
					detectedFormat: "elf-x64",
					detectedMachine: machine,
				};
			}

			return {
				valid: true,
				expectedPlatform: platform,
				expectedArch: arch,
				detectedFormat: "elf",
				detectedMachine: machine,
			};
		}

		if (platform === "darwin") {
			const magicLE = buf.readUInt32LE(0);
			const magicBE = buf.readUInt32BE(0);
			const isMachO64 = magicLE === 0xfeedfacf;
			const isMachO32 = magicLE === 0xfeedface;
			const isFat = magicBE === 0xcafebabe || magicLE === 0xbebafeca;

			if (!isMachO64 && !isMachO32 && !isFat) {
				return {
					valid: false,
					expectedPlatform: platform,
					expectedArch: arch,
					detectedFormat: "non-macho",
					error: "Missing Mach-O magic bytes",
				};
			}

			if (isMachO64) {
				const cputype = buf.readInt32LE(4);
				if (arch === "arm64" && cputype !== 0x0100000c) {
					return {
						valid: false,
						expectedPlatform: platform,
						expectedArch: arch,
						detectedFormat: "macho-64",
						error: `Expected Mach-O ARM64 cputype, got 0x${cputype.toString(16)}`,
					};
				}
				if (arch === "x64" && cputype !== 0x01000007) {
					return {
						valid: false,
						expectedPlatform: platform,
						expectedArch: arch,
						detectedFormat: "macho-64",
						error: `Expected Mach-O x86_64 cputype, got 0x${cputype.toString(16)}`,
					};
				}
			}

			return {
				valid: true,
				expectedPlatform: platform,
				expectedArch: arch,
				detectedFormat: isFat ? "macho-fat" : isMachO64 ? "macho-64" : "macho-32",
			};
		}

		if (platform === "win32" || platform === "windows") {
			const isMz = buf[0] === 0x4d && buf[1] === 0x5a;
			return { valid: isMz, expectedPlatform: platform, expectedArch: arch, detectedFormat: isMz ? "pe" : "non-pe" };
		}

		return { valid: true, expectedPlatform: platform, expectedArch: arch };
	} catch (err) {
		return { valid: false, expectedPlatform: platform, expectedArch: arch, error: String(err) };
	}
}
export function probeLocalTargetArch(options: { spawn?: string; pid?: number; process?: string }): {
	arch: string;
	pointerSize: number;
} {
	const defaultArch = process.arch;
	const defaultPtr = process.arch === "arm64" || process.arch === "x64" ? 8 : 4;

	if (process.platform !== "darwin") {
		return { arch: defaultArch, pointerSize: defaultPtr };
	}

	let targetBinaryPath: string | undefined;
	if (options.spawn) {
		targetBinaryPath = options.spawn.trim();
	} else if (options.pid) {
		try {
			const res = Bun.spawnSync(["ps", "-p", String(options.pid), "-o", "comm="]);
			if (res.exitCode === 0) {
				const comm = Buffer.from(res.stdout).toString("utf-8").trim();
				if (comm.length > 0 && fs.existsSync(comm)) {
					targetBinaryPath = comm;
				}
			}
		} catch {}
	}

	if (targetBinaryPath && fs.existsSync(targetBinaryPath)) {
		try {
			const fd = fs.openSync(targetBinaryPath, "r");
			const buf = Buffer.alloc(24);
			fs.readSync(fd, buf, 0, 24, 0);
			fs.closeSync(fd);

			if (buf.length >= 8) {
				const magicLE = buf.readUInt32LE(0);
				if (magicLE === 0xfeedfacf) {
					const cputype = buf.readInt32LE(4);
					if (cputype === 0x01000007) {
						return { arch: "x64", pointerSize: 8 };
					}
					if (cputype === 0x0100000c) {
						return { arch: "arm64", pointerSize: 8 };
					}
				}
			}
		} catch {}
	}

	return { arch: defaultArch, pointerSize: defaultPtr };
}

// ============================================================================
// Asset Resolution
// ============================================================================

export function resolveQbdiAssets(options: { agentDir?: string } = {}): ManagedQbdiAssets {
	const agentDir = options.agentDir?.trim() || getAgentDir();
	const candidateAgentDirs = [agentDir].filter(
		(d): d is string => typeof d === "string" && d.trim().length > 0 && fs.existsSync(d),
	);
	for (const candidateDir of candidateAgentDirs) {
		const qbdiDir = path.join(candidateDir, "tools", "qbdi");
		if (fs.existsSync(qbdiDir)) {
			const hostLibCandidates = [
				path.join(
					qbdiDir,
					process.platform === "darwin"
						? "libQBDI.dylib"
						: process.platform === "win32"
							? "QBDI.dll"
							: "libQBDI.so",
				),
				path.join(qbdiDir, "lib", process.platform === "darwin" ? "libQBDI.dylib" : "libQBDI.so"),
			];
			const hostLib = hostLibCandidates.find(p => fs.existsSync(p));

			const arm64Candidates = [
				path.join(qbdiDir, "android-arm64", "libQBDI.so"),
				path.join(qbdiDir, "android-arm64", "lib", "libQBDI.so"),
			];
			const androidArm64Lib = arm64Candidates.find(p => fs.existsSync(p));

			const arm32Candidates = [
				path.join(qbdiDir, "android-arm", "libQBDI.so"),
				path.join(qbdiDir, "android-arm", "lib", "libQBDI.so"),
			];
			const androidArmLib = arm32Candidates.find(p => fs.existsSync(p));

			const fridaBinding = path.join(qbdiDir, "frida-qbdi.js");

			return {
				assetsDir: qbdiDir,
				hostLib,
				androidArm64Lib,
				androidArmLib,
				fridaBinding: fs.existsSync(fridaBinding) ? fridaBinding : undefined,
				version: "0.12.1",
			};
		}
	}

	const fallbackResolved = resolveProtectionTool("qbdi", { agentDir: options.agentDir, allowMissing: true });
	return {
		assetsDir: fallbackResolved?.binDir ?? path.join(getAgentDir(), "tools", "qbdi"),
		hostLib: fallbackResolved?.metadata?.libPath as string | undefined,
		androidArm64Lib: fallbackResolved?.metadata?.androidArm64Lib as string | undefined,
		androidArmLib: fallbackResolved?.metadata?.androidArmLib as string | undefined,
		fridaBinding: fallbackResolved?.metadata?.fridaBinding as string | undefined,
		version: fallbackResolved?.version ?? "0.12.1",
	};
}

export function resolveManagedQbdiLibrary(
	platform: string,
	arch: string,
	options: { agentDir?: string } = {},
): { path: string; name: string } {
	const assets = resolveQbdiAssets(options);

	if (platform === "android") {
		if (arch === "arm64" || arch === "aarch64") {
			if (!assets.androidArm64Lib || !fs.existsSync(assets.androidArm64Lib)) {
				throw new ToolError(
					"QBDI Android ARM64 target library not installed. Run 'reverse setup reverse qbdi --execute' to download pinned QBDI v0.12.1 Android AARCH64 assets.",
				);
			}
			return { path: assets.androidArm64Lib, name: "libQBDI.so" };
		}

		if (arch === "arm" || arch === "armeabi" || arch === "armv7l") {
			if (!assets.androidArmLib || !fs.existsSync(assets.androidArmLib)) {
				throw new ToolError(
					"QBDI Android ARM32 target library not installed. Run 'reverse setup reverse qbdi --execute' to download pinned QBDI v0.12.1 Android ARM assets.",
				);
			}
			return { path: assets.androidArmLib, name: "libQBDI.so" };
		}

		throw new ToolError(
			`QBDI Android ${arch} target architecture is not provided in managed release assets (supported: android-arm64, android-arm). Supply a target library via qbdiLibPath.`,
		);
	}

	if (platform === "darwin") {
		if (assets.hostLib && fs.existsSync(assets.hostLib)) {
			const abi = validateLibraryAbi(assets.hostLib, "darwin", arch);
			if (abi.valid) {
				return { path: assets.hostLib, name: "libQBDI.dylib" };
			}
		}
		throw new ToolError(
			`QBDI macOS (${arch}) native library not installed. Run 'reverse setup reverse qbdi --execute' to install pinned QBDI v0.12.1.`,
		);
	}

	if (platform === "linux") {
		if (process.platform === "linux" && assets.hostLib && fs.existsSync(assets.hostLib)) {
			return { path: assets.hostLib, name: "libQBDI.so" };
		}
		throw new ToolError(
			`Remote Linux (${arch}) QBDI target library not available in local assets. Build or deploy libQBDI.so on the remote Linux host and supply its path via qbdiLibPath.`,
		);
	}

	throw new ToolError(
		`Unsupported target platform '${platform}' for remote QBDI deployment. Supply target library via qbdiLibPath.`,
	);
}

// ============================================================================
// Core QBDI Library Deployment
// ============================================================================

export async function deployQbdiLibrary(options: DeployQbdiOptions): Promise<DeployedQbdiResult> {
	if (options.signal?.aborted) {
		throw new ToolError("Deployment cancelled before start");
	}

	// 1. Resolve binding source
	let fridaBindingSource = options.fridaBindingSource;
	if (!fridaBindingSource || fridaBindingSource.trim().length === 0) {
		const assets = resolveQbdiAssets({ agentDir: options.agentDir });
		if (assets.fridaBinding && fs.existsSync(assets.fridaBinding)) {
			try {
				fridaBindingSource = await fsPromises.readFile(assets.fridaBinding, "utf-8");
			} catch {}
		}
	}

	// 2. Explicit target-side qbdiLibPath respected verbatim (never checked on host for remote)
	if (options.qbdiLibPath && options.qbdiLibPath.trim().length > 0) {
		const targetLibPath = options.qbdiLibPath.trim();
		const targetLibDir = options.qbdiLibDir?.trim() || path.posix.dirname(targetLibPath);
		return {
			targetLibPath,
			targetLibDir,
			fridaBindingSource: fridaBindingSource ?? "",
			platform: process.platform,
			arch: process.arch,
			pointerSize: process.arch === "arm64" || process.arch === "x64" ? 8 : 4,
			deployed: false,
			cleanup: async () => {},
		};
	}

	// 3. Resolve target attachment details
	let targetPid = options.pid;
	let targetProcess = options.process;
	let targetSpawn = options.spawn;
	let targetDevice = options.device;
	let targetUsb = options.usb;
	let targetHost = options.host;

	if (options.sessionId) {
		const sessionTarget = await resolveFridaSessionTarget(options.cwd, options.sessionId);
		if (sessionTarget) {
			targetPid = sessionTarget.pid ?? targetPid;
			targetProcess = sessionTarget.process ?? targetProcess;
			targetSpawn = sessionTarget.spawn ?? targetSpawn;
			targetDevice = sessionTarget.device ?? targetDevice;
			targetUsb = sessionTarget.usb ?? targetUsb;
			targetHost = sessionTarget.host ?? targetHost;
		}
	}

	const isRemote = Boolean(targetUsb || (targetDevice && targetDevice !== "local") || targetHost);

	// 4. Local target without explicit remote flags uses host library directly
	if (!isRemote) {
		const localTarget = probeLocalTargetArch({ spawn: targetSpawn, pid: targetPid, process: targetProcess });
		const hostMatch = resolveManagedQbdiLibrary(process.platform, localTarget.arch, { agentDir: options.agentDir });
		return {
			targetLibPath: hostMatch.path,
			targetLibDir: path.dirname(hostMatch.path),
			fridaBindingSource: fridaBindingSource ?? "",
			platform: process.platform,
			arch: localTarget.arch,
			pointerSize: localTarget.pointerSize,
			deployed: false,
			cleanup: async () => {},
		};
	}

	// 5. Remote target: resolve Python Frida environment
	const liveDep = await probeFridaLiveDependency();
	if (!liveDep.available || !liveDep.pythonPath) {
		throw new ToolError(
			"Frida Python environment not available for remote deployment. Run 'reverse setup reverse frida --execute'.",
		);
	}

	// 6. Build candidate libraries map for all supported target ABIs
	const assets = resolveQbdiAssets({ agentDir: options.agentDir });
	const candidateLibs: Record<string, string> = {};
	if (assets.androidArm64Lib && fs.existsSync(assets.androidArm64Lib)) {
		candidateLibs.android_arm64 = assets.androidArm64Lib;
		candidateLibs.android_aarch64 = assets.androidArm64Lib;
	}
	if (assets.androidArmLib && fs.existsSync(assets.androidArmLib)) {
		candidateLibs.android_arm = assets.androidArmLib;
		candidateLibs.android_armeabi = assets.androidArmLib;
		candidateLibs.android_armv7l = assets.androidArmLib;
	}
	if (assets.hostLib && fs.existsSync(assets.hostLib)) {
		candidateLibs[`${process.platform}_${process.arch}`] = assets.hostLib;
	}

	// 7. Execute single-attach probe + stream deployment via Python Frida runner with O_EXCL
	const randTag = crypto.randomBytes(6).toString("hex");
	const chunkSize = options.chunkSize && options.chunkSize > 0 ? options.chunkSize : 65536;

	const stagedScript = await stageRunnerScript("qbdi-deploy-worker", "py", PYTHON_DEPLOY_RUNNER_SCRIPT);
	const deployRes = await runDeploymentWorker<{
		status: string;
		pid?: number;
		spawned?: boolean;
		targetLibPath: string;
		targetLibDir: string;
		platform: string;
		arch: string;
		pointerSize: number;
		verification: { actualSize: number; actualSha256: string };
	}>(
		liveDep.pythonPath,
		stagedScript,
		{
			action: "deploy",
			agentCode: QBDI_DEPLOY_AGENT_SCRIPT,
			target: {
				pid: targetPid,
				process: targetProcess,
				spawn: targetSpawn,
				device: targetDevice,
				usb: targetUsb,
				host: targetHost,
			},
			candidateLibs,
			randTag,
			chunkSize,
		},
		{
			cwd: options.cwd,
			timeoutMs: options.timeoutMs,
			signal: options.signal,
		},
	);

	const finalPid = deployRes.pid ?? targetPid;
	const targetLibDir = deployRes.targetLibDir;
	const targetFileName = path.posix.basename(deployRes.targetLibPath);
	const wasSpawned = Boolean(deployRes.spawned);

	let hasResumed = false;
	const resume = async () => {
		if (hasResumed || !finalPid || !wasSpawned) return;
		hasResumed = true;
		try {
			await runDeploymentWorker(
				liveDep.pythonPath!,
				stagedScript,
				{
					action: "resume",
					agentCode: QBDI_DEPLOY_AGENT_SCRIPT,
					target: {
						pid: finalPid,
						device: targetDevice,
						usb: targetUsb,
						host: targetHost,
					},
				},
				{
					cwd: options.cwd,
					timeoutMs: 10000,
				},
			);
		} catch {}
	};

	const cleanup = async () => {
		try {
			await runDeploymentWorker(
				liveDep.pythonPath!,
				stagedScript,
				{
					action: "cleanup",
					agentCode: QBDI_DEPLOY_AGENT_SCRIPT,
					target: {
						pid: finalPid,
						device: targetDevice,
						usb: targetUsb,
						host: targetHost,
					},
					targetDir: targetLibDir,
					targetFileName,
				},
				{
					cwd: options.cwd,
					timeoutMs: 10000,
				},
			);
		} catch {}
	};

	return {
		targetLibPath: deployRes.targetLibPath,
		targetLibDir,
		fridaBindingSource: fridaBindingSource ?? "",
		platform: deployRes.platform,
		arch: deployRes.arch,
		pointerSize: deployRes.pointerSize,
		pid: finalPid,
		spawned: wasSpawned,
		deployed: true,
		ownedArtifactPath: deployRes.targetLibPath,
		ownedArtifactDir: targetLibDir,
		resume: wasSpawned ? resume : undefined,
		cleanup,
	};
}
