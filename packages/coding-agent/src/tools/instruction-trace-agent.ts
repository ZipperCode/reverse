/**
 * Instruction Trace Agent and Runtime Execution Helper.
 *
 * Provides Frida Stalker and QuarkslaB Dynamic binary Instrumentation (QBDI v0.12.1, Apache-2.0)
 * script synthesis, execution management, sequenced stream chunking, and trace artifact generation.
 *
 * Produces structured JSONL records accepted by Triton dynamic binary analysis:
 * 1. {"type": "registers", "values": {<name>: <hex>}}
 * 2. {"type": "memory_read", "address": <hex>, "size": <int>, "value": <hex>}
 * 3. {"type": "instruction", "address": <hex>, "bytes": <hex>, "size": <int>, "disasm": <str>}
 *
 * Licensed under Apache-2.0 (incorporating QBDI instrumentation patterns).
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { defaultFridaRunner, fridaDependency, type FridaRunner } from "./frida";
import type { FridaLiveClient } from "./frida-live-client";
import { computeStreamingHash } from "./vmp-common";
import { deployQbdiLibrary, type DeployedQbdiResult } from "./instruction-trace-deploy";

// ============================================================================
// Types & Options
// ============================================================================

export interface InstructionTraceScriptOptions {
	module?: string;
	function?: string;
	offset?: string | number;
	address?: string | number;
	threadId?: number;
	scope?: "function" | "thread" | "range";
	range?: { start: string | number; end: string | number };
	maxInstructions?: number;
	timeoutMs?: number;
	engine?: "auto" | "qbdi" | "stalker";
	format?: "jsonl" | "salwan";
	signature?: {
		return_type: string;
		arg_types: string[];
	};
	qbdiLibPath?: string;
	qbdiLibDir?: string;
	fridaBindingSource?: string;
}

export interface InstructionTraceExecutionOptions extends InstructionTraceScriptOptions {
	pid?: number;
	process?: string;
	spawn?: string;
	sessionId?: string;
	device?: string;
	usb?: boolean;
	host?: string;
	maxBytes?: number;
	outputPath?: string;
	artifactPath?: string;
	cwd: string;
	signal?: AbortSignal;
	runner?: FridaRunner;
	liveClient?: FridaLiveClient;
}

export interface InstructionTraceMetadata {
	trace_version: "1.0.0";
	created_at: string;
	target: {
		pid?: number;
		process?: string;
		spawn?: string;
		device?: string;
		arch?: string;
	};
	module?: {
		name?: string;
		base?: string;
		size?: number;
		path?: string;
		sha256?: string;
	};
	bounds: {
		scope: string;
		function?: string;
		offset?: string | number;
		address?: string | number;
		start_address?: string;
		end_address?: string;
		thread_id?: number;
		max_instructions: number;
	};
	stats: {
		total_instructions: number;
		unique_addresses: number;
		total_memory_reads: number;
		total_bytes: number;
		completion_reason: string;
		duration_ms: number;
		truncated: boolean;
	};
	flags: {
		engine: "qbdi" | "stalker";
		memory_reads_complete: boolean;
		thumb_mode: boolean;
		nzcv?: string;
		apsr?: string;
		cpsr?: string;
	};
	first_registers?: Record<string, string>;
	replay_handoff?: {
		tool: "triton_analyze";
		valid: boolean;
		notice?: string;
		params: {
			action: "replay";
			trace: string;
			arch: string;
			thumb?: boolean;
			initial_registers?: Record<string, string>;
			bounds?: {
				max_instructions: number;
			};
			output: {
				kind: "register";
				target: string;
			};
		};
	};
}

export interface InstructionTraceResult {
	success: boolean;
	status: "ok" | "truncated" | "error";
	engine: "qbdi" | "stalker";
	tracePath: string;
	manifestPath: string;
	sha256: string;
	instructionCount: number;
	memoryReadCount: number;
	totalBytes: number;
	completionReason: string;
	arch?: string;
	module?: {
		name?: string;
		base?: string;
		size?: number;
		sha256?: string;
	};
	metadata: InstructionTraceMetadata;
	error?: string;
}

// ============================================================================
// Frida JavaScript Agent Script Builder
// ============================================================================

/**
 * Builds the Frida JavaScript agent script to intercept and collect instructions,
 * pre-instruction register states, and concrete memory reads.
 */
export function buildInstructionTraceScript(options: InstructionTraceScriptOptions = {}): string {
	const moduleName = options.module ? JSON.stringify(options.module) : "null";
	const functionName = options.function ? JSON.stringify(options.function) : "null";
	const offsetVal = options.offset !== undefined ? JSON.stringify(String(options.offset)) : "null";
	const addressVal = options.address !== undefined ? JSON.stringify(String(options.address)) : "null";
	const threadIdVal = options.threadId !== undefined ? Number(options.threadId) : "null";
	const scopeMode = JSON.stringify(options.scope ?? "function");
	const maxInstructions = options.maxInstructions ?? 10000;
	const timeoutMs = options.timeoutMs ?? 30000;
	const requestedEngine = JSON.stringify(options.engine ?? "auto");
	const outputFormat = JSON.stringify(options.format ?? "jsonl");
	const signatureVal = options.signature ? JSON.stringify(options.signature) : "null";
	const qbdiLibPath = options.qbdiLibPath ? JSON.stringify(options.qbdiLibPath) : "null";
	const qbdiLibDir = options.qbdiLibDir ? JSON.stringify(options.qbdiLibDir) : "null";
	const rangeStart = options.range?.start !== undefined ? JSON.stringify(String(options.range.start)) : "null";
	const rangeEnd = options.range?.end !== undefined ? JSON.stringify(String(options.range.end)) : "null";

	// If official frida-qbdi.js binding source is provided, sanitize ES6 export keywords and patch QBDIBinder.load
	let qbdiBindingInjected = "";
	if (options.fridaBindingSource && options.fridaBindingSource.trim().length > 0) {
		let sanitized = options.fridaBindingSource.replaceAll(/^export\s+/gm, "");
		sanitized = sanitized.replace(/\bclass\s+VM\b/, "VM = class VM");
		sanitized = sanitized.replace(/\bclass\s+GPRState\b/, "GPRState = class GPRState");
		sanitized = sanitized.replace(/\bclass\s+FPRState\b/, "FPRState = class FPRState");
		sanitized = sanitized.replace(
			/get\s+QBDI_LIB\(\)\s*\{[\s\S]*?\}\s*\[Process\.platform\];\s*\}/,
			`get QBDI_LIB() {
    if (this.QBDI_CUSTOM_LIB) return this.QBDI_CUSTOM_LIB;
    return ({ 'linux': 'libQBDI.so', 'darwin': 'libQBDI.dylib', 'windows': 'QBDI.dll' })[Process.platform] || 'libQBDI.so';
}`,
		);
		sanitized = sanitized.replace(
			/get\s+QBDI_PATHS\(\)\s*\{[\s\S]*?return\s*\[[\s\S]*?\];\s*\}/,
			`get QBDI_PATHS() {
    var extra = [];
    if (typeof QBDI_LIB_DIR === 'string' && QBDI_LIB_DIR.length > 0) {
        extra.push(QBDI_LIB_DIR.endsWith('/') ? QBDI_LIB_DIR : (QBDI_LIB_DIR + '/'));
    }
    if (typeof QBDI_LIB_PATH === 'string' && QBDI_LIB_PATH.length > 0) {
        var idx = Math.max(QBDI_LIB_PATH.lastIndexOf('/'), QBDI_LIB_PATH.lastIndexOf('\\\\'));
        if (idx >= 0) extra.push(QBDI_LIB_PATH.slice(0, idx + 1));
    }
    return extra.concat([
        '/var/jb/usr/lib/',
        '/usr/lib/',
        '/usr/local/lib/',
        '/data/local/tmp/',
        './',
        './lib/',
        'C:\\\\Program Files\\\\QBDI ' + QBDI_MAJOR + '.' + QBDI_MINOR + '.' + QBDI_PATCH + '\\\\lib\\\\'
    ]);
}`,
		);
		sanitized = sanitized.replace(
			/var\s+_qbdibinder\s*=\s*new\s+QBDIBinder\(\);/,
			`var _qbdibinder = new QBDIBinder();
if (typeof QBDI_LIB_PATH === 'string' && QBDI_LIB_PATH.length > 0) {
    var customLibName = QBDI_LIB_PATH.split(/[\\\\/]/).pop();
    if (customLibName) {
        _qbdibinder.QBDI_CUSTOM_LIB = customLibName;
    }
}`,
		);
		qbdiBindingInjected = `
var VM, GPRState, FPRState, SyncDirection, VMAction, VMEvent, InstPosition, MemoryAccessType, MemoryAccessFlags, GPR_NAMES, REG_PC, REG_SP, REG_RETURN;
try {
// --- UPSTREAM QBDI FRIDA BINDINGS (Apache-2.0, Quarkslab) ---
${sanitized}
// Provide Int64.prototype.toRword if missing
if (typeof Int64 !== 'undefined' && typeof Int64.prototype.toRword !== 'function') {
    Int64.prototype.toRword = function() {
        return uint64(this.toString());
    };
}
// --- END QBDI BINDINGS ---
} catch(qbdiBindingErr) {}
`;
	}

	return `(function() {
'use strict';

var MODULE_NAME = ${moduleName};
var FUNCTION_NAME = ${functionName};
var OFFSET_VAL = ${offsetVal};
var ADDRESS_VAL = ${addressVal};
var THREAD_ID = ${threadIdVal};
var SCOPE_MODE = ${scopeMode};
var MAX_INSTRUCTIONS = ${maxInstructions};
var TIMEOUT_MS = ${timeoutMs};
var REQUESTED_ENGINE = ${requestedEngine};
var OUTPUT_FORMAT = ${outputFormat};
var SIGNATURE = ${signatureVal};
var QBDI_LIB_PATH = ${qbdiLibPath};
var QBDI_LIB_DIR = ${qbdiLibDir};
var RANGE_START_VAL = ${rangeStart};
var RANGE_END_VAL = ${rangeEnd};

${qbdiBindingInjected}

var startTime = Date.now();
var instructionCount = 0;
var memoryReadCount = 0;
var uniqueAddresses = {};
var uniqueAddressCount = 0;
var eventBuffer = [];
var CHUNK_RECORD_LIMIT = 50;
var chunkSequence = 0;
var isFinished = false;
var isRecordingActive = true;
var isVmCallRunning = false;
var deferredCompletionReason = null;
var completionReason = 'running';
var activeHooks = [];
var stalkerThreadId = null;
var firstRegistersCaptured = null;
var detectedThumb = false;
var lastNzcv = null;
var lastCpsr = null;
var resolvedEngine = 'stalker';
var memoryReadsComplete = false;
var activeInstCallback = null;
var _retainedCallbacks = [];
var execTransferOccurred = false;
// Helpers: emit framing markers
function emitMeta(meta) {
    console.log('__INSTRUCTION_TRACE_META__' + JSON.stringify(meta) + '__INSTRUCTION_TRACE_META_END__');
}

function flushChunk() {
    if (eventBuffer.length === 0) return;
    var text = eventBuffer.join('\\n') + '\\n';
    eventBuffer = [];
    var u8 = [];
    for (var i = 0; i < text.length; i++) {
        var code = text.charCodeAt(i);
        if (code < 128) {
            u8.push(code);
        } else if (code < 2048) {
            u8.push(192 | (code >> 6), 128 | (code & 63));
        } else {
            u8.push(224 | (code >> 12), 128 | ((code >> 6) & 63), 128 | (code & 63));
        }
    }
    // Base64 encode
    var b64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var b64 = '';
    for (var j = 0; j < u8.length; j += 3) {
        var b0 = u8[j];
        var b1 = j + 1 < u8.length ? u8[j + 1] : 0;
        var b2 = j + 2 < u8.length ? u8[j + 2] : 0;
        b64 += b64Chars[b0 >> 2];
        b64 += b64Chars[((b0 & 3) << 4) | (b1 >> 4)];
        b64 += j + 1 < u8.length ? b64Chars[((b1 & 15) << 2) | (b2 >> 6)] : '=';
        b64 += j + 2 < u8.length ? b64Chars[b2 & 63] : '=';
    }
    var seq = chunkSequence++;
    console.log('__INSTRUCTION_TRACE_CHUNK__' + seq + ':' + b64 + '__INSTRUCTION_TRACE_CHUNK_END__');
}

function emitRecord(line) {
    eventBuffer.push(line);
    if (eventBuffer.length >= CHUNK_RECORD_LIMIT) {
        flushChunk();
    }
}

function finishTrace(reason) {
    if (isFinished) return;
    if (isVmCallRunning) {
        isRecordingActive = false;
        deferredCompletionReason = reason;
        return;
    }
    isFinished = true;
    isRecordingActive = false;
    completionReason = reason;

    // Cleanup owned hooks
    cleanupHooks();

    flushChunk();

    var summary = {
        success: true,
        reason: reason,
        instruction_count: instructionCount,
        unique_addresses: uniqueAddressCount,
        memory_read_count: memoryReadCount,
        duration_ms: Date.now() - startTime,
        engine: resolvedEngine,
        memory_reads_complete: memoryReadsComplete && !execTransferOccurred,
        exec_transfer_occurred: execTransferOccurred,
        thumb_mode: detectedThumb,
        nzcv: lastNzcv,
        cpsr: lastCpsr,
        first_registers: firstRegistersCaptured
    };

    console.log('__INSTRUCTION_TRACE_DONE__' + JSON.stringify(summary) + '__INSTRUCTION_TRACE_DONE_END__');
}

function cleanupHooks() {
    for (var i = 0; i < activeHooks.length; i++) {
        try {
            activeHooks[i].detach();
        } catch (e) {}
    }
    activeHooks = [];

    if (stalkerThreadId !== null) {
        try {
            Stalker.unfollow(stalkerThreadId);
            Stalker.flush();
        } catch (e) {}
        stalkerThreadId = null;
    }

    activeInstCallback = null;
    _retainedCallbacks = [];
}

// Register reading helpers for Frida Stalker
function readStalkerRegisters(context, arch) {
    var regs = {};
    if (arch === 'arm') {
        for (var i = 0; i <= 12; i++) {
            var val = context['r' + i];
            if (val !== undefined) regs['r' + i] = '0x' + val.toString(16);
        }
        if (context.sp !== undefined) regs.sp = '0x' + context.sp.toString(16);
        if (context.lr !== undefined) {
            var lrStr = '0x' + context.lr.toString(16);
            regs.lr = lrStr;
            regs.r14 = lrStr; // Triton ARM32 canonical link register
        }
        if (context.pc !== undefined) regs.pc = '0x' + context.pc.toString(16);
        if (context.cpsr !== undefined) {
            var cpsrNum = parseInt(context.cpsr.toString(16), 16);
            var cpsrHex = '0x' + cpsrNum.toString(16);
            regs.cpsr = cpsrHex;
            regs.apsr = cpsrHex; // Triton ARM32 flag register
            regs.n = '0x' + ((cpsrNum >>> 31) & 1).toString(16);
            regs.z = '0x' + ((cpsrNum >>> 30) & 1).toString(16);
            regs.c = '0x' + ((cpsrNum >>> 29) & 1).toString(16);
            regs.v = '0x' + ((cpsrNum >>> 28) & 1).toString(16);
            lastCpsr = cpsrHex;
            if ((cpsrNum & 0x20) !== 0) detectedThumb = true;
        }
    } else if (arch === 'arm64') {
        for (var j = 0; j <= 28; j++) {
            var xval = context['x' + j];
            if (xval !== undefined) regs['x' + j] = '0x' + xval.toString(16);
        }
        // In Frida ARM64, x29 is exposed as context.fp, x30 as context.lr
        var fpVal = context.fp !== undefined ? context.fp : context.x29;
        if (fpVal !== undefined) {
            regs.x29 = '0x' + fpVal.toString(16); // Canonical Triton register
        }
        var lrVal = context.lr !== undefined ? context.lr : context.x30;
        if (lrVal !== undefined) {
            regs.x30 = '0x' + lrVal.toString(16); // Canonical Triton register (NOT r14)
        }
        if (context.sp !== undefined) regs.sp = '0x' + context.sp.toString(16);
        if (context.pc !== undefined) regs.pc = '0x' + context.pc.toString(16);
        if (context.nzcv !== undefined) {
            var nzcvVal = context.nzcv;
            var nzcvHex = '0x' + nzcvVal.toString(16);
            regs.nzcv = nzcvHex;
            lastNzcv = nzcvHex;
            var nzcvNum = parseInt(nzcvVal.toString(16), 16);
            regs.n = '0x' + ((nzcvNum >>> 31) & 1).toString(16);
            regs.z = '0x' + ((nzcvNum >>> 30) & 1).toString(16);
            regs.c = '0x' + ((nzcvNum >>> 29) & 1).toString(16);
            regs.v = '0x' + ((nzcvNum >>> 28) & 1).toString(16);
        }
    } else if (arch === 'x64') {
        var gprs64 = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rbp', 'rsp', 'rip'];
        for (var k = 0; k < gprs64.length; k++) {
            var g = gprs64[k];
            if (context[g] !== undefined) regs[g] = '0x' + context[g].toString(16);
        }
        if (context.rflags !== undefined) {
            var rf = parseInt(context.rflags.toString(16), 16);
            regs.rflags = '0x' + rf.toString(16);
            regs.zf = '0x' + ((rf >>> 6) & 1).toString(16);
            regs.cf = '0x' + (rf & 1).toString(16);
            regs.sf = '0x' + ((rf >>> 7) & 1).toString(16);
            regs.of = '0x' + ((rf >>> 11) & 1).toString(16);
        }
    } else if (arch === 'ia32') {
        var gprs32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip'];
        for (var l = 0; l < gprs32.length; l++) {
            var e = gprs32[l];
            if (context[e] !== undefined) regs[e] = '0x' + context[e].toString(16);
        }
        if (context.eflags !== undefined) {
            var ef = parseInt(context.eflags.toString(16), 16);
            regs.eflags = '0x' + ef.toString(16);
            regs.zf = '0x' + ((ef >>> 6) & 1).toString(16);
            regs.cf = '0x' + (ef & 1).toString(16);
            regs.sf = '0x' + ((ef >>> 7) & 1).toString(16);
            regs.of = '0x' + ((ef >>> 11) & 1).toString(16);
        }
    }
    return regs;
}

// Memory read helper in Stalker mode: inspects pre-snapshotted operand metadata
function readStalkerMemoryAccess(context, arch, memOps) {
    var reads = [];
    if (!memOps || !Array.isArray(memOps)) {
        return reads;
    }
    for (var i = 0; i < memOps.length; i++) {
        var op = memOps[i];
        try {
            var disp = op.disp || 0;
            var basePtr = ptr(0);
            if (op.base) {
                var baseLower = op.base.toLowerCase();
                if ((baseLower === 'rip' || baseLower === 'eip') && op.insAddr) {
                    basePtr = op.insAddr.add(op.insSize || 0);
                } else if (baseLower === 'pc' && op.insAddr) {
                    if (arch === 'arm') {
                        basePtr = detectedThumb ? ptr((op.insAddr.toInt32() + 4) & ~3) : op.insAddr.add(8);
                    } else {
                        basePtr = op.insAddr;
                    }
                } else if (context[op.base]) {
                    basePtr = context[op.base];
                }
            }
            if (!basePtr || basePtr.isNull()) continue;
            var indexPtr = op.index ? context[op.index] : ptr(0);
            var scale = op.scale || 1;
            var effectiveAddr = basePtr.add(disp);
            if (indexPtr && !indexPtr.isNull()) {
                effectiveAddr = effectiveAddr.add(indexPtr.toInt32() * scale);
            }
            var size = op.size || 4;
            if (size > 16) size = 8;
            var buf = effectiveAddr.readByteArray(size);
            if (buf) {
                var u8 = new Uint8Array(buf);
                var valHex = '0x';
                for (var b = u8.length - 1; b >= 0; b--) {
                    valHex += (u8[b] < 16 ? '0' : '') + u8[b].toString(16);
                }
                reads.push({
                    address: '0x' + effectiveAddr.toString(16),
                    size: size,
                    value: valHex
                });
            } else {
                memoryReadsComplete = false;
            }
        } catch (err) {
            // Inaccessible address encountered; do not claim full memory reads
            memoryReadsComplete = false;
        }
    }
    return reads;
}

// Main instrumentation setup
try {
    var targetModule = null;
    if (MODULE_NAME) {
        targetModule = Process.findModuleByName(MODULE_NAME);
        if (!targetModule) {
            var mods = Process.enumerateModules();
            for (var mIdx = 0; mIdx < mods.length; mIdx++) {
                if (mods[mIdx].name.toLowerCase() === MODULE_NAME.toLowerCase()) {
                    targetModule = mods[mIdx];
                    break;
                }
            }
            if (!targetModule) {
                throw new Error('Module "' + MODULE_NAME + '" not found in target process');
            }
        }
    }

    var baseAddr = targetModule ? targetModule.base : null;
    var moduleSize = targetModule ? targetModule.size : 0;
    var targetEntry = null;

    if (ADDRESS_VAL !== null) {
        targetEntry = ptr(ADDRESS_VAL);
    } else if (targetModule && OFFSET_VAL !== null) {
        var offsetNum = OFFSET_VAL.indexOf('0x') === 0 ? parseInt(OFFSET_VAL, 16) : parseInt(OFFSET_VAL, 10);
        targetEntry = targetModule.base.add(offsetNum);
    } else if (FUNCTION_NAME !== null) {
        if (targetModule) {
            targetEntry = targetModule.findExportByName(FUNCTION_NAME);
            if (!targetEntry) {
                var syms = targetModule.enumerateSymbols();
                for (var s = 0; s < syms.length; s++) {
                    if (syms[s].name === FUNCTION_NAME) {
                        targetEntry = syms[s].address;
                        break;
                    }
                }
            }
        }
        if (!targetEntry) {
            targetEntry = Module.findGlobalExportByName(FUNCTION_NAME);
        }
        if (!targetEntry) {
            throw new Error('Function "' + FUNCTION_NAME + '" not found in target process');
        }
    } else if (OFFSET_VAL !== null) {
        throw new Error('Offset requires a valid target module');
    } else if (targetModule) {
        targetEntry = targetModule.base;
    }

    // Check Thumb bit for metadata without stripping from targetEntry (Frida Interceptor handles Thumb automatically)
    if (targetEntry && (targetEntry.toInt32() & 1) !== 0) {
        detectedThumb = true;
    }

    if (SCOPE_MODE === 'function' && !targetEntry) {
        throw new Error('Function scope requires a valid target function or entry point');
    }

    // Range covers full module to capture internal helpers and tail-calls
    var rangeStart = RANGE_START_VAL !== null ? ptr(RANGE_START_VAL) : (targetModule ? targetModule.base : (targetEntry ? targetEntry : null));
    if (!rangeStart || rangeStart.isNull()) {
        throw new Error('Failed to resolve trace range start address');
    }
    var rangeEnd = RANGE_END_VAL !== null ? ptr(RANGE_END_VAL) : (targetModule ? targetModule.base.add(targetModule.size) : rangeStart.add(65536));

    // Try QBDI engine via upstream frida-qbdi.js VM bindings
    var qbdiAvailable = false;
    var qbdiVm = null;
    if ((REQUESTED_ENGINE === 'qbdi' || REQUESTED_ENGINE === 'auto') && typeof VM !== 'undefined' && SIGNATURE && SCOPE_MODE === 'function') {
        var argTypes = SIGNATURE.arg_types || [];
        var hasWide32BitArgs = Process.pointerSize === 4 && (SIGNATURE.return_type === 'uint64' || SIGNATURE.return_type === 'int64' || argTypes.some(function(t) { return t === 'uint64' || t === 'int64'; }));
        if (argTypes.length <= 10 && !hasWide32BitArgs) {
            try {
                qbdiVm = new VM();
                qbdiVm.recordMemoryAccess(MemoryAccessType.MEMORY_READ);
                qbdiVm.addInstrumentedRange(rangeStart, rangeEnd);
                qbdiAvailable = true;
            } catch (vmErr) {
                qbdiAvailable = false;
                qbdiVm = null;
            }
        }
    }

    if (REQUESTED_ENGINE === 'qbdi' && !qbdiAvailable) {
        console.log('__INSTRUCTION_TRACE_ERROR__' + JSON.stringify({
            error: "QBDI engine requested but QBDI runtime bindings not available or signature missing. Run 'reverse setup reverse qbdi --execute' to install pinned QBDI v0.12.1 or use engine: 'stalker' / 'auto'."
        }) + '__INSTRUCTION_TRACE_ERROR_END__');
        return;
    }

    resolvedEngine = qbdiAvailable ? 'qbdi' : 'stalker';
    memoryReadsComplete = qbdiAvailable;

    emitMeta({
        type: 'meta',
        arch: Process.arch,
        pointer_size: Process.pointerSize,
        module: targetModule ? {
            name: targetModule.name,
            base: '0x' + targetModule.base.toString(16),
            size: targetModule.size,
            path: targetModule.path
        } : null,
        target_entry: targetEntry ? '0x' + targetEntry.toString(16) : null,
        range_start: '0x' + rangeStart.toString(16),
        range_end: '0x' + rangeEnd.toString(16),
        scope: SCOPE_MODE,
        engine: resolvedEngine,
        format: OUTPUT_FORMAT,
        max_instructions: MAX_INSTRUCTIONS,
        thumb_mode: detectedThumb
    });

    // Watchdog timeout timer
    var watchdog = setTimeout(function() {
        if (isRecordingActive) {
            isRecordingActive = false;
            deferredCompletionReason = 'timeout';
        }
        finishTrace(deferredCompletionReason || 'timeout');
    }, TIMEOUT_MS);

    // Stalker Tracer Implementation (Frida Native)
    function setupStalkerTracing(tid, returnAddress) {
        stalkerThreadId = tid;
        try {
            Stalker.trustThreshold = -1; // Force re-decoding to track SMC modifications accurately
        } catch (eTrust) {}

        Stalker.follow(tid, {
            transform: function(iterator) {
                var instruction = iterator.next();
                while (instruction !== null) {
                    var addr = instruction.address;
                    if (addr.compare(rangeStart) >= 0 && addr.compare(rangeEnd) < 0) {
                        var insSize = instruction.size;
                        var insDisasm = instruction.toString();

                        // Snapshot operands metadata now; Frida wrapper is invalidated after transform returns
                        var memOps = [];
                        try {
                            if (instruction.operands && Array.isArray(instruction.operands)) {
                                for (var o = 0; o < instruction.operands.length; o++) {
                                    var op = instruction.operands[o];
                                    if (op.type === 'mem') {
                                        memOps.push({
                                            base: op.value && op.value.base ? op.value.base : null,
                                            disp: op.value && op.value.disp ? op.value.disp : 0,
                                            index: op.value && op.value.index ? op.value.index : null,
                                            scale: op.value && op.value.scale ? op.value.scale : 1,
                                            size: op.size || 4,
                                            insAddr: addr,
                                            insSize: insSize
                                        });
                                    }
                                }
                            }
                        } catch (e) {}

                        // Gate callout insertion on open memory access to protect exclusive-store (ldxr/stxr) sequences
                        var memAccessOpen = iterator.memoryAccess === 'open' || iterator.memoryAccess === undefined;
                        if (memAccessOpen) {
                            (function(curAddr, curSize, curDisasm, curMemOps) {
                                iterator.putCallout(function(context) {
                                    if (isFinished || !isRecordingActive) return;
                                    if (instructionCount >= MAX_INSTRUCTIONS) {
                                        isRecordingActive = false;
                                        deferredCompletionReason = 'max_instructions_reached';
                                        return;
                                    }

                                    instructionCount++;
                                    var addrHex = '0x' + curAddr.toString(16);
                                    if (!uniqueAddresses[addrHex]) {
                                        uniqueAddresses[addrHex] = true;
                                        uniqueAddressCount++;
                                    }

                                    var regMap = readStalkerRegisters(context, Process.arch);
                                    if (!firstRegistersCaptured) {
                                        firstRegistersCaptured = regMap;
                                    }

                                    var memReads = readStalkerMemoryAccess(context, Process.arch, curMemOps);

                                    // Live instruction bytes decode to handle SMC accurately
                                    var liveBytes = '';
                                    try {
                                        var bArr = curAddr.readByteArray(curSize);
                                        if (bArr) {
                                            var bU8 = new Uint8Array(bArr);
                                            for (var bIdx = 0; bIdx < bU8.length; bIdx++) {
                                                liveBytes += (bU8[bIdx] < 16 ? '0' : '') + bU8[bIdx].toString(16);
                                            }
                                        }
                                    } catch (e) {}

                                    if (OUTPUT_FORMAT === 'jsonl') {
                                        // 1. Concrete registers BEFORE instruction
                                        emitRecord(JSON.stringify({
                                            type: 'registers',
                                            values: regMap
                                        }));

                                        // 2. Concrete memory reads BEFORE instruction
                                        for (var m = 0; m < memReads.length; m++) {
                                            memoryReadCount++;
                                            emitRecord(JSON.stringify({
                                                type: 'memory_read',
                                                address: memReads[m].address,
                                                size: memReads[m].size,
                                                value: memReads[m].value
                                            }));
                                        }

                                        // 3. Instruction execution record
                                        emitRecord(JSON.stringify({
                                            type: 'instruction',
                                            address: addrHex,
                                            bytes: liveBytes,
                                            size: curSize,
                                            disasm: curDisasm
                                        }));
                                    } else {
                                        // Salwan Format
                                        var rParts = [];
                                        for (var rk in regMap) {
                                            rParts.push(rk + '=' + regMap[rk]);
                                        }
                                        emitRecord('r:' + rParts.join(':'));

                                        for (var sm = 0; sm < memReads.length; sm++) {
                                            memoryReadCount++;
                                            emitRecord('mr:' + memReads[sm].address + ':' + memReads[sm].size + ':' + memReads[sm].value);
                                        }

                                        emitRecord('i:' + addrHex + ':' + curSize + ':' + liveBytes + (curDisasm ? ':' + curDisasm : ''));
                                    }

                                    // Check return address
                                    if (returnAddress && curAddr.equals(returnAddress)) {
                                        finishTrace(deferredCompletionReason || 'function_return');
                                    }
                                });
                            })(addr, insSize, insDisasm, memOps);
                        } else {
                            // Memory access closed (exclusive load/store sequence) - do not insert JS callout to preserve monitor
                            memoryReadsComplete = false;
                        }
                    }
                    iterator.keep();
                    instruction = iterator.next();
                }
            }
        });
    }

    // QBDI Tracer Implementation (Upstream VM API)
    function setupQbdiTracing(vm, startAddr, stopAddr) {
        activeInstCallback = vm.newInstCallback(function(v, gpr, fpr, data) {
            if (isFinished || !isRecordingActive) return VMAction.CONTINUE;
            if (instructionCount >= MAX_INSTRUCTIONS) {
                isRecordingActive = false;
                deferredCompletionReason = 'max_instructions_reached';
                return VMAction.CONTINUE; // Continue function execution naturally without stopping real computation
            }

            instructionCount++;

            // Extract deterministic memory accesses via upstream getInstMemoryAccess
            var accesses = v.getInstMemoryAccess();
            var memReads = [];
            if (accesses && accesses.length > 0) {
                for (var a = 0; a < accesses.length; a++) {
                    var acc = accesses[a];
                    if (acc.type === MemoryAccessType.MEMORY_READ || acc.type === MemoryAccessType.MEMORY_READ_WRITE) {
                        var accAddrPtr = ptr(acc.accessAddress);
                        var accSize = acc.size || 0;
                        var accVal = ptr(acc.value);

                        // Pinned Callback.h flags: UNKNOWN_SIZE=1, MINIMUM_SIZE=2, UNKNOWN_VALUE=4
                        var flags = acc.flags || 0;
                        var isConcrete = true;
                        if ((flags & 0x4) !== 0 || (flags & 0x1) !== 0 || (flags & 0x2) !== 0 || accSize === 0) {
                            if (accSize > 0 && (flags & 0x1) === 0 && (flags & 0x2) === 0) {
                                try {
                                    var deref = accAddrPtr.readByteArray(accSize);
                                    if (deref) {
                                        var du8 = new Uint8Array(deref);
                                        var dhex = '0x';
                                        for (var db = du8.length - 1; db >= 0; db--) {
                                            dhex += (du8[db] < 16 ? '0' : '') + du8[db].toString(16);
                                        }
                                        accVal = dhex;
                                    } else {
                                        memoryReadsComplete = false;
                                        isConcrete = false;
                                    }
                                } catch (err) {
                                    memoryReadsComplete = false;
                                    isConcrete = false;
                                }
                            } else {
                                memoryReadsComplete = false;
                                isConcrete = false;
                            }
                        }

                        // Only push valid, concrete non-zero-sized memory read records into trace stream
                        if (isConcrete && accSize > 0 && accVal !== null && accVal !== undefined) {
                            memReads.push({
                                address: '0x' + accAddrPtr.toString(16),
                                size: accSize,
                                value: typeof accVal === 'string' ? accVal : ('0x' + accVal.toString(16))
                            });
                        }
                    }
                }
            }
            // Extract registers from upstream GPRState
            var allGprs = gpr.getRegisters();
            var regMap = {};
            for (var rk in allGprs) {
                regMap[rk.toLowerCase()] = '0x' + ptr(allGprs[rk]).toString(16);
            }
            if (Process.arch === 'arm') {
                if (regMap.lr && !regMap.r14) regMap.r14 = regMap.lr;
                if (regMap.cpsr && !regMap.apsr) regMap.apsr = regMap.cpsr;
                if (regMap.cpsr) lastCpsr = regMap.cpsr;
            } else if (Process.arch === 'arm64') {
                if (regMap.fp) {
                    if (!regMap.x29) regMap.x29 = regMap.fp;
                    delete regMap.fp;
                }
                if (regMap.lr) {
                    if (!regMap.x30) regMap.x30 = regMap.lr;
                    delete regMap.lr;
                }
                delete regMap.r14;
                if (regMap.nzcv) lastNzcv = regMap.nzcv;
            } else if (Process.arch === 'x64') {
                delete regMap.pc;
            }

            if (!firstRegistersCaptured) firstRegistersCaptured = regMap;

            var inst = v.getInstAnalysis();
            var instPtr = ptr(inst.address);
            var addrHex = '0x' + instPtr.toString(16);
            if (!uniqueAddresses[addrHex]) {
                uniqueAddresses[addrHex] = true;
                uniqueAddressCount++;
            }
            var insSize = inst.instSize || 4;
            var disasm = inst.disassembly || '';
            var insBytes = '';
            try {
                var bArr = instPtr.readByteArray(insSize);
                if (bArr) {
                    var bU8 = new Uint8Array(bArr);
                    for (var b = 0; b < bU8.length; b++) {
                        insBytes += (bU8[b] < 16 ? '0' : '') + bU8[b].toString(16);
                    }
                }
            } catch (e) {}

            if (OUTPUT_FORMAT === 'jsonl') {
                emitRecord(JSON.stringify({ type: 'registers', values: regMap }));
                for (var m = 0; m < memReads.length; m++) {
                    memoryReadCount++;
                    emitRecord(JSON.stringify({
                        type: 'memory_read',
                        address: memReads[m].address,
                        size: memReads[m].size,
                        value: memReads[m].value
                    }));
                }
                emitRecord(JSON.stringify({
                    type: 'instruction',
                    address: addrHex,
                    bytes: insBytes,
                    size: insSize,
                    disasm: disasm
                }));
            } else {
                var rParts = [];
                for (var r in regMap) rParts.push(r + '=' + regMap[r]);
                emitRecord('r:' + rParts.join(':'));
                for (var sm = 0; sm < memReads.length; sm++) {
                    memoryReadCount++;
                    emitRecord('mr:' + memReads[sm].address + ':' + memReads[sm].size + ':' + memReads[sm].value);
                }
                emitRecord('i:' + addrHex + ':' + insSize + ':' + insBytes + (disasm ? ':' + disasm : ''));
            }

            return VMAction.CONTINUE;
        });
        _retainedCallbacks.push(activeInstCallback);
        vm.addCodeCB(InstPosition.PREINST, activeInstCallback);

        if (typeof VMEvent !== 'undefined' && vm.addVMEventCB) {
            try {
                var transferCbk = vm.newVMCallback(function(v, state, gpr, fpr, data) {
                    memoryReadsComplete = false;
                    execTransferOccurred = true;
                    return VMAction.CONTINUE;
                });
                _retainedCallbacks.push(transferCbk);
                vm.addVMEventCB(VMEvent.EXEC_TRANSFER_CALL | VMEvent.EXEC_TRANSFER_RETURN, transferCbk);
            } catch (eTransfer) {}
        }
        var returnType = SIGNATURE ? SIGNATURE.return_type : 'pointer';
        var argTypes = SIGNATURE ? SIGNATURE.arg_types : [];
        if (targetEntry.compare(rangeStart) < 0 || targetEntry.compare(rangeEnd) >= 0) {
            throw new Error('Target function entry point 0x' + targetEntry.toString(16) + ' is outside the instrumented range [0x' + rangeStart.toString(16) + ', 0x' + rangeEnd.toString(16) + ']');
        }

        var replacement = Interceptor.replace(targetEntry, new NativeCallback(function() {
            Interceptor.revert(targetEntry);
            Interceptor.flush();

            var state = vm.getGPRState();
            state.synchronizeContext(this.context, SyncDirection.FRIDA_TO_QBDI);
            var stack = vm.allocateVirtualStack(state, 0x100000);

            var args = [];
            for (var a = 0; a < arguments.length; a++) {
                var arg = arguments[a];
                if (typeof arg === 'number' && arg < 0) {
                    if (Process.pointerSize === 4) {
                        args.push(arg >>> 0);
                    } else {
                        args.push(uint64(arg.toString()));
                    }
                } else {
                    args.push(arg);
                }
            }

            var p_fegetenv = Module.findGlobalExportByName('fegetenv') || Module.findExportByName(null, 'fegetenv');
            var p_fesetenv = Module.findGlobalExportByName('fesetenv') || Module.findExportByName(null, 'fesetenv');
            var fn_fegetenv = p_fegetenv ? new NativeFunction(p_fegetenv, 'int', ['pointer']) : null;
            var fn_fesetenv = p_fesetenv ? new NativeFunction(p_fesetenv, 'int', ['pointer']) : null;
            var fenvBuf = Memory.alloc(256);

            var fpr = null;
            try {
                fpr = vm.getFPRState();
            } catch (eFprGet) {}

            if (fpr && fpr.ptr) {
                if (Process.arch === 'arm64' || Process.arch === 'aarch64') {
                    if (fn_fegetenv) {
                        try {
                            fn_fegetenv(fenvBuf);
                            var incomingFpsr = fenvBuf.readU64();
                            var incomingFpcr = fenvBuf.add(8).readU64();
                            fpr.ptr.add(512).writeU64(incomingFpcr);
                            fpr.ptr.add(520).writeU64(incomingFpsr);
                        } catch (eFprCtrl) {}
                    }
                    for (var vi = 0; vi < 32; vi++) {
                        var vVal = this.context['q' + vi] || this.context['v' + vi];
                        if (vVal !== undefined && Array.isArray(vVal) && vVal.length >= 16) {
                            try { fpr.ptr.add(vi * 16).writeByteArray(vVal); } catch (eV) {}
                        }
                    }
                } else if (Process.arch === 'x64') {
                    if (fn_fegetenv) {
                        try {
                            fn_fegetenv(fenvBuf);
                            var incomingFcw = fenvBuf.readU16();
                            var incomingFsw = fenvBuf.add(2).readU16();
                            var incomingMxcsr = fenvBuf.add(4).readU32();
                            fpr.ptr.writeU16(incomingFcw);
                            fpr.ptr.add(2).writeU16(incomingFsw);
                            if (incomingMxcsr !== 0) {
                                fpr.ptr.add(24).writeU32(incomingMxcsr);
                            }
                        } catch (eFprX64) {}
                    }
                }
                try {
                    vm.setFPRState(fpr);
                } catch (eSetFpr) {}
            }

            var retPtr = null;
            var callSucceeded = false;
            var callErrorToPropagate = null;
            isVmCallRunning = true;
            try {
                retPtr = vm.call(targetEntry, args);
                callSucceeded = true;
            } catch (callErr) {
                callErrorToPropagate = callErr;
                console.log('__INSTRUCTION_TRACE_ERROR__' + JSON.stringify({
                    error: "QBDI vm.call execution failed: " + (callErr.message || String(callErr))
                }) + '__INSTRUCTION_TRACE_ERROR_END__');
            } finally {
                isVmCallRunning = false;
                if (fn_fesetenv) {
                    try { fn_fesetenv(fenvBuf); } catch (eFenvSet) {}
                }
                try {
                    vm.alignedFree(stack);
                } catch (freeErr) {}
                if (callSucceeded) {
                    finishTrace(deferredCompletionReason || 'function_return');
                }
            }
            if (callErrorToPropagate) {
                throw callErrorToPropagate;
            }
            if (returnType === 'void') {
                return;
            }
            if (!retPtr) {
                retPtr = ptr(0);
            }
            if (returnType === 'uint64') {
                return uint64(retPtr.toString());
            }
            if (returnType === 'int64') {
                return int64(retPtr.toString());
            }
            if (returnType === 'int' || returnType === 'int32' || returnType === 'uint32' || returnType === 'uint') {
                return retPtr.toInt32();
            }
            return retPtr;
        }, returnType, argTypes));
    }

    if (resolvedEngine === 'qbdi' && qbdiVm) {
        try {
            setupQbdiTracing(qbdiVm, rangeStart, rangeEnd);
        } catch (eQbdi) {
            if (REQUESTED_ENGINE === 'qbdi') {
                console.log('__INSTRUCTION_TRACE_ERROR__' + JSON.stringify({
                    error: "QBDI setup failed: " + (eQbdi.message || String(eQbdi))
                }) + '__INSTRUCTION_TRACE_ERROR_END__');
                return;
            }
            resolvedEngine = 'stalker';
            memoryReadsComplete = false;
        }
    } else {
        if (SCOPE_MODE === 'function' && targetEntry) {
            var targetThreadId = null;
            var callDepth = 0;

            var hook = Interceptor.attach(targetEntry, {
                onEnter: function(args) {
                    var currentTid = Process.getCurrentThreadId();
                    if (THREAD_ID !== null && currentTid !== THREAD_ID) return;
                    if (targetThreadId === null) {
                        targetThreadId = currentTid;
                        callDepth = 1;
                        setupStalkerTracing(targetThreadId, this.returnAddress);
                    } else if (currentTid === targetThreadId) {
                        callDepth++;
                    }
                },
                onLeave: function(retval) {
                    var currentTid = Process.getCurrentThreadId();
                    if (currentTid === targetThreadId) {
                        callDepth--;
                        if (callDepth <= 0) {
                            finishTrace(deferredCompletionReason || 'function_return');
                        }
                    }
                }
            });
            activeHooks.push(hook);
        } else {
            var allThreads = Process.enumerateThreads();
            var targetTid = THREAD_ID !== null ? THREAD_ID : ((allThreads && allThreads.length > 0) ? allThreads[0].id : Process.getCurrentThreadId());
            setupStalkerTracing(targetTid, null);
        }
    }

    // Export RPC methods for interactive live sessions
    rpc.exports = {
        getTraceSummary: function() {
            return {
                instruction_count: instructionCount,
                memory_read_count: memoryReadCount,
                unique_addresses: uniqueAddressCount,
                reason: completionReason,
                finished: isFinished
            };
        },
        stopTrace: function() {
            finishTrace('user_requested');
            return true;
        }
    };

} catch (err) {
    console.log('__INSTRUCTION_TRACE_ERROR__' + JSON.stringify({
        error: err.message || String(err),
        stack: err.stack || ''
    }) + '__INSTRUCTION_TRACE_ERROR_END__');
}
})();`;
}

// ============================================================================
// Instruction Trace Executor
// ============================================================================

/**
 * Executes instruction trace collection on target process, streaming framed chunks
 * into an immutable JSONL trace artifact and generating a companion metadata sidecar.
 */
export async function executeInstructionTrace(
	options: InstructionTraceExecutionOptions,
): Promise<InstructionTraceResult> {
	if (options.signal?.aborted) {
		throw new ToolError("Instruction trace cancelled before start");
	}

	// 1. Resolve and deploy QBDI runtime and official Frida binding if requested
	let deployedQbdi: DeployedQbdiResult | undefined;
	let qbdiLibPath: string | undefined = options.qbdiLibPath;
	let qbdiLibDir: string | undefined = options.qbdiLibDir;
	let fridaBindingSource: string | undefined = options.fridaBindingSource;

	if (options.engine === "qbdi" || options.engine === "auto" || !options.engine) {
		try {
			deployedQbdi = await deployQbdiLibrary(options);
			qbdiLibPath = deployedQbdi.targetLibPath;
			qbdiLibDir = deployedQbdi.targetLibDir;
			if (!fridaBindingSource && deployedQbdi.fridaBindingSource) {
				fridaBindingSource = deployedQbdi.fridaBindingSource;
			}
		} catch (err) {
			if (options.engine === "qbdi") {
				throw err;
			}
			// In auto mode, fall back to Stalker if QBDI deployment is unavailable
		}
	}

	if (options.engine === "qbdi" && (!qbdiLibPath || !fridaBindingSource)) {
		throw new ToolError(
			"QBDI engine requested but QBDI runtime or frida-qbdi.js binding not found. Run 'reverse setup reverse qbdi --execute' to install pinned QBDI v0.12.1, or select engine: 'auto' / 'stalker'.",
		);
	}

	// 2. Build injection script
	const scriptSource = buildInstructionTraceScript({
		...options,
		qbdiLibPath,
		qbdiLibDir,
		fridaBindingSource,
	});

	// 3. Prepare output destination with exclusive creation ('wx') to prevent overwriting existing files
	let traceFilePath = options.artifactPath ?? options.outputPath;
	if (!traceFilePath) {
		const ext = options.format === "salwan" ? "trace" : "jsonl";
		const tmpDir = await fs.mkdtemp(path.join(options.cwd, ".trace-temp-"));
		traceFilePath = path.join(tmpDir, `trace_${Date.now()}.${ext}`);
	}
	await fs.mkdir(path.dirname(traceFilePath), { recursive: true });

	// Open writable file for trace stream exclusively
	const fileHandle = await fs.open(traceFilePath, "wx", 0o600);

	const maxBytes = options.maxBytes ?? 32 * 1024 * 1024; // 32MB default
	let writtenBytes = 0;
	let parsedMeta: Record<string, unknown> | null = null;
	let parsedDone: Record<string, unknown> | null = null;
	let executionError: string | null = null;
	let firstRegisters: Record<string, string> | undefined;
	let expectedChunkSeq = 0;
	let missingChunksDetected = false;
	let writeQueue = Promise.resolve();
	let isTruncatedByLimit = false;

	const enqueueChunkPayload = (rawChunkText: string) => {
		writeQueue = writeQueue.then(async () => {
			if (isTruncatedByLimit) return;

			let chunkBody = rawChunkText;
			const colonIdx = rawChunkText.indexOf(":");
			if (colonIdx !== -1 && colonIdx < 10) {
				const seqNum = parseInt(rawChunkText.slice(0, colonIdx), 10);
				if (!Number.isNaN(seqNum)) {
					if (seqNum !== expectedChunkSeq) {
						missingChunksDetected = true;
					}
					expectedChunkSeq = seqNum + 1;
					chunkBody = rawChunkText.slice(colonIdx + 1);
				}
			}

			const decodedText = Buffer.from(chunkBody.trim(), "base64").toString("utf-8");

			if (!firstRegisters && options.format !== "salwan") {
				const firstRegMatch = decodedText.match(/\{"type":"registers","values":(\{.*?\})\}/);
				if (firstRegMatch) {
					try {
						firstRegisters = JSON.parse(firstRegMatch[1]);
					} catch {}
				}
			}

			// Split by whole lines to prevent writing broken/sliced lines
			const lines = decodedText.split("\n");
			for (let i = 0; i < lines.length; i++) {
				const line = lines[i];
				if (line.length === 0) continue;
				const lineBuf = Buffer.from(line + "\n", "utf-8");
				if (writtenBytes + lineBuf.length > maxBytes) {
					isTruncatedByLimit = true;
					parsedDone = {
						success: true,
						reason: "max_bytes_exceeded",
						truncated: true,
					};
					break;
				}
				await fileHandle.write(lineBuf);
				writtenBytes += lineBuf.length;
			}
		});
	};

	let stagedScriptPath: string | undefined;
	try {
		// 4. Execute via independent Frida CLI Runner
		const dep = fridaDependency();
		if (!dep.available || !dep.path) {
			throw new ToolError(
				`Frida CLI not found on PATH or managed toolchain. (${dep.installHint ?? "Not installed"})`,
			);
		}

		const cliArgs: string[] = [];
		if (options.usb) {
			cliArgs.push("-U");
		} else if (options.device && options.device !== "local") {
			cliArgs.push("-D", options.device.trim());
		} else if (options.host) {
			cliArgs.push("-H", options.host.trim());
		}

		const targetPid = deployedQbdi?.pid ?? options.pid;
		const targetSpawn = deployedQbdi?.pid ? undefined : options.spawn;

		if (targetPid !== undefined) {
			cliArgs.push("-p", String(targetPid));
		} else if (options.process) {
			cliArgs.push("-n", options.process.trim());
		} else if (targetSpawn) {
			cliArgs.push("-f", targetSpawn.trim());
		} else {
			throw new ToolError("Must specify target: 'pid', 'process', or 'spawn'");
		}

		const timeoutSeconds = Math.ceil((options.timeoutMs ?? 30000) / 1000);
		// Stage script to file to prevent E2BIG on POSIX/macOS with large bindings
		stagedScriptPath = path.join(path.dirname(traceFilePath), `tracer_${Date.now()}.js`);
		await fs.writeFile(stagedScriptPath, scriptSource, { mode: 0o600 });
		cliArgs.push("-q", "-t", String(timeoutSeconds), "-l", stagedScriptPath);
		const runnerTimeoutMs = (timeoutSeconds + 20) * 1000;
		const runner = options.runner ?? defaultFridaRunner;
		const runRes = await runner(dep.path, cliArgs, {
			cwd: options.cwd,
			timeoutMs: runnerTimeoutMs,
			maxBytes: maxBytes * 2,
			signal: options.signal,
		});

		const rawStdout = runRes.stdout;
		const stdout =
			Buffer.isBuffer(rawStdout) || rawStdout instanceof Uint8Array
				? Buffer.from(rawStdout).toString("utf-8")
				: String(rawStdout ?? "");

		if (runRes.timedOut) {
			parsedDone = { success: true, reason: "timeout", truncated: true };
		} else if (runRes.truncated) {
			parsedDone = { success: true, reason: "max_bytes_exceeded", truncated: true };
		}

		// Parse framing markers from stdout
		const metaMatch = stdout.match(/__INSTRUCTION_TRACE_META__(.*?)__INSTRUCTION_TRACE_META_END__/s);
		if (metaMatch) {
			try {
				parsedMeta = JSON.parse(metaMatch[1]);
			} catch {}
		}

		const errorMatch = stdout.match(/__INSTRUCTION_TRACE_ERROR__(.*?)__INSTRUCTION_TRACE_ERROR_END__/s);
		if (errorMatch) {
			try {
				const errObj = JSON.parse(errorMatch[1]);
				executionError = errObj.error ?? "Trace agent error";
			} catch {
				executionError = errorMatch[1];
			}
		}

		// Extract all chunks sequentially
		const chunkRegex = /__INSTRUCTION_TRACE_CHUNK__(.*?)__INSTRUCTION_TRACE_CHUNK_END__/gs;
		let match: RegExpExecArray | null;
		while ((match = chunkRegex.exec(stdout)) !== null) {
			enqueueChunkPayload(match[1]);
		}

		const doneMatch = stdout.match(/__INSTRUCTION_TRACE_DONE__(.*?)__INSTRUCTION_TRACE_DONE_END__/s);
		if (doneMatch && !parsedDone) {
			try {
				parsedDone = JSON.parse(doneMatch[1]);
			} catch {}
		}

		if (!parsedDone && runRes.exitCode !== 0 && !executionError) {
			executionError = `Frida process exited with code ${runRes.exitCode}: ${runRes.stderr || stdout || "unknown error"}`;
		}

		// Await all queued chunk writes to disk
		await writeQueue;
	} finally {
		await fileHandle.close();
		if (stagedScriptPath) {
			try {
				await fs.rm(stagedScriptPath, { force: true });
			} catch {}
		}
		if (deployedQbdi) {
			await deployedQbdi.cleanup().catch(() => {});
		}
	}

	if (executionError) {
		throw new ToolError(`Instruction trace failed: ${executionError}`);
	}
	if (writtenBytes === 0) {
		const failReason = parsedDone?.reason ?? "no_output";
		throw new ToolError(`Instruction trace capture produced 0 bytes (${failReason})`);
	}

	// 5. Compute real SHA-256 of generated trace artifact via streaming hash
	const { sha256 } = await computeStreamingHash(traceFilePath, maxBytes * 2);

	const metaObj = parsedMeta ?? {};
	const doneObj = parsedDone ?? {};
	const targetArch = (metaObj.arch as string) ?? "arm64";
	const instructionCount = (doneObj.instruction_count as number) ?? 0;
	const memoryReadCount = (doneObj.memory_read_count as number) ?? 0;
	const completionReason = (doneObj.reason as string) ?? "completed";
	const isCompletedNormally = completionReason === "function_return" || completionReason === "range_exit";
	const isTruncated = Boolean(
		doneObj.truncated ||
		completionReason === "max_instructions_reached" ||
		completionReason === "timeout" ||
		completionReason === "max_bytes_exceeded" ||
		missingChunksDetected ||
		isTruncatedByLimit ||
		!isCompletedNormally,
	);
	const engineUsed: "qbdi" | "stalker" = (doneObj.engine as "qbdi" | "stalker") ?? "stalker";
	const memoryReadsComplete = Boolean(doneObj.memory_reads_complete);

	// Compute real SHA-256 of the target module ONLY if on local host device
	let hostModuleSha256: string | undefined;
	const isLocalTarget = !options.usb && (!options.device || options.device === "local") && !options.host;
	const moduleMeta = metaObj.module as { name?: string; base?: string; size?: number; path?: string } | undefined;
	if (isLocalTarget && moduleMeta?.path) {
		try {
			const modBytes = await fs.readFile(moduleMeta.path);
			hostModuleSha256 = crypto.createHash("sha256").update(modBytes).digest("hex");
		} catch {
			// File not accessible on local filesystem - leave undefined honestly
		}
	}

	// Map architecture to Triton architecture identifier
	let tritonArch = "x86_64";
	let defaultTargetReg = "rax";
	if (targetArch === "arm" || targetArch === "arm32") {
		tritonArch = "arm32";
		defaultTargetReg = "r0";
	} else if (targetArch === "arm64" || targetArch === "aarch64") {
		tritonArch = "aarch64";
		defaultTargetReg = "x0";
	} else if (targetArch === "ia32" || targetArch === "x86") {
		tritonArch = "x86";
		defaultTargetReg = "eax";
	}

	// 6. Generate Companion Metadata Sidecar Manifest
	const manifestPath = `${traceFilePath}.manifest.json`;
	const isReplayValid = memoryReadsComplete && !isTruncated && isCompletedNormally;
	const replayNotice = isReplayValid
		? undefined
		: isTruncated
			? `Trace is truncated or bounded (${completionReason}); symbolic replay may diverge or fail.`
			: "Trace collected with Frida Stalker; memory reads may be incomplete without QBDI ('reverse setup reverse qbdi --execute'). Unobserved memory inputs must be explicitly initialized or symbolized in Triton.";

	const initialRegisters = firstRegisters ?? (doneObj.first_registers as Record<string, string>) ?? undefined;
	const replayBounds = {
		max_instructions: Math.max(instructionCount + 1000, 50000),
	};

	const metadata: InstructionTraceMetadata = {
		trace_version: "1.0.0",
		created_at: new Date().toISOString(),
		target: {
			pid: options.pid,
			process: options.process,
			spawn: options.spawn,
			device: options.device,
			arch: targetArch,
		},
		module: moduleMeta
			? {
					...moduleMeta,
					sha256: hostModuleSha256,
				}
			: {
					name: options.module,
					path: options.module,
					sha256: hostModuleSha256,
				},
		bounds: {
			scope: options.scope ?? "function",
			function: options.function,
			offset: options.offset,
			address: options.address,
			start_address: metaObj.range_start as string,
			end_address: metaObj.range_end as string,
			thread_id: options.threadId,
			max_instructions: options.maxInstructions ?? 10000,
		},
		stats: {
			total_instructions: instructionCount,
			unique_addresses: (doneObj.unique_addresses as number) ?? 0,
			total_memory_reads: memoryReadCount,
			total_bytes: writtenBytes,
			completion_reason: completionReason,
			duration_ms: (doneObj.duration_ms as number) ?? 0,
			truncated: isTruncated,
		},
		flags: {
			engine: engineUsed,
			memory_reads_complete: memoryReadsComplete,
			thumb_mode: Boolean(doneObj.thumb_mode || metaObj.thumb_mode),
			nzcv: (doneObj.nzcv as string) ?? undefined,
			apsr: (doneObj.cpsr as string) ?? undefined,
			cpsr: (doneObj.cpsr as string) ?? undefined,
		},
		first_registers: initialRegisters,
		replay_handoff: {
			tool: "triton_analyze",
			valid: isReplayValid,
			notice: replayNotice,
			params: {
				action: "replay",
				trace: traceFilePath,
				arch: tritonArch,
				...(tritonArch === "arm32" ? { thumb: Boolean(doneObj.thumb_mode || metaObj.thumb_mode) } : {}),
				initial_registers: initialRegisters,
				bounds: replayBounds,
				output: {
					kind: "register",
					target: defaultTargetReg,
				},
			},
		},
	};

	await fs.writeFile(manifestPath, JSON.stringify(metadata, null, 2), "utf-8");

	return {
		success: true,
		status: isTruncated ? "truncated" : "ok",
		engine: engineUsed,
		tracePath: traceFilePath,
		manifestPath,
		sha256,
		instructionCount,
		memoryReadCount,
		totalBytes: writtenBytes,
		completionReason,
		arch: targetArch,
		module: metadata.module,
		metadata,
	};
}
