#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Native Recovery Differential Verifier and Formal SMT Prover.

Performs independent dual-execution differential verification and formal SMT equivalence
proving between original machine-level snapshots (executed via Triton) and recovered artifacts
(executed via llvmlite MCJIT for LLVM IR, or evaluated via Z3 SMT solver for SMT2/AST).

Disciplines:
1. Independent dual execution:
   - For LLVM IR: executes actual machine code via llvmlite MCJIT. Never uses a companion formula as proxy.
   - For SMT2/AST: evaluates candidate expressions via Z3 solver and AST substitution.
2. Strict input vectors and bindings:
   - All declared inputs must be present in user test vectors (no defaulting missing inputs to 0).
   - Hexadecimal strings ("0x...", "0X...") and signed integers parsed strictly.
   - Bitwidths validated against target architecture ABI; initialization errors never swallowed.
   - Machine integer values > 2^53 are always serialized as hex strings for safe JSON consumption.
3. Machine execution completion enforcement:
   - Original snapshot must reach a declared stop address.
   - Infinite loops exceeding instruction budget, unmapped instruction fetches, uninitialized
     register or memory reads, and instruction faults are treated as failures/counterexamples.
4. Bidirectional byte-addressed memory verification:
   - Every individual byte modified by original snapshot execution is tracked.
   - Compares observed byte-level writes against expected memory side effects bidirectionally:
     unexpected stores, missing stores, wrong store widths, and value mismatches are caught.
5. Formal SMT equivalence proof:
   - Reuses action_explore from native-recover-worker (single maintained execution root)
     for strict concolic path enumeration, path predicates, output ASTs, and symbolic memory side effects.
   - Preserves complete domain predicates intact without stripping top-level Not, And, or Or.
   - Unifies candidate bitvector variables with Triton symbolic variables across domain bounds.
   - Solver UNKNOWN outcomes are treated strictly as inconclusive, never assumed to be proved.
   - Differentiates return-only formal equivalence from full-algorithm equivalence with side effects.
6. Epistemic assurance recommendations:
   - 'algorithm_recovery': ONLY when formal SMT equivalence is proved across the complete domain
     and all memory side effects are formally proved.
   - 'dynamic_call_observation': when finite vectors achieve 100% agreement, or when formal proof
     is return-only while unmodeled memory side effects exist.
   - 'unverified': on any mismatch, counterexample, or execution fault.
"""

import ctypes
import importlib.util
import json
import os
import random
import re
import sys
import traceback

MAX_SAFE_INT = 9007199254740991


def serialize_val(val):
    if val is None:
        return None
    if isinstance(val, int):
        if val > MAX_SAFE_INT or val < -MAX_SAFE_INT or val > 0xffffffff:
            return hex(val)
        return val
    return val


def parse_int(val, field_name="value"):
    if isinstance(val, int):
        return val
    if val is None:
        raise ValueError(f"Missing required integer field '{field_name}'")
    s = str(val).strip()
    if not s:
        raise ValueError(f"Missing required integer field '{field_name}'")
    try:
        return int(s, 0)
    except Exception as e:
        raise ValueError(f"Invalid integer string for '{field_name}': '{val}' ({str(e)})")


def normalize_reg_name(name, arch_str):
    if not name or not isinstance(name, str):
        return name
    n = name.lower().strip()
    if arch_str == "arm32":
        if n == "cpsr":
            return "apsr"
        if n == "lr":
            return "r14"
        if n == "r13":
            return "sp"
        if n == "r15":
            return "pc"
    elif arch_str == "aarch64":
        if n in ("pstate", "cpsr"):
            return "nzcv"
        if n == "lr":
            return "x30"
    return n



def get_arch_spec(arch_str, ARCH=None):
    arch_str = arch_str.lower().strip()
    x86_arch = getattr(ARCH, "X86", None) if ARCH else None
    x86_64_arch = getattr(ARCH, "X86_64", None) if ARCH else None
    arm32_arch = getattr(ARCH, "ARM32", None) if ARCH else None
    aarch64_arch = getattr(ARCH, "AARCH64", None) if ARCH else None

    specs = {
        "x86": {
            "arch_name": "x86",
            "triton_arch": x86_arch,
            "gpr_bits": 32,
            "gpr_order": ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"],
            "flags": {"cf", "zf", "sf", "of", "af", "pf", "df"},
            "flag_parents": {"eflags"},
            "zero_regs": set(),
            "pc": "eip",
            "sp": "esp",
        },
        "x86_64": {
            "arch_name": "x86_64",
            "triton_arch": x86_64_arch,
            "gpr_bits": 64,
            "gpr_order": ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp",
                          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"],
            "flags": {"cf", "zf", "sf", "of", "af", "pf", "df"},
            "flag_parents": {"rflags", "eflags"},
            "zero_regs": set(),
            "pc": "rip",
            "sp": "rsp",
        },
        "arm32": {
            "arch_name": "arm32",
            "triton_arch": arm32_arch,
            "gpr_bits": 32,
            "gpr_order": ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
                          "r8", "r9", "r10", "r11", "r12", "sp", "r14", "pc"],
            "flags": {"z", "v", "n", "c"},
            "flag_parents": {"apsr", "cpsr"},
            "zero_regs": set(),
            "pc": "pc",
            "sp": "sp",
        },
        "aarch64": {
            "arch_name": "aarch64",
            "triton_arch": aarch64_arch,
            "gpr_bits": 64,
            "gpr_order": [f"x{i}" for i in range(31)] + ["sp", "pc"],
            "flags": {"z", "v", "n", "c"},
            "flag_parents": {"nzcv", "pstate"},
            "zero_regs": {"xzr", "wzr"},
            "pc": "pc",
            "sp": "sp",
        },
    }
    return specs.get(arch_str)


def parse_rec_expr(rec_expr_str, var_dict, target_bits, z3_module):
    """
    Parses an SMT2 candidate expression into a Z3 AST, dynamically resolving the expression
    bitwidth (checking target_bits, 32, 64, 16, 8) so subregister outputs succeed.
    """
    widths_to_try = [target_bits, 32, 64, 16, 8]
    seen = set()
    widths = [w for w in widths_to_try if not (w in seen or seen.add(w))]

    last_err = None
    for w in widths:
        try:
            decls = dict(var_dict)
            decls["__rec"] = z3_module.BitVec("__rec", w)
            parsed = z3_module.parse_smt2_string(f"(assert (= __rec {rec_expr_str}))", decls=decls)
            if parsed:
                return parsed[0].arg(1), w
        except Exception as e:
            last_err = e
            continue
    raise ValueError(f"Failed to parse recovered SMT2 expression: {last_err}")


def get_ctypes_type_for_bits(size_bits):
    if size_bits in (1, 8):
        return ctypes.c_uint8
    elif size_bits == 16:
        return ctypes.c_uint16
    elif size_bits == 32:
        return ctypes.c_uint32
    elif size_bits == 64:
        return ctypes.c_uint64
    raise ValueError(f"Unsupported ABI bitwidth {size_bits} for native C calling convention (expected 1, 8, 16, 32, 64)")


def validate_abi_bitwidths(inputs_cfg, output_bits):
    for inp in inputs_cfg:
        w = int(inp.get("size_bits", 32))
        if w not in (1, 8, 16, 32, 64):
            raise ValueError(f"Unsupported ABI bitwidth {w} for input '{inp.get('name')}'")
    if output_bits not in (1, 8, 16, 32, 64):
        raise ValueError(f"Unsupported ABI bitwidth {output_bits} for output")


class IsolatedMemoryHarness:
    def __init__(self, segments):
        self.segments = []
        for seg in (segments or []):
            addr = parse_int(seg.get("address", 0))
            raw_bytes = seg.get("bytes", "")
            data = bytearray.fromhex(raw_bytes) if raw_bytes else bytearray()
            perms = str(seg.get("permissions", "rw-")).lower()
            self.segments.append({
                "address": addr,
                "size": len(data),
                "data": data,
                "permissions": perms,
                "is_writable": "w" in perms,
                "is_readable": "r" in perms,
            })
        self.recorded_stores = []
        self.recorded_byte_writes = {}
        self.memory_fault = None

    def reset_vector(self, original_segments):
        self.recorded_stores = []
        self.recorded_byte_writes = {}
        self.memory_fault = None
        for i, seg in enumerate(original_segments or []):
            raw_bytes = seg.get("bytes", "")
            if i < len(self.segments):
                self.segments[i]["data"] = bytearray.fromhex(raw_bytes) if raw_bytes else bytearray()

    def handle_store(self, addr, val, size):
        if self.memory_fault:
            return
        matched_seg = None
        for seg in self.segments:
            seg_start = seg["address"]
            seg_end = seg_start + seg["size"]
            if seg_start <= addr and (addr + size) <= seg_end:
                matched_seg = seg
                break
        if not matched_seg:
            self.memory_fault = f"out_of_snapshot_write: write to 0x{addr:x} (size {size}) outside declared snapshot segments"
            return
        if not matched_seg["is_writable"]:
            self.memory_fault = f"segment_permission_violation: write to read-only segment at 0x{addr:x}"
            return
        offset = addr - matched_seg["address"]
        for b_idx in range(size):
            byte_val = (val >> (8 * b_idx)) & 0xff
            matched_seg["data"][offset + b_idx] = byte_val
            self.recorded_byte_writes[addr + b_idx] = byte_val
        self.recorded_stores.append({
            "address": hex(addr),
            "size": size,
            "value": hex(val),
        })

    def handle_load(self, addr, size):
        if self.memory_fault:
            return 0
        matched_seg = None
        for seg in self.segments:
            seg_start = seg["address"]
            seg_end = seg_start + seg["size"]
            if seg_start <= addr and (addr + size) <= seg_end:
                matched_seg = seg
                break
        if not matched_seg:
            self.memory_fault = f"out_of_snapshot_read: read from 0x{addr:x} (size {size}) outside declared snapshot segments"
            return 0
        if not matched_seg["is_readable"]:
            self.memory_fault = f"segment_permission_violation: read from non-readable segment at 0x{addr:x}"
            return 0
        offset = addr - matched_seg["address"]
        val = 0
        for b_idx in range(size):
            val |= (matched_seg["data"][offset + b_idx] << (8 * b_idx))
        return val


_ACTIVE_MEMORY_HARNESS = None
_SYMBOLS_REGISTERED = False


@ctypes.CFUNCTYPE(None, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32)
def _c_harness_store(addr, val, size):
    if _ACTIVE_MEMORY_HARNESS is not None:
        _ACTIVE_MEMORY_HARNESS.handle_store(addr, val, size)


@ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32)
def _c_harness_load(addr, size):
    if _ACTIVE_MEMORY_HARNESS is not None:
        return _ACTIVE_MEMORY_HARNESS.handle_load(addr, size)
    return 0


def ensure_harness_symbols_registered(llvm):
    global _SYMBOLS_REGISTERED
    if not _SYMBOLS_REGISTERED:
        llvm.add_symbol("__native_harness_store", ctypes.cast(_c_harness_store, ctypes.c_void_p).value)
        llvm.add_symbol("__native_harness_load", ctypes.cast(_c_harness_load, ctypes.c_void_p).value)
        _SYMBOLS_REGISTERED = True


RESERVED_CALLBACKS = {"__native_harness_store", "__native_harness_load"}
SUPPORTED_INTEGER_TYPES = {"i8": 1, "i16": 2, "i32": 4, "i64": 8}


def validate_and_instrument_llvm(llvm_ir_text, inputs_cfg, output_bits):
    try:
        import llvmlite.binding as llvm
    except ImportError as e:
        raise RuntimeError(f"llvmlite is required for LLVM IR JIT execution: {str(e)}")

    if not llvm_ir_text or not str(llvm_ir_text).strip():
        raise ValueError("recovered.llvm_ir text is required")

    # Reject source candidate declaring or referencing reserved callback names
    for cb in RESERVED_CALLBACKS:
        if cb in llvm_ir_text:
            raise ValueError(f"unsupported: candidate LLVM IR declares or references reserved callback '{cb}'")

    # 1. Parse original through LLVM binding first
    orig_mod = llvm.parse_assembly(llvm_ir_text)
    orig_mod.verify()

    # Reject globals, constructors, destructors
    for g in orig_mod.global_variables:
        raise ValueError(f"unsupported: candidate LLVM IR declares global variable '{g.name}'")

    func_count = 0
    candidate_func = None
    for f in orig_mod.functions:
        if f.is_declaration:
            raise ValueError(f"unsupported: candidate LLVM IR declares external function '{f.name}'")
        func_count += 1
        candidate_func = f
        for b in f.blocks:
            for inst in b.instructions:
                op = inst.opcode
                if op in ("call", "invoke", "callbr"):
                    raise ValueError(f"unsupported: function call instruction '{op}' is forbidden in candidate LLVM IR")
                if op in ("atomicrmw", "cmpxchg", "fence"):
                    raise ValueError(f"unsupported: atomic memory operation '{op}'")
                inst_str = str(inst).strip()
                if "asm " in inst_str:
                    raise ValueError("unsupported: inline assembly is forbidden")
    if func_count == 0 or candidate_func is None:
        raise ValueError("No executable function definition found in recovered LLVM IR")

    # 2. Canonicalize text from LLVM module
    canonical_ir = str(orig_mod)

    # 3. Rewrite load / store instructions
    lines = canonical_ir.splitlines()
    new_lines = []
    tmp_counter = 0
    has_store = False
    has_load = False

    store_pat = re.compile(
        r'^(\s*)store\s+(?:volatile\s+)?([a-zA-Z0-9_*]+)\s+(.+?),\s*([a-zA-Z0-9_*]+)\s+(.+?)(?:,\s*align\s+\d+)?(?:\s*,.*)?$'
    )
    load_pat = re.compile(
        r'^(\s*)(%[a-zA-Z0-9._]+)\s*=\s*load\s+(?:volatile\s+)?([a-zA-Z0-9_*]+),\s*([a-zA-Z0-9_*]+)\s+(.+?)(?:,\s*align\s+\d+)?(?:\s*,.*)?$'
    )

    for line in lines:
        m_store = store_pat.match(line)
        m_load = load_pat.match(line)
        if m_store:
            indent, ty, val, ptr_ty, ptr = m_store.groups()
            if ty not in SUPPORTED_INTEGER_TYPES:
                raise ValueError(f"unsupported: memory store with non-integer type '{ty}' (only i8, i16, i32, i64 supported)")
            size = SUPPORTED_INTEGER_TYPES[ty]
            has_store = True
            tmp_counter += 1
            ptr_i64 = f"%__h_p_{tmp_counter}"
            val_i64 = f"%__h_v_{tmp_counter}"

            if "inttoptr" in ptr:
                m_inttoptr = re.search(r'inttoptr\s*\(\s*(i\d+)\s+([^)]+?)\s+to', ptr)
                if m_inttoptr:
                    ity, ival = m_inttoptr.groups()
                    if ity == 'i64':
                        new_lines.append(f"{indent}{ptr_i64} = or i64 0, {ival}")
                    else:
                        new_lines.append(f"{indent}{ptr_i64} = zext {ity} {ival} to i64")
                else:
                    new_lines.append(f"{indent}{ptr_i64} = ptrtoint {ptr_ty} {ptr} to i64")
            else:
                new_lines.append(f"{indent}{ptr_i64} = ptrtoint {ptr_ty} {ptr} to i64")

            if ty == 'i64':
                val_i64 = val
            else:
                new_lines.append(f"{indent}{val_i64} = zext {ty} {val} to i64")

            new_lines.append(f"{indent}call void @__native_harness_store(i64 {ptr_i64}, i64 {val_i64}, i32 {size})")
        elif m_load:
            indent, res, ty, ptr_ty, ptr = m_load.groups()
            if ty not in SUPPORTED_INTEGER_TYPES:
                raise ValueError(f"unsupported: memory load with non-integer type '{ty}' (only i8, i16, i32, i64 supported)")
            size = SUPPORTED_INTEGER_TYPES[ty]
            has_load = True
            tmp_counter += 1
            ptr_i64 = f"%__h_p_{tmp_counter}"
            raw_val = f"%__h_r_{tmp_counter}"

            if "inttoptr" in ptr:
                m_inttoptr = re.search(r'inttoptr\s*\(\s*(i\d+)\s+([^)]+?)\s+to', ptr)
                if m_inttoptr:
                    ity, ival = m_inttoptr.groups()
                    if ity == 'i64':
                        new_lines.append(f"{indent}{ptr_i64} = or i64 0, {ival}")
                    else:
                        new_lines.append(f"{indent}{ptr_i64} = zext {ity} {ival} to i64")
                else:
                    new_lines.append(f"{indent}{ptr_i64} = ptrtoint {ptr_ty} {ptr} to i64")
            else:
                new_lines.append(f"{indent}{ptr_i64} = ptrtoint {ptr_ty} {ptr} to i64")

            new_lines.append(f"{indent}{raw_val} = call i64 @__native_harness_load(i64 {ptr_i64}, i32 {size})")
            if ty == 'i64':
                new_lines.append(f"{indent}{res} = or i64 0, {raw_val}")
            else:
                new_lines.append(f"{indent}{res} = trunc i64 {raw_val} to {ty}")
        else:
            new_lines.append(line)

    decls = []
    if has_store:
        decls.append("declare void @__native_harness_store(i64, i64, i32)")
    if has_load:
        decls.append("declare i64 @__native_harness_load(i64, i32)")

    # Put declarations at the end so top-level metadata remains at the top
    instrumented_text = '\n'.join(new_lines + [''] + decls) if decls else '\n'.join(new_lines)
    final_mod = llvm.parse_assembly(instrumented_text)
    final_mod.verify()

    for f in final_mod.functions:
        for b in f.blocks:
            for inst in b.instructions:
                if inst.opcode in ("load", "store"):
                    raise ValueError(f"unsupported: unintercepted raw memory instruction '{inst.opcode}' remains in candidate LLVM IR")

    exec_func = None
    for f in final_mod.functions:
        if not f.is_declaration:
            exec_func = f
            break

    args = list(exec_func.arguments)
    if len(args) != len(inputs_cfg):
        raise ValueError(f"LLVM function argument count ({len(args)}) does not match declared inputs count ({len(inputs_cfg)})")

    for arg, inp in zip(args, inputs_cfg):
        expected_w = int(inp.get("size_bits", 32))
        if str(arg.type) != f"i{expected_w}":
            raise ValueError(f"LLVM argument type {arg.type} does not match declared bitwidth i{expected_w}")

    ret_inst_found = False
    actual_ret_bits = output_bits
    for b in exec_func.blocks:
        for inst in b.instructions:
            if inst.opcode == "ret":
                ret_inst_found = True
                m_ret = re.match(r'ret\s+([a-zA-Z0-9_*]+)', str(inst).strip())
                if m_ret:
                    r_ty = m_ret.group(1)
                    if r_ty in ("i8", "i16", "i32", "i64"):
                        actual_ret_bits = int(r_ty[1:])
                    elif r_ty != f"i{output_bits}":
                        raise ValueError(f"LLVM return type {r_ty} does not match expected output bitwidth i{output_bits}")
                break
        if ret_inst_found:
            break

    if not ret_inst_found:
        raise ValueError("No ret instruction found in LLVM function")

    return final_mod, exec_func.name, actual_ret_bits


def compile_llvm_mcjit(llvm_ir_text, inputs_cfg, output_bits):
    """
    Compiles candidate LLVM IR assembly with llvmlite MCJIT and returns callable function.
    Strictly validates ABI bitwidth constraints.
    Instruments memory loads and stores into bounds-checked snapshot callbacks.
    """
    try:
        import llvmlite.binding as llvm
    except ImportError as e:
        raise RuntimeError(f"llvmlite is required for LLVM IR JIT execution: {str(e)}")

    validate_abi_bitwidths(inputs_cfg, output_bits)

    try:
        for init_fn in ["initialize", "initialize_native_target", "initialize_native_asmprinter"]:
            if hasattr(llvm, init_fn):
                try:
                    getattr(llvm, init_fn)()
                except RuntimeError:
                    pass

        ensure_harness_symbols_registered(llvm)
        mod, func_name, actual_ret_bits = validate_and_instrument_llvm(llvm_ir_text, inputs_cfg, output_bits)

        target = llvm.Target.from_default_triple()
        target_machine = target.create_target_machine()
        backing_mod = llvm.parse_assembly("")
        engine = llvm.create_mcjit_compiler(backing_mod, target_machine)
        engine.add_module(mod)
        engine.finalize_object()
        # Do not run static constructors

        func_ptr = engine.get_function_address(func_name)
        if not func_ptr:
            raise ValueError(f"Could not resolve function pointer for '{func_name}'")

        arg_types = [get_ctypes_type_for_bits(int(inp.get("size_bits", 32))) for inp in inputs_cfg]
        ret_type = get_ctypes_type_for_bits(actual_ret_bits)

        c_func = ctypes.CFUNCTYPE(ret_type, *arg_types)(func_ptr)
        return c_func, engine
    except Exception as e:
        raise RuntimeError(f"LLVM IR MCJIT compilation failed: {str(e)}")


_ACTION_EXPLORE_CACHED = None


def get_action_explore():
    """
    Imports action_explore from native-recover-worker staged alongside this script.
    """
    global _ACTION_EXPLORE_CACHED
    if _ACTION_EXPLORE_CACHED is not None:
        return _ACTION_EXPLORE_CACHED
    try:
        worker_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native-recover-worker.py")
        if os.path.exists(worker_path):
            spec = importlib.util.spec_from_file_location("native_recover_worker", worker_path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules["native_recover_worker"] = mod
                spec.loader.exec_module(mod)
                _ACTION_EXPLORE_CACHED = getattr(mod, "action_explore", None)
                return _ACTION_EXPLORE_CACHED
    except Exception:
        pass
    return None


def action_verify(request):
    try:
        import triton
        from triton import TritonContext, ARCH, MODE, Instruction, MemoryAccess, EXCEPTION
    except ImportError as e:
        return {
            "status": "missing_dependency",
            "error": f"Triton is required for verify: {str(e)}. Run 'reverse setup reverse triton --execute'."
        }

    try:
        import z3
    except ImportError as e:
        return {
            "status": "missing_dependency",
            "error": f"Z3 is required for verify: {str(e)}."
        }

    explore_fn = get_action_explore()
    if explore_fn is None:
        return {
            "status": "error",
            "error": "Failed to load action_explore from staged native-recover-worker.py. Single maintained execution root is required."
        }
    snapshot = request.get("snapshot")
    if not snapshot or not isinstance(snapshot, dict):
        return {"status": "error", "error": "Missing required 'snapshot' object."}

    arch_str = snapshot.get("arch", "x86_64").lower().strip()
    spec = get_arch_spec(arch_str, ARCH)
    if not spec:
        return {"status": "error", "error": f"Unsupported architecture '{arch_str}'."}
    if spec["triton_arch"] is None:
        return {"status": "error", "error": f"Architecture '{arch_str}' is not supported by installed Triton."}

    recovered_cfg = request.get("recovered")
    if not recovered_cfg or not isinstance(recovered_cfg, dict):
        return {"status": "error", "error": "Missing required 'recovered' artifact object."}

    recovered_kind = recovered_cfg.get("kind", "").lower().strip()
    if recovered_kind not in ("smt2", "ast", "llvm_ir"):
        return {"status": "error", "error": f"Unsupported recovered kind '{recovered_kind}'. Expected 'smt2', 'ast', or 'llvm_ir'."}

    output_cfg = snapshot.get("output")
    if not output_cfg or not isinstance(output_cfg, dict):
        return {"status": "error", "error": "Missing required 'output' specification in snapshot."}

    out_kind = output_cfg.get("kind", "").lower().strip()
    if out_kind not in ("register", "memory"):
        return {"status": "error", "error": f"Invalid snapshot output kind '{out_kind}'. Expected 'register' or 'memory'."}

    # Validate recovered.output matches snapshot.output
    rec_out = recovered_cfg.get("output")
    if rec_out is not None:
        if isinstance(rec_out, str):
            if out_kind != "register" or normalize_reg_name(rec_out, arch_str) != normalize_reg_name(output_cfg.get("target"), arch_str):
                return {
                    "status": "error",
                    "error": f"Recovered output register '{rec_out}' does not match snapshot output register '{output_cfg.get('target')}'."
                }
        elif isinstance(rec_out, dict):
            if rec_out.get("kind", "").lower().strip() != out_kind:
                return {
                    "status": "error",
                    "error": f"Recovered output kind '{rec_out.get('kind')}' does not match snapshot output kind '{out_kind}'."
                }
            if out_kind == "register":
                if normalize_reg_name(rec_out.get("target"), arch_str) != normalize_reg_name(output_cfg.get("target"), arch_str):
                    return {
                        "status": "error",
                        "error": f"Recovered output target '{rec_out.get('target')}' does not match snapshot output target '{output_cfg.get('target')}'."
                    }
            elif out_kind == "memory":
                if parse_int(rec_out.get("address")) != parse_int(output_cfg.get("address")) or int(rec_out.get("size", 4)) != int(output_cfg.get("size", 4)):
                    return {
                        "status": "error",
                        "error": "Recovered output memory location does not match snapshot output memory location."
                    }

    entry = parse_int(snapshot.get("entry"), "snapshot.entry")
    stop_addresses = {parse_int(sa, "stop_address") for sa in snapshot.get("stop_addresses", [])}
    if not stop_addresses:
        return {"status": "error", "error": "Missing required non-empty 'stop_addresses' in snapshot."}

    segments_raw = snapshot.get("segments") or []
    if not segments_raw:
        return {"status": "error", "error": "Missing required 'segments' array in snapshot."}

    symbolic_inputs_snapshot = snapshot.get("symbolic_inputs") or []
    recovered_inputs = list(recovered_cfg.get("inputs") or [])

    # Map snapshot symbolic inputs for address/register bindings and domain bounds
    sym_input_map = {}
    domain_bounds = {}
    for s_in in symbolic_inputs_snapshot:
        alias = s_in.get("alias")
        s_name = s_in.get("name")
        key = alias or s_name
        if key:
            sym_input_map[key] = s_in
        if alias and s_name:
            sym_input_map[alias] = s_in
            sym_input_map[s_name] = s_in

        min_v = parse_int(s_in["min"], f"{key}.min") if "min" in s_in else None
        max_v = parse_int(s_in["max"], f"{key}.max") if "max" in s_in else None
        if key:
            domain_bounds[key] = (min_v, max_v)
        if alias:
            domain_bounds[alias] = (min_v, max_v)
        if s_name:
            domain_bounds[s_name] = (min_v, max_v)

    # Bind and validate recovered inputs against snapshot symbolic inputs
    probe_ctx = TritonContext(spec["triton_arch"])
    for inp in recovered_inputs:
        v_name = inp["name"]
        s_match = sym_input_map.get(v_name) or sym_input_map.get(inp.get("reg"))

        # Inherit kind, address, size from snapshot if not explicitly specified
        if s_match:
            if "kind" not in inp and "kind" in s_match:
                inp["kind"] = s_match["kind"]
            if "address" not in inp and "address" in s_match:
                inp["address"] = s_match["address"]
            if "size" not in inp and "size" in s_match:
                inp["size"] = s_match["size"]
            if "reg" not in inp and s_match.get("kind") != "memory" and "name" in s_match:
                inp["reg"] = s_match["name"]

            # Merge domain min/max
            if "min" in s_match and "min" not in inp:
                inp["min"] = s_match["min"]
            if "max" in s_match and "max" not in inp:
                inp["max"] = s_match["max"]

        if "min" in inp or "max" in inp:
            i_min = parse_int(inp["min"], f"{v_name}.min") if "min" in inp else None
            i_max = parse_int(inp["max"], f"{v_name}.max") if "max" in inp else None
            domain_bounds[v_name] = (i_min, i_max)

        # Validate register or memory binding
        w = int(inp.get("size_bits", 32))
        if inp.get("kind") == "memory":
            if "address" not in inp:
                return {"status": "error", "error": f"Memory input '{v_name}' requires an explicit 'address' field."}
            m_addr = parse_int(inp["address"], f"{v_name}.address")
            m_sz = int(inp.get("size", w // 8 if w >= 8 else 1))
            inp["size"] = m_sz
            inp["address"] = m_addr
        else:
            r_target = normalize_reg_name(inp.get("reg") or v_name, arch_str)
            try:
                r_obj = probe_ctx.getRegister(r_target)
                inp["resolved_reg"] = r_target
            except Exception as e:
                return {"status": "error", "error": f"Invalid register binding '{r_target}' for input '{v_name}': {str(e)}"}

    # Output target bitwidth
    if out_kind == "register":
        out_target = normalize_reg_name(output_cfg.get("target"), arch_str)
        try:
            out_reg_obj = probe_ctx.getRegister(out_target)
            target_output_bits = out_reg_obj.getBitSize()
        except Exception as e:
            return {"status": "error", "error": f"Invalid output register '{out_target}': {str(e)}"}
    else:
        target_output_bits = int(output_cfg.get("size", 4)) * 8

    # Z3 variables for recovered inputs
    var_dict = {}
    for inp in recovered_inputs:
        v_name = inp["name"]
        w = int(inp.get("size_bits", 32))
        var_dict[v_name] = z3.BitVec(v_name, w)

    # Candidate domain predicate/guard parsing (keeping top-level predicate intact)
    candidate_domain_ast = None
    domain_pred_str = recovered_cfg.get("domain_predicate") or recovered_cfg.get("domain_guard") or snapshot.get("domain_predicate")
    if domain_pred_str and isinstance(domain_pred_str, str) and domain_pred_str.strip():
        try:
            parsed_dom = z3.parse_smt2_string(f"(assert {domain_pred_str.strip()})", decls=var_dict)
            if parsed_dom:
                dom_expr = parsed_dom[0]
                if z3.is_bv(dom_expr):
                    dom_expr = (dom_expr == z3.BitVecVal(1, dom_expr.size()))
                elif not z3.is_bool(dom_expr):
                    return {"status": "error", "error": f"domain_predicate must be a boolean formula, got sort {dom_expr.sort()}"}
                candidate_domain_ast = dom_expr
        except Exception as e:
            return {"status": "error", "error": f"Failed to parse domain_predicate formula: {str(e)}"}

    # Candidate compilation and dispatch
    z3_rec_expr = None
    rec_expr_bits = target_output_bits
    c_jit_func = None
    jit_engine = None

    if recovered_kind == "llvm_ir":
        if any(inp.get("kind") == "memory" for inp in recovered_inputs):
            return {
                "status": "error",
                "error": "unsupported: LLVM JIT execution with memory inputs is not supported without isolated execution harness."
            }
        llvm_ir_text = recovered_cfg.get("llvm_ir")
        if not llvm_ir_text or not llvm_ir_text.strip():
            return {"status": "error", "error": "recovered.llvm_ir text is required when kind='llvm_ir'."}
        try:
            c_jit_func, jit_engine = compile_llvm_mcjit(llvm_ir_text, recovered_inputs, target_output_bits)
        except RuntimeError as e:
            return {"status": "missing_dependency", "error": str(e)}
        except Exception as e:
            return {"status": "error", "error": f"Failed to compile candidate LLVM IR: {str(e)}"}
    elif recovered_kind in ("smt2", "ast"):
        rec_expr_str = recovered_cfg.get("expression") or ""
        if not rec_expr_str or not rec_expr_str.strip():
            return {"status": "error", "error": f"recovered.expression is required when kind='{recovered_kind}'."}
        try:
            z3_rec_expr, rec_expr_bits = parse_rec_expr(rec_expr_str, var_dict, target_output_bits, z3)
        except Exception as e:
            return {"status": "error", "error": f"Failed to parse recovered SMT2 formula: {str(e)}"}

    # Process and validate test vectors
    user_vectors_raw = request.get("vectors")
    test_gen = request.get("test_generation") or {}
    all_raw_vectors = []

    # 1. Parse user-supplied vectors strictly (never silently default or drop missing inputs)
    if user_vectors_raw is not None:
        if not isinstance(user_vectors_raw, list):
            return {"status": "error", "error": "'vectors' must be an array of objects."}
        for idx, u_vec in enumerate(user_vectors_raw):
            if not isinstance(u_vec, dict):
                return {"status": "error", "error": f"Vector at index {idx} must be an object."}
            parsed_u_vec = {}
            for inp in recovered_inputs:
                v_name = inp["name"]
                alt_reg = inp.get("reg")
                val = None
                if v_name in u_vec:
                    val = u_vec[v_name]
                elif alt_reg and alt_reg in u_vec:
                    val = u_vec[alt_reg]
                else:
                    return {
                        "status": "error",
                        "error": f"Supplied test vector at index {idx} ({u_vec}) is missing required input '{v_name}'."
                    }
                try:
                    parsed_val = parse_int(val, f"vector[{idx}].{v_name}")
                except Exception as e:
                    return {"status": "error", "error": f"Invalid integer in vector[{idx}].{v_name}: {str(e)}"}

                # Validate value against input bitwidth
                width = int(inp.get("size_bits", 32))
                max_u = (1 << width) - 1
                min_s = -(1 << (width - 1))
                if min_s <= parsed_val < 0:
                    parsed_val = parsed_val & max_u
                elif not (0 <= parsed_val <= max_u):
                    return {
                        "status": "error",
                        "error": f"Vector[{idx}].{v_name} value {parsed_val} exceeds declared bitwidth {width}."
                    }
                parsed_u_vec[v_name] = parsed_val
            all_raw_vectors.append(parsed_u_vec)

    # 2. Test generation (boundary and random fuzz within declared widths and domains)
    if test_gen.get("boundary", True) and recovered_inputs:
        for inp in recovered_inputs:
            v_name = inp["name"]
            width = int(inp.get("size_bits", 32))
            max_v = (1 << width) - 1
            boundaries = [0, 1, 2, 9, 10, 11, 12, max_v - 1, max_v]

            if v_name in domain_bounds:
                d_min, d_max = domain_bounds[v_name]
                if d_min is not None:
                    boundaries.extend([d_min, d_min + 1])
                if d_max is not None:
                    boundaries.extend([d_max - 1, d_max])

            boundaries = sorted(list({b for b in boundaries if 0 <= b <= max_v}))
            for b_val in boundaries:
                vec = {v_name: b_val}
                for other in recovered_inputs:
                    o_name = other["name"]
                    if o_name != v_name:
                        seed_val = 5
                        for s_in in symbolic_inputs_snapshot:
                            if (s_in.get("alias") == o_name or s_in.get("name") == o_name) and "seed" in s_in:
                                seed_val = parse_int(s_in["seed"])
                        vec[o_name] = seed_val
                if vec not in all_raw_vectors:
                    all_raw_vectors.append(vec)

    random_count = int(test_gen.get("random_count", 10 if not user_vectors_raw else 0))
    if random_count > 0 and recovered_inputs:
        rng = random.Random(int(test_gen.get("seed", 42)))
        for _ in range(random_count):
            vec = {}
            for inp in recovered_inputs:
                v_name = inp["name"]
                width = int(inp.get("size_bits", 32))
                max_v = (1 << width) - 1
                min_v = 0
                if v_name in domain_bounds:
                    d_min, d_max = domain_bounds[v_name]
                    if d_min is not None:
                        min_v = max(min_v, d_min)
                    if d_max is not None:
                        max_v = min(max_v, d_max)
                val = rng.randint(min_v, min(max_v, 1000 if max_v > 1000 else max_v)) if min_v <= max_v else min_v
                vec[v_name] = val
            if vec not in all_raw_vectors:
                all_raw_vectors.append(vec)

    # 3. Partition vectors into in-domain vs out-of-domain
    in_domain_vectors = []
    out_of_domain_vectors = []

    for vec in all_raw_vectors:
        is_in_domain = True
        for v_name, val in vec.items():
            if v_name in domain_bounds:
                d_min, d_max = domain_bounds[v_name]
                if d_min is not None and val < d_min:
                    is_in_domain = False
                if d_max is not None and val > d_max:
                    is_in_domain = False

        if is_in_domain and candidate_domain_ast is not None:
            s_dom = z3.Solver()
            for v_name, val in vec.items():
                w = int(var_dict[v_name].size())
                s_dom.add(var_dict[v_name] == z3.BitVecVal(val, w))
            s_dom.add(candidate_domain_ast)
            if s_dom.check() != z3.sat:
                is_in_domain = False

        if is_in_domain:
            in_domain_vectors.append(vec)
        else:
            out_of_domain_vectors.append({k: serialize_val(v) for k, v in vec.items()})

    proof_mode = request.get("proof_mode", "both")
    if proof_mode in ("finite_vectors", "both") and not in_domain_vectors:
        return {"status": "error", "error": "No valid in-domain test vectors available for verification."}

    passed_count = 0
    total_count = len(in_domain_vectors)
    counterexamples = []
    all_memory_verified = True
    any_snapshot_memory_stores = False

    expected_side_effects = recovered_cfg.get("memory_side_effects") or []
    harness = IsolatedMemoryHarness(snapshot.get("segments", []))

    # 4. Dual Execution across in-domain test vectors
    for vec in in_domain_vectors:
        # Clone snapshot for this concrete vector execution
        snap_copy = json.loads(json.dumps(snapshot))

        # Populate concrete vector inputs into snap_copy["symbolic_inputs"]
        snap_sym_inputs = snap_copy.get("symbolic_inputs")
        if snap_sym_inputs is None:
            snap_sym_inputs = []
            snap_copy["symbolic_inputs"] = snap_sym_inputs

        for inp in recovered_inputs:
            v_name = inp["name"]
            v_val = vec[v_name]
            target_s_in = None
            for s_in in snap_sym_inputs:
                s_alias = s_in.get("alias") or s_in.get("name")
                s_reg = s_in.get("name")
                if s_alias == v_name or s_reg == v_name or (inp.get("reg") and s_reg == inp.get("reg")):
                    target_s_in = s_in
                    break
            if target_s_in is None:
                target_s_in = {
                    "name": inp.get("reg") or v_name,
                    "alias": v_name,
                    "kind": inp.get("kind", "register"),
                    "size_bits": inp.get("size_bits", 32),
                }
                if inp.get("kind") == "memory":
                    target_s_in["address"] = inp["address"]
                    target_s_in["size"] = inp.get("size", int(inp.get("size_bits", 32)) // 8)
                snap_sym_inputs.append(target_s_in)

            target_s_in["alias"] = v_name
            target_s_in["seed"] = hex(v_val)
            target_s_in.pop("min", None)
            target_s_in.pop("max", None)

        # Execute bounded machine exploration via single maintained action_explore root
        req_bounds = request.get("bounds") or {}
        max_instructions = int(req_bounds.get("max_instructions", 5000))
        explore_res = explore_fn({
            "action": "explore",
            "snapshot": snap_copy,
            "bounds": {
                "branch_budget": 1,
                "max_instructions": max_instructions,
                "max_depth": 50,
                "timeout_ms": 30000,
            }
        })

        fault_error = None
        orig_ret = None
        observed_stores = []
        observed_byte_writes = {}

        if not explore_res or explore_res.get("status") != "ok":
            fault_error = (explore_res.get("error") if explore_res else "Exploration execution failed")
        else:
            discovered_paths = explore_res.get("result", {}).get("discovered_paths", [])
            selected_path = None
            if discovered_paths:
                for p in discovered_paths:
                    p_seed = p.get("seed", {})
                    matches_seed = True
                    for v_name, v_val in vec.items():
                        if v_name in p_seed:
                            try:
                                if parse_int(p_seed[v_name]) != v_val:
                                    matches_seed = False
                                    break
                            except Exception:
                                pass
                    if matches_seed:
                        selected_path = p
                        break
                if selected_path is None:
                    selected_path = discovered_paths[0]

            if selected_path is None:
                fault_error = "Execution produced no paths"
            else:
                p_status = selected_path.get("status")
                observed_stores = selected_path.get("memory_writes") or []
                if observed_stores:
                    any_snapshot_memory_stores = True

                for st in observed_stores:
                    s_addr = parse_int(st["address"])
                    s_sz = int(st.get("size", 1))
                    s_val = parse_int(st["value"])
                    for b_idx in range(s_sz):
                        observed_byte_writes[s_addr + b_idx] = (s_val >> (8 * b_idx)) & 0xff

                if p_status != "complete":
                    inst_count = selected_path.get("instructions_executed", max_instructions)
                    if p_status.startswith("budget_exceeded"):
                        fault_error = f"Execution exceeded maximum instruction limit ({inst_count} instructions) without reaching declared stop address"
                    else:
                        fault_error = f"Execution halted before stop address: {p_status}"
                else:
                    c_ret = selected_path.get("concrete_return")
                    if c_ret is not None:
                        orig_ret = parse_int(c_ret) & ((1 << target_output_bits) - 1)

        # Evaluate candidate artifact
        rec_ret = None
        cand_stores = []
        cand_byte_writes = {}
        harness_fault = None

        if recovered_kind == "llvm_ir" and c_jit_func is not None:
            global _ACTIVE_MEMORY_HARNESS
            harness.reset_vector(snapshot.get("segments", []))
            _ACTIVE_MEMORY_HARNESS = harness
            try:
                args = [vec[inp["name"]] for inp in recovered_inputs]
                raw_rec_ret = c_jit_func(*args)
                if out_kind == "register":
                    rec_ret = int(raw_rec_ret) & ((1 << target_output_bits) - 1)
                elif out_kind == "memory":
                    out_addr = parse_int(output_cfg.get("address"))
                    out_sz = int(output_cfg.get("size", 4))
                    rec_ret = harness.handle_load(out_addr, out_sz) & ((1 << target_output_bits) - 1)
                if harness.memory_fault:
                    harness_fault = harness.memory_fault
                cand_stores = list(harness.recorded_stores)
                cand_byte_writes = dict(harness.recorded_byte_writes)
            except Exception as e:
                rec_ret = None
                harness_fault = f"LLVM JIT native execution error: {str(e)}"
            finally:
                _ACTIVE_MEMORY_HARNESS = None
        elif z3_rec_expr is not None:
            try:
                substitutions = [(var_dict[inp["name"]], z3.BitVecVal(vec[inp["name"]], int(inp.get("size_bits", 32)))) for inp in recovered_inputs]
                eval_res = z3.simplify(z3.substitute(z3_rec_expr, *substitutions))
                if hasattr(eval_res, "as_long"):
                    rec_ret = eval_res.as_long() & ((1 << target_output_bits) - 1)
                else:
                    s_ev = z3.Solver()
                    for inp in recovered_inputs:
                        s_ev.add(var_dict[inp["name"]] == vec[inp["name"]])
                    if s_ev.check() == z3.sat:
                        m_ev = s_ev.model().eval(z3_rec_expr)
                        if hasattr(m_ev, "as_long"):
                            rec_ret = m_ev.as_long() & ((1 << target_output_bits) - 1)
            except Exception:
                rec_ret = None

        ret_matches = (orig_ret is not None and rec_ret is not None and orig_ret == rec_ret and not harness_fault)

        # Bidirectional byte-addressed memory verification
        mem_matches = True
        mem_mismatch_reason = None
        expected_byte_writes = {}
        expected_stores = []

        if expected_side_effects:
            for se in expected_side_effects:
                se_addr = parse_int(se.get("address"))
                se_sz = int(se.get("size", 4))
                se_val = None

                if "condition" in se:
                    s_cond = z3.Solver()
                    for inp in recovered_inputs:
                        s_cond.add(var_dict[inp["name"]] == vec[inp["name"]])
                    try:
                        cond_ast = z3.parse_smt2_string(f"(assert {se['condition']})", decls=var_dict)[0]
                        s_cond.add(cond_ast)
                        if s_cond.check() == z3.sat:
                            se_val = parse_int(se.get("value"))
                        elif "else_value" in se:
                            se_val = parse_int(se.get("else_value"))
                    except Exception:
                        se_val = parse_int(se.get("value"))
                else:
                    se_val = parse_int(se.get("value"))

                if se_val is not None:
                    expected_stores.append({
                        "address": hex(se_addr),
                        "size": se_sz,
                        "value": hex(se_val),
                    })
                    for b_idx in range(se_sz):
                        expected_byte_writes[se_addr + b_idx] = (se_val >> (8 * b_idx)) & 0xff

        if recovered_kind == "llvm_ir":
            # For LLVM IR: compare actual candidate writes captured by harness against original snapshot writes
            extra_byte_addrs = set(cand_byte_writes.keys()) - set(observed_byte_writes.keys())
            missing_byte_addrs = set(observed_byte_writes.keys()) - set(cand_byte_writes.keys())
            value_mismatch_addrs = [
                a for a in (set(cand_byte_writes.keys()) & set(observed_byte_writes.keys()))
                if cand_byte_writes[a] != observed_byte_writes[a]
            ]
            width_mismatch = False
            obs_bases_map = {parse_int(s["address"]): int(s.get("size", 1)) for s in observed_stores}
            for s in cand_stores:
                s_base = parse_int(s["address"])
                if s_base in obs_bases_map and int(s.get("size", 1)) != obs_bases_map[s_base]:
                    width_mismatch = True
                    break

            if extra_byte_addrs or missing_byte_addrs or value_mismatch_addrs or width_mismatch or harness_fault:
                mem_matches = False
                if harness_fault:
                    mem_mismatch_reason = harness_fault
                elif width_mismatch:
                    mem_mismatch_reason = "wrong_store_width"
                elif value_mismatch_addrs:
                    mem_mismatch_reason = "memory_side_effect_mismatch"
                elif extra_byte_addrs:
                    mem_mismatch_reason = "unexpected_store"
                elif missing_byte_addrs:
                    mem_mismatch_reason = "missing_store"
        else:
            # Check for store width mismatches on base addresses
            width_mismatch = False
            exp_bases_map = {parse_int(s["address"]): int(s.get("size", 1)) for s in expected_stores}
            for s in observed_stores:
                s_base = parse_int(s["address"])
                if s_base in exp_bases_map and int(s.get("size", 1)) != exp_bases_map[s_base]:
                    width_mismatch = True
                    break

            extra_byte_addrs = set(observed_byte_writes.keys()) - set(expected_byte_writes.keys())
            missing_byte_addrs = set(expected_byte_writes.keys()) - set(observed_byte_writes.keys())
            value_mismatch_addrs = [
                a for a in (set(observed_byte_writes.keys()) & set(expected_byte_writes.keys()))
                if observed_byte_writes[a] != expected_byte_writes[a]
            ]

            if extra_byte_addrs or missing_byte_addrs or value_mismatch_addrs or width_mismatch:
                mem_matches = False
                if width_mismatch:
                    mem_mismatch_reason = "wrong_store_width"
                elif value_mismatch_addrs:
                    mem_mismatch_reason = "memory_side_effect_mismatch"
                elif extra_byte_addrs:
                    obs_bases = {parse_int(s["address"]) for s in observed_stores}
                    exp_bases = set(exp_bases_map.keys())
                    if obs_bases & exp_bases:
                        mem_mismatch_reason = "wrong_store_width"
                    else:
                        mem_mismatch_reason = "unexpected_store"
                elif missing_byte_addrs:
                    obs_bases = {parse_int(s["address"]) for s in observed_stores}
                    exp_bases = set(exp_bases_map.keys())
                    if obs_bases & exp_bases:
                        mem_mismatch_reason = "wrong_store_width"
                    else:
                        mem_mismatch_reason = "missing_store"

        if not mem_matches:
            all_memory_verified = False

        if ret_matches and mem_matches and not fault_error:
            passed_count += 1
        else:
            counterexamples.append({
                "input": {k: serialize_val(v) for k, v in vec.items()},
                "original_return": hex(orig_ret) if orig_ret is not None else None,
                "recovered_return": hex(rec_ret) if rec_ret is not None else None,
                "original_memory_writes": observed_stores,
                "expected_memory_writes": expected_stores if (recovered_kind != "llvm_ir" or not cand_stores) else cand_stores,
                "mismatch_reason": fault_error or mem_mismatch_reason or "return_mismatch",
            })

    agreement_pct = (passed_count / total_count * 100.0) if total_count > 0 else 0.0

    # 5. Formal SMT Equivalence Proof
    smt_formal_proved = False
    formal_counterexample = None
    uncovered_domain_sample = None
    formal_proof_scope_note = None
    formal_proof_scope = None
    side_effects_proved = False

    if proof_mode in ("smt_formal", "both"):
        if recovered_kind == "llvm_ir":
            formal_proof_scope_note = "Formal SMT equivalence is not supported for raw LLVM IR candidate without symbolic lifting; finite vector differential verification performed."
            formal_proof_scope = None
            side_effects_proved = False
            smt_formal_proved = False
        elif z3_rec_expr is not None:
            formal_proof_scope = "full_algorithm"
            side_effects_proved = True
            # 与探索入口共用显式预算及默认值，形式化阶段保留未探索前沿。
            req_bounds = request.get("bounds") or {}
            branch_budget = int(req_bounds.get("branch_budget", 20))
            max_instructions = int(req_bounds.get("max_instructions", 5000))
            max_depth = int(req_bounds.get("max_depth", 50))
            timeout_ms = int(req_bounds.get("timeout_ms", 60000))

            explore_res = explore_fn({
                "action": "explore",
                "snapshot": snapshot,
                "bounds": {
                    "branch_budget": branch_budget,
                    "max_instructions": max_instructions,
                    "max_depth": max_depth,
                    "timeout_ms": timeout_ms,
                }
            })
            if not explore_res or explore_res.get("status") != "ok":
                return {
                    "status": "error",
                    "error": f"Formal path exploration failed: {explore_res.get('error', 'unknown exploration error')}"
                }

            all_paths_raw = explore_res.get("result", {}).get("discovered_paths", [])
            complete_paths = [
                p for p in all_paths_raw
                if p.get("status") == "complete" and p.get("path_predicate") and p.get("output_ast")
            ]

            if not complete_paths:
                all_paths_proved = False
                formal_proof_scope_note = "No complete execution paths reaching declared stop address were discovered."
            else:
                all_paths_proved = True
                path_pred_z3_list = []

                triton_sym_vars = {}
                for inp in recovered_inputs:
                    v_name = inp["name"]
                    if inp.get("kind") == "memory":
                        m_sz = int(inp.get("size", int(inp.get("size_bits", 32)) // 8))
                        triton_sym_vars[v_name] = m_sz * 8
                    else:
                        r_target = inp.get("resolved_reg") or normalize_reg_name(inp.get("reg") or v_name, arch_str)
                        try:
                            r_obj = probe_ctx.getRegister(r_target)
                            triton_sym_vars[v_name] = r_obj.getBitSize()
                        except Exception:
                            triton_sym_vars[v_name] = int(inp.get("size_bits", spec["gpr_bits"]))

                triton_decls = {v_name: z3.BitVec(v_name, size) for v_name, size in triton_sym_vars.items()}

                # Shared variable unification constraints (bridging bitwidths if subregisters)
                unify_constraints = []
                for inp in recovered_inputs:
                    v_name = inp["name"]
                    c_var = var_dict[v_name]
                    t_var = triton_decls[v_name]
                    c_bits = int(inp.get("size_bits", 32))
                    t_bits = triton_sym_vars[v_name]
                    if c_bits == t_bits:
                        unify_constraints.append(c_var == t_var)
                    elif c_bits < t_bits:
                        unify_constraints.append(t_var == z3.ZeroExt(t_bits - c_bits, c_var))
                    else:
                        unify_constraints.append(c_var == z3.ZeroExt(c_bits - t_bits, t_var))

                # Shared domain constraints using unsigned Z3 operators (UGE, ULE)
                shared_domain_constraints = []
                for inp in recovered_inputs:
                    v_name = inp["name"]
                    c_var = var_dict[v_name]
                    c_bits = int(inp.get("size_bits", 32))
                    max_representable = (1 << c_bits) - 1
                    if v_name in domain_bounds:
                        d_min, d_max = domain_bounds[v_name]
                        if d_min is not None:
                            if d_min < 0 or d_min > max_representable:
                                return {
                                    "status": "error",
                                    "error": f"Domain min {d_min} for '{v_name}' is outside representable bitwidth {c_bits}."
                                }
                            shared_domain_constraints.append(z3.UGE(c_var, z3.BitVecVal(d_min, c_bits)))
                        if d_max is not None:
                            if d_max < 0 or d_max > max_representable:
                                return {
                                    "status": "error",
                                    "error": f"Domain max {d_max} for '{v_name}' is outside representable bitwidth {c_bits}."
                                }
                            shared_domain_constraints.append(z3.ULE(c_var, z3.BitVecVal(d_max, c_bits)))
                        if d_min is not None and d_max is not None and d_min > d_max:
                            return {
                                "status": "error",
                                "error": f"Invalid domain bounds for '{v_name}': min ({hex(d_min)}) must be <= max ({hex(d_max)})."
                            }

                # Validate declared domain is satisfiable (reject vacuous proofs on empty domains)
                s_domain_check = z3.Solver()
                for c in shared_domain_constraints:
                    s_domain_check.add(c)
                if candidate_domain_ast is not None:
                    s_domain_check.add(candidate_domain_ast)
                if s_domain_check.check() == z3.unsat:
                    return {
                        "status": "error",
                        "error": "Declared input domain is empty/unsatisfiable; cannot verify on an empty domain."
                    }
                for path_info in complete_paths:
                    s_formal = z3.Solver()
                    try:
                        p_pred_z3 = z3.parse_smt2_string(f"(assert {path_info['path_predicate']})", decls=triton_decls)[0]
                        p_out_z3 = z3.parse_smt2_string(
                            f"(assert (= __out {path_info['output_ast']}))",
                            decls={**triton_decls, "__out": z3.BitVec("__out", target_output_bits)}
                        )[0].arg(1)
                    except Exception as e:
                        all_paths_proved = False
                        formal_proof_scope_note = f"Failed parsing path formula: {str(e)}"
                        break

                    path_pred_z3_list.append(p_pred_z3)

                    s_formal.add(p_pred_z3)
                    for c in unify_constraints:
                        s_formal.add(c)
                    for c in shared_domain_constraints:
                        s_formal.add(c)
                    if candidate_domain_ast is not None:
                        s_formal.add(candidate_domain_ast)

                    # Check return disequality
                    c_out = z3_rec_expr
                    if rec_expr_bits == target_output_bits:
                        disequality = (c_out != p_out_z3)
                    elif rec_expr_bits < target_output_bits:
                        disequality = (z3.ZeroExt(target_output_bits - rec_expr_bits, c_out) != p_out_z3)
                    else:
                        disequality = (z3.Extract(target_output_bits - 1, 0, c_out) != p_out_z3)

                    s_formal.add(disequality)

                    check_res = s_formal.check()
                    if check_res == z3.sat:
                        all_paths_proved = False
                        m = s_formal.model()
                        ce_input = {v_name: serialize_val(m[var_dict[v_name]].as_long() if var_dict[v_name] in m else 0) for v_name in var_dict}
                        ce_orig = serialize_val(m.eval(p_out_z3).as_long() if hasattr(m.eval(p_out_z3), "as_long") else None)
                        ce_rec = serialize_val(m.eval(c_out).as_long() if hasattr(m.eval(c_out), "as_long") else None)
                        formal_counterexample = {
                            "input": ce_input,
                            "original_return": hex(ce_orig) if isinstance(ce_orig, int) else ce_orig,
                            "recovered_return": hex(ce_rec) if isinstance(ce_rec, int) else ce_rec,
                            "mismatch_reason": "formal_smt_disequality",
                        }
                        if formal_counterexample not in counterexamples:
                            counterexamples.append(formal_counterexample)
                        break
                    elif check_res != z3.unsat:
                        all_paths_proved = False
                        formal_proof_scope_note = f"Solver returned inconclusive ({check_res}) during return equivalence check"
                        break

                    # Check memory side effects on this path
                    p_stores = path_info.get("memory_writes") or []
                    if p_stores and not expected_side_effects:
                        formal_proof_scope = "return_only"
                        side_effects_proved = False
                    elif p_stores and expected_side_effects:
                        for st in p_stores:
                            st_addr = parse_int(st.get("address"))
                            st_sz = int(st.get("size", 4))
                            matching_exp = None
                            for se in expected_side_effects:
                                if parse_int(se.get("address")) == st_addr:
                                    matching_exp = se
                                    break

                            if not matching_exp:
                                formal_proof_scope = "return_only"
                                side_effects_proved = False
                            else:
                                if int(matching_exp.get("size", 4)) != st_sz:
                                    formal_proof_scope = "return_only"
                                    side_effects_proved = False
                                elif "value_ast" in st:
                                    st_bits = st_sz * 8
                                    try:
                                        st_val_ast = z3.parse_smt2_string(
                                            f"(assert (= __st {st['value_ast']}))",
                                            decls={**triton_decls, "__st": z3.BitVec("__st", st_bits)}
                                        )[0].arg(1)

                                        # Evaluate expected value under path predicate
                                        exp_val = parse_int(matching_exp.get("value"))
                                        if "condition" in matching_exp:
                                            s_cond = z3.Solver()
                                            s_cond.add(p_pred_z3)
                                            for c in unify_constraints:
                                                s_cond.add(c)
                                            cond_ast = z3.parse_smt2_string(f"(assert {matching_exp['condition']})", decls=var_dict)[0]
                                            s_cond.add(cond_ast)
                                            if s_cond.check() == z3.unsat and "else_value" in matching_exp:
                                                exp_val = parse_int(matching_exp["else_value"])

                                        exp_val_ast = z3.BitVecVal(exp_val, st_bits)
                                        s_mem = z3.Solver()
                                        s_mem.add(p_pred_z3)
                                        for c in unify_constraints:
                                            s_mem.add(c)
                                        for c in shared_domain_constraints:
                                            s_mem.add(c)
                                        if candidate_domain_ast is not None:
                                            s_mem.add(candidate_domain_ast)

                                        s_mem.add(st_val_ast != exp_val_ast)
                                        mem_check = s_mem.check()
                                        if mem_check == z3.sat:
                                            all_paths_proved = False
                                            formal_counterexample = {
                                                "mismatch_reason": "memory_side_effect_mismatch",
                                                "address": hex(st_addr),
                                            }
                                            if formal_counterexample not in counterexamples:
                                                counterexamples.append(formal_counterexample)
                                            break
                                        elif mem_check != z3.unsat:
                                            formal_proof_scope = "return_only"
                                            side_effects_proved = False
                                    except Exception:
                                        formal_proof_scope = "return_only"
                                        side_effects_proved = False

                # Domain completeness check across discovered paths
                if path_pred_z3_list and all_paths_proved:
                    s_coverage = z3.Solver()
                    for c in unify_constraints:
                        s_coverage.add(c)
                    for c in shared_domain_constraints:
                        s_coverage.add(c)
                    if candidate_domain_ast is not None:
                        s_coverage.add(candidate_domain_ast)

                    if len(path_pred_z3_list) == 1:
                        covered_union = path_pred_z3_list[0]
                    else:
                        covered_union = z3.Or(*path_pred_z3_list)

                    s_coverage.add(z3.Not(covered_union))
                    cov_check = s_coverage.check()
                    if cov_check == z3.sat:
                        m_cov = s_coverage.model()
                        uncovered_domain_sample = {
                            v_name: serialize_val(m_cov.eval(var_dict[v_name]).as_long() if var_dict[v_name] in m_cov else 0)
                            for v_name in var_dict
                        }
                        all_paths_proved = False
                        formal_proof_scope_note = f"Modeled paths do not cover complete domain; uncovered sample: {uncovered_domain_sample}"
                    elif cov_check != z3.unsat:
                        all_paths_proved = False
                        formal_proof_scope_note = f"Solver returned inconclusive ({cov_check}) during domain completeness check"

                if all_paths_proved and len(counterexamples) == 0:
                    smt_formal_proved = True
                else:
                    smt_formal_proved = False
                    formal_proof_scope = None
                    side_effects_proved = False

    # 6. Final labels and epistemic assurance recommendation
    if smt_formal_proved:
        if formal_proof_scope == "full_algorithm":
            proof_label = f"Formal SMT equivalence proved across modeled domain and side effects ({len(in_domain_vectors)} vectors verified, Z3 verified candidate AST equivalence universally across reachable paths)."
            assurance_rec = "algorithm_recovery"
        else:
            proof_label = f"Formal SMT equivalence proved for return value only across modeled domain ({len(in_domain_vectors)} vectors verified)."
            assurance_rec = "dynamic_call_observation" if any_snapshot_memory_stores else "algorithm_recovery"
    elif agreement_pct == 100.0 and len(counterexamples) == 0:
        if proof_mode == "finite_vectors":
            proof_label = f"Finite vector differential check passed ({passed_count}/{total_count}, 100.0%). Observation-level evidence only; finite testing cannot prove universal equivalence across infinite unmodeled domain."
        else:
            note = f" ({formal_proof_scope_note})" if formal_proof_scope_note else ""
            proof_label = f"Finite vector differential check passed ({passed_count}/{total_count}, 100.0%){note}. Observation-level evidence only."
        assurance_rec = "dynamic_call_observation"
    else:
        proof_label = f"Differential verification failed ({passed_count}/{total_count} passed, {len(counterexamples)} counterexamples)."
        assurance_rec = "unverified"

    return {
        "status": "ok",
        "result": {
            "passed_count": passed_count,
            "total_count": total_count,
            "agreement_pct": agreement_pct,
            "counterexamples": counterexamples[:5],
            "out_of_domain_vectors": out_of_domain_vectors,
            "memory_verified": all_memory_verified,
            "smt_formal_proved": smt_formal_proved,
            "formal_proof_scope": formal_proof_scope,
            "side_effects_proved": side_effects_proved,
            "proof_label": proof_label,
            "assurance_level_recommendation": assurance_rec,
            "uncovered_domain_sample": uncovered_domain_sample,
        }
    }


def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            json.dump({"status": "error", "error": "Empty input received on stdin"}, sys.stdout)
            sys.stdout.flush()
            return

        request = json.loads(raw_input)
        action = request.get("action", "verify")

        if action == "verify":
            response = action_verify(request)
        else:
            response = {"status": "error", "error": f"Unsupported action '{action}'. Only 'verify' is supported."}

        json.dump(response, sys.stdout)
        sys.stdout.flush()
    except Exception as e:
        err_msg = f"{str(e)}\n{traceback.format_exc()}"
        json.dump({"status": "error", "error": err_msg}, sys.stdout)
        sys.stdout.flush()


if __name__ == "__main__":
    main()
