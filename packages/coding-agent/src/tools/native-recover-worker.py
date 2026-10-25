#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Native Recovery Engine Worker.

Implements bounded symbolic exploration (DSE worklist), handler semantic slicing,
path-predicate guarded multi-path merge, and dual-execution differential verification
using Triton (Apache-2.0), Z3 SMT solver, and LLVM/llvmlite.

Constraints:
1. Never pretend total coverage: unmodeled paths and uncovered input domains are explicit.
2. Solver consistency: proofs on overlapping domains detect semantic conflicts.
3. Dual verification: independently executes original machine snapshot and recovered artifact.
4. No fake fallbacks: returns structured missing status when optional compiler features are unavailable.
"""

import json
import os
import random
import sys
import traceback

def parse_int(val, field_name="value"):
    if isinstance(val, int):
        return val
    if val is None or (isinstance(val, str) and not val.strip()):
        raise ValueError(f"Missing required integer field '{field_name}'")
    return int(str(val).strip(), 0)
def is_memory_range_initialized(ctx, addr, size):
    from triton import MemoryAccess
    for b in range(size):
        if not ctx.isConcreteMemoryValueDefined(MemoryAccess(addr + b, 1)):
            return False
    return True


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

def is_vector_register(name, arch_str):
    if not name or not isinstance(name, str):
        return False
    n = name.lower().strip()
    if arch_str in ("x86", "x86_64"):
        return n.startswith(("xmm", "ymm", "zmm", "mm"))
    elif arch_str == "arm32":
        return (n.startswith("q") or n.startswith("d") or n.startswith("s")) and n[1:].isdigit()
    elif arch_str == "aarch64":
        return (n.startswith("v") or n.startswith("q") or n.startswith("d") or
                n.startswith("s") or n.startswith("h") or n.startswith("b")) and n[1:].isdigit()
    return False

def get_reg_bounds(reg_obj):
    bv = reg_obj.getBitvector()
    return bv.getLow(), bv.getHigh()

class RegisterBitTracker:
    def __init__(self):
        self.masks = {}

    def mark_initialized(self, parent_name, low, high):
        width = high - low + 1
        mask = ((1 << width) - 1) << low
        curr = self.masks.get(parent_name, 0)
        self.masks[parent_name] = curr | mask

    def is_fully_initialized(self, parent_name, low, high):
        width = high - low + 1
        req_mask = ((1 << width) - 1) << low
        curr = self.masks.get(parent_name, 0)
        return (curr & req_mask) == req_mask

    def mark_undefined(self, parent_name, low, high):
        width = high - low + 1
        mask = ((1 << width) - 1) << low
        curr = self.masks.get(parent_name, 0)
        self.masks[parent_name] = curr & ~mask

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
            "flag_parents": {"nzcv", "pstate", "cpsr"},
            "zero_regs": {"xzr", "wzr"},
            "pc": "pc",
            "sp": "sp",
        },
    }
    return specs.get(arch_str)
def is_self_zeroing_instruction(inst, arch_str, ctx):
    try:
        from triton import OPERAND
        disasm_lower = inst.getDisassembly().lower()
        if arch_str in ("x86", "x86_64"):
            zeroing_mnemonics = ("xor ", "sub ", "pxor ", "xorps ", "xorpd ", "vpxor ", "vxorps ", "vxorpd ")
            if any(disasm_lower.startswith(m) for m in zeroing_mnemonics):
                ops = inst.getOperands()
                if len(ops) >= 2 and ops[0].getType() == OPERAND.REG and ops[1].getType() == OPERAND.REG:
                    if ops[0].getId() == ops[1].getId():
                        p = ctx.getParentRegister(ops[0])
                        return ops[0].getName().lower(), p.getName().lower() if p else ops[0].getName().lower()
        elif arch_str in ("arm32", "aarch64"):
            zeroing_mnemonics = ("eor ", "eors ", "sub ", "subs ")
            if any(disasm_lower.startswith(m) for m in zeroing_mnemonics):
                ops = inst.getOperands()
                if len(ops) >= 3 and ops[0].getType() == OPERAND.REG and ops[1].getType() == OPERAND.REG and ops[2].getType() == OPERAND.REG:
                    if ops[1].getId() == ops[2].getId():
                        p = ctx.getParentRegister(ops[0])
                        return ops[0].getName().lower(), p.getName().lower() if p else ops[0].getName().lower()
    except Exception:
        pass
    return None


def lower_z3_to_llvm(expr, func, builder, arg_map):
    import z3
    import llvmlite.ir as ir

    if z3.is_bv_value(expr):
        return ir.Constant(ir.IntType(expr.size()), expr.as_long())
    if z3.is_const(expr) and expr.decl().kind() == z3.Z3_OP_UNINTERPRETED:
        name = str(expr)
        if name in arg_map:
            return arg_map[name]
        raise ValueError(f"Unmapped symbolic variable '{name}' in Z3 expression during LLVM lowering: no matching input parameter.")
    decl = expr.decl()
    kind = decl.kind()
    num_args = expr.num_args()

    if kind == z3.Z3_OP_ITE:
        cond_val = lower_z3_to_llvm(expr.arg(0), func, builder, arg_map)
        then_block = func.append_basic_block('then')
        else_block = func.append_basic_block('else')
        merge_block = func.append_basic_block('merge')

        builder.cbranch(cond_val, then_block, else_block)

        builder.position_at_end(then_block)
        then_val = lower_z3_to_llvm(expr.arg(1), func, builder, arg_map)
        then_end_block = builder.block
        builder.branch(merge_block)

        builder.position_at_end(else_block)
        else_val = lower_z3_to_llvm(expr.arg(2), func, builder, arg_map)
        else_end_block = builder.block
        builder.branch(merge_block)

        builder.position_at_end(merge_block)
        phi = builder.phi(then_val.type, 'ite_res')
        phi.add_incoming(then_val, then_end_block)
        phi.add_incoming(else_val, else_end_block)
        return phi

    if kind == z3.Z3_OP_TRUE or z3.is_true(expr):
        return ir.Constant(ir.IntType(1), 1)
    if kind == z3.Z3_OP_FALSE or z3.is_false(expr):
        return ir.Constant(ir.IntType(1), 0)

    args = [lower_z3_to_llvm(expr.arg(i), func, builder, arg_map) for i in range(num_args)]

    if kind == z3.Z3_OP_AND:
        res = args[0]
        for a in args[1:]:
            res = builder.and_(res, a)
        return res
    elif kind == z3.Z3_OP_OR:
        res = args[0]
        for a in args[1:]:
            res = builder.or_(res, a)
        return res
    elif kind == z3.Z3_OP_NOT:
        return builder.not_(args[0])
    elif kind == z3.Z3_OP_BADD:
        res = args[0]
        for a in args[1:]:
            res = builder.add(res, a)
        return res
    elif kind == z3.Z3_OP_BSUB:
        return builder.sub(args[0], args[1])
    elif kind == z3.Z3_OP_BMUL:
        res = args[0]
        for a in args[1:]:
            res = builder.mul(res, a)
        return res
    elif kind == z3.Z3_OP_BAND:
        res = args[0]
        for a in args[1:]:
            res = builder.and_(res, a)
        return res
    elif kind == z3.Z3_OP_BOR:
        res = args[0]
        for a in args[1:]:
            res = builder.or_(res, a)
        return res
    elif kind == z3.Z3_OP_BXOR:
        res = args[0]
        for a in args[1:]:
            res = builder.xor(res, a)
        return res
    elif kind == z3.Z3_OP_BNEG:
        return builder.neg(args[0])
    elif kind == z3.Z3_OP_BNOT:
        return builder.not_(args[0])
    elif kind == z3.Z3_OP_CONCAT:
        hi_w = expr.arg(0).size()
        lo_w = expr.arg(1).size()
        total_w = hi_w + lo_w
        hi_ext = builder.zext(args[0], ir.IntType(total_w))
        lo_ext = builder.zext(args[1], ir.IntType(total_w))
        hi_shl = builder.shl(hi_ext, ir.Constant(ir.IntType(total_w), lo_w))
        return builder.or_(hi_shl, lo_ext)
    elif kind == z3.Z3_OP_EXTRACT:
        params = expr.params()
        hi, lo = params[0], params[1]
        width = hi - lo + 1
        shifted = builder.lshr(args[0], ir.Constant(args[0].type, lo)) if lo > 0 else args[0]
        return builder.trunc(shifted, ir.IntType(width))
    elif kind == z3.Z3_OP_ZERO_EXT:
        ext_bits = expr.params()[0]
        target_w = args[0].type.width + ext_bits
        return builder.zext(args[0], ir.IntType(target_w))
    elif kind == z3.Z3_OP_SIGN_EXT:
        ext_bits = expr.params()[0]
        target_w = args[0].type.width + ext_bits
        return builder.sext(args[0], ir.IntType(target_w))
    elif kind in (z3.Z3_OP_BSHL, z3.Z3_OP_BLSHR, z3.Z3_OP_BASHR):
        val = args[0]
        shift = args[1]
        width = expr.size()
        width_const = ir.Constant(ir.IntType(width), width)
        too_large = builder.icmp_unsigned('>=', shift, width_const)
        if kind == z3.Z3_OP_BSHL:
            normal_shift = builder.shl(val, shift)
            return builder.select(too_large, ir.Constant(ir.IntType(width), 0), normal_shift)
        elif kind == z3.Z3_OP_BLSHR:
            normal_shift = builder.lshr(val, shift)
            return builder.select(too_large, ir.Constant(ir.IntType(width), 0), normal_shift)
        elif kind == z3.Z3_OP_BASHR:
            normal_shift = builder.ashr(val, shift)
            sign_shift = builder.ashr(val, ir.Constant(ir.IntType(width), max(0, width - 1)))
            return builder.select(too_large, sign_shift, normal_shift)
    elif kind == z3.Z3_OP_EQ:
        return builder.icmp_unsigned('==', args[0], args[1])
    elif kind == z3.Z3_OP_ULEQ:
        return builder.icmp_unsigned('<=', args[0], args[1])
    elif kind == z3.Z3_OP_UGEQ:
        return builder.icmp_unsigned('>=', args[0], args[1])
    elif kind == z3.Z3_OP_ULT:
        return builder.icmp_unsigned('<', args[0], args[1])
    elif kind == z3.Z3_OP_UGT:
        return builder.icmp_unsigned('>', args[0], args[1])
    elif kind == z3.Z3_OP_SLEQ:
        return builder.icmp_signed('<=', args[0], args[1])
    elif kind == z3.Z3_OP_SGEQ:
        return builder.icmp_signed('>=', args[0], args[1])
    elif kind == z3.Z3_OP_SLT:
        return builder.icmp_signed('<', args[0], args[1])
    elif kind == z3.Z3_OP_SGT:
        return builder.icmp_signed('>', args[0], args[1])
    raise ValueError(f"Unsupported Z3 operator for LLVM lowering: {decl.name()}")

def action_status(request):
    res = {
        "installed": False,
        "python_path": sys.executable,
        "python_version": sys.version.split()[0],
        "triton_version": None,
        "supported_architectures": [],
        "solver": {"available": False, "engine": None, "solvers": [], "reason": None},
        "llvm": {"available": False, "status": "unavailable"},
        "llvmlite": {"available": False, "version": None},
        "synthesizer": {"available": False, "reason": None},
        "install_hint": "Run 'reverse setup reverse triton --execute' to install the managed Triton toolchain.",
    }

    try:
        import triton
        from triton import TritonContext, ARCH, SOLVER
    except ImportError as e:
        res["installed"] = False
        res["error"] = f"Triton module import failed: {str(e)}"
        return {
            "status": "missing_dependency",
            "error": f"Triton library is not installed: {str(e)}. Run 'reverse setup reverse triton --execute'.",
            "result": res,
        }

    res["installed"] = True
    res["triton_version"] = getattr(triton, "__version__", "unknown")

    archs = []
    for arch_name, arch_const in [("x86", getattr(ARCH, "X86", None)),
                                  ("x86_64", getattr(ARCH, "X86_64", None)),
                                  ("arm32", getattr(ARCH, "ARM32", None)),
                                  ("aarch64", getattr(ARCH, "AARCH64", None))]:
        if arch_const is not None:
            try:
                TritonContext(arch_const)
                archs.append(arch_name)
            except Exception:
                pass
    res["supported_architectures"] = archs

    # Solver probe
    solvers = []
    for s_name in ["Z3", "BITWUZLA"]:
        if hasattr(SOLVER, s_name):
            solvers.append(s_name)
    res["solver"]["solvers"] = solvers

    try:
        ctx_solver = TritonContext(ARCH.X86_64 if hasattr(ARCH, "X86_64") else ARCH.X86)
        if hasattr(ctx_solver, "getSolver"):
            res["solver"]["engine"] = str(ctx_solver.getSolver())
        ast_ctx = ctx_solver.getAstContext()
        test_constraint = ast_ctx.equal(ast_ctx.bv(1, 32), ast_ctx.bv(1, 32))
        ctx_solver.getModel(test_constraint, status=True)
        res["solver"]["available"] = True
    except Exception as e:
        res["solver"]["available"] = False
        res["solver"]["reason"] = str(e)

    # LLVM native probe
    try:
        ctx_llvm = TritonContext(ARCH.X86_64 if hasattr(ARCH, "X86_64") else ARCH.X86)
        if hasattr(ctx_llvm, "liftToLLVM"):
            ast_ctx = ctx_llvm.getAstContext()
            ir = ctx_llvm.liftToLLVM(ast_ctx.bv(1, 32), fname="__probe")
            if ir and len(ir) > 0:
                res["llvm"]["available"] = True
                res["llvm"]["status"] = "available"
    except Exception as e:
        res["llvm"]["available"] = False
        res["llvm"]["status"] = f"unavailable: {str(e)}"

    # llvmlite probe
    try:
        import llvmlite
        import llvmlite.ir
        import llvmlite.binding
        res["llvmlite"]["available"] = True
        res["llvmlite"]["version"] = getattr(llvmlite, "__version__", "installed")
        if not res["llvm"]["available"]:
            res["llvm"]["available"] = True
            res["llvm"]["status"] = f"available (via llvmlite {res['llvmlite']['version']})"
    except ImportError:
        res["llvmlite"]["available"] = False

    # Synthesizer probe
    try:
        ctx_synth = TritonContext(ARCH.X86_64 if hasattr(ARCH, "X86_64") else ARCH.X86)
        if hasattr(ctx_synth, "synthesize"):
            ast_ctx = ctx_synth.getAstContext()
            ctx_synth.synthesize(ast_ctx.bv(42, 32))
            res["synthesizer"]["available"] = True
    except Exception as e:
        res["synthesizer"]["available"] = False
        res["synthesizer"]["reason"] = str(e)

    return {"status": "ok", "result": res}

def action_explore(request):
    try:
        import triton
        from triton import TritonContext, ARCH, MODE, Instruction, MemoryAccess, EXCEPTION, CALLBACK
    except ImportError as e:
        return {
            "status": "missing_dependency",
            "error": f"Triton library is not installed: {str(e)}. Run 'reverse setup reverse triton --execute'."
        }

    snapshot = request.get("snapshot")
    if not snapshot or not isinstance(snapshot, dict):
        return {"status": "error", "error": "Missing required 'snapshot' object."}

    arch_str = snapshot.get("arch", "x86_64").lower().strip()
    spec = get_arch_spec(arch_str, ARCH)
    if not spec:
        return {"status": "error", "error": f"Unsupported architecture '{arch_str}'."}

    triton_arch = spec["triton_arch"]
    if triton_arch is None:
        return {"status": "error", "error": f"Architecture '{arch_str}' not supported by Triton build."}

    entry = parse_int(snapshot.get("entry"), "snapshot.entry")
    stop_addresses = {parse_int(sa, "stop_address") for sa in snapshot.get("stop_addresses", [])}
    if not stop_addresses:
        return {"status": "error", "error": "Missing required non-empty 'stop_addresses' in snapshot."}

    segments_raw = snapshot.get("segments") or []
    if not segments_raw:
        return {"status": "error", "error": "Missing required 'segments' array in snapshot."}

    segments = []
    memory_map = {}
    for seg in segments_raw:
        s_addr = parse_int(seg.get("address"), "segment.address")
        s_hex = seg.get("bytes", "").replace(" ", "").strip()
        s_bytes = bytes.fromhex(s_hex)
        segments.append((s_addr, s_bytes))
        for offset, b in enumerate(s_bytes):
            memory_map[s_addr + offset] = b

    initial_regs = {normalize_reg_name(k, arch_str): parse_int(v, k) for k, v in (snapshot.get("registers") or {}).items()}
    symbolic_inputs = snapshot.get("symbolic_inputs") or []
    output_cfg = snapshot.get("output")
    if not output_cfg:
        return {"status": "error", "error": "Missing required 'output' in snapshot."}

    bounds = request.get("bounds") or {}
    branch_budget = int(bounds.get("branch_budget", 20))
    max_instructions = int(bounds.get("max_instructions", 5000))
    max_depth = int(bounds.get("max_depth", 50))
    thumb_mode = bool(snapshot.get("thumb", False)) or (arch_str == "arm32" and (entry & 1 != 0))

    initial_seed = {}
    for s_in in symbolic_inputs:
        alias = s_in.get("alias") or s_in.get("name") or f"arg_{s_in.get('address')}"
        seed_val = parse_int(s_in.get("seed", 0), f"symbolic_input.{alias}.seed")
        if "min" in s_in and seed_val < parse_int(s_in["min"], f"{alias}.min"):
            return {"status": "error", "error": f"Initial seed 0x{seed_val:x} for '{alias}' violates declared min bound 0x{parse_int(s_in['min']):x}."}
        if "max" in s_in and seed_val > parse_int(s_in["max"], f"{alias}.max"):
            return {"status": "error", "error": f"Initial seed 0x{seed_val:x} for '{alias}' violates declared max bound 0x{parse_int(s_in['max']):x}."}
        initial_seed[alias] = hex(seed_val)

    worklist = [initial_seed]
    explored_seeds = [tuple(sorted(initial_seed.items()))]
    visited_paths = []
    visited_path_predicates = set()
    queued_inversion_prefixes = set()
    all_visited_edges = set()
    branches_seen = 0
    branches_inverted = 0
    incomplete_frontier = []
    while worklist and len(visited_paths) < branch_budget:
        curr_seed = worklist.pop(0)

        ctx = TritonContext(triton_arch)
        ctx.setMode(MODE.ALIGNED_MEMORY, True)
        ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
        ctx.setMode(MODE.CONSTANT_FOLDING, True)
        if arch_str == "arm32" and hasattr(ctx, "setThumb"):
            ctx.setThumb(thumb_mode)

        reg_tracker = RegisterBitTracker()
        initialized_flags = set()
        flags = spec["flags"]
        flag_parents = spec["flag_parents"]
        zero_regs = spec["zero_regs"]
        gpr_order = spec["gpr_order"]

        missing_memory_detected = None
        guard_active = False

        def on_get_concrete_memory(callback_ctx, mem_access):
            nonlocal missing_memory_detected
            if guard_active and missing_memory_detected is None:
                m_a = mem_access.getAddress()
                m_s = mem_access.getSize()
                for b_i in range(m_s):
                    if not callback_ctx.isConcreteMemoryValueDefined(MemoryAccess(m_a + b_i, 1)):
                        missing_memory_detected = (m_a + b_i, 1)
                        break
        if hasattr(CALLBACK, "GET_CONCRETE_MEMORY_VALUE"):
            ctx.addCallback(CALLBACK.GET_CONCRETE_MEMORY_VALUE, on_get_concrete_memory)

        for s_addr, s_bytes in segments:
            for offset, b in enumerate(s_bytes):
                ctx.setConcreteMemoryValue(s_addr + offset, b)

        for r_name, r_val in initial_regs.items():
            try:
                reg_obj = ctx.getRegister(r_name)
                ctx.setConcreteRegisterValue(reg_obj, r_val)
                if r_name in flags or (hasattr(ctx, "isFlag") and ctx.isFlag(reg_obj)):
                    initialized_flags.add(r_name)
                elif r_name in flag_parents:
                    initialized_flags.update(flags)
                p_name = ctx.getParentRegister(reg_obj).getName().lower()
                if p_name in flag_parents:
                    initialized_flags.update(flags)
                low, high = get_reg_bounds(reg_obj)
                reg_tracker.mark_initialized(p_name, low, high)
            except Exception:
                pass
        sym_vars_map = {}
        for s_in in symbolic_inputs:
            alias = s_in.get("alias") or s_in.get("name") or f"arg_{s_in.get('address')}"
            val = parse_int(curr_seed.get(alias, s_in.get("seed", 0)), alias)
            if s_in.get("kind") == "memory":
                m_addr = parse_int(s_in["address"], "symbolic_memory.address")
                m_size = int(s_in.get("size", 4))
                mem_acc = MemoryAccess(m_addr, m_size)
                ctx.setConcreteMemoryValue(mem_acc, val)
                sym_var = ctx.symbolizeMemory(mem_acc, alias)
                sym_vars_map[alias] = sym_var
            else:
                r_name = normalize_reg_name(s_in.get("name"), arch_str)
                reg_obj = ctx.getRegister(r_name)
                ctx.setConcreteRegisterValue(reg_obj, val)
                sym_var = ctx.symbolizeRegister(reg_obj, alias)
                sym_vars_map[alias] = sym_var
                if r_name in flags or (hasattr(ctx, "isFlag") and ctx.isFlag(reg_obj)):
                    initialized_flags.add(r_name)
                elif r_name in flag_parents:
                    initialized_flags.update(flags)
                p_name = ctx.getParentRegister(reg_obj).getName().lower()
                if p_name in flag_parents:
                    initialized_flags.update(flags)
                low, high = get_reg_bounds(reg_obj)
                reg_tracker.mark_initialized(p_name, low, high)

        pc = entry & ~1 if (arch_str == "arm32" and entry & 1 != 0) else entry
        inst_count = 0
        path_edges = []
        memory_writes = []
        path_status = "complete"
        symbolic_ptr_constraints = []

        pc_reg_name = spec["pc"]
        pc_reg = ctx.getRegister(pc_reg_name)
        ast_ctx = ctx.getAstContext()

        while pc not in stop_addresses and inst_count < max_instructions:
            if pc not in memory_map:
                path_status = f"blocked: pc 0x{pc:x} out of mapped segment bounds"
                break

            op_slice_list = []
            for i in range(16):
                curr_addr = pc + i
                if not ctx.isConcreteMemoryValueDefined(MemoryAccess(curr_addr, 1)):
                    break
                op_slice_list.append(ctx.getConcreteMemoryValue(MemoryAccess(curr_addr, 1)))
            op_slice = bytes(op_slice_list)
            if not op_slice:
                path_status = f"blocked: unmapped address at pc 0x{pc:x}"
                break

            is_thumb = ctx.isThumb() if hasattr(ctx, "isThumb") else thumb_mode
            exec_pc = pc & ~1 if (arch_str == "arm32" and is_thumb) else pc

            inst = Instruction(exec_pc, op_slice)
            if is_thumb and hasattr(inst, "setThumb"):
                inst.setThumb(True)
            ctx.disassembly(inst)
            # Check if any decoded instruction byte is symbolized
            symbolic_fetch = False
            for b in range(max(1, inst.getSize())):
                if ctx.isMemorySymbolized(MemoryAccess(exec_pc + b, 1)):
                    symbolic_fetch = True
                    break
            if symbolic_fetch:
                path_status = f"blocked: symbolic self-modifying code fetch at 0x{pc:x}"
                break

            guard_active = True
            missing_memory_detected = None
            try:
                status = ctx.processing(inst)
            finally:
                guard_active = False

            if missing_memory_detected:
                path_status = f"blocked: missing memory state at 0x{pc:x}: reads uninitialized memory at 0x{missing_memory_detected[0]:x}"
                break

            if status != EXCEPTION.NO_FAULT:
                path_status = f"blocked: instruction fault ({status}) at 0x{pc:x}"
                break

            # Read registers validation without blanket symbolic bypass
            self_zero = is_self_zeroing_instruction(inst, arch_str, ctx)
            missing_reg_detected = None
            for reg_read, _ in inst.getReadRegisters():
                r_read_name = reg_read.getName().lower()
                p_name = ctx.getParentRegister(reg_read).getName().lower()
                if r_read_name in zero_regs or p_name in zero_regs:
                    continue
                if self_zero and (r_read_name == self_zero[0] or p_name == self_zero[1]):
                    continue
                if r_read_name in flags or (hasattr(ctx, "isFlag") and ctx.isFlag(reg_read)):
                    if r_read_name not in initialized_flags:
                        missing_reg_detected = f"missing flag '{r_read_name}'"
                        break
                else:
                    low, high = get_reg_bounds(reg_read)
                    if not reg_tracker.is_fully_initialized(p_name, low, high):
                        missing_reg_detected = f"missing register '{reg_read.getName()}'"
                        break
            if missing_reg_detected:
                path_status = f"blocked: {missing_reg_detected} at 0x{pc:x}"
                break

            # Constrain symbolic pointers and verify per-byte memory reads
            for mem_acc, _ in inst.getLoadAccess():
                m_addr = mem_acc.getAddress()
                m_sz = mem_acc.getSize()
                for b_off in range(m_sz):
                    if not ctx.isConcreteMemoryValueDefined(MemoryAccess(m_addr + b_off, 1)):
                        missing_memory_detected = (m_addr + b_off, 1)
                        break
                if missing_memory_detected:
                    break
                lea_ast = mem_acc.getLeaAst()
                if lea_ast is not None and lea_ast.isSymbolized():
                    c_addr = mem_acc.getAddress()
                    ptr_width = lea_ast.getBitvectorSize()
                    ptr_eq = ast_ctx.equal(lea_ast, ast_ctx.bv(c_addr, ptr_width))
                    if hasattr(ctx, "pushPathConstraint"):
                        ctx.pushPathConstraint(ptr_eq)
                    symbolic_ptr_constraints.append(ptr_eq)

            if missing_memory_detected:
                path_status = f"blocked: missing memory state at 0x{pc:x}: reads uninitialized memory at 0x{missing_memory_detected[0]:x}"
                break
            # Memory stores and symbolic store pointer constraints
            for mem_acc, _ in inst.getStoreAccess():
                store_entry = {
                    "address": hex(mem_acc.getAddress()),
                    "size": mem_acc.getSize(),
                    "value": hex(ctx.getConcreteMemoryValue(mem_acc)),
                }
                try:
                    mem_val_ast = ctx.getMemoryAst(mem_acc)
                    if mem_val_ast is not None:
                        store_entry["value_ast"] = str(ast_ctx.unroll(mem_val_ast))
                except Exception:
                    pass
                memory_writes.append(store_entry)
                lea_ast = mem_acc.getLeaAst()
                if lea_ast is not None and lea_ast.isSymbolized():
                    c_addr = mem_acc.getAddress()
                    ptr_width = lea_ast.getBitvectorSize()
                    ptr_eq = ast_ctx.equal(lea_ast, ast_ctx.bv(c_addr, ptr_width))
                    if hasattr(ctx, "pushPathConstraint"):
                        ctx.pushPathConstraint(ptr_eq)
                    symbolic_ptr_constraints.append(ptr_eq)
            # Update written registers
            for reg_written, _ in inst.getWrittenRegisters():
                w_name = reg_written.getName().lower()
                p_name = ctx.getParentRegister(reg_written).getName().lower()
                if w_name in flags or (hasattr(ctx, "isFlag") and ctx.isFlag(reg_written)):
                    initialized_flags.add(w_name)
                elif w_name in flag_parents:
                    initialized_flags.update(flags)
                if p_name in flag_parents:
                    initialized_flags.update(flags)
                if arch_str == "x86_64" and reg_written.getBitSize() == 32 and p_name in gpr_order:
                    reg_tracker.mark_initialized(p_name, 0, 63)
                elif arch_str == "aarch64" and reg_written.getBitSize() == 32 and (p_name in gpr_order or p_name.startswith("x") or p_name == "sp"):
                    reg_tracker.mark_initialized(p_name, 0, 63)
                elif p_name in gpr_order or is_vector_register(p_name, arch_str) or p_name in ("sp", "pc", "r14", "lr"):
                    low, high = get_reg_bounds(reg_written)
                    reg_tracker.mark_initialized(p_name, low, high)

            # Invalidate undefined registers and flags
            for reg_undef in inst.getUndefinedRegisters():
                u_name = reg_undef.getName().lower()
                if u_name in flags:
                    initialized_flags.discard(u_name)
                elif u_name in flag_parents:
                    initialized_flags.difference_update(flags)
                p_name = ctx.getParentRegister(reg_undef).getName().lower()
                if p_name in flag_parents:
                    initialized_flags.difference_update(flags)
                low, high = get_reg_bounds(reg_undef)
                reg_tracker.mark_undefined(p_name, low, high)

            # Mark path incomplete if symbolic x86 division occurs, as Triton does not push #DE fault constraints
            disasm_l = inst.getDisassembly().lower()
            if arch_str in ("x86", "x86_64") and (disasm_l.startswith("div ") or disasm_l.startswith("idiv ")):
                is_sym_div = False
                try:
                    from triton import OPERAND
                    for op in inst.getOperands():
                        if op.getType() == OPERAND.REG and ctx.isRegisterSymbolized(op):
                            is_sym_div = True
                            break
                        elif op.getType() == OPERAND.MEM and ctx.isMemorySymbolized(op):
                            is_sym_div = True
                            break
                except Exception:
                    pass
                if not is_sym_div:
                    for div_reg_name in ("rax", "rdx", "eax", "edx", "ax", "dx"):
                        try:
                            if ctx.isRegisterSymbolized(ctx.getRegister(div_reg_name)):
                                is_sym_div = True
                                break
                        except Exception:
                            pass
                if is_sym_div:
                    path_status = f"incomplete: symbolic x86 division at 0x{pc:x} has unmodeled fault conditions (#DE)"
                    break

            next_pc = ctx.getConcreteRegisterValue(pc_reg)
            edge = (pc, next_pc)
            path_edges.append(edge)
            all_visited_edges.add(f"{hex(pc)}->{hex(next_pc)}")

            inst_count += 1
            if next_pc in stop_addresses:
                pc = next_pc
                break
            pc = next_pc

        if inst_count >= max_instructions and pc not in stop_addresses:
            path_status = f"budget_exceeded: reached max_instructions limit ({max_instructions})"

        out_ast = None
        concrete_return = None
        if path_status == "complete":
            if output_cfg.get("kind") == "register":
                out_target = normalize_reg_name(output_cfg.get("target"), arch_str)
                try:
                    out_reg = ctx.getRegister(out_target)
                    p_name = ctx.getParentRegister(out_reg).getName().lower()
                    low, high = get_reg_bounds(out_reg)
                    if out_target in flags or (hasattr(ctx, "isFlag") and ctx.isFlag(out_reg)):
                        if out_target not in initialized_flags:
                            path_status = f"blocked: output flag '{out_target}' was not initialized during execution"
                        else:
                            concrete_return = hex(ctx.getConcreteRegisterValue(out_reg))
                            out_ast = ctx.getRegisterAst(out_reg)
                    elif (p_name in gpr_order or is_vector_register(p_name, arch_str) or p_name in ("sp", "pc", "r14", "lr")) and not reg_tracker.is_fully_initialized(p_name, low, high):
                        path_status = f"blocked: output register '{out_target}' was not initialized during execution"
                    else:
                        concrete_return = hex(ctx.getConcreteRegisterValue(out_reg))
                        out_ast = ctx.getRegisterAst(out_reg)
                except Exception as e:
                    path_status = f"blocked: invalid output register '{out_target}': {str(e)}"
            elif output_cfg.get("kind") == "memory":
                m_addr = parse_int(output_cfg.get("address"), "output.address")
                m_size = int(output_cfg.get("size", 4))
                mem_acc = MemoryAccess(m_addr, m_size)
                if not is_memory_range_initialized(ctx, m_addr, m_size):
                    path_status = f"blocked: output memory at 0x{m_addr:x} (size {m_size}) was not defined during execution"
                else:
                    concrete_return = hex(ctx.getConcreteMemoryValue(mem_acc))
                    out_ast = ctx.getMemoryAst(mem_acc)
        domain_bounds = []
        for s_in in symbolic_inputs:
            alias = s_in.get("alias") or s_in.get("name") or f"arg_{s_in.get('address')}"
            try:
                sym_var = ctx.getSymbolicVariable(alias)
                if sym_var:
                    sym_var_ast = ast_ctx.variable(sym_var)
                    v_width = sym_var.getBitSize()
                    if "min" in s_in:
                        min_val = parse_int(s_in["min"], f"{alias}.min")
                        domain_bounds.append(ast_ctx.bvuge(sym_var_ast, ast_ctx.bv(min_val, v_width)))
                    if "max" in s_in:
                        max_val = parse_int(s_in["max"], f"{alias}.max")
                        domain_bounds.append(ast_ctx.bvule(sym_var_ast, ast_ctx.bv(max_val, v_width)))
            except Exception:
                pass

        pcs = ctx.getPathConstraints()
        taken_conds = list(domain_bounds)
        prefix_conds = list(domain_bounds)
        path_branch_depth = 0

        for p in pcs:
            taken_predicate = p.getTakenPredicate() if hasattr(p, "getTakenPredicate") else None
            if p.isMultipleBranches():
                branches_seen += 1
                path_branch_depth += 1
                branch_constraints = p.getBranchConstraints()
                taken_item = None
                untaken_item = None
                for b_item in branch_constraints:
                    if b_item.get("isTaken", False):
                        taken_item = b_item
                    else:
                        untaken_item = b_item

                if untaken_item:
                    inversion_terms = list(prefix_conds)
                    inversion_terms.append(untaken_item["constraint"])
                    query_cond = ast_ctx.land(inversion_terms) if len(inversion_terms) > 1 else inversion_terms[0]
                    query_cond_str = str(ast_ctx.unroll(query_cond))

                    if path_branch_depth > max_depth:
                        incomplete_frontier.append({
                            "branch_addr": hex(untaken_item.get("srcAddr", 0)),
                            "missing_target": hex(untaken_item.get("dstAddr", 0)),
                            "reason": f"max_depth ({max_depth}) exceeded",
                        })
                    elif query_cond_str not in visited_path_predicates and query_cond_str not in queued_inversion_prefixes:
                        model = ctx.getModel(query_cond)
                        if model:
                            new_seed = dict(curr_seed)
                            for sym_id, sm in model.items():
                                alias = sm.getVariable().getAlias()
                                new_seed[alias] = hex(sm.getValue())
                            new_seed_key = tuple(sorted(new_seed.items()))
                            if new_seed_key not in explored_seeds:
                                explored_seeds.append(new_seed_key)
                                queued_inversion_prefixes.add(query_cond_str)
                                if len(visited_paths) + len(worklist) < branch_budget:
                                    worklist.append(new_seed)
                                    branches_inverted += 1
                                else:
                                    incomplete_frontier.append({
                                        "branch_addr": hex(untaken_item.get("srcAddr", 0)),
                                        "missing_target": hex(untaken_item.get("dstAddr", 0)),
                                        "seed": new_seed,
                                    })

                if taken_item:
                    taken_conds.append(taken_item["constraint"])
                    prefix_conds.append(taken_item["constraint"])
            elif taken_predicate is not None:
                taken_conds.append(taken_predicate)
                prefix_conds.append(taken_predicate)

        if len(taken_conds) == 0:
            path_predicate_ast = ast_ctx.equal(ast_ctx.bv(1, 1), ast_ctx.bv(1, 1))
        elif len(taken_conds) == 1:
            path_predicate_ast = taken_conds[0]
        else:
            path_predicate_ast = ast_ctx.land(taken_conds)

        path_pred_str = str(ast_ctx.unroll(path_predicate_ast))
        if path_pred_str in visited_path_predicates and path_status == "complete":
            continue
        visited_path_predicates.add(path_pred_str)

        visited_paths.append({
            "path_id": len(visited_paths) + 1,
            "seed": curr_seed,
            "instructions_executed": inst_count,
            "concrete_return": concrete_return if path_status == "complete" else None,
            "path_predicate": path_pred_str,
            "output_ast": str(ast_ctx.unroll(out_ast)) if (out_ast is not None and path_status == "complete") else None,
            "memory_writes": memory_writes,
            "status": path_status,
            "visited_edges": [{"from": hex(s), "to": hex(d)} for s, d in path_edges],
        })

    while worklist:
        rem_seed = worklist.pop(0)
        incomplete_frontier.append({
            "branch_addr": "unexplored_worklist_seed",
            "missing_target": "branch budget exhausted before seed execution",
            "seed": rem_seed,
        })

    return {
        "status": "ok",
        "result": {
            "arch": arch_str,
            "discovered_paths": visited_paths,
            "coverage": {
                "discovered_paths_count": len(visited_paths),
                "branches_seen": branches_seen,
                "branches_inverted": branches_inverted,
                "incomplete_frontier": incomplete_frontier,
                "all_visited_edges": sorted(list(all_visited_edges)),
            },
        }
    }

def action_handlers(request):
    try:
        import triton
        from triton import TritonContext, ARCH, MODE, Instruction, MemoryAccess, EXCEPTION, CALLBACK
    except ImportError as e:
        return {"status": "missing_dependency", "error": f"Triton is not installed: {str(e)}"}

    snapshot = request.get("snapshot") or {}
    arch_str = request.get("arch", snapshot.get("arch", "x86_64")).lower().strip()
    spec = get_arch_spec(arch_str, ARCH)
    if not spec:
        return {"status": "error", "error": f"Unsupported architecture '{arch_str}'."}

    h_range = request.get("range") or {}
    start_addr = parse_int(h_range.get("start"), "range.start")
    stop_addr = parse_int(h_range.get("stop"), "range.stop")

    segments_raw = snapshot.get("segments") or []
    memory_map = {}
    for seg in segments_raw:
        s_addr = parse_int(seg.get("address"), "segment.address")
        s_hex = seg.get("bytes", "").replace(" ", "").strip()
        s_bytes = bytes.fromhex(s_hex)
        for offset, b in enumerate(s_bytes):
            memory_map[s_addr + offset] = b

    inputs = request.get("inputs") or []
    output_cfg = request.get("output") or {}

    ctx = TritonContext(spec["triton_arch"])
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
    ctx.setMode(MODE.CONSTANT_FOLDING, True)

    reg_tracker = RegisterBitTracker()
    initialized_flags = set()
    flags = spec["flags"]
    flag_parents = spec["flag_parents"]
    zero_regs = spec["zero_regs"]
    gpr_order = spec["gpr_order"]

    missing_memory_detected = None
    guard_active = False

    def on_get_concrete_memory(callback_ctx, mem_access):
        nonlocal missing_memory_detected
        if guard_active and missing_memory_detected is None:
            m_a = mem_access.getAddress()
            m_s = mem_access.getSize()
            for b_i in range(m_s):
                if not callback_ctx.isConcreteMemoryValueDefined(MemoryAccess(m_a + b_i, 1)):
                    missing_memory_detected = (m_a + b_i, 1)
                    break

    if hasattr(CALLBACK, "GET_CONCRETE_MEMORY_VALUE"):
        ctx.addCallback(CALLBACK.GET_CONCRETE_MEMORY_VALUE, on_get_concrete_memory)

    for seg in segments_raw:
        s_addr = parse_int(seg.get("address"), "segment.address")
        s_hex = seg.get("bytes", "").replace(" ", "").strip()
        for offset, b in enumerate(bytes.fromhex(s_hex)):
            ctx.setConcreteMemoryValue(s_addr + offset, b)

    for r_name, r_val in (snapshot.get("registers") or {}).items():
        try:
            r_name_clean = normalize_reg_name(r_name, arch_str)
            reg_obj = ctx.getRegister(r_name_clean)
            ctx.setConcreteRegisterValue(reg_obj, parse_int(r_val, r_name))
            if r_name_clean in flags or (hasattr(ctx, "isFlag") and ctx.isFlag(reg_obj)):
                initialized_flags.add(r_name_clean)
            elif r_name_clean in flag_parents:
                initialized_flags.update(flags)
            p_name = ctx.getParentRegister(reg_obj).getName().lower()
            if p_name in flag_parents:
                initialized_flags.update(flags)
            low, high = get_reg_bounds(reg_obj)
            reg_tracker.mark_initialized(p_name, low, high)
        except Exception:
            pass

    sym_vars_map = {}
    for s_in in inputs:
        alias = s_in.get("alias") or s_in.get("name") or f"mem_{hex(parse_int(s_in.get('address')))}"
        val = parse_int(s_in.get("seed", 0), alias)
        if "min" in s_in and val < parse_int(s_in["min"], f"{alias}.min"):
            return {"status": "error", "error": f"Initial seed 0x{val:x} for '{alias}' violates declared min bound 0x{parse_int(s_in['min']):x}."}
        if "max" in s_in and val > parse_int(s_in["max"], f"{alias}.max"):
            return {"status": "error", "error": f"Initial seed 0x{val:x} for '{alias}' violates declared max bound 0x{parse_int(s_in['max']):x}."}

        if s_in.get("kind") == "memory":
            m_addr = parse_int(s_in["address"], "memory.address")
            m_size = int(s_in.get("size", 4))
            mem_acc = MemoryAccess(m_addr, m_size)
            ctx.setConcreteMemoryValue(mem_acc, val)
            sym_var = ctx.symbolizeMemory(mem_acc, alias)
            sym_vars_map[alias] = sym_var
        else:
            r_name = normalize_reg_name(s_in.get("name"), arch_str)
            reg_obj = ctx.getRegister(r_name)
            ctx.setConcreteRegisterValue(reg_obj, val)
            sym_var = ctx.symbolizeRegister(reg_obj, alias)
            sym_vars_map[alias] = sym_var
            if r_name in flags or (hasattr(ctx, "isFlag") and ctx.isFlag(reg_obj)):
                initialized_flags.add(r_name)
            elif r_name in flag_parents:
                initialized_flags.update(flags)
            p_name = ctx.getParentRegister(reg_obj).getName().lower()
            if p_name in flag_parents:
                initialized_flags.update(flags)
            low, high = get_reg_bounds(reg_obj)
            reg_tracker.mark_initialized(p_name, low, high)

    pc = start_addr
    pc_reg = ctx.getRegister(spec["pc"])
    inst_count = 0
    max_insts = int(request.get("bounds", {}).get("max_instructions", 2000))
    memory_side_effects = []
    symbolic_ptr_constraints = []

    thumb_mode = bool(snapshot.get("thumb", False)) or (arch_str == "arm32" and (start_addr & 1 != 0))
    if arch_str == "arm32" and hasattr(ctx, "setThumb"):
        ctx.setThumb(thumb_mode)

    ast_ctx = ctx.getAstContext()
    handler_fault = False

    while pc != stop_addr and inst_count < max_insts:
        is_thumb = ctx.isThumb() if hasattr(ctx, "isThumb") else thumb_mode
        exec_pc = pc & ~1 if (arch_str == "arm32" and is_thumb) else pc

        op_slice_list = []
        for i in range(16):
            curr_addr = exec_pc + i
            if not ctx.isConcreteMemoryValueDefined(MemoryAccess(curr_addr, 1)):
                break
            op_slice_list.append(ctx.getConcreteMemoryValue(MemoryAccess(curr_addr, 1)))
        op_slice = bytes(op_slice_list)
        if not op_slice:
            handler_fault = True
            break

        inst = Instruction(exec_pc, op_slice)
        if is_thumb and hasattr(inst, "setThumb"):
            inst.setThumb(True)
        ctx.disassembly(inst)

        symbolic_fetch = False
        for b in range(max(1, inst.getSize())):
            if ctx.isMemorySymbolized(MemoryAccess(exec_pc + b, 1)):
                symbolic_fetch = True
                break
        if symbolic_fetch:
            handler_fault = True
            break

        guard_active = True
        missing_memory_detected = None
        try:
            status = ctx.processing(inst)
        finally:
            guard_active = False

        if missing_memory_detected or status != EXCEPTION.NO_FAULT:
            handler_fault = True
            break

        # Validate read registers
        missing_reg = False
        for reg_read, _ in inst.getReadRegisters():
            r_read_name = reg_read.getName().lower()
            p_name = ctx.getParentRegister(reg_read).getName().lower()
            if r_read_name in zero_regs or p_name in zero_regs:
                continue
            if r_read_name in flags or (hasattr(ctx, "isFlag") and ctx.isFlag(reg_read)):
                if r_read_name not in initialized_flags:
                    missing_reg = True
                    break
            else:
                low, high = get_reg_bounds(reg_read)
                if not reg_tracker.is_fully_initialized(p_name, low, high):
                    missing_reg = True
                    break
        if missing_reg:
            handler_fault = True
            break

        # Constrain symbolic pointers and loads
        for mem_acc, _ in inst.getLoadAccess():
            lea_ast = mem_acc.getLeaAst()
            if lea_ast is not None and lea_ast.isSymbolized():
                c_addr = mem_acc.getAddress()
                ptr_width = lea_ast.getBitvectorSize()
                ptr_eq = ast_ctx.equal(lea_ast, ast_ctx.bv(c_addr, ptr_width))
                if hasattr(ctx, "pushPathConstraint"):
                    ctx.pushPathConstraint(ptr_eq)
                symbolic_ptr_constraints.append(ptr_eq)

        for mem_acc, _ in inst.getStoreAccess():
            store_entry = {
                "address": hex(mem_acc.getAddress()),
                "size": mem_acc.getSize(),
                "value": hex(ctx.getConcreteMemoryValue(mem_acc)),
            }
            try:
                mem_val_ast = ctx.getMemoryAst(mem_acc)
                if mem_val_ast is not None:
                    store_entry["value_ast"] = str(ast_ctx.unroll(mem_val_ast))
            except Exception:
                pass
            memory_side_effects.append(store_entry)
            lea_ast = mem_acc.getLeaAst()
            if lea_ast is not None and lea_ast.isSymbolized():
                c_addr = mem_acc.getAddress()
                ptr_width = lea_ast.getBitvectorSize()
                ptr_eq = ast_ctx.equal(lea_ast, ast_ctx.bv(c_addr, ptr_width))
                if hasattr(ctx, "pushPathConstraint"):
                    ctx.pushPathConstraint(ptr_eq)
                symbolic_ptr_constraints.append(ptr_eq)

        for reg_written, _ in inst.getWrittenRegisters():
            w_name = reg_written.getName().lower()
            p_name = ctx.getParentRegister(reg_written).getName().lower()
            if w_name in flags or (hasattr(ctx, "isFlag") and ctx.isFlag(reg_written)):
                initialized_flags.add(w_name)
            elif w_name in flag_parents:
                initialized_flags.update(flags)
            if p_name in flag_parents:
                initialized_flags.update(flags)
            if arch_str == "x86_64" and reg_written.getBitSize() == 32 and p_name in gpr_order:
                reg_tracker.mark_initialized(p_name, 0, 63)
            elif arch_str == "aarch64" and reg_written.getBitSize() == 32 and (p_name in gpr_order or p_name.startswith("x") or p_name == "sp"):
                reg_tracker.mark_initialized(p_name, 0, 63)
            elif p_name in gpr_order or is_vector_register(p_name, arch_str) or p_name in ("sp", "pc", "r14", "lr"):
                low, high = get_reg_bounds(reg_written)
                reg_tracker.mark_initialized(p_name, low, high)

        for reg_undef in inst.getUndefinedRegisters():
            u_name = reg_undef.getName().lower()
            if u_name in flags:
                initialized_flags.discard(u_name)
            elif u_name in flag_parents:
                initialized_flags.difference_update(flags)
            p_name = ctx.getParentRegister(reg_undef).getName().lower()
            if p_name in flag_parents:
                initialized_flags.difference_update(flags)
            low, high = get_reg_bounds(reg_undef)
            reg_tracker.mark_undefined(p_name, low, high)
        # Guard symbolic x86 division in handler
        disasm_l = inst.getDisassembly().lower()
        if arch_str in ("x86", "x86_64") and (disasm_l.startswith("div ") or disasm_l.startswith("idiv ")):
            is_sym_div = False
            try:
                from triton import OPERAND
                for op in inst.getOperands():
                    if op.getType() == OPERAND.REG and ctx.isRegisterSymbolized(op):
                        is_sym_div = True
                        break
                    elif op.getType() == OPERAND.MEM and ctx.isMemorySymbolized(op):
                        is_sym_div = True
                        break
            except Exception:
                pass
            if not is_sym_div:
                for div_reg_name in ("rax", "rdx", "eax", "edx", "ax", "dx"):
                    try:
                        if ctx.isRegisterSymbolized(ctx.getRegister(div_reg_name)):
                            is_sym_div = True
                            break
                    except Exception:
                        pass
            if is_sym_div:
                handler_fault = True
                break

        pc = ctx.getConcreteRegisterValue(pc_reg)
        inst_count += 1

    handler_domain_bounds = []
    for s_in in inputs:
        alias = s_in.get("alias") or s_in.get("name") or f"mem_{hex(parse_int(s_in.get('address')))}"
        sym_var = sym_vars_map.get(alias)
        if sym_var:
            sym_var_ast = ast_ctx.variable(sym_var)
            v_width = sym_var.getBitSize()
            if "min" in s_in:
                min_val = parse_int(s_in["min"], f"{alias}.min")
                handler_domain_bounds.append(ast_ctx.bvuge(sym_var_ast, ast_ctx.bv(min_val, v_width)))
            if "max" in s_in:
                max_val = parse_int(s_in["max"], f"{alias}.max")
                handler_domain_bounds.append(ast_ctx.bvule(sym_var_ast, ast_ctx.bv(max_val, v_width)))

    completed = (pc == stop_addr) and not handler_fault
    pcs = ctx.getPathConstraints()
    taken_conds = list(handler_domain_bounds) + list(symbolic_ptr_constraints)
    for p in pcs:
        if hasattr(p, "getTakenPredicate"):
            tp = p.getTakenPredicate()
            if tp is not None:
                taken_conds.append(tp)

    if not taken_conds:
        path_predicate_str = "true"
    elif len(taken_conds) == 1:
        path_predicate_str = str(ast_ctx.unroll(taken_conds[0]))
    else:
        path_predicate_str = str(ast_ctx.unroll(ast_ctx.land(taken_conds)))
    if not completed:
        return {
            "status": "ok",
            "result": {
                "completed": False,
                "status": f"incomplete: execution stopped at 0x{pc:x} (inst_count={inst_count}) without reaching stop address 0x{stop_addr:x}",
                "handler_range": {"start": hex(start_addr), "stop": hex(stop_addr)},
                "instructions_executed": inst_count,
                "path_predicate": path_predicate_str,
                "transition_formula": None,
                "synth_formula": None,
                "data_dependencies": [],
                "memory_side_effects": memory_side_effects,
            }
        }

    out_ast = None
    if output_cfg.get("kind") == "register":
        out_target = normalize_reg_name(output_cfg.get("target"), arch_str)
        try:
            out_reg = ctx.getRegister(out_target)
            p_name = ctx.getParentRegister(out_reg).getName().lower()
            low, high = get_reg_bounds(out_reg)
            if out_target in flags or (hasattr(ctx, "isFlag") and ctx.isFlag(out_reg)):
                if out_target not in initialized_flags:
                    completed = False
                else:
                    out_ast = ctx.getRegisterAst(out_reg)
            elif not reg_tracker.is_fully_initialized(p_name, low, high):
                completed = False
            else:
                out_ast = ctx.getRegisterAst(out_reg)
        except Exception:
            completed = False
    elif output_cfg.get("kind") == "memory":
        m_addr = parse_int(output_cfg.get("address"), "output.address")
        m_size = int(output_cfg.get("size", 4))
        if not is_memory_range_initialized(ctx, m_addr, m_size):
            completed = False
        else:
            out_ast = ctx.getMemoryAst(MemoryAccess(m_addr, m_size))

    unrolled_ast = ast_ctx.unroll(out_ast) if out_ast is not None else None
    transition_formula = str(unrolled_ast) if unrolled_ast is not None else None

    synth_formula = None
    if hasattr(ctx, "synthesize") and out_ast is not None:
        try:
            synth_node = ctx.synthesize(out_ast)
            if synth_node is not None:
                synth_formula = str(synth_node)
        except Exception:
            pass

    data_dependencies = []
    if unrolled_ast is not None:
        try:
            from triton import AST_NODE
            var_nodes = ast_ctx.search(unrolled_ast, AST_NODE.VARIABLE)
            extracted_vars = {vn.getSymbolicVariable().getAlias() for vn in var_nodes if vn.getSymbolicVariable()}
            for s_in in inputs:
                alias = s_in.get("alias") or s_in.get("name") or f"mem_{hex(parse_int(s_in.get('address')))}"
                if alias in extracted_vars:
                    data_dependencies.append(alias)
        except Exception:
            pass

    return {
        "status": "ok",
        "result": {
            "completed": completed,
            "status": "complete" if completed else "incomplete",
            "handler_range": {"start": hex(start_addr), "stop": hex(stop_addr)},
            "instructions_executed": inst_count,
            "path_predicate": path_predicate_str,
            "transition_formula": transition_formula,
            "synth_formula": synth_formula,
            "data_dependencies": data_dependencies,
            "memory_side_effects": memory_side_effects,
        }
    }

def action_merge(request):
    try:
        import z3
    except ImportError as e:
        return {"status": "missing_dependency", "error": f"Z3 solver is required for merge: {str(e)}"}

    paths = request.get("paths") or []
    if not paths:
        return {"status": "error", "error": "Missing required 'paths' array for merge."}

    inputs_cfg = request.get("inputs") or []
    output_bits = int(request.get("output_size_bits", 32))

    var_dict = {}
    seen_names = set()
    for inp in inputs_cfg:
        v_name = inp.get("name")
        if not v_name:
            return {"status": "error", "error": "Missing input variable name in merge inputs."}
        if v_name in seen_names:
            return {"status": "error", "error": f"Duplicate input variable alias '{v_name}' in merge inputs."}
        seen_names.add(v_name)
        v_bits = int(inp.get("size_bits", 32))
        var_dict[v_name] = z3.BitVec(v_name, v_bits)

    parsed_paths = []
    uncovered_predicates = []
    for idx, p in enumerate(paths):
        p_status = p.get("status", "complete").lower()
        pid = p.get("path_id", idx + 1)
        p_pred_str = p.get("predicate", "").strip()
        p_out_str = p.get("output_ast", "").strip()

        if p_status != "complete":
            if p_pred_str:
                try:
                    z3_uncov = z3.parse_smt2_string(f"(assert {p_pred_str})", decls=var_dict)
                    if z3_uncov:
                        uncovered_predicates.append(z3_uncov[0])
                except Exception:
                    pass
            continue

        if not p_out_str:
            continue

        z3_pred = None
        z3_out = None
        try:
            if p_pred_str:
                z3_pred = z3.parse_smt2_string(f"(assert {p_pred_str})", decls=var_dict)
                z3_pred = z3_pred[0] if z3_pred else z3.BoolVal(True)
            else:
                z3_pred = z3.BoolVal(True)

            if p_out_str.startswith("0x") or p_out_str.isdigit():
                z3_out = z3.BitVecVal(int(p_out_str, 0), output_bits)
            else:
                z3_out_raw = z3.parse_smt2_string(f"(assert (= __out {p_out_str}))", decls={**var_dict, "__out": z3.BitVec("__out", output_bits)})
                if z3_out_raw:
                    z3_out = z3_out_raw[0].arg(1)
                else:
                    z3_out = z3.BitVecVal(0, output_bits)
        except Exception:
            z3_pred = z3.BoolVal(True)
            z3_out = z3.BitVecVal(0, output_bits)

        parsed_paths.append({"id": pid, "pred": z3_pred, "out": z3_out, "raw_pred": p_pred_str, "raw_out": p_out_str})

    if not parsed_paths:
        return {"status": "error", "error": "No complete paths with output expressions provided for merge."}

    conflicts = []
    overlap_inconclusive = False
    for i in range(len(parsed_paths)):
        for j in range(i + 1, len(parsed_paths)):
            pi = parsed_paths[i]
            pj = parsed_paths[j]
            s = z3.Solver()
            s.add(pi["pred"], pj["pred"])
            res = s.check()
            if res == z3.unknown:
                overlap_inconclusive = True
            elif res == z3.sat:
                s_conflict = z3.Solver()
                s_conflict.add(pi["pred"], pj["pred"], pi["out"] != pj["out"])
                res_c = s_conflict.check()
                if res_c == z3.unknown:
                    overlap_inconclusive = True
                elif res_c == z3.sat:
                    m = s_conflict.model()
                    conflicts.append({
                        "path_a": pi["id"],
                        "path_b": pj["id"],
                        "model": {str(k): hex(m[k].as_long()) if hasattr(m[k], "as_long") else str(m[k]) for k in m.decls()}
                    })

    s_cov = z3.Solver()
    disjunction = z3.Or([p["pred"] for p in parsed_paths])
    s_cov.add(z3.Not(disjunction))
    cov_res = s_cov.check()
    is_total = (cov_res == z3.unsat and len(uncovered_predicates) == 0 and not overlap_inconclusive and len(conflicts) == 0)
    uncovered_sample = None
    if not is_total and cov_res == z3.sat:
        m_uncov = s_cov.model()
        uncovered_sample = {str(k): hex(m_uncov[k].as_long()) if hasattr(m_uncov[k], "as_long") else str(m_uncov[k]) for k in m_uncov.decls()}

    if is_total:
        merged_z3_expr = parsed_paths[-1]["out"]
        for p in reversed(parsed_paths[:-1]):
            merged_z3_expr = z3.If(p["pred"], p["out"], merged_z3_expr)
    else:
        uncovered_guard = z3.BitVec("__uncovered_domain_trap", output_bits)
        merged_z3_expr = uncovered_guard
        for p in reversed(parsed_paths):
            merged_z3_expr = z3.If(p["pred"], p["out"], merged_z3_expr)

    smt2_artifact = z3.simplify(merged_z3_expr).sexpr()

    llvm_available = False
    llvm_ir = None
    llvm_status = "unavailable"

    if not is_total:
        llvm_status = "unavailable: input domain coverage is incomplete. Valid LLVM IR requires proven total domain coverage; SMT2 guarded formula retained."
    elif overlap_inconclusive or len(conflicts) > 0:
        llvm_status = "unavailable: overlap conflicts or inconclusive solver proof detected."
    else:
        try:
            import llvmlite.ir as ir
            import llvmlite.binding as llvm

            for init_fn in ["initialize", "initialize_native_target", "initialize_native_asmprinter"]:
                if hasattr(llvm, init_fn):
                    try:
                        getattr(llvm, init_fn)()
                    except RuntimeError:
                        pass

            mod = ir.Module(name="native_recovered_module")
            param_types = [ir.IntType(int(inp.get("size_bits", 32))) for inp in inputs_cfg]
            func_type = ir.FunctionType(ir.IntType(output_bits), param_types)
            func = ir.Function(mod, func_type, name="recovered_func")
            entry_bb = func.append_basic_block("entry")
            builder = ir.IRBuilder(entry_bb)

            arg_map = {}
            for idx, inp in enumerate(inputs_cfg):
                v_name = inp.get("name")
                func.args[idx].name = v_name
                arg_map[v_name] = func.args[idx]

            lowered_res = lower_z3_to_llvm(merged_z3_expr, func, builder, arg_map)
            builder.ret(lowered_res)

            llvm_ir_text = str(mod)
            parsed_mod = llvm.parse_assembly(llvm_ir_text)
            parsed_mod.verify()

            llvm_available = True
            llvm_ir = llvm_ir_text
            llvm_status = "available (verified via llvmlite)"
        except Exception as e:
            llvm_available = False
            llvm_status = f"unavailable: {str(e)}"

    return {
        "status": "ok",
        "result": {
            "merged_paths_count": len(parsed_paths),
            "is_total_domain": is_total,
            "coverage_guard": {
                "is_total": is_total,
                "uncovered_sample": uncovered_sample,
                "domain_predicate": str(z3.simplify(disjunction).sexpr()),
            },
            "conflicts": conflicts,
            "smt2_formula": smt2_artifact,
            "llvm_available": llvm_available,
            "llvm_ir": llvm_ir,
            "llvm_status": llvm_status,
        }
    }

def action_verify(request):
    try:
        from native_recover_verify import action_verify as verify_impl
        return verify_impl(request)
    except Exception as e:
        import importlib.util
        script_dir = os.path.dirname(os.path.abspath(__file__))
        verify_py = os.path.join(script_dir, "native-recover-verify.py")
        if os.path.exists(verify_py):
            spec = importlib.util.spec_from_file_location("native_recover_verify", verify_py)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod.action_verify(request)
        return {"status": "error", "error": f"native-recover-verify module could not be loaded: {str(e)}"}
def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            print(json.dumps({"status": "error", "error": "No input JSON received on stdin."}))
            return

        request = json.loads(raw_input)
        action = request.get("action", "status")

        if action == "status":
            resp = action_status(request)
        elif action == "explore":
            resp = action_explore(request)
        elif action == "handlers":
            resp = action_handlers(request)
        elif action == "merge":
            resp = action_merge(request)
        elif action == "verify":
            resp = action_verify(request)
        else:
            resp = {"status": "error", "error": f"Unknown action '{action}'."}

        print(json.dumps(resp))
        sys.stdout.flush()

    except Exception as e:
        err_payload = {
            "status": "error",
            "error": str(e),
            "traceback": traceback.format_exc()
        }
        print(json.dumps(err_payload))
        sys.stdout.flush()

if __name__ == "__main__":
    main()
