#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Triton 离线符号执行与跟踪回放执行器。

核心约束：
1. 严禁硬编码 Linux SysV 寄存器（如 RDI/RSI/EAX），符号变量与目标输出必须显式声明。
2. 缺失状态校验：通用寄存器位、标志位或内存读取未初始化时，严禁使用 0 隐式填补，必须报错。
3. 符号状态保真：跟踪快照对比现有状态，仅在不一致时同步；若符号寄存器发生不一致则报错，严禁覆盖丢失符号表达式。
4. 符号种子必须真实有效：符号输入必须声明具体种子数值（seed 或 initial_registers/memory），严禁假定为 0。
5. 离线仿真与路径覆盖：目标代码仅在 Triton 引擎内模拟执行；回放结果仅代表录制路径，不宣称覆盖完整函数。
"""

import json
import os
import sys
import traceback

FLAGS = {"cf", "zf", "sf", "of", "af", "pf", "df"}

def parse_int(val, field_name="value"):
    if isinstance(val, int):
        return val
    if val is None or (isinstance(val, str) and not val.strip()):
        raise ValueError(f"Missing required integer field '{field_name}'")
    return int(str(val).strip(), 0)

def get_reg_bounds(reg_obj):
    bv = reg_obj.getBitvector()
    return bv.getLow(), bv.getHigh()

class RegisterBitTracker:
    """按位跟踪通用寄存器的初始化状态，防止读 AL 误判整个 RAX 已初始化"""
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

def parse_trace_line(line, line_no, gpr_order):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # JSONL 格式支持
    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
        except Exception as e:
            raise ValueError(f"Invalid JSON syntax at line {line_no}: {str(e)}")

        kind = data.get("type")
        if not kind:
            raise ValueError(f"Missing required 'type' in JSONL record at line {line_no}")

        if kind == "instruction":
            if "address" not in data:
                raise ValueError(f"Missing required 'address' in instruction at line {line_no}")
            addr = parse_int(data["address"], "address")

            opcode_hex = data.get("bytes")
            if not opcode_hex or not isinstance(opcode_hex, str):
                raise ValueError(f"Missing required 'bytes' hex string in instruction at line {line_no}")
            opcode_hex = opcode_hex.strip().replace(" ", "")

            size = int(data.get("size", len(opcode_hex) // 2))
            disasm = data.get("disasm", "")
            return ("i", addr, size, opcode_hex, disasm)

        elif kind == "memory_read":
            if "address" not in data:
                raise ValueError(f"Missing required 'address' in memory_read at line {line_no}")
            addr = parse_int(data["address"], "address")
            size = int(data.get("size", 1))

            if "value" not in data:
                raise ValueError(f"Missing required 'value' in memory_read at line {line_no}")
            val = parse_int(data["value"], "value")
            return ("mr", addr, size, val)

        elif kind == "registers":
            regs = data.get("values")
            if not isinstance(regs, dict) or not regs:
                raise ValueError(f"Missing or empty 'values' dict in registers record at line {line_no}")
            parsed_regs = {k.lower(): parse_int(v, k) for k, v in regs.items()}
            return ("r", parsed_regs)

        else:
            raise ValueError(f"Unsupported JSONL record type '{kind}' at line {line_no}")

    # Salwan 规范文本格式
    if line.startswith("mr:"):
        parts = line.split(":")
        if len(parts) < 4:
            raise ValueError(f"Malformed Salwan mr: record at line {line_no}: expected 'mr:<addr>:<size>:<data>'")
        addr = parse_int(parts[1], "addr")
        try:
            size = int(parts[2], 10)
        except Exception:
            raise ValueError(f"Invalid decimal size '{parts[2]}' in mr: record at line {line_no}")
        data = parse_int(parts[3], "data")
        return ("mr", addr, size, data)

    elif line.startswith("r:"):
        parts = line.split(":")
        if len(parts) < 2:
            raise ValueError(f"Malformed Salwan r: record at line {line_no}")
        raw_items = parts[1:]
        reg_map = {}
        if any("=" in p for p in raw_items):
            for p in raw_items:
                if "=" in p:
                    k, v = p.split("=", 1)
                    reg_map[k.strip().lower()] = parse_int(v.strip(), k.strip())
        else:
            for i, p in enumerate(raw_items):
                if i < len(gpr_order):
                    reg_map[gpr_order[i]] = parse_int(p.strip(), gpr_order[i])
        return ("r", reg_map)

    elif line.startswith("i:"):
        parts = line.split(":")
        if len(parts) < 4:
            raise ValueError(f"Malformed Salwan i: record at line {line_no}: expected 'i:<addr>:<size>:<bytes_hex>'")
        addr = parse_int(parts[1], "addr")
        try:
            size = int(parts[2], 10)
        except Exception:
            raise ValueError(f"Invalid decimal instruction size '{parts[2]}' at line {line_no}")
        opcode_hex = parts[3].strip().replace(" ", "")
        disasm = parts[4].strip() if len(parts) >= 5 else ""
        return ("i", addr, size, opcode_hex, disasm)

    raise ValueError(f"Unrecognized trace line format at line {line_no}: '{line}'")

def action_status(request):
    res = {
        "installed": False,
        "python_path": sys.executable,
        "python_version": sys.version.split()[0],
        "triton_version": None,
        "supported_architectures": [],
        "solver": {"available": False, "engine": None, "solvers": [], "reason": None},
        "llvm": {"available": False, "status": "unavailable"},
        "synthesizer": {"available": False, "reason": None},
        "install_hint": "Run 'reverse setup reverse triton --execute' to install the managed Triton toolchain.",
    }

    try:
        import triton
        from triton import TritonContext, ARCH, SOLVER
    except ImportError as e:
        res["error"] = f"Triton module import failed: {str(e)}"
        return {"status": "ok", "result": res}

    res["installed"] = True
    res["triton_version"] = getattr(triton, "__version__", "unknown")

    # 1. 架构探测：逐一尝试实例化 TritonContext
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

    # 2. SMT 求解器探测：实际调用 getModel 验证求解能力
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

    # 3. AST 综合器探测：实际调用 synthesize 验证
    try:
        ctx_synth = TritonContext(ARCH.X86_64 if hasattr(ARCH, "X86_64") else ARCH.X86)
        if hasattr(ctx_synth, "synthesize"):
            ast_ctx = ctx_synth.getAstContext()
            ctx_synth.synthesize(ast_ctx.bv(42, 32))
            res["synthesizer"]["available"] = True
        else:
            res["synthesizer"]["available"] = False
            res["synthesizer"]["reason"] = "synthesize method not present in TritonContext"
    except Exception as e:
        res["synthesizer"]["available"] = False
        res["synthesizer"]["reason"] = str(e)

    # 4. LLVM 抬升探测：实际调用 liftToLLVM 验证（编译期依赖 LLVM）
    try:
        ctx_llvm = TritonContext(ARCH.X86_64 if hasattr(ARCH, "X86_64") else ARCH.X86)
        if hasattr(ctx_llvm, "liftToLLVM"):
            ast_ctx = ctx_llvm.getAstContext()
            ir = ctx_llvm.liftToLLVM(ast_ctx.bv(1, 32), fname="__triton_probe")
            if ir and len(ir) > 0:
                res["llvm"]["available"] = True
                res["llvm"]["status"] = "available"
            else:
                res["llvm"]["status"] = "unavailable: empty IR returned by liftToLLVM"
        else:
            res["llvm"]["status"] = "unavailable: liftToLLVM method not present"
    except Exception as e:
        res["llvm"]["available"] = False
        res["llvm"]["status"] = f"unavailable: {str(e)}"

    return {"status": "ok", "result": res}

def action_replay(request):
    try:
        import triton
        from triton import TritonContext, ARCH, MODE, Instruction, MemoryAccess, EXCEPTION, CALLBACK
    except ImportError as e:
        return {
            "status": "missing_dependency",
            "error": f"Triton library is not installed: {str(e)}. Run 'reverse setup reverse triton --execute' to install the managed Triton toolchain."
        }

    arch_str = request.get("arch", "x86_64").lower()
    if arch_str == "x86":
        triton_arch = ARCH.X86
        gpr_bits = 32
        gpr_order = ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]
    elif arch_str == "x86_64":
        triton_arch = ARCH.X86_64
        gpr_bits = 64
        gpr_order = ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    else:
        return {
            "status": "error",
            "error": f"Unsupported architecture '{arch_str}'. Supported architectures: x86, x86_64."
        }

    output_cfg = request.get("output")
    if not output_cfg or not isinstance(output_cfg, dict):
        return {
            "status": "error",
            "error": "Missing required 'output' specification. Must be an object with kind='register' or 'memory'."
        }

    out_kind = output_cfg.get("kind", "").lower()
    if out_kind == "register":
        out_target = output_cfg.get("target")
        if not out_target:
            return {"status": "error", "error": "Missing required 'target' register in output specification."}
    elif out_kind == "memory":
        if "address" not in output_cfg:
            return {"status": "error", "error": "Missing required 'address' in output memory specification."}
        if "size" not in output_cfg:
            return {"status": "error", "error": "Missing required 'size' in output memory specification."}
    else:
        return {"status": "error", "error": f"Invalid output kind '{out_kind}'. Expected 'register' or 'memory'."}

    ctx = TritonContext(triton_arch)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setMode(MODE.AST_OPTIMIZATIONS, True)
    ctx.setMode(MODE.CONSTANT_FOLDING, True)

    bounds = request.get("bounds") or {}
    max_instructions = int(bounds.get("max_instructions") or 50000)
    do_synthesize = bool(request.get("synthesize", True))
    do_lift_llvm = bool(request.get("lift_llvm", True))

    reg_tracker = RegisterBitTracker()
    initialized_flags = set()

    # 安装内存读取回调，防止 RMW 指令后检查逃逸未初始化内存
    missing_memory_detected = None
    guard_active = False

    def on_get_concrete_memory(callback_ctx, mem_access):
        nonlocal missing_memory_detected
        if guard_active and missing_memory_detected is None:
            if not callback_ctx.isConcreteMemoryValueDefined(mem_access) and not callback_ctx.isMemorySymbolized(mem_access):
                missing_memory_detected = (mem_access.getAddress(), mem_access.getSize())

    if hasattr(CALLBACK, "GET_CONCRETE_MEMORY_VALUE"):
        ctx.addCallback(CALLBACK.GET_CONCRETE_MEMORY_VALUE, on_get_concrete_memory)

    # 1. 显式具体寄存器初始化
    initial_regs = request.get("initial_registers") or {}
    for r_name, r_val_raw in initial_regs.items():
        r_name_clean = r_name.lower().strip()
        try:
            reg_obj = ctx.getRegister(r_name_clean)
        except Exception:
            return {"status": "error", "error": f"Invalid register name '{r_name}' for architecture {arch_str}."}

        val = parse_int(r_val_raw, r_name)
        max_val = (1 << reg_obj.getBitSize()) - 1
        if val < 0 or val > max_val:
            return {
                "status": "error",
                "error": f"Register '{r_name}' value 0x{val:x} out of bounds (bit size: {reg_obj.getBitSize()})."
            }
        ctx.setConcreteRegisterValue(reg_obj, val)

        if r_name_clean in FLAGS:
            initialized_flags.add(r_name_clean)
        elif r_name_clean in ("eflags", "rflags"):
            initialized_flags.update(FLAGS)

        p_name = ctx.getParentRegister(reg_obj).getName().lower()
        if arch_str == "x86_64" and reg_obj.getBitSize() == 32 and p_name in gpr_order:
            reg_tracker.mark_initialized(p_name, 0, 63)
        elif p_name in gpr_order:
            low, high = get_reg_bounds(reg_obj)
            reg_tracker.mark_initialized(p_name, low, high)

    # 2. 显式具体内存初始化（校验 bounds 与数值宽度）
    initial_mem = request.get("initial_memory") or []
    for item in initial_mem:
        addr = parse_int(item.get("address"), "initial_memory.address")
        size = int(item.get("size") or 1)
        if size < 1:
            return {"status": "error", "error": f"initial_memory size must be >= 1, got {size}"}
        if addr < 0 or (addr + size) > (1 << gpr_bits):
            return {"status": "error", "error": f"initial_memory address 0x{addr:x} + size {size} out of range for {arch_str}."}

        val = parse_int(item.get("value", 0), "initial_memory.value")
        max_mem_val = (1 << (size * 8)) - 1
        if val < 0 or val > max_mem_val:
            return {
                "status": "error",
                "error": f"initial_memory value 0x{val:x} exceeds size {size} bytes (maximum 0x{max_mem_val:x})"
            }

        mem_acc = MemoryAccess(addr, size)
        ctx.setConcreteMemoryValue(mem_acc, val)

    # 3. 显式符号输入寄存器（提取真实种子数值，严禁假定为 0）
    sym_regs_req = request.get("symbolic_registers") or []
    for sym_item in sym_regs_req:
        r_name = sym_item.get("name", "").lower().strip()
        alias = sym_item.get("alias") or r_name
        try:
            reg_obj = ctx.getRegister(r_name)
        except Exception:
            return {"status": "error", "error": f"Invalid symbolic register name '{r_name}' for {arch_str}."}

        reg_bits = reg_obj.getBitSize()
        max_seed_val = (1 << reg_bits) - 1

        if "seed" in sym_item:
            seed = parse_int(sym_item["seed"], f"symbolic_register.{r_name}.seed")
            if seed < 0 or seed > max_seed_val:
                return {
                    "status": "error",
                    "error": f"Symbolic register '{r_name}' seed 0x{seed:x} exceeds width {reg_bits} bits."
                }
            ctx.setConcreteRegisterValue(reg_obj, seed)
        else:
            p_name = ctx.getParentRegister(reg_obj).getName().lower()
            low, high = get_reg_bounds(reg_obj)
            if p_name in gpr_order and not reg_tracker.is_fully_initialized(p_name, low, high):
                return {
                    "status": "error",
                    "error": f"Symbolic register '{r_name}' requires an explicit concrete seed value (via initial_registers or seed field); never assume zero."
                }
            seed = ctx.getConcreteRegisterValue(reg_obj)

        ctx.symbolizeRegister(reg_obj, alias)

        if r_name in FLAGS:
            initialized_flags.add(r_name)

        p_name = ctx.getParentRegister(reg_obj).getName().lower()
        if arch_str == "x86_64" and reg_obj.getBitSize() == 32 and p_name in gpr_order:
            reg_tracker.mark_initialized(p_name, 0, 63)
        elif p_name in gpr_order:
            low, high = get_reg_bounds(reg_obj)
            reg_tracker.mark_initialized(p_name, low, high)

    # 4. 显式符号输入内存（必须提供真实种子）
    sym_mem_req = request.get("symbolic_memory") or []
    for sym_mem in sym_mem_req:
        addr = parse_int(sym_mem.get("address"), "symbolic_memory.address")
        size = int(sym_mem.get("size") or 1)
        alias = sym_mem.get("alias") or f"mem_{hex(addr)}"

        if "seed" not in sym_mem:
            return {
                "status": "error",
                "error": f"Symbolic memory at 0x{addr:x} requires an explicit concrete seed value (via seed field); never assume zero."
            }
        seed = parse_int(sym_mem["seed"], f"symbolic_memory.seed")
        max_mem_seed = (1 << (size * 8)) - 1
        if seed < 0 or seed > max_mem_seed:
            return {
                "status": "error",
                "error": f"Symbolic memory at 0x{addr:x} seed 0x{seed:x} exceeds width {size * 8} bits."
            }

        mem_acc = MemoryAccess(addr, size)
        ctx.setConcreteMemoryValue(mem_acc, seed)
        ctx.symbolizeMemory(mem_acc, alias)

    # 5. 读取追踪文件
    trace_path = request.get("trace")
    if not trace_path:
        return {"status": "error", "error": "Missing required 'trace' file path."}
    if not os.path.exists(trace_path):
        return {"status": "error", "error": f"Trace file not found: {trace_path}"}

    with open(trace_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    instructions_executed = 0

    # 6. 回放执行主循环
    for line_idx, raw_line in enumerate(lines):
        line_no = line_idx + 1
        try:
            parsed = parse_trace_line(raw_line, line_no, gpr_order)
        except Exception as e:
            return {"status": "error", "error": str(e)}

        if not parsed:
            continue

        tag = parsed[0]

        if tag == "mr":
            _, m_addr, m_size, m_data = parsed
            mem_acc = MemoryAccess(m_addr, m_size)
            if ctx.isMemorySymbolized(mem_acc):
                curr = ctx.getConcreteMemoryValue(mem_acc)
                if curr != m_data:
                    return {
                        "status": "error",
                        "error": (
                            f"Unmodelled gap at line {line_no}: memory access at 0x{m_addr:x} is symbolized but trace "
                            f"concrete snapshot 0x{m_data:x} mismatches current state 0x{curr:x}. Concretizing would destroy symbolic state."
                        )
                    }
            else:
                if not ctx.isConcreteMemoryValueDefined(mem_acc) or ctx.getConcreteMemoryValue(mem_acc) != m_data:
                    ctx.setConcreteMemoryValue(mem_acc, m_data)

        elif tag == "r":
            _, reg_dict = parsed
            for r_k, r_v in reg_dict.items():
                try:
                    reg_obj = ctx.getRegister(r_k)
                except Exception:
                    return {"status": "error", "error": f"Unknown register '{r_k}' at line {line_no}"}

                if ctx.isRegisterSymbolized(reg_obj):
                    curr = ctx.getConcreteRegisterValue(reg_obj)
                    if curr != r_v:
                        return {
                            "status": "error",
                            "error": (
                                f"Unmodelled gap at line {line_no}: register '{r_k}' is symbolized but trace concrete "
                                f"snapshot value 0x{r_v:x} mismatches current state 0x{curr:x}. Concretizing would destroy symbolic state."
                            )
                        }
                else:
                    curr = ctx.getConcreteRegisterValue(reg_obj)
                    if curr != r_v:
                        ctx.setConcreteRegisterValue(reg_obj, r_v)

                    if r_k in FLAGS:
                        initialized_flags.add(r_k)
                    elif r_k in ("eflags", "rflags"):
                        initialized_flags.update(FLAGS)

                    p_name = ctx.getParentRegister(reg_obj).getName().lower()
                    if arch_str == "x86_64" and reg_obj.getBitSize() == 32 and p_name in gpr_order:
                        reg_tracker.mark_initialized(p_name, 0, 63)
                    elif p_name in gpr_order:
                        low, high = get_reg_bounds(reg_obj)
                        reg_tracker.mark_initialized(p_name, low, high)

        elif tag == "i":
            _, i_addr, i_size, i_hex, i_disasm = parsed

            if instructions_executed >= max_instructions:
                return {
                    "status": "error",
                    "error": f"Instruction bound exceeded: trace reached limit of {max_instructions} instructions."
                }

            try:
                opcodes = bytes.fromhex(i_hex)
            except Exception as e:
                return {
                    "status": "error",
                    "error": f"Invalid instruction opcode hex '{i_hex}' at line {line_no}: {str(e)}"
                }

            inst = Instruction(i_addr, opcodes)

            # 激活内存回调守卫并执行模拟
            guard_active = True
            missing_memory_detected = None
            try:
                emul_status = ctx.processing(inst)
            finally:
                guard_active = False

            if missing_memory_detected:
                return {
                    "status": "error",
                    "error": (
                        f"Missing memory state at line {line_no}: instruction at 0x{i_addr:x} ({inst.getDisassembly()}) "
                        f"reads memory at 0x{missing_memory_detected[0]:x} (size {missing_memory_detected[1]} bytes), which was neither defined nor symbolized."
                    )
                }

            if emul_status != EXCEPTION.NO_FAULT:
                return {
                    "status": "error",
                    "error": f"Instruction emulation fault ({emul_status}) at 0x{i_addr:x} (line {line_no}): {inst.getDisassembly() or i_hex}"
                }

            instructions_executed += 1

            # 执行后验证读取的内存（兜底非回调路径）
            for mem_acc, _ in inst.getLoadAccess():
                if not ctx.isConcreteMemoryValueDefined(mem_acc) and not ctx.isMemorySymbolized(mem_acc):
                    return {
                        "status": "error",
                        "error": (
                            f"Missing memory state at line {line_no}: instruction at 0x{i_addr:x} ({inst.getDisassembly()}) "
                            f"reads memory at 0x{mem_acc.getAddress():x} (size {mem_acc.getSize()} bytes), which was neither defined nor symbolized."
                        )
                    }

            # 执行后验证读取的通用寄存器与标志位：严格校验位范围，哪怕部分位被标记为符号，未初始化的位也必须报错
            for reg_read, _ in inst.getReadRegisters():
                r_read_name = reg_read.getName().lower()
                p_name = ctx.getParentRegister(reg_read).getName().lower()

                # 标志位校验
                if r_read_name in FLAGS:
                    if r_read_name not in initialized_flags and not ctx.isRegisterSymbolized(reg_read):
                        return {
                            "status": "error",
                            "error": (
                                f"Missing flag state at line {line_no}: instruction at 0x{i_addr:x} ({inst.getDisassembly()}) "
                                f"reads uninitialized flag '{r_read_name}'."
                            )
                        }

                # 通用寄存器按位校验（即使父寄存器包含部分符号，未初始化的位也必须拦截）
                if p_name in gpr_order:
                    low, high = get_reg_bounds(reg_read)
                    if not reg_tracker.is_fully_initialized(p_name, low, high):
                        return {
                            "status": "error",
                            "error": (
                                f"Missing register state at line {line_no}: instruction at 0x{i_addr:x} ({inst.getDisassembly()}) "
                                f"reads uninitialized register '{reg_read.getName()}'."
                            )
                        }

            # 记录写入的寄存器位区间与标志位
            for reg_written, _ in inst.getWrittenRegisters():
                w_name = reg_written.getName().lower()
                if w_name in FLAGS:
                    initialized_flags.add(w_name)
                elif w_name in ("eflags", "rflags"):
                    initialized_flags.update(FLAGS)

                p_name = ctx.getParentRegister(reg_written).getName().lower()
                if arch_str == "x86_64" and reg_written.getBitSize() == 32 and p_name in gpr_order:
                    reg_tracker.mark_initialized(p_name, 0, 63)
                elif p_name in gpr_order:
                    low, high = get_reg_bounds(reg_written)
                    reg_tracker.mark_initialized(p_name, low, high)

    # 7. 提取目标输出（必须显式验证存在且已初始化）
    target_ast = None
    concrete_return = None

    if out_kind == "register":
        out_target = output_cfg["target"].strip().lower()
        try:
            out_reg = ctx.getRegister(out_target)
        except Exception:
            return {"status": "error", "error": f"Output register '{out_target}' not found for {arch_str}."}

        p_name = ctx.getParentRegister(out_reg).getName().lower()
        low, high = get_reg_bounds(out_reg)
        if p_name in gpr_order and not reg_tracker.is_fully_initialized(p_name, low, high):
            return {
                "status": "error",
                "error": f"Requested output register '{out_target}' was not initialized during execution."
            }

        concrete_return = hex(ctx.getConcreteRegisterValue(out_reg))
        target_ast = ctx.getRegisterAst(out_reg)

    elif out_kind == "memory":
        m_addr = parse_int(output_cfg["address"], "output.address")
        m_size = int(output_cfg["size"])
        mem_acc = MemoryAccess(m_addr, m_size)
        if not ctx.isConcreteMemoryValueDefined(mem_acc) and not ctx.isMemorySymbolized(mem_acc):
            return {
                "status": "error",
                "error": f"Requested output memory at 0x{m_addr:x} (size {m_size}) was not defined during execution."
            }
        concrete_return = hex(ctx.getConcreteMemoryValue(mem_acc))
        target_ast = ctx.getMemoryAst(mem_acc)

    ast_ctx = ctx.getAstContext()
    devirt_expr = None
    if target_ast is not None:
        try:
            unrolled = ast_ctx.unroll(target_ast)
            devirt_expr = str(unrolled)
        except Exception:
            devirt_expr = str(target_ast)

    # 8. AST 综合与简化
    synth_expr = None
    synth_node = None
    if do_synthesize and target_ast is not None and hasattr(ctx, "synthesize"):
        try:
            synth_node = ctx.synthesize(target_ast)
            if synth_node is not None:
                synth_expr = str(synth_node)
        except Exception:
            pass

    # 9. LLVM IR 抬升（无支持时如实返回 unavailable 状态）
    llvm_available = False
    llvm_ir = None
    llvm_status = "unavailable"

    if do_lift_llvm and target_ast is not None and hasattr(ctx, "liftToLLVM"):
        try:
            lift_target = synth_node if (synth_node is not None) else target_ast
            ir = ctx.liftToLLVM(lift_target, fname="__triton", optimize=False)
            if ir and len(ir) > 0:
                llvm_available = True
                llvm_ir = str(ir)
                llvm_status = "available"
            else:
                llvm_status = "unavailable: empty IR returned"
        except Exception as e:
            llvm_available = False
            llvm_status = f"unavailable: {str(e)}"
    else:
        llvm_status = "unavailable: liftToLLVM disabled or not supported"

    # 10. 收集实际路径约束
    path_constraints = []
    try:
        p_constraints = ctx.getPathConstraints()
        for idx, pc in enumerate(p_constraints):
            path_constraints.append({
                "index": idx,
                "comment": pc.getComment() if hasattr(pc, "getComment") else "",
                "taken": pc.isTaken() if hasattr(pc, "isTaken") else True,
                "address": hex(pc.getSourceAddress()) if hasattr(pc, "getSourceAddress") else None
            })
    except Exception:
        pass

    return {
        "status": "ok",
        "result": {
            "arch": arch_str,
            "instructions_executed": instructions_executed,
            "concrete_return": concrete_return,
            "devirt_expr": devirt_expr,
            "synth_expr": synth_expr,
            "llvm_available": llvm_available,
            "llvm_ir": llvm_ir,
            "llvm_status": llvm_status,
            "path_constraints_count": len(path_constraints),
            "path_constraints": path_constraints,
            "execution_notice": (
                "Trace replay completed. Note: Offline symbolic trace replay models only the executed trace path, "
                "not the entire function. Covered paths do not imply full-function semantic equivalence."
            )
        }
    }

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
        elif action == "replay":
            resp = action_replay(request)
        else:
            resp = {"status": "error", "error": f"Unknown action '{action}'. Supported: 'status', 'replay'."}

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
