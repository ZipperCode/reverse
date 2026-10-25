#!/usr/bin/env python3
"""
d810-ng Headless IDA 9+ Microcode Deobfuscation Script.

Runs inside IDA Pro 9+ batch/headless mode (`idat64 -A -S...`) or idalib session.
Locates target function, extracts pre-deobfuscation Hex-Rays pseudocode with hooks
suppressed, loads project configuration, activates verified d810-ng microcode
rules and control-flow unflatteners, re-decompiles, and exports before/after
pseudocode and actual optimization statistics.
"""

from __future__ import annotations

import sys
import os
import json
import time
from typing import Optional, List, Dict, Any, Union


def parse_target_address(addr_val: Union[int, str], idc_mod) -> Optional[int]:
    if isinstance(addr_val, int):
        return addr_val
    if isinstance(addr_val, str):
        val_str = addr_val.strip()
        if val_str.startswith("0x") or val_str.startswith("0X"):
            try:
                return int(val_str, 16)
            except ValueError:
                return None
        if val_str.isdigit():
            return int(val_str, 10)
        # Try resolving symbol name
        ea = idc_mod.get_name_ea_simple(val_str)
        if ea != idc_mod.BADADDR:
            return ea
        try:
            return int(val_str, 16)
        except ValueError:
            return None
    return None


def run_d810_deobfuscation(config_path: str) -> None:
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    target_func = cfg.get("function")
    unflattener_type = str(cfg.get("unflattener", "ollvm")).lower()
    custom_config_path = cfg.get("config_json")
    output_path = cfg.get("output_path")

    report: Dict[str, Any] = {
        "status": "error",
        "backend": "d810-ng",
        "function": target_func,
        "unflattener": unflattener_type,
        "metadata": {},
    }

    if not target_func:
        report["error"] = "No target function specified. 'function' parameter is required for d810-ng."
        _write_report(output_path, report)
        return

    # 1. Insert managed site-packages if specified
    site_packages = cfg.get("site_packages")
    if site_packages and os.path.isdir(site_packages) and site_packages not in sys.path:
        sys.path.insert(0, site_packages)

    # 2. Import IDA and d810 modules
    try:
        import idaapi
        import ida_auto
        import ida_funcs
        import ida_hexrays
        import idc

        import d810
        import d810._vendor.ida_reloader as reloadable
        from d810.manager import D810State, d810_hooks_suppressed
        from d810.core.config import ProjectConfiguration
    except ImportError as e:
        report["error"] = f"Failed to import required IDA / d810 modules: {e}. Ensure IDA Pro 9+ and d810-ng (v0.6.6+) are installed."
        _write_report(output_path, report)
        return

    # Wait for IDA initial auto-analysis
    ida_auto.auto_wait()

    # 2. Ensure Hex-Rays decompiler is active for target architecture
    if not ida_hexrays.init_hexrays_plugin():
        ALL_DECOMPILERS = {
            idaapi.PLFM_386: "hexx64",
            idaapi.PLFM_ARM: "hexarm",
            idaapi.PLFM_PPC: "hexppc",
            idaapi.PLFM_MIPS: "hexmips",
            idaapi.PLFM_RISCV: "hexrv",
        }
        decompiler = ALL_DECOMPILERS.get(idaapi.ph.id)
        if decompiler:
            idaapi.load_plugin(decompiler)
            ida_hexrays.init_hexrays_plugin()

    if not ida_hexrays.init_hexrays_plugin():
        report["error"] = "Hex-Rays decompiler is not available or license check failed for this architecture."
        _write_report(output_path, report)
        return

    # 3. Locate target function (FAIL CLOSED: do NOT silently fallback to another function)
    ea = parse_target_address(target_func, idc)
    if ea is None or ea == idc.BADADDR:
        report["error"] = f"Target function '{target_func}' could not be resolved to an address in database."
        _write_report(output_path, report)
        return

    func = ida_funcs.get_func(ea)
    if not func:
        report["error"] = f"No function exists in database at resolved address {hex(ea)} (target was '{target_func}')."
        _write_report(output_path, report)
        return

    func_ea = func.start_ea
    func_name = idc.get_func_name(func_ea)
    report["resolved_ea"] = hex(func_ea)
    report["function_name"] = func_name

    # 4. Populate d810 rule registries and initialize headless state
    try:
        reloadable.Scanner.scan(d810.__path__, "d810.", skip_packages=False)
        state = D810State()
        state.load(gui=False)
    except Exception as e:
        report["error"] = f"Failed to initialize d810-ng state: {e}"
        _write_report(output_path, report)
        return

    # 5. Select and configure project
    config_used = "default_unflattening_ollvm.json"
    if custom_config_path and os.path.exists(custom_config_path):
        try:
            custom_project = ProjectConfiguration.from_file(custom_config_path)
            state.add_project(custom_project)
            project_idx = state.project_manager.index(custom_project.path.name)
            state.load_project(project_idx)
            config_used = custom_project.path.name
        except Exception as e:
            report["error"] = f"Failed to load custom project configuration '{custom_config_path}': {e}"
            _write_report(output_path, report)
            return
    else:
        config_map = {
            "ollvm": "default_unflattening_ollvm.json",
            "tigress": "default_unflattening_approov.json",
            "approov": "default_unflattening_approov.json",
            "hodur": "example_hodur.json",
            "generic": "default_instruction_only.json",
            "none": "default_instruction_only.json",
        }
        config_name = config_map.get(unflattener_type, "default_unflattening_ollvm.json")
        try:
            project_idx = state.project_manager.index(config_name)
            state.load_project(project_idx)
            config_used = config_name
        except Exception as e:
            report["error"] = f"Failed to select d810 project configuration '{config_name}': {e}"
            _write_report(output_path, report)
            return

    report["config_used"] = config_used
    report["d810_version"] = getattr(d810, "__version__", "0.6.6")

    t0 = time.time()

    # 6. Decompile BEFORE optimization (with d810 hooks suppressed)
    try:
        with d810_hooks_suppressed(state.manager):
            cfunc_before = ida_hexrays.decompile(func_ea, ida_hexrays.DECOMP_NO_CACHE)
            if not cfunc_before:
                report["error"] = f"Hex-Rays baseline decompilation failed for {func_name} at {hex(func_ea)}."
                _write_report(output_path, report)
                return
            code_before = str(cfunc_before)
    except Exception as e:
        report["error"] = f"Error during baseline decompilation: {e}"
        _write_report(output_path, report)
        return

    # 7. Start d810 hooks and decompile AFTER optimization
    code_after = None
    try:
        state.start_d810()
        cfunc_after = ida_hexrays.decompile(func_ea, ida_hexrays.DECOMP_NO_CACHE)
        if not cfunc_after:
            report["error"] = f"Hex-Rays decompilation with d810 hooks failed for {func_name} at {hex(func_ea)}."
            _write_report(output_path, report)
            return
        code_after = str(cfunc_after)
    except Exception as e:
        report["error"] = f"Error during d810-optimized decompilation: {e}"
        _write_report(output_path, report)
        return
    finally:
        state.stop_d810()
        state.unload(gui=False)

    duration = time.time() - t0

    lines_before = len(code_before.splitlines())
    lines_after = len(code_after.splitlines())

    report["status"] = "ok"
    report["duration_seconds"] = round(duration, 3)
    report["before"] = {
        "lines": lines_before,
        "pseudocode": code_before,
    }
    report["after"] = {
        "lines": lines_after,
        "pseudocode": code_after,
    }
    report["complexity_reduction"] = {
        "lines_before": lines_before,
        "lines_after": lines_after,
        "lines_reduced": max(0, lines_before - lines_after),
        "reduction_ratio": round(lines_after / lines_before, 4) if lines_before > 0 else 1.0,
    }

    _write_report(output_path, report)


def _write_report(output_path: Optional[str], data: Dict[str, Any]) -> None:
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        sys.stdout.write(json.dumps(data, indent=2))


if __name__ == "__main__":
    config_file = None
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    elif "D810_CONFIG_JSON" in os.environ:
        config_file = os.environ["D810_CONFIG_JSON"]

    if config_file and os.path.exists(config_file):
        run_d810_deobfuscation(config_file)
    else:
        sys.stdout.write(json.dumps({
            "status": "probe",
            "message": "d810-ng worker ready for IDA 9+ batch execution"
        }))

    try:
        import idc
        idc.process_config_directive("ABANDON_DATABASE=YES")
        idc.qexit(0)
    except Exception:
        pass
