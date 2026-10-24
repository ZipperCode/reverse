#!/usr/bin/env python3
"""ELF deep inspection and structural validation companion worker using LIEF.

Exposes structured queries of ELF segments, dynamic entries, relocations,
constructors, and address-to-file mappings, as well as structural validation
of reconstructed memory-dump ELF candidates (SoFixer).
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from typing import Any


def _format_hex(val: Any) -> str | None:
    if val is None or isinstance(val, bool) or not isinstance(val, int):
        return None
    return f"0x{val:x}"


def _parse_int(val: Any) -> int | None:
    if val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        val_str = val.strip()
        if val_str.startswith("0x") or val_str.startswith("0X"):
            return int(val_str, 16)
        return int(val_str)
    return None


def handle_probe(_req: dict[str, Any]) -> dict[str, Any]:
    try:
        import lief

        version = getattr(lief, "__version__", "unknown")
        return {
            "status": "ok",
            "available": True,
            "lief_version": version,
        }
    except ImportError as e:
        return {
            "status": "ok",
            "available": False,
            "error": str(e),
        }


def _extract_header(binary: Any) -> dict[str, Any]:
    hdr = binary.header
    machine_str = str(hdr.machine_type).replace("ARCH.", "").replace("MACHINE_TYPES.", "")
    file_type_str = str(hdr.file_type).replace("E_TYPE.", "")
    endian_str = "little" if "LSB" in str(hdr.identity_data) else "big"
    bitness = 64 if "ELF64" in str(hdr.identity_class) else 32

    return {
        "machine": machine_str,
        "bitness": bitness,
        "endianness": endian_str,
        "file_type": file_type_str,
        "entrypoint": _format_hex(hdr.entrypoint),
        "header_size": hdr.header_size,
    }


def _extract_segments(binary: Any, filter_str: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    all_segments = []
    for idx, seg in enumerate(binary.segments):
        seg_type = str(seg.type).replace("SEGMENT_TYPES.", "").replace("TYPE.", "")
        if filter_str and filter_str.lower() not in seg_type.lower():
            continue

        flags_str = ""
        f_int = int(seg.flags)
        if f_int & 4:
            flags_str += "R"
        if f_int & 2:
            flags_str += "W"
        if f_int & 1:
            flags_str += "X"

        sec_names = []
        try:
            sec_names = [s.name for s in seg.sections]
        except Exception:
            pass

        all_segments.append({
            "index": idx,
            "type": seg_type,
            "flags": flags_str,
            "flags_value": f_int,
            "virtual_address": _format_hex(seg.virtual_address),
            "virtual_size": seg.virtual_size,
            "file_offset": _format_hex(seg.file_offset),
            "physical_size": seg.physical_size,
            "alignment": seg.alignment,
            "sections": sec_names,
        })

    total = len(all_segments)
    paged = all_segments[offset : offset + limit]
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": paged,
    }


def _extract_dynamic(binary: Any, filter_str: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    needed_libs = []
    soname = None
    init_va = None
    fini_va = None
    init_array_va = None
    init_array_size = None
    fini_array_va = None
    fini_array_size = None
    entries_list = []

    for entry in binary.dynamic_entries:
        tag_str = str(entry.tag).replace("DYNAMIC_TAGS.", "").replace("TAG.", "")
        val = entry.value

        if tag_str == "NEEDED":
            name = getattr(entry, "name", str(val))
            needed_libs.append(name)
        elif tag_str == "SONAME":
            soname = getattr(entry, "name", str(val))
        elif tag_str == "INIT":
            init_va = _format_hex(val)
        elif tag_str == "FINI":
            fini_va = _format_hex(val)
        elif tag_str == "INIT_ARRAY":
            init_array_va = _format_hex(val)
        elif tag_str == "INIT_ARRAYSZ":
            init_array_size = val
        elif tag_str == "FINI_ARRAY":
            fini_array_va = _format_hex(val)
        elif tag_str == "FINI_ARRAYSZ":
            fini_array_size = val

        if filter_str:
            name_val = getattr(entry, "name", "")
            if filter_str.lower() not in tag_str.lower() and filter_str.lower() not in name_val.lower():
                continue

        entry_dict = {
            "tag": tag_str,
            "value": _format_hex(val) if isinstance(val, int) else val,
        }
        if hasattr(entry, "name") and entry.name:
            entry_dict["name"] = entry.name
        entries_list.append(entry_dict)

    total = len(entries_list)
    paged = entries_list[offset : offset + limit]

    return {
        "soname": soname,
        "needed_libraries": needed_libs,
        "init": init_va,
        "fini": fini_va,
        "init_array": init_array_va,
        "init_array_size": init_array_size,
        "fini_array": fini_array_va,
        "fini_array_size": fini_array_size,
        "total_entries": total,
        "limit": limit,
        "offset": offset,
        "entries": paged,
    }


def _extract_constructors(binary: Any) -> dict[str, Any]:
    ctors = []
    try:
        for idx, func in enumerate(binary.ctor_functions):
            addr = func.address
            file_off = None
            try:
                res = binary.virtual_address_to_offset(addr)
                if isinstance(res, int) and not isinstance(res, bool):
                    file_off = res
            except Exception:
                pass

            ctors.append({
                "index": idx,
                "name": func.name if func.name else f"ctor_{idx}",
                "address": _format_hex(addr),
                "file_offset": _format_hex(file_off),
            })
    except Exception:
        pass

    dtors = []
    try:
        for idx, func in enumerate(binary.dtor_functions):
            addr = func.address
            file_off = None
            try:
                res = binary.virtual_address_to_offset(addr)
                if isinstance(res, int) and not isinstance(res, bool):
                    file_off = res
            except Exception:
                pass

            dtors.append({
                "index": idx,
                "name": func.name if func.name else f"dtor_{idx}",
                "address": _format_hex(addr),
                "file_offset": _format_hex(file_off),
            })
    except Exception:
        pass

    # Inspect .init_array section directly if present
    init_array_section = None
    try:
        if binary.has_section(".init_array"):
            sec = binary.get_section(".init_array")
            init_array_section = {
                "virtual_address": _format_hex(sec.virtual_address),
                "file_offset": _format_hex(sec.offset),
                "size": sec.size,
            }
    except Exception:
        pass

    init_func_va = None
    for entry in binary.dynamic_entries:
        tag_str = str(entry.tag)
        if "INIT" in tag_str and "ARRAY" not in tag_str and "SZ" not in tag_str:
            init_func_va = _format_hex(entry.value)
            break

    return {
        "constructor_count": len(ctors),
        "destructor_count": len(dtors),
        "dt_init": init_func_va,
        "init_array_section": init_array_section,
        "constructors": ctors,
        "destructors": dtors,
    }


def _extract_relocations(binary: Any, filter_str: str | None = None, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    relocs_list = []
    reloc_type_counts: dict[str, int] = {}
    total_relocs = 0

    try:
        for rel in binary.relocations:
            total_relocs += 1
            type_str = str(rel.type).replace("RELOCATION_ARM.", "").replace("RELOCATION_AARCH64.", "").replace("RELOCATION_X86_64.", "").replace("RELOCATION_i386.", "").replace("TYPE.", "")
            reloc_type_counts[type_str] = reloc_type_counts.get(type_str, 0) + 1
            sym_name = None
            if rel.has_symbol and rel.symbol:
                sym_name = rel.symbol.name

            if filter_str:
                if filter_str.lower() not in type_str.lower() and (not sym_name or filter_str.lower() not in sym_name.lower()):
                    continue

            file_off = None
            try:
                res = binary.virtual_address_to_offset(rel.address)
                if isinstance(res, int) and not isinstance(res, bool):
                    file_off = res
            except Exception:
                pass

            is_relative = "RELATIVE" in type_str.upper() or "RELR" in type_str.upper() or getattr(rel, "is_relatively_encoded", False)
            is_packed = getattr(rel, "is_android_packed", False)

            relocs_list.append({
                "address": _format_hex(rel.address),
                "file_offset": _format_hex(file_off),
                "type": type_str,
                "addend": rel.addend if hasattr(rel, "addend") else 0,
                "symbol": sym_name,
                "is_relative": is_relative,
                "is_android_packed": is_packed,
            })
    except Exception:
        pass
    paged = relocs_list[offset : offset + limit]
    return {
        "total_relocations": total_relocs,
        "matched_relocations": len(relocs_list),
        "type_counts": reloc_type_counts,
        "limit": limit,
        "offset": offset,
        "relocations": paged,
    }


def _extract_sections(binary: Any, filter_str: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    secs = []
    for idx, sec in enumerate(binary.sections):
        sec_name = sec.name
        if filter_str and filter_str.lower() not in sec_name.lower():
            continue

        sec_type = str(sec.type).replace("SECTION_TYPES.", "").replace("TYPE.", "")
        entropy = 0.0
        try:
            entropy = round(float(sec.entropy), 3)
        except Exception:
            pass

        secs.append({
            "index": idx,
            "name": sec_name,
            "type": sec_type,
            "virtual_address": _format_hex(sec.virtual_address),
            "file_offset": _format_hex(sec.offset),
            "size": sec.size,
            "alignment": sec.alignment,
            "entropy": entropy,
        })

    total = len(secs)
    paged = secs[offset : offset + limit]
    return {
        "total_sections": total,
        "limit": limit,
        "offset": offset,
        "sections": paged,
    }


def _extract_symbols(binary: Any, filter_str: str | None = None, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    symbols = []
    exported_names = set()
    try:
        for exp in binary.exported_symbols:
            exported_names.add(exp.name)
    except Exception:
        pass

    imported_names = set()
    try:
        for imp in binary.imported_symbols:
            imported_names.add(imp.name)
    except Exception:
        pass

    try:
        for sym in binary.symbols:
            name = sym.name
            if not name:
                continue
            if filter_str and filter_str.lower() not in name.lower():
                continue

            symbols.append({
                "name": name,
                "value": _format_hex(sym.value),
                "size": sym.size,
                "type": str(sym.type).replace("ELF_SYMBOL_TYPES.", ""),
                "binding": str(sym.binding).replace("SYMBOL_BINDINGS.", ""),
                "visibility": str(sym.visibility).replace("SYMBOL_VISIBILITY.", ""),
                "is_exported": name in exported_names,
                "is_imported": name in imported_names,
            })
    except Exception:
        pass

    total = len(symbols)
    paged = symbols[offset : offset + limit]
    return {
        "total_symbols": total,
        "limit": limit,
        "offset": offset,
        "symbols": paged,
    }


def _map_address(binary: Any, va_int: int | None, file_off_int: int | None) -> dict[str, Any]:
    res: dict[str, Any] = {}
    if va_int is not None:
        file_offset = None
        seg_info = None
        sec_info = None

        try:
            v2o = binary.virtual_address_to_offset(va_int)
            if isinstance(v2o, int) and not isinstance(v2o, bool):
                file_offset = v2o
        except Exception:
            pass
        try:
            seg = binary.segment_from_virtual_address(va_int)
            if seg:
                seg_info = {
                    "type": str(seg.type).replace("SEGMENT_TYPES.", ""),
                    "virtual_address": _format_hex(seg.virtual_address),
                    "file_offset": _format_hex(seg.file_offset),
                    "virtual_size": seg.virtual_size,
                    "offset_in_segment": va_int - seg.virtual_address,
                }
        except Exception:
            pass

        try:
            sec = binary.section_from_virtual_address(va_int)
            if sec:
                sec_info = {
                    "name": sec.name,
                    "virtual_address": _format_hex(sec.virtual_address),
                    "file_offset": _format_hex(sec.offset),
                    "size": sec.size,
                    "offset_in_section": va_int - sec.virtual_address,
                }
        except Exception:
            pass

        res["address_to_file"] = {
            "virtual_address": _format_hex(va_int),
            "file_offset": _format_hex(file_offset),
            "containing_segment": seg_info,
            "containing_section": sec_info,
        }

    if file_off_int is not None:
        va = None
        seg_info = None
        sec_info = None

        try:
            o2v = binary.offset_to_virtual_address(file_off_int)
            if isinstance(o2v, int) and not isinstance(o2v, bool):
                va = o2v
        except Exception:
            pass
        try:
            seg = binary.segment_from_offset(file_off_int)
            if seg:
                seg_info = {
                    "type": str(seg.type).replace("SEGMENT_TYPES.", ""),
                    "virtual_address": _format_hex(seg.virtual_address),
                    "file_offset": _format_hex(seg.file_offset),
                    "virtual_size": seg.virtual_size,
                }
        except Exception:
            pass

        try:
            sec = binary.section_from_offset(file_off_int)
            if sec:
                sec_info = {
                    "name": sec.name,
                    "virtual_address": _format_hex(sec.virtual_address),
                    "file_offset": _format_hex(sec.offset),
                    "size": sec.size,
                }
        except Exception:
            pass

        res["file_to_address"] = {
            "file_offset": _format_hex(file_off_int),
            "virtual_address": _format_hex(va),
            "containing_segment": seg_info,
            "containing_section": sec_info,
        }

    return res


def handle_query(req: dict[str, Any]) -> dict[str, Any]:
    import lief

    file_path = req.get("path")
    if not file_path or not os.path.exists(file_path):
        return {"status": "error", "error": f"Target file not found: {file_path}"}

    query_type = req.get("query_type", "info")
    filter_str = req.get("filter")
    limit = min(max(req.get("limit", 50), 1), 500)
    offset = max(req.get("offset", 0), 0)
    va_param = _parse_int(req.get("address"))
    file_off_param = _parse_int(req.get("file_offset"))

    try:
        binary = lief.parse(file_path)
    except Exception as e:
        return {"status": "error", "error": f"Failed to parse ELF file with LIEF: {e}"}

    if not binary or not isinstance(binary, lief.ELF.Binary):
        return {"status": "error", "error": f"File is not a valid ELF binary: {file_path}"}

    details: dict[str, Any] = {
        "path": file_path,
        "query_type": query_type,
    }

    if query_type in ("info", "all"):
        details["header"] = _extract_header(binary)
        details["identity"] = {
            "has_interpreter": binary.has_interpreter,
            "interpreter": binary.interpreter if binary.has_interpreter else None,
            "total_segments": len(binary.segments),
            "total_sections": len(binary.sections),
            "total_dynamic_entries": len(binary.dynamic_entries),
            "total_relocations": len(binary.relocations),
            "has_constructors": len(binary.ctor_functions) > 0,
        }
        details["constructors_summary"] = {
            "count": len(binary.ctor_functions),
        }

    if query_type == "segments":
        details["segments"] = _extract_segments(binary, filter_str, limit, offset)
    elif query_type == "dynamic":
        details["dynamic"] = _extract_dynamic(binary, filter_str, limit, offset)
    elif query_type == "constructors":
        details["constructors"] = _extract_constructors(binary)
    elif query_type == "relocations":
        details["relocations"] = _extract_relocations(binary, filter_str, limit, offset)
    elif query_type == "sections":
        details["sections"] = _extract_sections(binary, filter_str, limit, offset)
    elif query_type == "symbols":
        details["symbols"] = _extract_symbols(binary, filter_str, limit, offset)
    elif query_type == "address_map":
        details["address_map"] = _map_address(binary, va_param, file_off_param)
    elif query_type == "all":
        details["segments"] = _extract_segments(binary, filter_str, limit=20, offset=0)
        details["dynamic"] = _extract_dynamic(binary, filter_str, limit=20, offset=0)
        details["constructors"] = _extract_constructors(binary)
        details["relocations"] = _extract_relocations(binary, filter_str, limit=20, offset=0)
        if va_param is not None or file_off_param is not None:
            details["address_map"] = _map_address(binary, va_param, file_off_param)

    return {
        "status": "ok",
        "result": details,
    }


def handle_validate(req: dict[str, Any]) -> dict[str, Any]:
    import lief

    file_path = req.get("path")
    if not file_path or not os.path.exists(file_path):
        return {"status": "error", "error": f"Candidate file not found: {file_path}"}

    file_size = os.path.getsize(file_path)
    if file_size < 52:
        return {
            "status": "ok",
            "result": {
                "candidate_valid": False,
                "is_analyzable": False,
                "is_runnable": False,
                "fatal_error": f"Candidate file too small for ELF header ({file_size} bytes)",
                "risks": ["File size is smaller than minimal ELF header"],
            },
        }

    try:
        binary = lief.parse(file_path)
    except Exception as e:
        return {
            "status": "ok",
            "result": {
                "candidate_valid": False,
                "is_analyzable": False,
                "is_runnable": False,
                "fatal_error": f"LIEF structural parse failed: {e}",
                "risks": ["Malformed ELF structures rejected by LIEF parser"],
            },
        }

    if not binary or not isinstance(binary, lief.ELF.Binary):
        return {
            "status": "ok",
            "result": {
                "candidate_valid": False,
                "is_analyzable": False,
                "is_runnable": False,
                "fatal_error": "LIEF did not recognize candidate as an ELF binary",
                "risks": ["File is not an ELF binary"],
            },
        }

    risks: list[str] = []
    header = _extract_header(binary)
    load_segments = [s for s in binary.segments if "LOAD" in str(s.type)]

    if not load_segments:
        risks.append("No PT_LOAD segments found in binary")

    # Page alignment verification
    max_align = 0
    alignment_mismatch = False
    for load in load_segments:
        align = load.alignment
        if align > max_align:
            max_align = align
        if align > 0:
            if (load.virtual_address % align) != (load.file_offset % align):
                alignment_mismatch = True

    if alignment_mismatch:
        risks.append("PT_LOAD segment (vaddr % align) != (offset % align): loader page-mapping constraint violated")

    # Android 15 ARM64 16KB page size compatibility check
    if header["machine"] in ("AARCH64", "ARM64"):
        if max_align > 0 and max_align < 16384:
            risks.append(
                f"ARM64 ELF segment alignment is 0x{max_align:x} (< 16KB). Android 15+ devices with 16KB page size require 16KB (0x4000) or 64KB alignment; dynamic linker may refuse to load."
            )

    # Dynamic entries check
    has_dynamic = any("DYNAMIC" in str(s.type) for s in binary.segments)
    if not has_dynamic and not binary.dynamic_entries:
        risks.append("No PT_DYNAMIC segment or dynamic entries found; symbol resolution may be impaired")

    # Relocations sanity check
    out_of_bounds_relocs = 0
    try:
        min_va = min(s.virtual_address for s in load_segments) if load_segments else 0
        max_va = max(s.virtual_address + s.virtual_size for s in load_segments) if load_segments else 0

        for r in binary.relocations:
            if r.address < min_va or r.address >= max_va:
                out_of_bounds_relocs += 1
    except Exception:
        pass

    if out_of_bounds_relocs > 0:
        risks.append(f"Detected {out_of_bounds_relocs} relocation entries with target address outside PT_LOAD virtual span")

    candidate_valid = len(load_segments) > 0 and not alignment_mismatch and out_of_bounds_relocs == 0

    return {
        "status": "ok",
        "result": {
            "candidate_valid": candidate_valid,
            "is_analyzable": True,
            "is_runnable": False,
            "analyzable_notice": "Analyzable candidate only. Runtime execution is not certified due to reconstructed headers, potential stripped tables, or displaced memory state.",
            "header": header,
            "total_segments": len(binary.segments),
            "load_segments_count": len(load_segments),
            "max_segment_alignment": _format_hex(max_align),
            "total_sections": len(binary.sections),
            "total_dynamic_entries": len(binary.dynamic_entries),
            "total_relocations": len(binary.relocations),
            "total_constructors": len(binary.ctor_functions),
            "risks": risks,
        },
    }


def main() -> None:
    try:
        raw_input = sys.stdin.read()
        if not raw_input:
            sys.stdout.write(json.dumps({"status": "error", "error": "Empty stdin request"}))
            sys.stdout.flush()
            return

        req = json.loads(raw_input)
        action = req.get("action", "query")

        if action == "probe":
            resp = handle_probe(req)
        elif action == "query":
            resp = handle_query(req)
        elif action == "validate":
            resp = handle_validate(req)
        else:
            resp = {"status": "error", "error": f"Unknown action: {action}"}

        sys.stdout.write(json.dumps(resp, ensure_ascii=False))
        sys.stdout.flush()
    except Exception as e:
        sys.stdout.write(json.dumps({"status": "error", "error": str(e), "traceback": traceback.format_exc()}))
        sys.stdout.flush()


if __name__ == "__main__":
    main()
