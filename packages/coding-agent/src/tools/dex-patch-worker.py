# -*- coding: utf-8 -*-
from __future__ import annotations

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 apk-reverse contributors
# Adapted from apk-reverse dex_patch_bytes.py & dex_check_verifier.py (commit bd6dd0c59ce1f9af75f1293ef9518fb6f5d28c6c)
"""Structured JSON worker for dex_patch tool actions: inspect, validate, patch.

Dispatches actions over stdin/stdout JSON protocol:
- inspect: locates methods, decodes bytecode, extracts branch targets and CFG details.
- validate: limited structural verifier (header integrity, instruction alignment, move-result CFG edges).
- patch: applies equal-length bytecode patches with multi-patch cumulative tracking,
  polarity assertion, verifier safety checks, SHA-1 + Adler-32 recomputation, and byte-diff reports.
"""

import json
import os
import struct
import sys
import tempfile
from dexutil import (
    Dex, IF_TEST, IF_TESTZ, INVOKE_OPS, MOVE_RESULT_OPS, RETURN_OPS,
    IFIELD_OPS, SFIELD_OPS, PFIELD_OPS,
    fix_dex_header, insn_units, load_dex, s32, u16, u32, verify_dex_header
)


def _normalize_class_name(name):
    if not name:
        return ""
    name = name.strip()
    if name.startswith("L") and name.endswith(";"):
        return name
    clean = name.replace(".", "/")
    return "L" + clean + ";"


def _kind_of(insn):
    if insn.get("is_payload"):
        return "payload"
    op = insn["op"]
    if op in IF_TEST:
        return "if-test"
    if op in IF_TESTZ:
        return "if-testz"
    if op in INVOKE_OPS:
        return "invoke"
    if op in RETURN_OPS:
        return "return"
    if op in MOVE_RESULT_OPS:
        return "move-result"
    if op == 0x12:
        return "const4"
    if op == 0x00:
        return "nop"
    return insn["name"]


def _matches(dex, insn, crit, code_off=None):
    if crit is None:
        return True

    # Pseudo-instruction payloads are data, never matching code match criteria
    if insn.get("is_payload"):
        return False

    op = insn["op"]

    # 1. Kind match (if explicitly specified)
    want = crit.get("kind")
    if want:
        if want == "if-test" and op not in IF_TEST:
            return False
        elif want == "if-testz" and op not in IF_TESTZ:
            return False
        elif want == "invoke" and op not in INVOKE_OPS:
            return False
        elif want == "return" and op not in RETURN_OPS:
            return False
        elif want == "move-result" and op not in MOVE_RESULT_OPS:
            return False
        elif want == "const4" and op != 0x12:
            return False
        elif want == "nop" and op != 0x00:
            return False
        elif want not in ("if-test", "if-testz", "invoke", "return", "move-result", "const4", "nop"):
            if insn["name"] != want:
                return False

    # 2. Raw bytes match
    raw_eq = crit.get("bytes")
    if raw_eq and insn["raw"].hex().lower() != raw_eq.replace(" ", "").lower():
        return False

    # 3. Literal match (const4 format 11n: B|A|op; B is high nibble, A is low nibble)
    if "literal" in crit and crit["literal"] is not None:
        if op != 0x12:
            return False  # literal specified but instruction is not const/4
        # High nibble is signed 4-bit literal
        raw_val = (insn["raw"][1] >> 4) & 0x0F
        signed_val = raw_val - 16 if raw_val > 7 else raw_val
        if signed_val != crit["literal"]:
            return False

    # 4. Target register match
    if "target_reg" in crit and crit["target_reg"] is not None:
        treg = crit["target_reg"]
        if op in IF_TEST:
            # 22t: low nibble A, high nibble B
            if treg not in (insn["raw"][1] & 0x0F, insn["raw"][1] >> 4):
                return False
        elif op in IF_TESTZ:
            # 21t: full byte AA
            if treg != insn["raw"][1]:
                return False
        elif op == 0x12:
            # 11n: low nibble A is destination register
            if treg != (insn["raw"][1] & 0x0F):
                return False
        elif op in (0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11):
            # 11x: full byte AA is register
            if treg != insn["raw"][1]:
                return False
        elif op in (0x01, 0x04, 0x07):
            # 12x: low nibble A, high nibble B
            if treg not in (insn["raw"][1] & 0x0F, insn["raw"][1] >> 4):
                return False
        elif op in IFIELD_OPS or op in PFIELD_OPS:
            # 22c: low nibble value/dest, high nibble object
            if treg not in (insn["raw"][1] & 0x0F, insn["raw"][1] >> 4):
                return False
        elif op in SFIELD_OPS:
            # 21c: full byte AA is value/dest register
            if treg != insn["raw"][1]:
                return False
        else:
            return False  # instruction does not have a register operand

    # 5. Method invoke target match (target_class / target_method)
    has_target_class = bool(crit.get("target_class"))
    has_target_method = bool(crit.get("target_method"))
    if has_target_class or has_target_method:
        if op not in INVOKE_OPS:
            return False
        midx = struct.unpack_from("<H", insn["raw"], 2)[0]
        cls, nm, _ds = dex.method(midx)
        if has_target_class:
            norm_cls = _normalize_class_name(crit["target_class"])
            if cls != norm_cls:
                return False
        if has_target_method:
            if nm != crit["target_method"]:
                return False

    # 6. Field access target match (target_reads_field_of / target_field)
    has_field_cls = bool(crit.get("target_reads_field_of"))
    has_field_nm = bool(crit.get("target_field"))
    if has_field_cls or has_field_nm:
        # Branch gate: checks if branch target instruction reads field
        if op in IF_TEST or op in IF_TESTZ:
            if code_off is None:
                return False
            tgt = dex.branch_target(insn)
            if tgt is None:
                return False
            t_insn = dex.insn_at(code_off, tgt)
            if t_insn is None or t_insn["op"] not in IFIELD_OPS and t_insn["op"] not in SFIELD_OPS:
                return False
            fidx = struct.unpack_from("<H", t_insn["raw"], 2)[0]
            f_cls, f_nm, _f_ty = dex.field(fidx)
            if has_field_cls and f_cls != _normalize_class_name(crit["target_reads_field_of"]):
                return False
            if has_field_nm and f_nm != crit["target_field"]:
                return False
        elif op in IFIELD_OPS or op in SFIELD_OPS:
            fidx = struct.unpack_from("<H", insn["raw"], 2)[0]
            f_cls, f_nm, _f_ty = dex.field(fidx)
            if has_field_cls and f_cls != _normalize_class_name(crit["target_reads_field_of"]):
                return False
            if has_field_nm and f_nm != crit["target_field"]:
                return False
        else:
            return False

    return True


def _find_site(dex, code_off, spec):
    insns = list(dex.decode(code_off))
    hits = [i for i in insns if _matches(dex, i, spec.get("match"), code_off)]

    ordv = spec.get("match", {}).get("ordinal")
    if ordv is not None:
        if 0 <= ordv < len(hits):
            return hits[ordv], insns
        return ("ordinal_out_of_bounds", len(hits), ordv), insns

    if len(hits) == 1:
        return hits[0], insns
    if not hits:
        return None, insns

    return ("ambiguous", hits), insns


def _verifier_report(dex, code_off):
    """Verify CFG and structural legality for one method body.

    Checks:
    1. Direct branch bounds & instruction start alignment.
    2. Branch destination cannot be a pseudo-instruction payload.
    3. Switch payloads must be 4-byte aligned and inside method bounds.
       Switch targets (relative to switch instruction) must land on valid instruction starts.
    4. Producer adjacency: move-result / move-result-wide must be immediately preceded by invoke.
       move-result-object must be immediately preceded by invoke or filled-new-array[/range].
       A nop between invoke and move-result is ILLEGAL.
    5. Branch into move-result: no branch or switch target may land on a move-result* instruction.
    """
    findings = []
    insns = list(dex.decode(code_off))
    if not insns:
        return findings

    info = dex.code_info(code_off)
    insns_start = info["insns_off"]
    insns_end = insns_start + info["insns_size"] * 2

    insn_by_off = {i["off"]: i for i in insns}
    insn_offsets = set(insn_by_off.keys())

    payload_offsets = {i["off"] for i in insns if i.get("is_payload")}
    move_result_offsets = {i["off"] for i in insns if i["op"] in MOVE_RESULT_OPS}

    # 1. Producer adjacency
    INVOKE_SET = set(INVOKE_OPS)
    FILLED_ARRAY_SET = {0x24, 0x25}  # filled-new-array, filled-new-array/range

    for idx, insn in enumerate(insns):
        op = insn["op"]
        if op in (0x0A, 0x0B):  # move-result, move-result-wide
            if idx == 0:
                findings.append({
                    "branch_off": insn["off"],
                    "target_off": insn["off"],
                    "branch_op": insn["name"],
                    "is_conditional": False,
                    "detail": f"{insn['name']} at start of method has no producing invoke",
                })
            else:
                prev = insns[idx - 1]
                if prev["op"] not in INVOKE_SET:
                    findings.append({
                        "branch_off": prev["off"],
                        "target_off": insn["off"],
                        "branch_op": prev["name"],
                        "is_conditional": False,
                        "detail": f"{insn['name']} at 0x{insn['off']:x} preceded by {prev['name']} (0x{prev['off']:x}), not invoke",
                    })
        elif op == 0x0C:  # move-result-object
            if idx == 0:
                findings.append({
                    "branch_off": insn["off"],
                    "target_off": insn["off"],
                    "branch_op": insn["name"],
                    "is_conditional": False,
                    "detail": "move-result-object at start of method has no producer",
                })
            else:
                prev = insns[idx - 1]
                if prev["op"] not in INVOKE_SET and prev["op"] not in FILLED_ARRAY_SET:
                    findings.append({
                        "branch_off": prev["off"],
                        "target_off": insn["off"],
                        "branch_op": prev["name"],
                        "is_conditional": False,
                        "detail": f"move-result-object at 0x{insn['off']:x} preceded by {prev['name']} (0x{prev['off']:x}), not invoke/filled-new-array",
                    })

    # 2. Branch targets check (direct branches + switches)
    for insn in insns:
        op = insn["op"]
        pos = insn["off"]
        # Handle packed-switch (0x2B) and sparse-switch (0x2C)
        if op in (0x2B, 0x2C):
            s_offset = s32(u32(dex.d, pos + 2))
            payload_off = pos + s_offset * 2
            # Check 4-byte payload alignment
            if payload_off % 4 != 0:
                findings.append({
                    "branch_off": pos,
                    "target_off": payload_off,
                    "branch_op": insn["name"],
                    "is_conditional": False,
                    "detail": f"{insn['name']} payload at 0x{payload_off:x} is not 4-byte aligned",
                })
            if payload_off < insns_start or payload_off >= insns_end:
                findings.append({
                    "branch_off": pos,
                    "target_off": payload_off,
                    "branch_op": insn["name"],
                    "is_conditional": False,
                    "detail": f"{insn['name']} payload at 0x{payload_off:x} is outside method body",
                })
            elif payload_off in insn_by_off:
                p_insn = insn_by_off[payload_off]
                if not p_insn.get("is_payload"):
                    findings.append({
                        "branch_off": pos,
                        "target_off": payload_off,
                        "branch_op": insn["name"],
                        "is_conditional": False,
                        "detail": f"{insn['name']} target 0x{payload_off:x} is not a switch payload",
                    })
                else:
                    # Switch targets are relative to the SWITCH instruction offset pos
                    p_raw = p_insn["raw"]
                    if op == 0x2B and len(p_raw) >= 8:
                        size = u16(p_raw, 2)
                        for k in range(size):
                            if 8 + (k + 1) * 4 <= len(p_raw):
                                target_delta = s32(u32(p_raw, 8 + k * 4))
                                case_target = pos + target_delta * 2
                                if case_target not in insn_offsets:
                                    findings.append({
                                        "branch_off": pos,
                                        "target_off": case_target,
                                        "branch_op": "packed-switch-case",
                                        "is_conditional": True,
                                        "detail": f"packed-switch case target 0x{case_target:x} is not a valid instruction boundary",
                                    })
                                elif case_target in move_result_offsets:
                                    findings.append({
                                        "branch_off": pos,
                                        "target_off": case_target,
                                        "branch_op": "packed-switch-case",
                                        "is_conditional": True,
                                        "detail": f"packed-switch case target lands on move-result at 0x{case_target:x}",
                                    })
                                elif case_target in payload_offsets:
                                    findings.append({
                                        "branch_off": pos,
                                        "target_off": case_target,
                                        "branch_op": "packed-switch-case",
                                        "is_conditional": True,
                                        "detail": f"packed-switch case target lands on payload at 0x{case_target:x}",
                                    })
                    elif op == 0x2C and len(p_raw) >= 4:
                        size = u16(p_raw, 2)
                        keys_end = 4 + size * 4
                        for k in range(size):
                            t_off = keys_end + k * 4
                            if t_off + 4 <= len(p_raw):
                                target_delta = s32(u32(p_raw, t_off))
                                case_target = pos + target_delta * 2
                                if case_target not in insn_offsets:
                                    findings.append({
                                        "branch_off": pos,
                                        "target_off": case_target,
                                        "branch_op": "sparse-switch-case",
                                        "is_conditional": True,
                                        "detail": f"sparse-switch case target 0x{case_target:x} is not a valid instruction boundary",
                                    })
                                elif case_target in move_result_offsets:
                                    findings.append({
                                        "branch_off": pos,
                                        "target_off": case_target,
                                        "branch_op": "sparse-switch-case",
                                        "is_conditional": True,
                                        "detail": f"sparse-switch case target lands on move-result at 0x{case_target:x}",
                                    })
                                elif case_target in payload_offsets:
                                    findings.append({
                                        "branch_off": pos,
                                        "target_off": case_target,
                                        "branch_op": "sparse-switch-case",
                                        "is_conditional": True,
                                        "detail": f"sparse-switch case target lands on payload at 0x{case_target:x}",
                                    })

        # Regular branches (if-test, if-testz, goto, goto/16, goto/32)
        tgt = dex.branch_target(insn)
        if tgt is not None:
            if tgt not in insn_offsets:
                findings.append({
                    "branch_off": pos,
                    "target_off": tgt,
                    "branch_op": insn["name"],
                    "is_conditional": (op in IF_TEST or op in IF_TESTZ),
                    "detail": f"Branch 0x{pos:x} ({insn['name']}) targets 0x{tgt:x} which is not a valid instruction boundary",
                })
            elif tgt in move_result_offsets:
                findings.append({
                    "branch_off": pos,
                    "target_off": tgt,
                    "branch_op": insn["name"],
                    "is_conditional": (op in IF_TEST or op in IF_TESTZ),
                    "detail": f"Branch 0x{pos:x} ({insn['name']}) targets move-result at 0x{tgt:x}",
                })
            elif tgt in payload_offsets:
                findings.append({
                    "branch_off": pos,
                    "target_off": tgt,
                    "branch_op": insn["name"],
                    "is_conditional": (op in IF_TEST or op in IF_TESTZ),
                    "detail": f"Branch 0x{pos:x} ({insn['name']}) targets payload at 0x{tgt:x}",
                })

    return findings


def _describe_neighbours(dex, code_off, target_off, span=3):
    insns = list(dex.decode(code_off))
    idx = None
    for i, insn in enumerate(insns):
        if insn["off"] == target_off:
            idx = i
            break
    if idx is None:
        return [], None, []
    before = insns[max(0, idx - span):idx]
    after = insns[idx + 1:idx + 1 + span]
    return before, insns[idx], after


def do_inspect(req):
    target = req.get("path") or req.get("target")
    if not target:
        raise ValueError("Parameter 'path' is required for inspect")
    entry = req.get("entry")
    cls_param = req.get("class")
    if not cls_param:
        raise ValueError("Parameter 'class' is required for inspect")
    method_name = req.get("method")
    if not method_name:
        raise ValueError("Parameter 'method' is required for inspect")
    desc = req.get("desc")

    dex, entry_name = load_dex(target, entry)
    fqcn = _normalize_class_name(cls_param)

    if desc:
        found = dex.find_method(fqcn, method_name, desc)
        if not found:
            try:
                available = [
                    f"{nm}{ds}" for _s, _idx, _c, nm, ds, _co in dex.methods_of(fqcn)
                ]
            except Exception:
                available = []
            raise RuntimeError(
                f"Method not found: {fqcn}->{method_name}{desc}. Available in class: {available}"
            )
        section, midx, code_off = found
    else:
        overloads = dex.find_methods_named(fqcn, method_name)
        if not overloads:
            try:
                available = [
                    f"{nm}{ds}" for _s, _idx, _c, nm, ds, _co in dex.methods_of(fqcn)
                ]
            except Exception:
                available = []
            raise RuntimeError(
                f"Method not found: {fqcn}->{method_name}. Available in class: {available}"
            )
        if len(overloads) > 1:
            descriptors = [d for _s, _i, d, _c in overloads]
            raise RuntimeError(
                f"Method {fqcn}->{method_name} has {len(overloads)} overloads. Specify 'desc' to disambiguate: {descriptors}"
            )
        section, midx, desc, code_off = overloads[0]

    if code_off == 0:
        return {
            "ok": True,
            "action": "inspect",
            "path": target,
            "entry": entry_name,
            "method": {
                "class": fqcn,
                "name": method_name,
                "desc": desc,
                "section": section,
                "method_idx": midx,
                "code_off": 0,
                "is_abstract_or_native": True,
                "instructions": [],
            },
        }

    info = dex.code_info(code_off)
    insns, clean, expected_end = dex.decode_all(code_off)
    branch_targets = dex.all_targets(code_off)
    verifier_violations = _verifier_report(dex, code_off)

    formatted_insns = []
    for insn in insns:
        tgt = dex.branch_target(insn)
        formatted_insns.append({
            "off": insn["off"],
            "offset_hex": "0x%x" % insn["off"],
            "op": insn["op"],
            "op_hex": "0x%02x" % insn["op"],
            "units": insn["units"],
            "name": insn["name"],
            "raw_hex": insn["raw"].hex(),
            "disassembly": dex.describe(insn),
            "branch_target": tgt,
            "branch_target_hex": ("0x%x" % tgt) if tgt is not None else None,
            "is_branch_target": (insn["off"] in branch_targets),
        })

    return {
        "ok": True,
        "action": "inspect",
        "path": target,
        "entry": entry_name,
        "method": {
            "class": fqcn,
            "name": method_name,
            "desc": desc,
            "section": section,
            "method_idx": midx,
            "code_off": code_off,
            "code_off_hex": "0x%x" % code_off,
            "registers": info["registers"],
            "ins": info["ins"],
            "outs": info["outs"],
            "tries": info["tries"],
            "insns_size": info["insns_size"],
            "insns_off": info["insns_off"],
            "insns_off_hex": "0x%x" % info["insns_off"],
            "instruction_count": len(insns),
            "clean_decode": clean,
            "expected_end_hex": "0x%x" % expected_end,
            "branch_targets": sorted(list(branch_targets)),
            "verifier_violations": verifier_violations,
            "instructions": formatted_insns,
        },
    }


def do_validate(req):
    target = req.get("path") or req.get("target")
    if not target:
        raise ValueError("Parameter 'path' is required for validate")
    entry = req.get("entry")
    class_filter = req.get("class")

    dex, entry_name = load_dex(target, entry)
    problems = dex.check()
    checksum_ok, signature_ok = verify_dex_header(dex.d)

    total_classes = 0
    total_methods = 0
    methods_with_code = 0
    unclean_methods = []
    verifier_violations = []

    filter_norm = _normalize_class_name(class_filter) if class_filter else None

    for fqcn in dex.class_names():
        if filter_norm and filter_norm != fqcn:
            continue
        total_classes += 1
        try:
            methods = list(dex.methods_of(fqcn))
        except Exception:
            continue
        for section, midx, _c, name, desc, code_off in methods:
            total_methods += 1
            if code_off == 0:
                continue
            methods_with_code += 1
            _insns, clean, expected = dex.decode_all(code_off)
            if not clean:
                unclean_methods.append({
                    "class": fqcn,
                    "method": name,
                    "desc": desc,
                    "code_off": code_off,
                    "expected_end": expected,
                })
            edges = _verifier_report(dex, code_off)
            if edges:
                for edge in edges:
                    verifier_violations.append({
                        "class": fqcn,
                        "method": name,
                        "desc": desc,
                        **edge,
                    })

    return {
        "ok": True,
        "action": "validate",
        "path": target,
        "entry": entry_name,
        "verifier_scope": "Limited structural verifier, never full ART verification",
        "header": {
            "valid": len(problems) == 0 and checksum_ok and signature_ok,
            "checksum_ok": checksum_ok,
            "signature_ok": signature_ok,
            "file_size": len(dex.d),
            "problems": problems,
        },
        "summary": {
            "total_classes": total_classes,
            "total_methods": total_methods,
            "methods_with_code": methods_with_code,
            "unclean_decodes": len(unclean_methods),
            "verifier_violations": len(verifier_violations),
        },
        "violations": verifier_violations[:50],
        "unclean_methods": unclean_methods[:50],
    }


def _apply_replace(data, insn, repl):
    if not repl or not isinstance(repl, dict):
        raise ValueError("Spec 'replace' field must be an object with kind='nops' or kind='bytes'")
    kind = repl.get("kind")
    if kind == "nops":
        return b"\x00" * len(insn["raw"])
    if kind == "bytes":
        raw_hex = repl.get("bytes", "").replace(" ", "")
        if not raw_hex:
            raise ValueError("Replacement bytes must not be empty")
        return bytes.fromhex(raw_hex)
    raise ValueError(f"Unsupported replacement kind: {kind} (expected 'nops' or 'bytes')")


def _verify_instruction_units(new_bytes):
    """Verify that the replacement bytes decode cleanly into instruction units."""
    pos = 0
    span = len(new_bytes)
    while pos < span:
        op = new_bytes[pos]
        units = insn_units(op, new_bytes, pos, span)
        if units < 1 or pos + units * 2 > span:
            return False
        pos += units * 2
    return pos == span


def do_patch(req):
    target = req.get("path") or req.get("target")
    if not target:
        raise ValueError("Parameter 'path' is required for patch")
    entry = req.get("entry")
    out_path = req.get("out")
    dry_run = req.get("dry_run", True)
    specs = req.get("specs")

    if not specs or not isinstance(specs, list) or len(specs) == 0:
        raise ValueError("Non-empty patch specs list is required for action 'patch'")

    dex, entry_name = load_dex(target, entry)

    # Strict source verification: reject corrupt source before attempting patch
    checksum_ok, signature_ok = verify_dex_header(dex.d)
    if not (checksum_ok and signature_ok):
        raise RuntimeError(
            f"Refusing to patch source with corrupted header (checksum_ok={checksum_ok}, signature_ok={signature_ok})"
        )
    problems = dex.check()
    if problems:
        raise RuntimeError("Refusing to patch structurally broken source: " + "; ".join(problems))

    # Working copy of bytes that mutates cumulatively across all specs
    data = bytearray(dex.d)
    reports = []
    diff_records = []

    # Keep mutated DEX reader in sync so subsequent patches observe preceding edits
    mutated_dex = Dex(bytes(data), entry_name)

    for i, spec in enumerate(specs):
        label = spec.get("name") or f"patch_{i}"
        cls_raw = spec.get("class")
        if not cls_raw:
            raise ValueError(f"[{label}] Spec missing 'class'")
        fqcn = _normalize_class_name(cls_raw)
        method_name = spec.get("method")
        if not method_name:
            raise ValueError(f"[{label}] Spec missing 'method'")
        desc = spec.get("desc")

        # Resolve method against mutated_dex
        if desc:
            found = mutated_dex.find_method(fqcn, method_name, desc)
            if not found:
                raise RuntimeError(f"[{label}] Method not found: {fqcn}->{method_name}{desc}")
            section, midx, code_off = found
        else:
            overloads = mutated_dex.find_methods_named(fqcn, method_name)
            if not overloads:
                raise RuntimeError(f"[{label}] Method not found: {fqcn}->{method_name}")
            if len(overloads) > 1:
                descriptors = [d for _s, _i, d, _c in overloads]
                raise RuntimeError(
                    f"[{label}] Method {fqcn}->{method_name} has {len(overloads)} overloads. Specify 'desc': {descriptors}"
                )
            section, midx, desc, code_off = overloads[0]

        if code_off == 0:
            raise RuntimeError(f"[{label}] Cannot patch native or abstract method {fqcn}->{method_name}")

        site_result, _all_insns = _find_site(mutated_dex, code_off, spec)
        if site_result is None:
            raise RuntimeError(f"[{label}] No instruction matched spec['match'] in {fqcn}->{method_name}")
        if isinstance(site_result, tuple):
            if site_result[0] == "ordinal_out_of_bounds":
                total_hits, requested_ord = site_result[1], site_result[2]
                raise RuntimeError(
                    f"[{label}] match.ordinal {requested_ord} is out of bounds ({total_hits} matches found)"
                )
            if site_result[0] == "ambiguous":
                candidates_hex = ", ".join("0x%x" % h["off"] for h in site_result[1])
                raise RuntimeError(
                    f"[{label}] Match is ambiguous ({len(site_result[1])} hits: {candidates_hex}); tighten match criteria or specify match.ordinal"
                )

        site = site_result

        # Forbid patching pseudo-instruction payloads
        if site.get("is_payload"):
            raise RuntimeError(f"[{label}] Target site at 0x{site['off']:x} is a pseudo-instruction payload, not code")

        before, cur, after = _describe_neighbours(mutated_dex, code_off, site["off"])

        # Capture old disassembly from mutated_dex BEFORE applying mutation
        old_disassembly = mutated_dex.describe(cur)

        # Polarity check: assert immediate successor instruction
        exp = spec.get("expect_next")
        expect_next_ok = False
        if exp is not None:
            nxt = after[0] if after else None
            if nxt is None or not _matches(mutated_dex, nxt, exp, code_off):
                found_desc = mutated_dex.describe(nxt) if nxt else "<end-of-method>"
                raise RuntimeError(
                    f"[{label}] Polarity check failed: expect_next not satisfied after 0x{cur['off']:x}. Expected {exp}, found {found_desc}."
                )
            expect_next_ok = True

        new_bytes = _apply_replace(data, cur, spec.get("replace"))
        if len(new_bytes) != len(cur["raw"]):
            raise RuntimeError(
                f"[{label}] Replacement is {len(new_bytes)} bytes but target instruction is {len(cur['raw'])}. Equal length is required."
            )

        if not _verify_instruction_units(new_bytes):
            raise RuntimeError(
                f"[{label}] Replacement bytes ({new_bytes.hex()}) do not decode into aligned Dalvik instruction units."
            )

        # Apply edit to mutable data bytearray
        site_off = cur["off"]
        old_raw = bytes(data[site_off:site_off + len(new_bytes)])
        data[site_off:site_off + len(new_bytes)] = new_bytes

        # Update mutated_dex for subsequent verification and subsequent specs
        mutated_dex = Dex(bytes(data), entry_name)

        # Verify method decodes cleanly after edit
        _post_insns, clean, expected_end = mutated_dex.decode_all(code_off)
        if not clean:
            raise RuntimeError(
                f"[{label}] Method decode desynchronised after edit (ended at 0x{expected_end:x}). Instruction boundary corrupted."
            )

        # Verify verifier legality (CFG edges, move-result, payloads, bounds)
        verifier_edges = _verifier_report(mutated_dex, code_off)
        if verifier_edges:
            violation_strs = [
                e.get("detail") or f"0x{e['branch_off']:x}->0x{e['target_off']:x} ({e['branch_op']})"
                for e in verifier_edges
            ]
            raise RuntimeError(
                f"[{label}] Verifier legality violation: {'; '.join(violation_strs)}; class will fail ART loading (VerifyError)."
            )

        new_insn_probe = mutated_dex.insn_at(code_off, site_off)
        new_text = mutated_dex.describe(new_insn_probe) if new_insn_probe else new_bytes.hex()

        report_entry = {
            "name": label,
            "class": fqcn,
            "method": method_name,
            "desc": desc,
            "site_off": site_off,
            "site_off_hex": "0x%x" % site_off,
            "old_bytes": old_raw.hex(),
            "new_bytes": new_bytes.hex(),
            "old_text": old_disassembly,
            "new_text": new_text,
            "expect_next_ok": expect_next_ok,
            "before": [mutated_dex.describe(b) for b in before],
            "after": [mutated_dex.describe(a) for a in after],
        }
        reports.append(report_entry)

        diff_records.append({
            "offset": site_off,
            "offset_hex": "0x%x" % site_off,
            "length": len(new_bytes),
            "old_bytes": old_raw.hex(),
            "new_bytes": new_bytes.hex(),
            "method": f"{fqcn}->{method_name}{desc}",
            "old_disassembly": old_disassembly,
            "new_disassembly": new_text,
        })

    # Dry-run finishes after simulating all specs and verifications without writing
    if dry_run:
        return {
            "ok": True,
            "action": "patch",
            "dry_run": True,
            "input_path": target,
            "input_entry": entry_name,
            "output_path": None,
            "patches_count": len(reports),
            "patches": reports,
            "byte_diffs": diff_records,
            "verifier_notice": "Limited structural verifier passed (header integrity, instruction bounds, CFG move-result adjacency). Not full ART runtime verification.",
        }

    # Non-dry-run requires explicit output path
    if not out_path:
        raise ValueError("Parameter 'out' is required for writes (dry_run: false)")

    # Recompute header signature (SHA-1) first, then checksum (Adler-32)
    header_info = fix_dex_header(data)
    checksum_ok, signature_ok = verify_dex_header(bytes(data))
    if not (checksum_ok and signature_ok):
        raise RuntimeError("FATAL: Recomputed DEX header failed self-verification")

    # Post-validation on final published byte stream
    final_dex = Dex(bytes(data), entry_name)
    final_problems = final_dex.check()
    if final_problems:
        raise RuntimeError("FATAL: Post-validation failed on patched DEX: " + "; ".join(final_problems))

    # Write output DEX file atomically with exclusive no-clobber guarantee
    out_dir = os.path.dirname(os.path.abspath(out_path)) or "."
    os.makedirs(out_dir, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out_dir) as staging_dir:
        temp_out = os.path.join(staging_dir, "patched.dex")
        with open(temp_out, "wb") as fh:
            fh.write(bytes(data))
            fh.flush()
            os.fsync(fh.fileno())

        # Atomic link guarantees exclusive publish without clobbering existing target
        try:
            os.link(temp_out, out_path)
        except FileExistsError:
            raise RuntimeError(f"Output file already exists (no-clobber): {out_path}")
    return {
        "ok": True,
        "action": "patch",
        "dry_run": False,
        "input_path": target,
        "input_entry": entry_name,
        "output_path": out_path,
        "patches_count": len(reports),
        "patches": reports,
        "header_change": {
            "before_checksum": "0x%08x" % header_info["before_checksum"],
            "after_checksum": "0x%08x" % header_info["after_checksum"],
            "before_signature": header_info["before_signature"].hex(),
            "after_signature": header_info["after_signature"].hex(),
        },
        "byte_diffs": diff_records,
        "verifier_notice": "Limited structural verifier passed (header integrity, instruction bounds, CFG move-result adjacency). Not full ART runtime verification.",
    }


def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            sys.stderr.write("dex-patch-worker: empty input\n")
            json.dump({"ok": False, "error": "Empty input JSON"}, sys.stdout)
            sys.exit(1)

        req = json.loads(raw_input)
        action = req.get("action")
        if action == "inspect":
            res = do_inspect(req)
        elif action == "validate":
            res = do_validate(req)
        elif action == "patch":
            res = do_patch(req)
        else:
            raise ValueError(f"Unknown action: {action} (expected 'inspect', 'validate', or 'patch')")

        json.dump(res, sys.stdout)
        sys.exit(0)
    except Exception as exc:
        sys.stderr.write(f"dex-patch-worker error: {exc}\n")
        json.dump({"ok": False, "error": str(exc)}, sys.stdout)
        sys.exit(1)


if __name__ == "__main__":
    main()
