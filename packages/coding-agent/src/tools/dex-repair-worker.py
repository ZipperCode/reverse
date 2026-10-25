# -*- coding: utf-8 -*-
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright 2019 hanbinglengyue (FART project)
# Copyright 2026 reverse contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Structured JSON worker for FART Dalvik CodeItem offline DEX repair.

Consumes FART runtime CodeItem records (*_ins.bin and .bin dumps), correlates
method indices, relocates changed-size CodeItems with contiguous typed sections,
updates map_list item counts and file headers, recomputes SHA-1 and Adler-32
checksums, and validates the reconstructed Dalvik DEX.
"""

import base64
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
from dexutil import (
    Dex, fix_dex_header, insn_units, load_dex, read_uleb, read_sleb, write_uleb, write_sleb, u16, u32, verify_dex_header
)

# Regex matching standard FART _ins.bin record serialization
FART_RECORD_REGEX = re.compile(
    r"\{name:\s*(.*?)\s*,\s*method_idx:\s*(\d+)\s*,\s*offset:\s*(\d+)\s*,\s*code_item_len:\s*(\d+)\s*,\s*ins:\s*([A-Za-z0-9+/=]+)\s*\}"
)


def parse_fart_records(source_spec: str | list | dict) -> list[dict]:
    """Parse FART CodeItem records from file path, directory, raw text, or JSON structure."""
    records: list[dict] = []

    if isinstance(source_spec, list):
        for item in source_spec:
            if isinstance(item, dict) and "method_idx" in item:
                midx = int(item["method_idx"])
                raw_ins = item.get("ins") or item.get("code_bytes")
                if isinstance(raw_ins, str):
                    code_bytes = base64.b64decode(raw_ins)
                elif isinstance(raw_ins, (bytes, bytearray)):
                    code_bytes = bytes(raw_ins)
                else:
                    continue
                records.append({
                    "method_idx": midx,
                    "name": str(item.get("name", "")),
                    "offset": int(item.get("offset", 0)),
                    "code_item_len": len(code_bytes),
                    "code_bytes": code_bytes,
                })
        return records

    if not isinstance(source_spec, str):
        return records

    content_str = source_spec
    source_path = source_spec.strip()

    # If source is a directory, gather all matching dump files
    if os.path.isdir(source_path):
        for root, _dirs, files in os.walk(source_path):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                if fname.endswith("_ins.bin") or fname.endswith(".txt"):
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                            records.extend(parse_fart_records(fh.read()))
                    except Exception:
                        pass
                elif fname.endswith(".bin"):
                    try:
                        with open(fpath, "rb") as fh:
                            raw = fh.read()
                        text_match = FART_RECORD_REGEX.findall(raw.decode("ascii", errors="ignore"))
                        if text_match:
                            records.extend(parse_fart_records(raw.decode("utf-8", errors="replace")))
                        else:
                            m = re.search(r"(?:^|_)(\d+)\.bin$", fname)
                            if m and len(raw) >= 16:
                                midx = int(m.group(1))
                                records.append({
                                    "method_idx": midx,
                                    "name": "",
                                    "offset": 0,
                                    "code_item_len": len(raw),
                                    "code_bytes": raw,
                                })
                    except Exception:
                        pass
        return records

    # If source is an existing file, read it
    if os.path.isfile(source_path):
        try:
            with open(source_path, "rb") as fh:
                raw_file = fh.read()
            try:
                text_content = raw_file.decode("utf-8")
                matches = list(FART_RECORD_REGEX.finditer(text_content))
                if matches:
                    content_str = text_content
                else:
                    try:
                        parsed_json = json.loads(text_content)
                        return parse_fart_records(parsed_json)
                    except Exception:
                        m = re.search(r"(?:^|_)(\d+)\.bin$", os.path.basename(source_path))
                        if m and len(raw_file) >= 16:
                            return [{
                                "method_idx": int(m.group(1)),
                                "name": "",
                                "offset": 0,
                                "code_item_len": len(raw_file),
                                "code_bytes": raw_file,
                            }]
            except UnicodeDecodeError:
                m = re.search(r"(?:^|_)(\d+)\.bin$", os.path.basename(source_path))
                if m and len(raw_file) >= 16:
                    return [{
                        "method_idx": int(m.group(1)),
                        "name": "",
                        "offset": 0,
                        "code_item_len": len(raw_file),
                        "code_bytes": raw_file,
                    }]
        except Exception as exc:
            sys.stderr.write(f"Failed to read records file '{source_path}': {exc}\n")

    # Parse standard FART text records
    for m in FART_RECORD_REGEX.finditer(content_str):
        name = m.group(1).strip()
        midx = int(m.group(2))
        off = int(m.group(3))
        clen = int(m.group(4))
        raw_b64 = m.group(5).strip()
        try:
            code_bytes = base64.b64decode(raw_b64)
        except Exception:
            continue
        records.append({
            "name": name,
            "method_idx": midx,
            "offset": off,
            "code_item_len": clen,
            "code_bytes": code_bytes,
        })

    return records

def read_uleb_strict(b: bytes | bytearray, o: int) -> tuple[int, int]:
    """Decode unsigned LEB128 with strict bounds checking. Returns (val, new_offset) or (-1, o) on error."""
    if o >= len(b):
        return -1, o
    result = 0
    shift = 0
    length = len(b)
    count = 0
    while o < length and count < 5:
        byte = b[o]
        o += 1
        count += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, o
        shift += 7
    return -1, o


def read_sleb_strict(b: bytes | bytearray, o: int) -> tuple[int | None, int]:
    """Decode signed LEB128 with strict bounds checking. Returns (val, new_offset) or (None, o) on error."""
    if o >= len(b):
        return None, o
    result = 0
    shift = 0
    length = len(b)
    count = 0
    while o < length and count < 5:
        byte = b[o]
        o += 1
        count += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if (byte & 0x80) == 0:
            if count == 5 and (byte & 0x70) not in (0x00, 0x70):
                return None, o
            if (byte & 0x40) != 0:
                result |= -(1 << shift)
            result = result & 0xFFFFFFFF
            if result > 0x7FFFFFFF:
                result -= 0x100000000
            return result, o
    return None, o

def dex_type_to_java(t: str) -> str:
    """Convert Dalvik type descriptor to Java type name."""
    if not t:
        return ""
    array_dim = 0
    while t.startswith("["):
        array_dim += 1
        t = t[1:]
    prims = {
        "V": "void", "Z": "boolean", "B": "byte", "S": "short",
        "C": "char", "I": "int", "J": "long", "F": "float", "D": "double"
    }
    base = prims.get(t)
    if not base:
        if t.startswith("L") and t.endswith(";"):
            base = t[1:-1].replace("/", ".")
        else:
            base = t
    return base + ("[]" * array_dim)


def parse_proto_descriptor(proto: str) -> tuple[list[str], str]:
    """Parse Dalvik prototype descriptor into (params_list, return_type)."""
    if not proto.startswith("("):
        return [], proto
    idx = 1
    params = []
    while idx < len(proto) and proto[idx] != ")":
        start = idx
        while proto[idx] == "[":
            idx += 1
        if proto[idx] == "L":
            end = proto.find(";", idx)
            if end == -1:
                break
            idx = end + 1
        else:
            idx += 1
        params.append(proto[start:idx])
    ret = proto[idx + 1:] if idx < len(proto) and proto[idx] == ")" else ""
    return params, ret


def method_to_pretty_method(cls_desc: str, method_name: str, proto_desc: str) -> str:
    """Convert DEX class descriptor, method name, and prototype into ART PrettyMethod format."""
    cls_java = cls_desc[1:-1].replace("/", ".") if (cls_desc.startswith("L") and cls_desc.endswith(";")) else cls_desc
    params, ret = parse_proto_descriptor(proto_desc)
    params_java = [dex_type_to_java(p) for p in params]
    ret_java = dex_type_to_java(ret)
    return f"{ret_java} {cls_java}.{method_name}({', '.join(params_java)})"


def is_method_name_compatible(rec_name: str, cls_name: str, m_name: str, proto_desc: str) -> tuple[bool, str]:
    """Check compatibility between FART record name (PrettyMethod or smali) and DEX method."""
    if not rec_name:
        return True, ""
    clean_rec = rec_name.strip()
    if clean_rec.startswith("artMethod::"):
        return True, ""
    if "->" in clean_rec:
        parts = clean_rec.split("->", 1)
        rec_cls = parts[0].strip()
        rec_sig = parts[1].strip()
        if rec_cls != cls_name:
            return False, f"Class descriptor mismatch: record specifies '{rec_cls}', DEX method is '{cls_name}'"
        if "(" in rec_sig:
            full_sig = f"{m_name}{proto_desc}"
            if rec_sig != full_sig:
                return False, f"Method signature mismatch: record specifies '{rec_sig}', DEX method is '{full_sig}'"
        elif rec_sig != m_name:
            return False, f"Method name mismatch: record specifies '{rec_sig}', DEX method is '{m_name}'"
        return True, ""

    pretty = method_to_pretty_method(cls_name, m_name, proto_desc)
    pretty_no_ret = pretty.split(" ", 1)[-1]

    if "." in clean_rec and "(" in clean_rec:
        if clean_rec == pretty or clean_rec == pretty_no_ret:
            return True, ""
        return False, f"PrettyMethod mismatch: record specifies '{clean_rec}', DEX method is '{pretty}'"

    if "(" not in clean_rec and "." not in clean_rec and " " not in clean_rec:
        if clean_rec != m_name:
            return False, f"Method name mismatch: record specifies '{clean_rec}', DEX method is '{m_name}'"
        return True, ""

    if clean_rec == f"{m_name}{proto_desc}" or clean_rec == m_name:
        return True, ""

    return False, f"Unrecognized or mismatched name format: record '{clean_rec}', expected '{pretty}' or smali '{cls_name}->{m_name}{proto_desc}'"




def validate_code_item_structure(code_bytes: bytes, dex: Dex, method_idx: int, rec_name: str = "", access_flags: int = 0) -> dict:
    """Validate raw Dalvik code_item integrity, instruction payloads, try-catch handlers, and method correspondence."""
    if len(code_bytes) < 16:
        return {"valid": False, "reason": f"CodeItem byte length {len(code_bytes)} < 16 header minimum"}

    method_ids_size = dex.header.get("method_ids_size", 0)
    if method_idx >= method_ids_size:
        return {
            "valid": False,
            "reason": f"method_idx {method_idx} exceeds DEX method_ids_size ({method_ids_size})"
        }

    cls_name, m_name, proto_desc = dex.method(method_idx)

    registers_size = u16(code_bytes, 0)
    ins_size = u16(code_bytes, 2)
    outs_size = u16(code_bytes, 4)
    tries_size = u16(code_bytes, 6)
    debug_info_off = u32(code_bytes, 8)
    insns_size = u32(code_bytes, 12)

    if registers_size < ins_size:
        return {
            "valid": False,
            "reason": f"Verifier constraint violation: registers_size ({registers_size}) < ins_size ({ins_size})"
        }

    # Verify ins_size against method prototype and static/instance receiver
    params, ret = parse_proto_descriptor(proto_desc)
    param_words = sum(2 if p_desc in ("J", "D") else 1 for p_desc in params)
    is_static = bool(access_flags & 0x0008)
    expected_ins = param_words if is_static else (param_words + 1)
    if ins_size != expected_ins:
        return {
            "valid": False,
            "reason": f"Verifier constraint violation: code_item ins_size ({ins_size}) != expected ({expected_ins}) for {'static' if is_static else 'instance'} method {cls_name}->{m_name}{proto_desc}"
        }

    insns_bytes = insns_size * 2
    if 16 + insns_bytes > len(code_bytes):
        return {
            "valid": False,
            "reason": f"Truncated instructions: header specifies {insns_size} units ({insns_bytes} bytes), total bytes {len(code_bytes)}"
        }

    # Sanitize out-of-bounds debug_info_off from dumped runtime environments
    sanitized_bytes = bytearray(code_bytes)
    data_off = dex.header.get("data_off", 0)
    data_size = dex.header.get("data_size", 0)
    max_data_bound = data_off + data_size
    if debug_info_off != 0 and (debug_info_off < data_off or debug_info_off >= max_data_bound):
        struct.pack_into("<I", sanitized_bytes, 8, 0)
        debug_info_off = 0

    string_ids_size = dex.header.get("string_ids_size", 0)
    type_ids_size = dex.header.get("type_ids_size", 0)
    field_ids_size = dex.header.get("field_ids_size", 0)

    # Decode instructions to verify opcode validity and operand table bounds
    pos = 16
    end = 16 + insns_bytes
    insn_count = 0
    while pos < end:
        op = code_bytes[pos]
        units = insn_units(op, code_bytes, pos, end)
        if units < 1 or pos + units * 2 > end:
            return {
                "valid": False,
                "reason": f"Invalid instruction at relative code offset 0x{pos:x} (op 0x{op:02x})"
            }

        # Validate operand table indices against DEX header bounds
        if op == 0x1A and pos + 4 <= end:
            s_idx = u16(code_bytes, pos + 2)
            if s_idx >= string_ids_size:
                return {"valid": False, "reason": f"const-string operand string_idx {s_idx} >= string_ids_size ({string_ids_size})"}
        elif op == 0x1B and pos + 6 <= end:
            s_idx = u32(code_bytes, pos + 2)
            if s_idx >= string_ids_size:
                return {"valid": False, "reason": f"const-string/jumbo operand string_idx {s_idx} >= string_ids_size ({string_ids_size})"}
        elif op in (0x1C, 0x1F, 0x20, 0x22, 0x23) and pos + 4 <= end:
            t_idx = u16(code_bytes, pos + 2)
            if t_idx >= type_ids_size:
                return {"valid": False, "reason": f"Type instruction 0x{op:02x} operand type_idx {t_idx} >= type_ids_size ({type_ids_size})"}
        elif op == 0x24 and pos + 4 <= end:
            t_idx = u16(code_bytes, pos + 2)
            if t_idx >= type_ids_size:
                return {"valid": False, "reason": f"filled-new-array operand type_idx {t_idx} >= type_ids_size ({type_ids_size})"}
        elif 0x52 <= op <= 0x6D and pos + 4 <= end:
            f_idx = u16(code_bytes, pos + 2)
            if f_idx >= field_ids_size:
                return {"valid": False, "reason": f"Field instruction 0x{op:02x} operand field_idx {f_idx} >= field_ids_size ({field_ids_size})"}
        elif ((0x6E <= op <= 0x72) or (0x74 <= op <= 0x78)) and pos + 4 <= end:
            m_idx = u16(code_bytes, pos + 2)
            if m_idx >= method_ids_size:
                return {"valid": False, "reason": f"Invoke instruction 0x{op:02x} operand method_idx {m_idx} >= method_ids_size ({method_ids_size})"}

        # Return instruction type compatibility
        if op == 0x0E and ret != "V":
            return {"valid": False, "reason": f"Method return type is '{ret}' but returns void"}
        elif op == 0x11 and not (ret.startswith("L") or ret.startswith("[")):
            return {"valid": False, "reason": f"Method return type is primitive '{ret}' but returns object"}

        pos += units * 2
        insn_count += 1
    # Verify try-catch handlers if tries_size > 0
    p = end
    if tries_size > 0:
        if insns_size % 2 == 1:
            if p + 2 > len(code_bytes):
                return {"valid": False, "reason": "Truncated try-items padding spacer"}
            spacer = u16(code_bytes, p)
            if spacer != 0:
                return {
                    "valid": False,
                    "reason": f"Non-zero try items padding spacer 0x{spacer:04x} (must be 0x0000 per ART verifier)"
                }
            p += 2

        tries_base = p
        tries_bytes = tries_size * 8
        if tries_base + tries_bytes > len(code_bytes):
            return {
                "valid": False,
                "reason": f"Truncated tries table: requires {tries_base + tries_bytes} bytes, got {len(code_bytes)}"
            }

        # Parse try_items with strict ordering and non-overlapping bounds check
        try_items = []
        prev_end = 0
        for t_i in range(tries_size):
            t_off = tries_base + t_i * 8
            start_addr = u32(code_bytes, t_off)
            count = u16(code_bytes, t_off + 4)
            h_off = u16(code_bytes, t_off + 6)
            if start_addr < prev_end:
                return {
                    "valid": False,
                    "reason": f"Try item {t_i} overlaps or is out of order: start_addr {start_addr} < previous try end {prev_end}"
                }
            if start_addr >= insns_size or (start_addr + count) > insns_size:
                return {
                    "valid": False,
                    "reason": f"Try item {t_i} range [{start_addr}, {start_addr + count}) exceeds insns_size {insns_size}"
                }
            prev_end = start_addr + count
            try_items.append((start_addr, count, h_off))
        # Parse encoded_catch_handler_list
        handlers_base = tries_base + tries_bytes
        if handlers_base >= len(code_bytes):
            return {
                "valid": False,
                "reason": "Missing encoded_catch_handler_list following tries table"
            }

        p = handlers_base
        handlers_count, p = read_uleb_strict(code_bytes, p)
        if handlers_count < 0 or p > len(code_bytes):
            return {
                "valid": False,
                "reason": "Malformed or truncated handlers_count in encoded_catch_handler_list"
            }

        handler_offsets: set[int] = set()
        type_ids_size = dex.header.get("type_ids_size", 0)

        for h_i in range(handlers_count):
            h_rel_off = p - handlers_base
            handler_offsets.add(h_rel_off)
            h_size_res = read_sleb_strict(code_bytes, p)
            if h_size_res[0] is None:
                return {
                    "valid": False,
                    "reason": f"Truncated handler size at handler index {h_i}"
                }
            h_size, p = h_size_res
            typed_count = abs(h_size)
            has_catch_all = (h_size <= 0)

            for _ in range(typed_count):
                type_idx, p = read_uleb_strict(code_bytes, p)
                t_addr, p = read_uleb_strict(code_bytes, p)
                if type_idx < 0 or (type_ids_size > 0 and type_idx >= type_ids_size):
                    return {
                        "valid": False,
                        "reason": f"Invalid catch type_idx {type_idx} (exceeds type_ids_size {type_ids_size})"
                    }
                if t_addr < 0 or t_addr >= insns_size:
                    return {
                        "valid": False,
                        "reason": f"Catch target address {t_addr} exceeds insns_size {insns_size}"
                    }

            if has_catch_all:
                catch_all_addr, p = read_uleb_strict(code_bytes, p)
                if catch_all_addr < 0 or catch_all_addr >= insns_size:
                    return {
                        "valid": False,
                        "reason": f"Catch-all target address {catch_all_addr} exceeds insns_size {insns_size}"
                    }

        # Check every try item handler_off points to a valid handler in the list
        for t_i, (_s, _c, h_off) in enumerate(try_items):
            if h_off not in handler_offsets:
                return {
                    "valid": False,
                    "reason": f"Try item {t_i} handler_off {h_off} does not match any encoded handler offset"
                }

    if len(code_bytes) < p:
        return {
            "valid": False,
            "reason": f"CodeItem payload truncated: expected {p} bytes, got {len(code_bytes)}"
        }
    sanitized_bytes = sanitized_bytes[:p]

    # Name compatibility check if record provided a name
    if rec_name:
        compatible, reason = is_method_name_compatible(rec_name, cls_name, m_name, proto_desc)
        if not compatible:
            return {
                "valid": False,
                "reason": reason,
            }
    return {
        "valid": True,
        "registers_size": registers_size,
        "ins_size": ins_size,
        "outs_size": outs_size,
        "tries_size": tries_size,
        "debug_info_off": debug_info_off,
        "insns_size": insns_size,
        "insn_count": insn_count,
        "class_name": cls_name,
        "method_name": m_name,
        "proto": proto_desc,
        "exact_code_len": p,
        "sanitized_bytes": bytes(sanitized_bytes),
    }

def parse_code_item_length(data: bytes, code_off: int) -> int:
    """Parse exact byte length of an existing valid code_item."""
    if code_off + 16 > len(data):
        return 0
    tries_size = u16(data, code_off + 6)
    insns_size = u32(data, code_off + 12)
    p = code_off + 16 + insns_size * 2
    if tries_size == 0:
        return p - code_off
    if insns_size % 2 == 1:
        p += 2
    tries_bytes = tries_size * 8
    p += tries_bytes
    if p >= len(data):
        return p - code_off
    handlers_base = p
    handlers_count, p = read_uleb(data, p)
    if handlers_count < 0 or p > len(data):
        return p - code_off
    for _ in range(handlers_count):
        h_size, p = read_sleb(data, p)
        typed_count = abs(h_size)
        has_catch_all = (h_size <= 0)
        for _ in range(typed_count):
            _tidx, p = read_uleb(data, p)
            _taddr, p = read_uleb(data, p)
        if has_catch_all:
            _caddr, p = read_uleb(data, p)
    return p - code_off

def get_class_data_length(data: bytes, cd_off: int) -> int:
    """Parse exact byte length of an existing class_data_item."""
    if cd_off >= len(data):
        return 0
    p = cd_off
    sf, p = read_uleb(data, p)
    inf, p = read_uleb(data, p)
    dm, p = read_uleb(data, p)
    vm, p = read_uleb(data, p)
    for _ in range(sf + inf):
        _, p = read_uleb(data, p)
        _, p = read_uleb(data, p)
    for _ in range(dm + vm):
        _, p = read_uleb(data, p)
        _, p = read_uleb(data, p)
        _, p = read_uleb(data, p)
    return p - cd_off


def do_repair(req: dict) -> dict:
    target = req.get("path") or req.get("target")
    if not target:
        raise ValueError("Missing required parameter 'path' (or 'target')")

    entry_name = req.get("entry")
    dex_obj, effective_name = load_dex(target, entry_name)
    initial_check = dex_obj.check()
    if initial_check:
        raise ValueError(f"Target DEX file has initial structural issues: {'; '.join(initial_check)}")

    records_spec = req.get("records") or req.get("dump") or req.get("bins")
    if not records_spec:
        raise ValueError("Missing required parameter 'records' (or 'dump'/'bins') containing FART CodeItem records")

    parsed_records = parse_fart_records(records_spec)
    if not parsed_records:
        raise ValueError("No FART CodeItem records could be parsed from the provided input")

    dry_run = req.get("dry_run", True) is not False
    out_path = req.get("out")
    if not dry_run and not out_path:
        raise ValueError("Parameter 'out' is required when dry_run is false")

    data = bytearray(dex_obj.d)
    initial_size = len(data)

    class_defs_size = dex_obj.header.get("class_defs_size", 0)
    class_defs_off = dex_obj.header.get("class_defs_off", 0)

    # 1. Unpack all class definitions and their methods
    classes_info = []
    method_to_class: dict[int, dict] = {}

    for c_i in range(class_defs_size):
        c_off = class_defs_off + c_i * 32
        cd_off = u32(data, c_off + 24)
        if cd_off == 0 or cd_off >= len(data):
            classes_info.append({"class_idx": c_i, "class_def_off": c_off, "has_data": False})
            continue

        p = cd_off
        sf, p = read_uleb(data, p)
        inf, p = read_uleb(data, p)
        dm, p = read_uleb(data, p)
        vm, p = read_uleb(data, p)

        static_fields = []
        for _ in range(sf):
            f_diff, p = read_uleb(data, p)
            f_flags, p = read_uleb(data, p)
            static_fields.append((f_diff, f_flags))

        instance_fields = []
        for _ in range(inf):
            f_diff, p = read_uleb(data, p)
            f_flags, p = read_uleb(data, p)
            instance_fields.append((f_diff, f_flags))

        direct_methods = []
        running = 0
        for _ in range(dm):
            m_diff, p = read_uleb(data, p)
            running += m_diff
            m_flags, p = read_uleb(data, p)
            m_code_off, p = read_uleb(data, p)
            direct_methods.append({"idx": running, "flags": m_flags, "code_off": m_code_off})
            method_to_class[running] = {"class_idx": c_i, "is_virtual": False, "access_flags": m_flags, "code_off": m_code_off}

        virtual_methods = []
        running = 0
        for _ in range(vm):
            m_diff, p = read_uleb(data, p)
            running += m_diff
            m_flags, p = read_uleb(data, p)
            m_code_off, p = read_uleb(data, p)
            virtual_methods.append({"idx": running, "flags": m_flags, "code_off": m_code_off})
            method_to_class[running] = {"class_idx": c_i, "is_virtual": True, "access_flags": m_flags, "code_off": m_code_off}

        classes_info.append({
            "class_idx": c_i,
            "class_def_off": c_off,
            "has_data": True,
            "static_fields": static_fields,
            "instance_fields": instance_fields,
            "direct_methods": direct_methods,
            "virtual_methods": virtual_methods,
        })

    # 2. Correlate and validate records against this target; detect duplicate and conflicting captures
    validated_repairs: dict[int, dict] = {}
    skipped_records: list[dict] = []
    conflicts: list[dict] = []

    for rec in parsed_records:
        midx = rec["method_idx"]

        if midx not in method_to_class:
            cls_name, m_name, proto_desc = dex_obj.method(midx)
            skipped_records.append({
                "method_idx": midx,
                "name": f"{cls_name}->{m_name}{proto_desc}",
                "reason": "Method is not defined in this DEX class_defs (may belong to another DEX in multidex container)"
            })
            continue

        flags = method_to_class[midx].get("access_flags", 0)
        val_res = validate_code_item_structure(rec["code_bytes"], dex_obj, midx, rec.get("name", ""), access_flags=flags)
        if not val_res["valid"]:
            skipped_records.append({
                "method_idx": midx,
                "name": rec.get("name", ""),
                "reason": val_res["reason"],
            })
            continue

        # Now that record is validated as belonging to this target method, check for duplicate/conflict
        if midx in validated_repairs:
            existing_rec = validated_repairs[midx]["record"]
            if existing_rec["code_bytes"] != rec["code_bytes"]:
                conflicts.append({
                    "method_idx": midx,
                    "reason": f"Conflicting CodeItem captures for method_idx {midx} with differing byte payloads"
                })
                del validated_repairs[midx]
            continue

        validated_repairs[midx] = {
            "record": rec,
            "validation": val_res,
            "mapping": method_to_class[midx],
        }

    if conflicts:
        raise ValueError(f"Ambiguous conflicting captures detected for {len(conflicts)} methods: {conflicts[0]['reason']}")

    if not validated_repairs:
        raise ValueError(
            f"None of the {len(parsed_records)} provided records could be matched to methods in this DEX. Skipped: {len(skipped_records)}"
        )

    # 3. Gather existing map items (excluding old code_items, class_data, and map_list)
    map_off = dex_obj.header.get("map_off", 0)
    existing_map_items = []
    if map_off > 0 and map_off + 4 <= len(data):
        m_size = u32(data, map_off)
        for i in range(m_size):
            ioff = map_off + 4 + i * 12
            if ioff + 12 <= len(data):
                itype = u16(data, ioff)
                isize = u32(data, ioff + 4)
                ioffset = u32(data, ioff + 8)
                if itype not in (0x2001, 0x2000, 0x1000):
                    existing_map_items.append({"type": itype, "size": isize, "offset": ioffset})

    # 4. REBUILD CONTIGUOUS TYPED SECTIONS
    new_data = bytearray(data)

    # 4.1 CONTIGUOUS CODE_ITEMS SECTION
    pad = (4 - (len(new_data) % 4)) % 4
    if pad:
        new_data.extend(b"\x00" * pad)
    code_items_start_off = len(new_data)

    new_code_offsets: dict[int, int] = {}
    code_items_count = 0
    repair_reports: list[dict] = []

    for c_entry in classes_info:
        if not c_entry["has_data"]:
            continue
        for m in c_entry["direct_methods"] + c_entry["virtual_methods"]:
            midx = m["idx"]
            code_bytes = None
            old_code_off = m["code_off"]
            old_info = dex_obj.code_info(old_code_off) if old_code_off != 0 else None

            if midx in validated_repairs:
                item = validated_repairs[midx]
                val = item["validation"]
                code_bytes = val.get("sanitized_bytes") or item["record"]["code_bytes"]
            elif old_code_off != 0 and old_info:
                # Copy existing code item preserving instructions, tries, and handlers
                c_len = parse_code_item_length(data, old_code_off)
                if c_len > 0 and old_code_off + c_len <= len(data):
                    code_bytes = data[old_code_off : old_code_off + c_len]

            if code_bytes:
                # 4-byte align each code item
                pad = (4 - (len(new_data) % 4)) % 4
                if pad:
                    new_data.extend(b"\x00" * pad)
                c_off = len(new_data)
                new_data.extend(code_bytes)
                new_code_offsets[midx] = c_off
                code_items_count += 1

                if midx in validated_repairs:
                    repair_reports.append({
                        "method_idx": midx,
                        "class": val["class_name"],
                        "name": val["method_name"],
                        "desc": val["proto"],
                        "old_code_off": old_code_off,
                        "new_code_off": c_off,
                        "old_insns_size": old_info["insns_size"] if old_info else 0,
                        "new_insns_size": val["insns_size"],
                        "relocated": True,
                    })
            else:
                new_code_offsets[midx] = 0

    # 4.2 CONTIGUOUS CLASS_DATA_ITEMS SECTION
    pad = (4 - (len(new_data) % 4)) % 4
    if pad:
        new_data.extend(b"\x00" * pad)
    class_data_start_off = len(new_data)
    class_data_count = 0

    for c_entry in classes_info:
        if not c_entry["has_data"]:
            continue
        new_cd = bytearray()
        new_cd += write_uleb(len(c_entry["static_fields"]))
        new_cd += write_uleb(len(c_entry["instance_fields"]))
        new_cd += write_uleb(len(c_entry["direct_methods"]))
        new_cd += write_uleb(len(c_entry["virtual_methods"]))

        for fd, fl in c_entry["static_fields"]:
            new_cd += write_uleb(fd)
            new_cd += write_uleb(fl)
        for fd, fl in c_entry["instance_fields"]:
            new_cd += write_uleb(fd)
            new_cd += write_uleb(fl)

        prev = 0
        for m in c_entry["direct_methods"]:
            diff = m["idx"] - prev
            prev = m["idx"]
            new_cd += write_uleb(diff)
            new_cd += write_uleb(m["flags"])
            new_cd += write_uleb(new_code_offsets.get(m["idx"], 0))

        prev = 0
        for m in c_entry["virtual_methods"]:
            diff = m["idx"] - prev
            prev = m["idx"]
            new_cd += write_uleb(diff)
            new_cd += write_uleb(m["flags"])
            new_cd += write_uleb(new_code_offsets.get(m["idx"], 0))

        cd_off = len(new_data)
        new_data.extend(new_cd)
        class_data_count += 1
        # Update class_def.class_data_off
        struct.pack_into("<I", new_data, c_entry["class_def_off"] + 24, cd_off)

    # 4.3 CONTIGUOUS MAP_LIST SECTION
    pad = (4 - (len(new_data) % 4)) % 4
    if pad:
        new_data.extend(b"\x00" * pad)
    new_map_off = len(new_data)

    final_map_items = list(existing_map_items)
    if code_items_count > 0:
        final_map_items.append({"type": 0x2001, "size": code_items_count, "offset": code_items_start_off})
    if class_data_count > 0:
        final_map_items.append({"type": 0x2000, "size": class_data_count, "offset": class_data_start_off})
    final_map_items.append({"type": 0x1000, "size": 1, "offset": new_map_off})

    # Sort map items strictly by offset
    final_map_items.sort(key=lambda x: x["offset"])

    map_buf = struct.pack("<I", len(final_map_items))
    for it in final_map_items:
        map_buf += struct.pack("<HHI I", it["type"], 0, it["size"], it["offset"])
    new_data.extend(map_buf)

    # Zero out old unmapped code_items, class_data_items, and old map_list section ranges
    # bounded by the next map offset, ensuring unreferenced orphan code items and inter-section
    # gaps are completely zeroed so ART DexFileVerifier::CheckPadding sees 100% zero padding.
    if map_off > 0 and map_off + 4 <= len(data):
        m_size = u32(data, map_off)
        orig_map_entries = []
        for i in range(m_size):
            ioff = map_off + 4 + i * 12
            if ioff + 12 <= len(data):
                orig_map_entries.append({
                    "type": u16(data, ioff),
                    "size": u32(data, ioff + 4),
                    "offset": u32(data, ioff + 8),
                })
        orig_map_entries.sort(key=lambda x: x["offset"])

        removed_types = {0x2001, 0x2000, 0x1000}
        for i, m_item in enumerate(orig_map_entries):
            if m_item["type"] in removed_types:
                sec_start = m_item["offset"]
                sec_end = orig_map_entries[i + 1]["offset"] if (i + 1 < len(orig_map_entries)) else initial_size
                if sec_start < code_items_start_off:
                    clear_end = min(sec_end, code_items_start_off)
                    if clear_end > sec_start:
                        new_data[sec_start:clear_end] = b"\x00" * (clear_end - sec_start)

    # Also zero any specific old code_offs or class_data_offs that might lie before code_items_start_off
    for c_entry in classes_info:
        if not c_entry["has_data"]:
            continue
        for m in c_entry["direct_methods"] + c_entry["virtual_methods"]:
            old_off = m["code_off"]
            if old_off > 0 and old_off < code_items_start_off:
                c_len = parse_code_item_length(data, old_off)
                if c_len > 0:
                    new_data[old_off : min(code_items_start_off, old_off + c_len)] = b"\x00" * (min(code_items_start_off, old_off + c_len) - old_off)

        c_off = c_entry["class_def_off"]
        old_cd_off = u32(data, c_off + 24)
        if old_cd_off > 0 and old_cd_off < code_items_start_off:
            cd_len = get_class_data_length(data, old_cd_off)
            if cd_len > 0:
                new_data[old_cd_off : min(code_items_start_off, old_cd_off + cd_len)] = b"\x00" * (min(code_items_start_off, old_cd_off + cd_len) - old_cd_off)

    if map_off > 0 and map_off < code_items_start_off:
        m_size = u32(data, map_off)
        old_map_len = 4 + m_size * 12
        new_data[map_off : min(code_items_start_off, map_off + old_map_len)] = b"\x00" * (min(code_items_start_off, map_off + old_map_len) - map_off)
    # 4.4 UPDATE FILE HEADERS
    new_file_size = len(new_data)
    data_off = dex_obj.header.get("data_off", 0)
    new_data_size = new_file_size - data_off
    struct.pack_into("<I", new_data, 0x20, new_file_size)
    struct.pack_into("<I", new_data, 0x34, new_map_off)
    struct.pack_into("<I", new_data, 0x68, new_data_size)

    # 4.5 FIX CHECKSUMS (SHA-1 signature then Adler-32 checksum)
    header_info = fix_dex_header(new_data)

    # 5. POST-VALIDATION
    post_dex = Dex(bytes(new_data))
    post_problems = post_dex.check()
    c_ok, s_ok = verify_dex_header(bytes(new_data))

    for rep in repair_reports:
        c_off = rep["new_code_off"]
        insns, clean, _exp = post_dex.decode_all(c_off)
        if not clean:
            post_problems.append(f"Method {rep['name']} at 0x{c_off:x} did not decode cleanly")

    out_sha256 = hashlib.sha256(new_data).hexdigest()

    # 6. ATOMIC NO-CLOBBER DESTINATION PUBLISH
    if not dry_run and out_path:
        out_dir = os.path.dirname(os.path.abspath(out_path))
        os.makedirs(out_dir, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=out_dir) as staging_dir:
            temp_out = os.path.join(staging_dir, "repaired.dex")
            with open(temp_out, "wb") as fh:
                fh.write(bytes(new_data))
                fh.flush()
                os.fsync(fh.fileno())

            try:
                os.link(temp_out, out_path)
            except FileExistsError:
                raise FileExistsError(f"Destination output path already exists (no-clobber policy): {out_path}")

    return {
        "ok": True,
        "action": "repair",
        "dry_run": dry_run,
        "target": target,
        "entry": effective_name,
        "total_methods": dex_obj.header.get("method_ids_size", 0),
        "records_count": len(parsed_records),
        "repaired_count": len(repair_reports),
        "skipped_count": len(skipped_records),
        "repairs": repair_reports,
        "skipped": skipped_records,
        "header_change": {
            "before_checksum": "0x%08x" % header_info["before_checksum"],
            "after_checksum": "0x%08x" % header_info["after_checksum"],
            "before_signature": header_info["before_signature"].hex(),
            "after_signature": header_info["after_signature"].hex(),
            "old_file_size": initial_size,
            "new_file_size": new_file_size,
        },
        "validation": {
            "check_clean": len(post_problems) == 0,
            "problems": post_problems,
            "checksum_verified": c_ok,
            "signature_verified": s_ok,
        },
        "out_path": out_path if not dry_run else None,
        "out_sha256": out_sha256,
        "lineage": {
            "origin_dex": target,
            "entry": effective_name,
            "records_source": str(records_spec) if len(str(records_spec)) < 256 else "<inline_records>",
            "engine": "FART offline CodeItem contiguous rebuilder (Apache-2.0)",
            "methods_repaired": len(repair_reports),
        },
    }


def do_status(req: dict) -> dict:
    target = req.get("path") or req.get("target")
    res = {
        "ok": True,
        "action": "status",
        "engine": "FART offline CodeItem repair engine",
        "license": "Apache-2.0",
        "version": "1.0.0",
    }
    if target:
        try:
            entry_name = req.get("entry")
            dex_obj, effective_name = load_dex(target, entry_name)
            problems = dex_obj.check()
            c_ok, s_ok = verify_dex_header(dex_obj.d)

            class_defs_size = dex_obj.header.get("class_defs_size", 0)
            class_defs_off = dex_obj.header.get("class_defs_off", 0)
            total_methods = dex_obj.header.get("method_ids_size", 0)
            empty_code = 0
            with_code = 0

            for c_i in range(class_defs_size):
                c_off = class_defs_off + c_i * 32
                cd_off = u32(dex_obj.d, c_off + 24)
                if cd_off == 0:
                    continue
                p = cd_off
                sf, p = read_uleb(dex_obj.d, p)
                inf, p = read_uleb(dex_obj.d, p)
                dm, p = read_uleb(dex_obj.d, p)
                vm, p = read_uleb(dex_obj.d, p)
                for _ in range(sf + inf):
                    _, p = read_uleb(dex_obj.d, p)
                    _, p = read_uleb(dex_obj.d, p)
                for _ in range(dm + vm):
                    _, p = read_uleb(dex_obj.d, p)
                    _, p = read_uleb(dex_obj.d, p)
                    co, p = read_uleb(dex_obj.d, p)
                    if co == 0:
                        empty_code += 1
                    else:
                        with_code += 1

            res["target_info"] = {
                "path": target,
                "entry": effective_name,
                "file_size": len(dex_obj.d),
                "header_file_size": dex_obj.header.get("file_size"),
                "class_defs_size": class_defs_size,
                "method_ids_size": total_methods,
                "methods_with_code": with_code,
                "methods_empty_or_stripped": empty_code,
                "checksum_valid": c_ok,
                "signature_valid": s_ok,
                "problems": problems,
                "needs_repair": empty_code > 0,
            }
        except Exception as exc:
            res["target_error"] = str(exc)

    records_spec = req.get("records") or req.get("dump") or req.get("bins")
    if records_spec:
        try:
            records = parse_fart_records(records_spec)
            res["records_info"] = {
                "records_count": len(records),
                "sample_indices": [r["method_idx"] for r in records[:10]],
            }
        except Exception as exc:
            res["records_error"] = str(exc)

    return res


def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            json.dump({"ok": False, "error": "Empty input JSON"}, sys.stdout)
            sys.exit(1)

        req = json.loads(raw_input)
        action = req.get("action", "repair")
        if action == "status":
            res = do_status(req)
        elif action == "repair":
            res = do_repair(req)
        else:
            raise ValueError(f"Unknown action: {action} (expected 'status' or 'repair')")

        json.dump(res, sys.stdout)
        sys.exit(0)
    except Exception as exc:
        sys.stderr.write(f"dex-repair-worker error: {exc}\n")
        json.dump({"ok": False, "error": str(exc)}, sys.stdout)
        sys.exit(1)


if __name__ == "__main__":
    main()
