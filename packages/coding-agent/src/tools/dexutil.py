# -*- coding: utf-8 -*-
from __future__ import annotations

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 apk-reverse contributors
# Adapted from apk-reverse dexutil.py (commit bd6dd0c59ce1f9af75f1293ef9518fb6f5d28c6c)
"""Minimal, dependency-free dex reader: structure walk + exact instruction decode.

Pure standard library Dalvik DEX parser. Key characteristics:
- Resolves class -> class_data_item -> method -> code_item.
- Decodes instructions with exact format and width specification table.
- Accurately tracks ULEB128 delta-encoded member indices.
- Handles pseudo-instruction payload structures and instruction alignment.
"""

import hashlib
import struct
import sys
import zipfile
import zlib

# Verified dex header offsets (little-endian uint32s after magic(8)+checksum(4)+signature(20))
OFFSETS = {
    "file_size": 0x20, "header_size": 0x24, "endian_tag": 0x28,
    "link_size": 0x2C, "link_off": 0x30, "map_off": 0x34,
    "string_ids_size": 0x38, "string_ids_off": 0x3C,
    "type_ids_size": 0x40, "type_ids_off": 0x44,
    "proto_ids_size": 0x48, "proto_ids_off": 0x4C,
    "field_ids_size": 0x50, "field_ids_off": 0x54,
    "method_ids_size": 0x58, "method_ids_off": 0x5C,
    "class_defs_size": 0x60, "class_defs_off": 0x64,
    "data_size": 0x68, "data_off": 0x6C,
}

# Dalvik instruction mnemonics aligned to standard Dalvik opcode definitions.
OP_NAMES = {
    0x00: "nop", 0x01: "move", 0x02: "move/from16", 0x03: "move/16",
    0x04: "move-wide", 0x05: "move-wide/from16", 0x06: "move-wide/16", 0x07: "move-object",
    0x08: "move-object/from16", 0x09: "move-object/16", 0x0A: "move-result", 0x0B: "move-result-wide",
    0x0C: "move-result-object", 0x0D: "move-exception", 0x0E: "return-void", 0x0F: "return",
    0x10: "return-wide", 0x11: "return-object", 0x12: "const/4", 0x13: "const/16",
    0x14: "const", 0x15: "const/high16", 0x16: "const-wide/16", 0x17: "const-wide/32",
    0x18: "const-wide", 0x19: "const-wide/high16", 0x1A: "const-string", 0x1B: "const-string/jumbo",
    0x1C: "const-class", 0x1D: "monitor-enter", 0x1E: "monitor-exit", 0x1F: "check-cast",
    0x20: "instance-of", 0x21: "array-length", 0x22: "new-instance", 0x23: "new-array",
    0x24: "filled-new-array", 0x25: "filled-new-array/range", 0x26: "fill-array-data", 0x27: "throw",
    0x28: "goto", 0x29: "goto/16", 0x2A: "goto/32", 0x2B: "packed-switch",
    0x2C: "sparse-switch", 0x2D: "cmpl-float", 0x2E: "cmpg-float", 0x2F: "cmpl-double",
    0x30: "cmpg-double", 0x31: "cmp-long", 0x32: "if-eq", 0x33: "if-ne",
    0x34: "if-lt", 0x35: "if-ge", 0x36: "if-gt", 0x37: "if-le",
    0x38: "if-eqz", 0x39: "if-nez", 0x3A: "if-ltz", 0x3B: "if-gez",
    0x3C: "if-gtz", 0x3D: "if-lez", 0x44: "aget", 0x45: "aget-wide",
    0x46: "aget-object", 0x47: "aget-boolean", 0x48: "aget-byte", 0x49: "aget-char",
    0x4A: "aget-short", 0x4B: "aput", 0x4C: "aput-wide", 0x4D: "aput-object",
    0x4E: "aput-boolean", 0x4F: "aput-byte", 0x50: "aput-char", 0x51: "aput-short",
    0x52: "iget", 0x53: "iget-wide", 0x54: "iget-object", 0x55: "iget-boolean",
    0x56: "iget-byte", 0x57: "iget-char", 0x58: "iget-short", 0x59: "iput",
    0x5A: "iput-wide", 0x5B: "iput-object", 0x5C: "iput-boolean", 0x5D: "iput-byte",
    0x5E: "iput-char", 0x5F: "iput-short", 0x60: "sget", 0x61: "sget-wide",
    0x62: "sget-object", 0x63: "sget-boolean", 0x64: "sget-byte", 0x65: "sget-char",
    0x66: "sget-short", 0x67: "sput", 0x68: "sput-wide", 0x69: "sput-object",
    0x6A: "sput-boolean", 0x6B: "sput-byte", 0x6C: "sput-char", 0x6D: "sput-short",
    0x6E: "invoke-virtual", 0x6F: "invoke-super", 0x70: "invoke-direct", 0x71: "invoke-static",
    0x72: "invoke-interface", 0x74: "invoke-virtual/range", 0x75: "invoke-super/range", 0x76: "invoke-direct/range",
    0x77: "invoke-static/range", 0x78: "invoke-interface/range", 0x7B: "neg-int", 0x7C: "not-int",
    0x7D: "neg-long", 0x7E: "not-long", 0x7F: "neg-float", 0x80: "neg-double",
    0x81: "int-to-long", 0x82: "int-to-float", 0x83: "int-to-double", 0x84: "long-to-int",
    0x85: "long-to-float", 0x86: "long-to-double", 0x87: "float-to-int", 0x88: "float-to-long",
    0x89: "float-to-double", 0x8A: "double-to-int", 0x8B: "double-to-long", 0x8C: "double-to-float",
    0x8D: "int-to-byte", 0x8E: "int-to-char", 0x8F: "int-to-short", 0x90: "add-int",
    0x91: "sub-int", 0x92: "mul-int", 0x93: "div-int", 0x94: "rem-int",
    0x95: "and-int", 0x96: "or-int", 0x97: "xor-int", 0x98: "shl-int",
    0x99: "shr-int", 0x9A: "ushr-int", 0x9B: "add-long", 0x9C: "sub-long",
    0x9D: "mul-long", 0x9E: "div-long", 0x9F: "rem-long", 0xA0: "and-long",
    0xA1: "or-long", 0xA2: "xor-long", 0xA3: "shl-long", 0xA4: "shr-long",
    0xA5: "ushr-long", 0xA6: "add-float", 0xA7: "sub-float", 0xA8: "mul-float",
    0xA9: "div-float", 0xAA: "rem-float", 0xAB: "add-double", 0xAC: "sub-double",
    0xAD: "mul-double", 0xAE: "div-double", 0xAF: "rem-double", 0xB0: "add-int/2addr",
    0xB1: "sub-int/2addr", 0xB2: "mul-int/2addr", 0xB3: "div-int/2addr", 0xB4: "rem-int/2addr",
    0xB5: "and-int/2addr", 0xB6: "or-int/2addr", 0xB7: "xor-int/2addr", 0xB8: "shl-int/2addr",
    0xB9: "shr-int/2addr", 0xBA: "ushr-int/2addr", 0xBB: "add-long/2addr", 0xBC: "sub-long/2addr",
    0xBD: "mul-long/2addr", 0xBE: "div-long/2addr", 0xBF: "rem-long/2addr", 0xC0: "and-long/2addr",
    0xC1: "or-long/2addr", 0xC2: "xor-long/2addr", 0xC3: "shl-long/2addr", 0xC4: "shr-long/2addr",
    0xC5: "ushr-long/2addr", 0xC6: "add-float/2addr", 0xC7: "sub-float/2addr", 0xC8: "mul-float/2addr",
    0xC9: "div-float/2addr", 0xCA: "rem-float/2addr", 0xCB: "add-double/2addr", 0xCC: "sub-double/2addr",
    0xCD: "mul-double/2addr", 0xCE: "div-double/2addr", 0xCF: "rem-double/2addr", 0xD0: "add-int/lit16",
    0xD1: "rsub-int", 0xD2: "mul-int/lit16", 0xD3: "div-int/lit16", 0xD4: "rem-int/lit16",
    0xD5: "and-int/lit16", 0xD6: "or-int/lit16", 0xD7: "xor-int/lit16", 0xD8: "add-int/lit8",
    0xD9: "rsub-int/lit8", 0xDA: "mul-int/lit8", 0xDB: "div-int/lit8", 0xDC: "rem-int/lit8",
    0xDD: "and-int/lit8", 0xDE: "or-int/lit8", 0xDF: "xor-int/lit8", 0xE0: "shl-int/lit8",
    0xE1: "shr-int/lit8", 0xE2: "ushr-int/lit8", 0xFA: "invoke-polymorphic", 0xFB: "invoke-polymorphic/range",
    0xFC: "invoke-custom", 0xFD: "invoke-custom/range", 0xFE: "const-method-handle", 0xFF: "const-method-type",
}

# Instruction length in 16-bit code units, keyed by opcode value.
OP_UNITS = {
    0x00: 1, 0x01: 1, 0x02: 2, 0x03: 3,
    0x04: 1, 0x05: 2, 0x06: 3, 0x07: 1,
    0x08: 2, 0x09: 3, 0x0A: 1, 0x0B: 1,
    0x0C: 1, 0x0D: 1, 0x0E: 1, 0x0F: 1,
    0x10: 1, 0x11: 1, 0x12: 1, 0x13: 2,
    0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3,
    0x18: 5, 0x19: 2, 0x1A: 2, 0x1B: 3,
    0x1C: 2, 0x1D: 1, 0x1E: 1, 0x1F: 2,
    0x20: 2, 0x21: 1, 0x22: 2, 0x23: 2,
    0x24: 3, 0x25: 3, 0x26: 3, 0x27: 1,
    0x28: 1, 0x29: 2, 0x2A: 3, 0x2B: 3,
    0x2C: 3, 0x2D: 2, 0x2E: 2, 0x2F: 2,
    0x30: 2, 0x31: 2, 0x32: 2, 0x33: 2,
    0x34: 2, 0x35: 2, 0x36: 2, 0x37: 2,
    0x38: 2, 0x39: 2, 0x3A: 2, 0x3B: 2,
    0x3C: 2, 0x3D: 2, 0x44: 2, 0x45: 2,
    0x46: 2, 0x47: 2, 0x48: 2, 0x49: 2,
    0x4A: 2, 0x4B: 2, 0x4C: 2, 0x4D: 2,
    0x4E: 2, 0x4F: 2, 0x50: 2, 0x51: 2,
    0x52: 2, 0x53: 2, 0x54: 2, 0x55: 2,
    0x56: 2, 0x57: 2, 0x58: 2, 0x59: 2,
    0x5A: 2, 0x5B: 2, 0x5C: 2, 0x5D: 2,
    0x5E: 2, 0x5F: 2, 0x60: 2, 0x61: 2,
    0x62: 2, 0x63: 2, 0x64: 2, 0x65: 2,
    0x66: 2, 0x67: 2, 0x68: 2, 0x69: 2,
    0x6A: 2, 0x6B: 2, 0x6C: 2, 0x6D: 2,
    0x6E: 3, 0x6F: 3, 0x70: 3, 0x71: 3,
    0x72: 3, 0x74: 3, 0x75: 3, 0x76: 3,
    0x77: 3, 0x78: 3, 0x7B: 1, 0x7C: 1,
    0x7D: 1, 0x7E: 1, 0x7F: 1, 0x80: 1,
    0x81: 1, 0x82: 1, 0x83: 1, 0x84: 1,
    0x85: 1, 0x86: 1, 0x87: 1, 0x88: 1,
    0x89: 1, 0x8A: 1, 0x8B: 1, 0x8C: 1,
    0x8D: 1, 0x8E: 1, 0x8F: 1, 0x90: 2,
    0x91: 2, 0x92: 2, 0x93: 2, 0x94: 2,
    0x95: 2, 0x96: 2, 0x97: 2, 0x98: 2,
    0x99: 2, 0x9A: 2, 0x9B: 2, 0x9C: 2,
    0x9D: 2, 0x9E: 2, 0x9F: 2, 0xA0: 2,
    0xA1: 2, 0xA2: 2, 0xA3: 2, 0xA4: 2,
    0xA5: 2, 0xA6: 2, 0xA7: 2, 0xA8: 2,
    0xA9: 2, 0xAA: 2, 0xAB: 2, 0xAC: 2,
    0xAD: 2, 0xAE: 2, 0xAF: 2, 0xB0: 1,
    0xB1: 1, 0xB2: 1, 0xB3: 1, 0xB4: 1,
    0xB5: 1, 0xB6: 1, 0xB7: 1, 0xB8: 1,
    0xB9: 1, 0xBA: 1, 0xBB: 1, 0xBC: 1,
    0xBD: 1, 0xBE: 1, 0xBF: 1, 0xC0: 1,
    0xC1: 1, 0xC2: 1, 0xC3: 1, 0xC4: 1,
    0xC5: 1, 0xC6: 1, 0xC7: 1, 0xC8: 1,
    0xC9: 1, 0xCA: 1, 0xCB: 1, 0xCC: 1,
    0xCD: 1, 0xCE: 1, 0xCF: 1, 0xD0: 2,
    0xD1: 2, 0xD2: 2, 0xD3: 2, 0xD4: 2,
    0xD5: 2, 0xD6: 2, 0xD7: 2, 0xD8: 2,
    0xD9: 2, 0xDA: 2, 0xDB: 2, 0xDC: 2,
    0xDD: 2, 0xDE: 2, 0xDF: 2, 0xE0: 2,
    0xE1: 2, 0xE2: 2, 0xFA: 4, 0xFB: 4,
    0xFC: 3, 0xFD: 3, 0xFE: 2, 0xFF: 2,
}

IF_TEST = set(range(0x32, 0x38))    # 22t: B|A|op (A low nibble, B high nibble)
IF_TESTZ = set(range(0x38, 0x3E))   # 21t: AA|op (AA full byte)
RETURN_OPS = (0x0E, 0x0F, 0x10, 0x11)
MOVE_RESULT_OPS = (0x0A, 0x0B, 0x0C, 0x0D)
INVOKE_OPS = tuple(range(0x6E, 0x73)) + tuple(range(0x74, 0x79)) + (0xFA, 0xFB, 0xFC, 0xFD)
IFIELD_OPS = tuple(range(0x52, 0x59))
PFIELD_OPS = tuple(range(0x59, 0x60))
SFIELD_OPS = tuple(range(0x60, 0x6E))


def u16(b, o):
    if o + 2 > len(b):
        return 0
    return b[o] | (b[o + 1] << 8)


def u32(b, o):
    if o + 4 > len(b):
        return 0
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)


def s16(v):
    return v - 0x10000 if v > 0x7FFF else v


def s32(v):
    return v - 0x100000000 if v > 0x7FFFFFFF else v


def read_uleb(b, o):
    """Decode unsigned LEB128 -> (value, new_offset)."""
    result = 0
    shift = 0
    length = len(b)
    while o < length:
        x = b[o]
        o += 1
        result |= (x & 0x7F) << shift
        if (x & 0x80) == 0:
            break
        shift += 7
    return result, o


def insn_units(op, data, pos, end):
    """Instruction length in 16-bit code units with safe bounds enforcement.
    Returns -1 for invalid/unknown opcodes or truncated/oversized payloads.
    """
    if op == 0x00:
        if pos + 2 > end:
            return -1
        ident = data[pos + 1] & 0xFF
        if ident == 0x00:
            return 1  # 1-unit nop
        if pos + 8 > end:
            return -1  # truncated pseudo-instruction header
        if ident == 0x01:  # packed-switch-payload
            size = u16(data, pos + 2)
            units = 4 + size * 2
            return units if pos + units * 2 <= end else -1
        if ident == 0x02:  # sparse-switch-payload
            size = u16(data, pos + 2)
            units = 2 + size * 4
            return units if pos + units * 2 <= end else -1
        if ident == 0x03:  # fill-array-data-payload
            width = u16(data, pos + 2)
            count = u32(data, pos + 4)
            units = 4 + (count * width + 1) // 2
            return units if pos + units * 2 <= end else -1
        return -1  # unknown pseudo-instruction ident
    # Reject unknown/reserved opcodes
    return OP_UNITS.get(op, -1)


class Dex(object):
    """Structural reader and instruction decoder for a Dalvik DEX file."""

    def __init__(self, data, name="classes.dex"):
        self.d = bytes(data)
        self.name = name
        self.header = {k: u32(self.d, v) for k, v in OFFSETS.items()}

    def check(self):
        """Return structural issues. Empty list means clean parse."""
        problems = []
        size = len(self.d)
        if size < 0x70:
            return ["file too small for dex header: %d bytes" % size]
        if self.d[:4] != b"dex\n":
            problems.append("invalid magic: %r" % self.d[:4])
        for name in ("string_ids", "type_ids", "proto_ids", "field_ids", "method_ids", "class_defs"):
            sz = self.header.get(name + "_size", 0)
            off = self.header.get(name + "_off", 0)
            if sz > 0:
                if not (0 < off < size):
                    problems.append("%s_off=0x%x out of file bounds (size %d)" % (name, off, size))
            elif off != 0 and not (0 <= off <= size):
                problems.append("%s_off=0x%x out of file bounds" % (name, off))
        declared = self.header.get("file_size", 0)
        if declared and declared != size:
            problems.append("header file_size=%d but actual=%d" % (declared, size))
        return problems

    def string(self, idx):
        if idx >= self.header.get("string_ids_size", 0):
            raise IndexError("string idx %d >= size %d" % (idx, self.header.get("string_ids_size", 0)))
        p = u32(self.d, self.header["string_ids_off"] + idx * 4)
        _utf16_len, p = read_uleb(self.d, p)
        end = self.d.find(b"\x00", p)
        if end == -1:
            end = len(self.d)
        return self.d[p:end].decode("utf-8", "replace")

    def string_safe(self, idx):
        try:
            return self.string(idx)
        except Exception:
            return "<string_idx_%d>" % idx

    def type_(self, idx):
        if idx >= self.header.get("type_ids_size", 0):
            return "<type_idx_%d>" % idx
        str_idx = u32(self.d, self.header["type_ids_off"] + idx * 4)
        return self.string_safe(str_idx)

    def proto(self, idx):
        if idx >= self.header.get("proto_ids_size", 0):
            return "()<proto_idx_%d>" % idx
        o = self.header["proto_ids_off"] + idx * 12
        ret = self.type_(u32(self.d, o + 4))
        poff = u32(self.d, o + 8)
        params = []
        if poff and poff + 4 <= len(self.d):
            n = u32(self.d, poff)
            p = poff + 4
            for _ in range(n):
                if p + 2 <= len(self.d):
                    params.append(self.type_(u16(self.d, p)))
                    p += 2
        return "(" + "".join(params) + ")" + ret

    def field(self, idx):
        if idx >= self.header.get("field_ids_size", 0):
            return ("<cls>", "<field_%d>" % idx, "<type>")
        o = self.header["field_ids_off"] + idx * 8
        return (self.type_(u16(self.d, o)), self.string_safe(u32(self.d, o + 4)),
                self.type_(u16(self.d, o + 2)))

    def method(self, idx):
        if idx >= self.header.get("method_ids_size", 0):
            return ("<cls>", "<method_%d>" % idx, "()V")
        o = self.header["method_ids_off"] + idx * 8
        return (self.type_(u16(self.d, o)), self.string_safe(u32(self.d, o + 4)),
                self.proto(u16(self.d, o + 2)))

    def find_class(self, fqcn):
        for i in range(self.header.get("class_defs_size", 0)):
            o = self.header["class_defs_off"] + i * 32
            if self.type_(u32(self.d, o)) == fqcn:
                return o
        return None

    def class_names(self):
        for i in range(self.header.get("class_defs_size", 0)):
            o = self.header["class_defs_off"] + i * 32
            yield self.type_(u32(self.d, o))

    def methods_at(self, class_def_off):
        if class_def_off + 28 > len(self.d):
            return
        p = u32(self.d, class_def_off + 24)
        if p == 0 or p >= len(self.d):
            return
        sf, p = read_uleb(self.d, p)
        inf, p = read_uleb(self.d, p)
        dm, p = read_uleb(self.d, p)
        vm, p = read_uleb(self.d, p)
        for _ in range(sf + inf):
            _i, p = read_uleb(self.d, p)
            _a, p = read_uleb(self.d, p)
        for section, count in (("direct", dm), ("virtual", vm)):
            running = 0
            for _ in range(count):
                diff, p = read_uleb(self.d, p)
                running += diff  # delta-encoded index
                _acc, p = read_uleb(self.d, p)
                code_off, p = read_uleb(self.d, p)
                cls, name, desc = self.method(running)
                yield section, running, cls, name, desc, code_off

    def methods_of(self, fqcn):
        cd = self.find_class(fqcn)
        if cd is None:
            raise KeyError("Class not found: %s" % fqcn)
        for item in self.methods_at(cd):
            yield item

    def find_method(self, fqcn, name, desc):
        for section, idx, _cls, nm, ds, code_off in self.methods_of(fqcn):
            if nm == name and ds == desc:
                return section, idx, code_off
        return None

    def find_methods_named(self, fqcn, name):
        out = []
        for section, idx, _cls, nm, ds, code_off in self.methods_of(fqcn):
            if nm == name:
                out.append((section, idx, ds, code_off))
        return out

    def code_info(self, code_off):
        if code_off + 16 > len(self.d):
            return {
                "registers": 0, "ins": 0, "outs": 0, "tries": 0,
                "debug_info_off": 0, "insns_size": 0, "insns_off": code_off + 16,
            }
        return {
            "registers": u16(self.d, code_off),
            "ins": u16(self.d, code_off + 2),
            "outs": u16(self.d, code_off + 4),
            "tries": u16(self.d, code_off + 6),
            "debug_info_off": u32(self.d, code_off + 8),
            "insns_size": u32(self.d, code_off + 12),
            "insns_off": code_off + 16,
        }

    def decode(self, code_off):
        info = self.code_info(code_off)
        pos = info["insns_off"]
        end = min(len(self.d), pos + info["insns_size"] * 2)
        while pos < end:
            op = self.d[pos]
            units = insn_units(op, self.d, pos, end)
            if units < 1 or pos + units * 2 > end:
                return
            is_payload = False
            name = OP_NAMES.get(op, "op_%02x" % op)
            if op == 0x00 and pos + 2 <= end:
                ident = self.d[pos + 1] & 0xFF
                if ident == 0x01:
                    name = "packed-switch-payload"
                    is_payload = True
                elif ident == 0x02:
                    name = "sparse-switch-payload"
                    is_payload = True
                elif ident == 0x03:
                    name = "fill-array-data-payload"
                    is_payload = True

            yield {
                "off": pos, "op": op, "units": units,
                "name": name,
                "is_payload": is_payload,
                "raw": bytes(self.d[pos:pos + units * 2]),
                "registers": info["registers"],
            }
            pos += units * 2

    def decode_all(self, code_off):
        insns = list(self.decode(code_off))
        info = self.code_info(code_off)
        expected = info["insns_off"] + info["insns_size"] * 2
        ended = insns[-1]["off"] + insns[-1]["units"] * 2 if insns else info["insns_off"]
        return insns, (ended == expected), expected

    def insn_at(self, code_off, target_off):
        for insn in self.decode(code_off):
            if insn["off"] == target_off:
                return insn
        return None

    def branch_target(self, insn):
        op, pos, raw = insn["op"], insn["off"], insn["raw"]
        if op in IF_TEST or op in IF_TESTZ:
            if pos + 4 <= len(self.d):
                return pos + s16(u16(self.d, pos + 2)) * 2
        elif op == 0x28:  # goto (10t)
            off = raw[1]
            if off > 127:
                off -= 256
            return pos + off * 2
        elif op == 0x29:  # goto/16 (20t)
            if pos + 4 <= len(self.d):
                return pos + s16(u16(self.d, pos + 2)) * 2
        elif op == 0x2A:  # goto/32 (30t)
            if pos + 6 <= len(self.d):
                off = u32(self.d, pos + 2)
                if off > 0x7FFFFFFF:
                    off -= 0x100000000
                return pos + off * 2
        return None

    def branch_regs(self, insn):
        if insn["op"] in IF_TEST:
            # 22t format: B|A|op -> A is low nibble (first reg), B is high nibble (second reg)
            return [insn["raw"][1] & 0x0F, insn["raw"][1] >> 4], "if-test"
        if insn["op"] in IF_TESTZ:
            # 21t format: AA|op -> AA is full 8-bit register
            return [insn["raw"][1]], "if-testz"
        return [], None

    def all_targets(self, code_off):
        targets = set()
        for insn in self.decode(code_off):
            t = self.branch_target(insn)
            if t is not None:
                targets.add(t)
        return targets

    def describe(self, insn):
        op, pos, raw = insn["op"], insn["off"], insn["raw"]
        text = "0x%x: %-14s %s" % (pos, raw.hex(), insn["name"])
        if op in IF_TEST:
            text += " v%d, v%d -> 0x%x" % (raw[1] & 0x0F, raw[1] >> 4, self.branch_target(insn) or 0)
        elif op in IF_TESTZ:
            text += " v%d -> 0x%x" % (raw[1], self.branch_target(insn) or 0)
        elif op in (0x28, 0x29, 0x2A):
            text += " -> 0x%x" % (self.branch_target(insn) or 0)
        elif op in IFIELD_OPS and pos + 4 <= len(self.d):
            cls, nm, ty = self.field(u16(self.d, pos + 2))
            text += " v%d <- v%d.%s:%s" % (raw[1] & 0x0F, raw[1] >> 4, nm, ty)
        elif op in PFIELD_OPS and pos + 4 <= len(self.d):
            cls, nm, ty = self.field(u16(self.d, pos + 2))
            text += " v%d -> v%d.%s:%s" % (raw[1] & 0x0F, raw[1] >> 4, nm, ty)
        elif op in SFIELD_OPS and pos + 4 <= len(self.d):
            cls, nm, ty = self.field(u16(self.d, pos + 2))
            text += " %s.%s:%s" % (cls, nm, ty)
        elif op in INVOKE_OPS and pos + 4 <= len(self.d):
            cls, nm, ds = self.method(u16(self.d, pos + 2))
            text += " %s.%s%s" % (cls, nm, ds)
        elif op == 0x1A and pos + 4 <= len(self.d):
            text += ' "%s"' % self.string_safe(u16(self.d, pos + 2))
        elif op == 0x1B and pos + 6 <= len(self.d):
            text += ' "%s"' % self.string_safe(u32(self.d, pos + 2))
        elif op == 0x12:
            reg = raw[1] & 0x0F
            lit = (raw[1] >> 4) & 0x0F
            val = lit - 16 if lit > 7 else lit
            text += " v%d, %d" % (reg, val)
        return text


def fix_dex_header(data: bytearray):
    """Recompute DEX checksum and signature in correct order:

    1. SHA-1 signature over bytes 32..end -> written to bytes 12..32.
    2. Adler-32 checksum over bytes 12..end -> written to bytes 8..12.
    """
    before_checksum = int.from_bytes(data[8:12], "little")
    before_signature = bytes(data[12:32])

    data[12:32] = hashlib.sha1(bytes(data[32:])).digest()
    after_signature = bytes(data[12:32])

    after_checksum = zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF
    data[8:12] = after_checksum.to_bytes(4, "little")

    return {
        "before_checksum": before_checksum, "after_checksum": after_checksum,
        "before_signature": before_signature, "after_signature": after_signature,
    }


def verify_dex_header(data: bytes):
    """Check whether DEX checksum and signature match header fields."""
    if len(data) < 32:
        return False, False
    stored_c = int.from_bytes(data[8:12], "little")
    calc_c = zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF
    stored_sig = bytes(data[12:32])
    calc_sig = hashlib.sha1(bytes(data[32:])).digest()
    return (stored_c == calc_c), (stored_sig == calc_sig)


def load_dex(source, entry=None):
    """Load Dex from file, zip/apk archive member, or raw bytes."""
    if isinstance(source, (bytes, bytearray)):
        return Dex(bytes(source), entry or "<bytes>"), entry or "<bytes>"
    path = str(source)
    if path.lower().endswith((".apk", ".zip", ".jar", ".xapk", ".apks", ".apkm")):
        with zipfile.ZipFile(path) as z:
            if entry:
                return Dex(z.read(entry), entry), entry
            candidates = sorted(n for n in z.namelist()
                                if n.startswith("classes") and n.endswith(".dex"))
            if not candidates:
                raise ValueError("No classes*.dex found in %s" % path)
            chosen = candidates[0]
            return Dex(z.read(chosen), chosen), chosen
    with open(path, "rb") as fh:
        raw = fh.read()
        return Dex(raw, path), path
