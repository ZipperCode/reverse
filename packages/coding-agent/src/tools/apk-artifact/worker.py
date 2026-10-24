# Copyright (c) 2026 apk-reverse contributors
# MIT License
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib


def eprint(*args, **kwargs):
    """Log to stderr to keep stdout strictly reserved for JSON output."""
    kwargs["file"] = sys.stderr
    print(*args, **kwargs)
    sys.stderr.flush()


# ============================================================================
# Entry Classification & Constants
# ============================================================================

INTERESTING_PREFIXES = ("lib/", "assets/", "META-INF/services/")
SIGNATURE_EXTENSIONS = (".RSA", ".SF", ".MF", ".DSA", ".EC")
STORE_ONLY_NAMES = ("AndroidManifest.xml", "resources.arsc")
ALIGN_DEFAULT = 4
ALIGN_PAGE_SO = 16384  # 16KiB page alignment for Android 15+ native libraries
SO_PATTERN = re.compile(r"^lib/(?:[^/]+/)*[^/]+\.so$")

MAX_ENTRY_SIZE = 1024 * 1024 * 1024          # 1 GiB per entry limit
MAX_TOTAL_UNCOMPRESSED = 4 * 1024 * 1024 * 1024  # 4 GiB total limit

PACKAGE_REGEX = re.compile(r"^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+$")
ACTIVITY_REGEX = re.compile(r"^[a-zA-Z0-9_.]+$")
PERMISSION_REGEX = re.compile(r"^[a-zA-Z0-9_.]+$")


def classify_entry(name: str) -> str:
    if re.match(r"^classes\d*\.dex$", name):
        return "dex"
    if is_signature_entry(name):
        return "signature"
    if name.startswith(INTERESTING_PREFIXES):
        return "code_or_assets"
    return "other"


def is_signature_entry(name: str) -> bool:
    """True ONLY for JAR/APK signature metadata directly under META-INF/.

    META-INF/services/**, META-INF/native-image/**, META-INF/androidx/** and every
    other subdirectory are RUNTIME RESOURCES and MUST survive repacking. Anything
    that is in a subdirectory under META-INF/ is preserved by construction.
    """
    if not name.upper().startswith("META-INF/"):
        return False
    rest = name[len("META-INF/"):]
    if "/" in rest:
        return False
    up = rest.upper()
    if up == "MANIFEST.MF":
        return True
    if up.startswith("SIG-"):
        return True
    return up.endswith(SIGNATURE_EXTENSIONS)


# ============================================================================
# Atomic Exclusive Publishing (No-Clobber)
# ============================================================================

def publish_file_exclusive(src_path: str, dest_path: str):
    """Atomically publish src_path to dest_path without clobbering existing files.

    Stages the scratch file in a private directory inside the parent directory
    of dest_path so os.link is guaranteed to be on the same filesystem.
    """
    dest_dir = os.path.dirname(os.path.abspath(dest_path))
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)

    try:
        os.link(src_path, dest_path)
    except FileExistsError:
        raise FileExistsError(f"Output destination already exists: {dest_path}")
    finally:
        if os.path.exists(src_path):
            try:
                os.unlink(src_path)
            except OSError:
                pass


# ============================================================================
# Raw Deflate & Aligned ZIP Generation
# ============================================================================

def _dos_time_date(dt):
    """(time, date) MS-DOS words for a zip local header."""
    y, mo, d, h, mi, s = dt
    if y < 1980:
        y, mo, d, h, mi, s = 1980, 1, 1, 0, 0, 0
    time_word = (h << 11) | (mi << 5) | (s // 2)
    date_word = ((y - 1980) << 9) | (mo << 5) | d
    return time_word, date_word


def _deflate_raw(data: bytes) -> bytes:
    """Raw deflate (wbits=-15, no zlib header/checksum)."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def _get_entry_alignment(name: str, page_align_so: bool) -> int:
    if name == "resources.arsc":
        return ALIGN_DEFAULT
    if SO_PATTERN.match(name):
        return ALIGN_PAGE_SO if page_align_so else ALIGN_DEFAULT
    return 1


def write_aligned_apk(out_path: str, plan, page_align_so: bool = True):
    """Write an aligned APK.

    plan: list of (name, info, data, keep_stored) tuples.
    - resources.arsc: STORED, 4-byte aligned
    - lib/**/*.so: STORED entries aligned to 16KiB (16384 bytes) when page_align_so is True, or 4-byte when False
    - entry names encoded as UTF-8 with flag bit 11 (0x0800) set
    - data descriptor bit 3 cleared, encrypted bit 0 rejected
    - uses Android standard alignment extra field 0xd935
    - writes in private temp workspace in dest parent, exclusively publishes to out_path
    """
    dest_dir = os.path.dirname(os.path.abspath(out_path))
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)
    temp_dir = tempfile.mkdtemp(dir=dest_dir, prefix=".apk_stage_")
    scratch = os.path.join(temp_dir, "staged.apk")

    order = []
    meta = {}
    offset = 0

    try:
        with open(scratch, "wb") as out:
            for name, info, data, keep_stored in plan:
                name_b = name.encode("utf-8")
                if keep_stored:
                    method = 0
                    payload = data
                else:
                    method = 8
                    payload = _deflate_raw(data)
                crc = zlib.crc32(data) & 0xFFFFFFFF

                alignment = _get_entry_alignment(name, page_align_so) if keep_stored else 1

                head = 30 + len(name_b)
                extra = b""
                extralen = 0

                if alignment > 1:
                    base_offset = offset + head
                    rem = base_offset % alignment
                    if rem != 0:
                        pad = (alignment - rem) % alignment
                        if pad < 4:
                            pad += alignment
                        extra_payload_len = pad - 4
                        extra = b"\x35\xd9" + struct.pack("<H", extra_payload_len) + (b"\x00" * extra_payload_len)
                        extralen = len(extra)

                flags = getattr(info, "flag_bits", 0)
                if flags & 0x0001:
                    raise ValueError(f"Encrypted ZIP entry is not supported: {name}")
                flags &= ~0x0008  # Clear data descriptor bit
                flags |= 0x0800   # Set UTF-8 bit
                if keep_stored:
                    flags &= ~0x0006  # Clear compression options

                t_word, d_word = _dos_time_date(getattr(info, "date_time", (1980, 1, 1, 0, 0, 0)))

                local_header = struct.pack(
                    "<IHHHHHIIIHH",
                    0x04034B50,
                    20,
                    flags,
                    method,
                    t_word,
                    d_word,
                    crc,
                    len(payload),
                    len(data),
                    len(name_b),
                    extralen,
                )

                local_offset = offset
                out.write(local_header)
                out.write(name_b)
                out.write(extra)

                data_offset = offset + head + extralen
                if out.tell() != data_offset:
                    raise RuntimeError(f"Offset bookkeeping drift for {name}: expected {data_offset}, got {out.tell()}")

                if alignment > 1 and (data_offset % alignment) != 0:
                    raise RuntimeError(f"{name} not aligned: data at 0x{data_offset:x} % {alignment} != 0")

                out.write(payload)
                offset = out.tell()

                order.append(name)
                meta[name] = {
                    "name_b": name_b,
                    "method": method,
                    "crc": crc,
                    "csize": len(payload),
                    "usize": len(data),
                    "local_offset": local_offset,
                    "date_time": getattr(info, "date_time", (1980, 1, 1, 0, 0, 0)),
                    "flag_bits": flags,
                    "external_attr": getattr(info, "external_attr", 0),
                }

            # Central Directory
            cd_start = out.tell()
            for name in order:
                m = meta[name]
                t_word, d_word = _dos_time_date(m["date_time"])
                cd_header = struct.pack(
                    "<IHHHHHHIIIHHHHHII",
                    0x02014B50,
                    20,
                    20,
                    m["flag_bits"],
                    m["method"],
                    t_word,
                    d_word,
                    m["crc"],
                    m["csize"],
                    m["usize"],
                    len(m["name_b"]),
                    0,
                    0,
                    0,
                    0,
                    (m["external_attr"] >> 16) & 0xFFFF,
                    m["local_offset"],
                )
                out.write(cd_header)
                out.write(m["name_b"])

            cd_size = out.tell() - cd_start
            eocd = struct.pack(
                "<IHHHHIIH",
                0x06054B50,
                0,
                0,
                len(order),
                len(order),
                cd_size,
                cd_start,
                0,
            )
            out.write(eocd)

        publish_file_exclusive(scratch, out_path)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def verify_zip_alignment(apk_path: str, page_align_so: bool = True):
    """Verify storage and alignment of required entries in an APK."""
    issues = []
    checked_entries = []

    with zipfile.ZipFile(apk_path, "r") as z, open(apk_path, "rb") as fh:
        for it in z.infolist():
            name = it.filename
            is_arsc = (name == "resources.arsc")
            is_so = bool(SO_PATTERN.match(name))

            if not (is_arsc or is_so):
                continue

            fh.seek(it.header_offset)
            lh = fh.read(30)
            if len(lh) < 30:
                issues.append(f"{name}: truncated local file header at 0x{it.header_offset:x}")
                continue

            nlen, elen = struct.unpack("<HH", lh[26:30])
            data_off = it.header_offset + 30 + nlen + elen

            if is_arsc:
                if it.compress_type != 0:
                    issues.append(f"{name} is compressed (method {it.compress_type}); Android requires STORED")
                if data_off % ALIGN_DEFAULT != 0:
                    issues.append(f"{name} offset 0x{data_off:x} is not {ALIGN_DEFAULT}-byte aligned")
                checked_entries.append({
                    "name": name,
                    "stored": it.compress_type == 0,
                    "offset": data_off,
                    "aligned": data_off % ALIGN_DEFAULT == 0,
                    "alignment_required": ALIGN_DEFAULT,
                })

            elif is_so and it.compress_type == 0:
                target_align = ALIGN_PAGE_SO if page_align_so else ALIGN_DEFAULT
                if data_off % target_align != 0:
                    issues.append(f"{name} uncompressed offset 0x{data_off:x} is not {target_align}-byte aligned")
                checked_entries.append({
                    "name": name,
                    "stored": True,
                    "offset": data_off,
                    "aligned": data_off % target_align == 0,
                    "alignment_required": target_align,
                })

    return {
        "ok": len(issues) == 0,
        "issues": issues,
        "checked_entries": checked_entries,
    }


def check_apk_signing_block(apk_path: str) -> bool:
    """Validate APK Signing Block located immediately preceding the Central Directory.

    Specification:
    - Central Directory starts at offset `cd_offset`.
    - APK Signing Block ends at `cd_offset`.
    - Last 24 bytes of block: [8 bytes block_size] [16 bytes magic b"APK Sig Block 42"]
    - Leading 8 bytes at block_start: [8 bytes block_size]
    """
    try:
        with open(apk_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            file_len = f.tell()
            if file_len < 22:
                return False

            max_search = min(file_len, 65535 + 22)
            f.seek(file_len - max_search)
            tail = f.read(max_search)
            eocd_pos_in_tail = tail.rfind(b"\x50\x4b\x05\x06")
            if eocd_pos_in_tail == -1:
                return False

            eocd_offset = (file_len - max_search) + eocd_pos_in_tail
            f.seek(eocd_offset + 16)
            cd_offset = struct.unpack("<I", f.read(4))[0]

            if cd_offset < 24:
                return False

            f.seek(cd_offset - 24)
            footer = f.read(24)
            if len(footer) < 24:
                return False

            block_size, magic = struct.unpack("<Q16s", footer)
            if magic != b"APK Sig Block 42":
                return False

            block_start = cd_offset - block_size - 8
            if block_start < 0:
                return False

            f.seek(block_start)
            leading_size = struct.unpack("<Q", f.read(8))[0]
            return leading_size == block_size
    except Exception:
        return False


# ============================================================================
# Action: diff
# ============================================================================

def handle_diff(params: dict) -> dict:
    original_path = params.get("original_path") or params.get("path_a") or params.get("path")
    modified_path = params.get("modified_path") or params.get("path_b")

    if not original_path or not modified_path:
        raise ValueError("diff requires both 'original_path' and 'modified_path'")

    original_path = os.path.abspath(original_path)
    modified_path = os.path.abspath(modified_path)

    if not os.path.isfile(original_path):
        raise FileNotFoundError(f"Original APK file not found: {original_path}")
    if not os.path.isfile(modified_path):
        raise FileNotFoundError(f"Modified APK file not found: {modified_path}")

    def file_info(p):
        h = hashlib.sha256()
        size = 0
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
                size += len(chunk)
        return {"path": p, "size": size, "sha256": h.hexdigest()}

    orig_meta = file_info(original_path)
    mod_meta = file_info(modified_path)

    def read_entries(p):
        res = {}
        total_size = 0
        seen_names = set()
        with zipfile.ZipFile(p, "r") as z:
            for it in z.infolist():
                if it.is_dir():
                    continue
                if it.filename in seen_names:
                    raise ValueError(f"Duplicate ZIP entry name detected in {p}: '{it.filename}'")
                seen_names.add(it.filename)

                if it.file_size > MAX_ENTRY_SIZE:
                    raise ValueError(f"Entry '{it.filename}' uncompressed size ({it.file_size}) exceeds limit ({MAX_ENTRY_SIZE})")
                total_size += it.file_size
                if total_size > MAX_TOTAL_UNCOMPRESSED:
                    raise ValueError(f"Archive {p} cumulative uncompressed size exceeds limit ({MAX_TOTAL_UNCOMPRESSED})")

                data = z.read(it.filename)
                sha = hashlib.sha256(data).hexdigest()
                res[it.filename] = {
                    "name": it.filename,
                    "size": len(data),
                    "sha256": sha,
                    "compress_type": it.compress_type,
                    "crc": it.CRC,
                    "classification": classify_entry(it.filename),
                }
        return res

    a = read_entries(original_path)
    b = read_entries(modified_path)

    only_a = sorted(set(a.keys()) - set(b.keys()))
    only_b = sorted(set(b.keys()) - set(a.keys()))
    common = sorted(set(a.keys()) & set(b.keys()))

    changed = []
    same_size_changed = []
    identical_count = 0
    total_changed_unfiltered = 0

    rx_pattern = params.get("filter") or params.get("only")
    rx = re.compile(rx_pattern) if rx_pattern else None

    for name in common:
        ea, eb = a[name], b[name]
        has_content_diff = (ea["sha256"] != eb["sha256"])
        has_layout_diff = (ea["compress_type"] != eb["compress_type"])

        if has_content_diff or has_layout_diff:
            total_changed_unfiltered += 1
            same_size = (ea["size"] == eb["size"] and has_content_diff)
            diff_item = {
                "name": name,
                "classification": ea["classification"],
                "original_size": ea["size"],
                "modified_size": eb["size"],
                "original_sha256": ea["sha256"],
                "modified_sha256": eb["sha256"],
                "same_size": same_size,
                "content_changed": has_content_diff,
                "compression_changed": has_layout_diff,
                "original_compress_type": ea["compress_type"],
                "modified_compress_type": eb["compress_type"],
            }
            if not rx or rx.search(name):
                changed.append(diff_item)
            if same_size:
                same_size_changed.append(name)
        else:
            identical_count += 1

    added = [b[n] for n in only_b if not rx or rx.search(n)]
    removed = [a[n] for n in only_a if not rx or rx.search(n)]

    sig_only = [n for n in (only_a + only_b) if classify_entry(n) == "signature"]
    max_entries = int(params.get("max_entries") or 200)

    has_diffs = bool(only_a or only_b or total_changed_unfiltered > 0)

    return {
        "action": "diff",
        "status": "ok",
        "original": orig_meta,
        "modified": mod_meta,
        "summary": {
            "original_entries": len(a),
            "modified_entries": len(b),
            "added_count": len(only_b),
            "removed_count": len(only_a),
            "changed_count": total_changed_unfiltered,
            "same_size_changed_count": len(same_size_changed),
            "identical_count": identical_count,
            "signature_noise_count": len(sig_only),
            "has_differences": has_diffs,
        },
        "added": added[:max_entries],
        "removed": removed[:max_entries],
        "changed": changed[:max_entries],
        "truncated": {
            "added": len(added) > max_entries,
            "removed": len(removed) > max_entries,
            "changed": len(changed) > max_entries,
        },
    }


# ============================================================================
# Action: repack
# ============================================================================

def handle_repack(params: dict) -> dict:
    apk_path = params.get("path") or params.get("input_path")
    out_path = params.get("output_path") or params.get("out_apk")

    if not apk_path:
        raise ValueError("repack requires 'path' (input APK)")
    if not out_path:
        raise ValueError("repack requires 'output_path'")

    apk_path = os.path.abspath(apk_path)
    out_path = os.path.abspath(out_path)

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"Input APK not found: {apk_path}")

    # Aliasing protection
    if apk_path == out_path:
        raise ValueError("Output path cannot be identical to input APK path (anti-aliasing safety violation)")
    try:
        if os.path.exists(out_path) and os.path.samefile(apk_path, out_path):
            raise ValueError("Output path resolves to the same filesystem entity as input APK")
    except OSError:
        pass

    if os.path.exists(out_path):
        raise FileExistsError(f"output_path already exists: {out_path} (overwriting existing outputs is not permitted)")

    page_align_so = bool(params.get("page_align_so", True))

    dex_files = params.get("dex_files") or {}
    if not isinstance(dex_files, dict):
        raise ValueError("dex_files must be a dictionary mapping entry names to file paths")

    if "dex_path" in params and "classes.dex" not in dex_files:
        dex_files["classes.dex"] = params["dex_path"]

    def normalize_entry_name(name: str) -> str:
        clean = name.strip().replace("\\", "/").lstrip("/")
        if not clean:
            raise ValueError(f"Entry name cannot be empty: {name!r}")
        parts = clean.split("/")
        if any(p in ("", ".", "..") for p in parts):
            raise ValueError(f"Invalid path traversal or empty segment in entry name: {name!r}")
        return clean

    replacements = {}
    for entry_name, file_on_disk in dex_files.items():
        if not isinstance(entry_name, str) or not entry_name.strip():
            raise ValueError("dex_files keys must be non-empty entry name strings")
        if not isinstance(file_on_disk, str) or not file_on_disk.strip():
            raise ValueError(f"dex_files value for '{entry_name}' must be a non-empty file path string")
        entry_clean = normalize_entry_name(entry_name)
        if entry_clean in replacements:
            raise ValueError(f"Duplicate entry '{entry_clean}' declared in dex_files")
        disk_abs = os.path.abspath(file_on_disk)
        if not os.path.isfile(disk_abs):
            raise FileNotFoundError(f"Replacement DEX file not found: {disk_abs} (for {entry_clean})")
        with open(disk_abs, "rb") as df:
            data = df.read()
        if len(data) < 32 or not data.startswith(b"dex\n"):
            raise ValueError(f"File {disk_abs} is not a valid DEX file (missing DEX magic header)")
        replacements[entry_clean] = data

    replace_files = params.get("replace_files") or {}
    if not isinstance(replace_files, dict):
        raise ValueError("replace_files must be a dictionary mapping entry names to file paths")

    for entry_name, file_on_disk in replace_files.items():
        if not isinstance(entry_name, str) or not entry_name.strip():
            raise ValueError("replace_files keys must be non-empty entry name strings")
        if not isinstance(file_on_disk, str) or not file_on_disk.strip():
            raise ValueError(f"replace_files value for '{entry_name}' must be a non-empty file path string")
        entry_clean = normalize_entry_name(entry_name)
        if entry_clean in replacements:
            raise ValueError(f"Overlapping replacement entry '{entry_clean}' declared in both dex_files and replace_files")
        disk_abs = os.path.abspath(file_on_disk)
        if not os.path.isfile(disk_abs):
            raise FileNotFoundError(f"Replacement file not found: {disk_abs} (for {entry_clean})")
        with open(disk_abs, "rb") as df:
            data = df.read()
        replacements[entry_clean] = data
    strip_signatures = bool(params.get("strip_signatures", True))

    plan = []
    seen = set()
    dropped_entries = []
    replaced_entries = []
    preserved_count = 0
    total_uncompressed = 0

    with zipfile.ZipFile(apk_path, "r") as z:
        for it in z.infolist():
            name = it.filename
            if it.is_dir():
                continue
            if name in seen:
                raise ValueError(f"Duplicate entry '{name}' detected in input APK archive")
            seen.add(name)

            if it.file_size > MAX_ENTRY_SIZE:
                raise ValueError(f"Entry '{name}' size ({it.file_size}) exceeds limit ({MAX_ENTRY_SIZE})")
            total_uncompressed += it.file_size
            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
                raise ValueError(f"Cumulative uncompressed size exceeds limit ({MAX_TOTAL_UNCOMPRESSED})")

            if strip_signatures and is_signature_entry(name):
                dropped_entries.append(name)
                continue

            if name in replacements:
                replaced_entries.append(name)
                new_data = replacements[name]
                keep_stored = (it.compress_type == 0)
                plan.append((name, it, new_data, keep_stored))
            else:
                data = z.read(name)
                base = os.path.basename(name)
                keep_stored = (
                    name in STORE_ONLY_NAMES
                    or base in STORE_ONLY_NAMES
                    or it.compress_type == 0
                    or (SO_PATTERN.match(name) and it.compress_type == 0)
                )
                plan.append((name, it, data, keep_stored))
                preserved_count += 1

    for entry_name, data in replacements.items():
        if entry_name not in seen:
            replaced_entries.append(entry_name)
            dummy_info = zipfile.ZipInfo(entry_name)
            dummy_info.date_time = (1980, 1, 1, 0, 0, 0)
            plan.append((entry_name, dummy_info, data, False))

    should_sign = bool(params.get("sign", False))

    if should_sign:
        # Stage unsigned in private temporary workspace, sign directly to out_path
        stage_dir = tempfile.mkdtemp(prefix="apk_repack_sign_stage_")
        try:
            unsigned_stage = os.path.join(stage_dir, "unsigned.apk")
            write_aligned_apk(unsigned_stage, plan, page_align_so=page_align_so)

            sign_params = dict(params)
            sign_params["path"] = unsigned_stage
            sign_params["output_path"] = out_path
            sign_result = handle_sign(sign_params)

            align_report = verify_zip_alignment(out_path, page_align_so=page_align_so)

            return {
                "action": "repack",
                "status": "ok",
                "output_path": out_path,
                "size": sign_result["size"],
                "sha256": sign_result["sha256"],
                "signed": True,
                "replaced_entries": replaced_entries,
                "preserved_entries_count": preserved_count,
                "dropped_signatures": dropped_entries,
                "alignment": align_report,
                "signature_details": sign_result,
            }
        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)

    # Unsigned repack: write directly to out_path via atomic exclusive publish
    write_aligned_apk(out_path, plan, page_align_so=page_align_so)
    align_report = verify_zip_alignment(out_path, page_align_so=page_align_so)

    h = hashlib.sha256()
    with open(out_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    out_sha = h.hexdigest()
    out_size = os.path.getsize(out_path)

    return {
        "action": "repack",
        "status": "ok",
        "output_path": out_path,
        "size": out_size,
        "sha256": out_sha,
        "signed": False,
        "replaced_entries": replaced_entries,
        "preserved_entries_count": preserved_count,
        "dropped_signatures": dropped_entries,
        "alignment": align_report,
    }


# ============================================================================
# Action: sign
# ============================================================================

def resolve_tool_path(name: str, explicit: str | None = None) -> str | None:
    if explicit:
        p = os.path.abspath(explicit)
        if os.path.exists(p):
            return p
    found = shutil.which(name)
    if found:
        return found
    sdk_roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")]
    for root in sdk_roots:
        if root and os.path.isdir(root):
            bt = os.path.join(root, "build-tools")
            if os.path.isdir(bt):
                for ver in sorted(os.listdir(bt), reverse=True):
                    cand = os.path.join(bt, ver, name)
                    if os.path.exists(cand):
                        return cand
                    if name == "apksigner":
                        cand_jar = os.path.join(bt, ver, "lib", "apksigner.jar")
                        if os.path.exists(cand_jar):
                            return cand_jar
    return None


def handle_sign(params: dict) -> dict:
    apk_path = params.get("path") or params.get("input_path")
    out_path = params.get("output_path") or params.get("out_apk")

    if not apk_path:
        raise ValueError("sign requires 'path' (input APK)")
    if not out_path:
        raise ValueError("sign requires explicit 'output_path' (cannot default to input or derive implicitly)")

    apk_path = os.path.abspath(apk_path)
    out_path = os.path.abspath(out_path)

    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    if os.path.exists(out_path):
        raise FileExistsError(f"output_path already exists: {out_path} (overwriting existing outputs is not permitted)")

    keystore_path = params.get("keystore_path")
    if not keystore_path:
        raise ValueError("sign requires 'keystore_path'")
    keystore_path = os.path.abspath(keystore_path)
    if not os.path.isfile(keystore_path):
        raise FileNotFoundError(f"Keystore file not found: {keystore_path}")

    key_alias = params.get("key_alias")
    if not key_alias:
        raise ValueError("sign requires 'key_alias'")

    # Keystore password configuration: NEVER pass plaintext secrets in argv!
    # apksigner natively supports env:<VAR_NAME> and file:<PATH>
    if "ks_pass_env" in params and params["ks_pass_env"]:
        var_name = params["ks_pass_env"]
        if var_name not in os.environ or not os.environ[var_name]:
            raise ValueError(f"Keystore password environment variable '{var_name}' is not set or empty")
        ks_pass_arg = f"env:{var_name}"
    elif "ks_pass_file" in params and params["ks_pass_file"]:
        pf = os.path.abspath(params["ks_pass_file"])
        if not os.path.isfile(pf):
            raise FileNotFoundError(f"Keystore password file not found: {pf}")
        ks_pass_arg = f"file:{pf}"
    else:
        raise ValueError("sign requires keystore password via 'ks_pass_env' or 'ks_pass_file'")

    # Key password: OMIT --key-pass unless explicitly supplied!
    key_pass_arg = None
    if "key_pass_env" in params and params["key_pass_env"]:
        var_name = params["key_pass_env"]
        if var_name not in os.environ or not os.environ[var_name]:
            raise ValueError(f"Key password environment variable '{var_name}' is not set or empty")
        key_pass_arg = f"env:{var_name}"
    elif "key_pass_file" in params and params["key_pass_file"]:
        kpf = os.path.abspath(params["key_pass_file"])
        if not os.path.isfile(kpf):
            raise FileNotFoundError(f"Key password file not found: {kpf}")
        key_pass_arg = f"file:{kpf}"

    # Tool discovery
    apksigner = resolve_tool_path("apksigner", params.get("apksigner_path"))
    zipalign = resolve_tool_path("zipalign", params.get("zipalign_path"))
    java = resolve_tool_path("java", params.get("java_path"))

    if not zipalign:
        raise RuntimeError("zipalign tool not found on PATH or Android SDK build-tools. Signing requires zipalign.")
    if not apksigner:
        raise RuntimeError("apksigner not found on PATH or Android SDK build-tools. Signing requires apksigner.")

    if apksigner.lower().endswith(".jar"):
        if not java:
            raise RuntimeError(f"java required to execute apksigner.jar ({apksigner}) but java was not found")
        signer_cmd = [java, "-jar", apksigner]
    else:
        signer_cmd = [apksigner]

    # Staging in a private temporary workspace
    dest_dir = os.path.dirname(out_path)
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)
    work_dir = tempfile.mkdtemp(dir=dest_dir, prefix=".apk_sign_work_")
    try:
        temp_aligned = os.path.join(work_dir, "aligned.apk")

        align_cmd_p16 = [zipalign, "-P", "16", "-f", "4", apk_path, temp_aligned]
        eprint(f"[zipalign] Running: {' '.join(align_cmd_p16)}")
        res_align = subprocess.run(align_cmd_p16, capture_output=True, text=True)
        if res_align.returncode != 0:
            eprint(f"[zipalign] -P 16 not supported or failed, falling back to -p 4: {res_align.stderr}")
            align_cmd_p4 = [zipalign, "-p", "-f", "4", apk_path, temp_aligned]
            res_align = subprocess.run(align_cmd_p4, capture_output=True, text=True)
            if res_align.returncode != 0 or not os.path.exists(temp_aligned):
                raise RuntimeError(f"zipalign failed (rc={res_align.returncode}): {res_align.stderr or res_align.stdout}")

        temp_signed = os.path.join(work_dir, "signed.apk")

        cmd = signer_cmd + [
            "sign",
            "--ks", keystore_path,
            "--ks-key-alias", key_alias,
            "--ks-pass", ks_pass_arg,
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true",
        ]

        if key_pass_arg:
            cmd.extend(["--key-pass", key_pass_arg])

        if "min_sdk_version" in params and params["min_sdk_version"] is not None:
            cmd.extend(["--min-sdk-version", str(params["min_sdk_version"])])
        if "max_sdk_version" in params and params["max_sdk_version"] is not None:
            cmd.extend(["--max-sdk-version", str(params["max_sdk_version"])])

        cmd.extend(["--out", temp_signed, temp_aligned])

        eprint(f"[apksigner] Running: {' '.join(cmd)}")
        res_sign = subprocess.run(cmd, capture_output=True, text=True)
        if res_sign.returncode != 0 or not os.path.exists(temp_signed):
            raise RuntimeError(f"apksigner failed (rc={res_sign.returncode}): {res_sign.stderr or res_sign.stdout}")

        # Post-signing cryptographic verification
        verify_cmd = signer_cmd + ["verify", "--print-certs", "--verbose"]
        min_sdk = params.get("min_sdk_version") or 21
        verify_cmd.extend(["--min-sdk-version", str(min_sdk)])
        if "max_sdk_version" in params and params["max_sdk_version"] is not None:
            verify_cmd.extend(["--max-sdk-version", str(params["max_sdk_version"])])
        verify_cmd.append(temp_signed)

        v_res = subprocess.run(verify_cmd, capture_output=True, text=True)
        if v_res.returncode != 0:
            raise RuntimeError(f"apksigner post-sign verification failed:\n{v_res.stderr or v_res.stdout}")

        # Post-signing alignment verification
        page_align_so = bool(params.get("page_align_so", True))
        align_report = verify_zip_alignment(temp_signed, page_align_so=page_align_so)
        if not align_report["ok"]:
            raise RuntimeError(f"Post-sign alignment verification failed: {align_report['issues']}")

        # Exclusive publish to final destination
        publish_file_exclusive(temp_signed, out_path)

        fps = sorted({m.lower() for m in re.findall(r"SHA-256 digest:\s*([0-9a-fA-F:]+)", v_res.stdout)})
        h = hashlib.sha256()
        with open(out_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)

        return {
            "action": "sign",
            "status": "ok",
            "output_path": out_path,
            "size": os.path.getsize(out_path),
            "sha256": h.hexdigest(),
            "signed": True,
            "v1_signed": "Verifies using v1 scheme (JAR signing): true" in v_res.stdout,
            "v2_signed": "Verifies using v2 scheme (APK Signature Scheme v2): true" in v_res.stdout,
            "v3_signed": "Verifies using v3 scheme (APK Signature Scheme v3): true" in v_res.stdout,
            "cert_fingerprints": fps,
            "verify_output": v_res.stdout.strip(),
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


# ============================================================================
# Action: verify
# ============================================================================

def handle_verify(params: dict) -> dict:
    apk_path = params.get("path")
    if not apk_path:
        raise ValueError("verify requires 'path'")

    apk_path = os.path.abspath(apk_path)
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    h = hashlib.sha256()
    with open(apk_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    apk_sha = h.hexdigest()
    apk_size = os.path.getsize(apk_path)

    entry_count = 0
    total_uncompressed = 0
    seen_names = set()
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            infolist = z.infolist()
            entry_count = len(infolist)
            for it in infolist:
                if it.is_dir():
                    continue
                if it.filename in seen_names:
                    return {
                        "action": "verify",
                        "status": "corrupt_archive",
                        "path": apk_path,
                        "size": apk_size,
                        "sha256": apk_sha,
                        "error": f"Duplicate entry '{it.filename}' detected in archive",
                        "verified": False,
                    }
                seen_names.add(it.filename)
                if it.file_size > MAX_ENTRY_SIZE:
                    return {
                        "action": "verify",
                        "status": "corrupt_archive",
                        "path": apk_path,
                        "size": apk_size,
                        "sha256": apk_sha,
                        "error": f"Entry '{it.filename}' exceeds size limit",
                        "verified": False,
                    }
                total_uncompressed += it.file_size
                if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
                    return {
                        "action": "verify",
                        "status": "corrupt_archive",
                        "path": apk_path,
                        "size": apk_size,
                        "sha256": apk_sha,
                        "error": "Archive cumulative uncompressed size exceeds limit",
                        "verified": False,
                    }
                z.read(it.filename)
    except Exception as e:
        return {
            "action": "verify",
            "status": "corrupt_archive",
            "path": apk_path,
            "size": apk_size,
            "sha256": apk_sha,
            "error": f"ZIP archive integrity check failed: {e}",
            "verified": False,
        }

    page_align_so = bool(params.get("page_align_so", True))
    alignment_report = verify_zip_alignment(apk_path, page_align_so=page_align_so)

    has_v2_signing_block = check_apk_signing_block(apk_path)

    apksigner = resolve_tool_path("apksigner", params.get("apksigner_path"))
    java = resolve_tool_path("java", params.get("java_path"))

    sig_checked = False
    sig_verified = False
    v1_scheme = False
    v2_scheme = False
    v3_scheme = False
    v4_scheme = False
    cert_fps = []
    apksigner_msg = None

    if apksigner:
        if apksigner.lower().endswith(".jar"):
            signer_cmd = [java, "-jar", apksigner] if java else None
        else:
            signer_cmd = [apksigner]

        if signer_cmd:
            sig_checked = True
            verify_cmd = signer_cmd + ["verify", "--print-certs", "--verbose"]
            min_sdk = params.get("min_sdk_version") or 21
            verify_cmd.extend(["--min-sdk-version", str(min_sdk)])
            if "max_sdk_version" in params and params["max_sdk_version"] is not None:
                verify_cmd.extend(["--max-sdk-version", str(params["max_sdk_version"])])
            verify_cmd.append(apk_path)

            v_res = subprocess.run(verify_cmd, capture_output=True, text=True)
            apksigner_msg = (v_res.stdout or "") + (v_res.stderr or "")
            if v_res.returncode == 0:
                sig_verified = True
                v1_scheme = "Verifies using v1 scheme (JAR signing): true" in v_res.stdout
                v2_scheme = "Verifies using v2 scheme (APK Signature Scheme v2): true" in v_res.stdout
                v3_scheme = "Verifies using v3 scheme (APK Signature Scheme v3): true" in v_res.stdout
                v4_scheme = "Verifies using v4 scheme (APK Signature Scheme v4): true" in v_res.stdout
                cert_fps = sorted({m.lower() for m in re.findall(r"SHA-256 digest:\s*([0-9a-fA-F:]+)", v_res.stdout)})
            else:
                sig_verified = False

    overall_ok = alignment_report["ok"] and sig_checked and sig_verified

    return {
        "action": "verify",
        "status": "ok" if overall_ok else "unverified_or_failed",
        "path": apk_path,
        "size": apk_size,
        "sha256": apk_sha,
        "entry_count": entry_count,
        "alignment": alignment_report,
        "signing_block_present": has_v2_signing_block,
        "signature": {
            "tool_available": sig_checked,
            "verified": sig_verified,
            "v1_scheme": v1_scheme,
            "v2_scheme": v2_scheme,
            "v3_scheme": v3_scheme,
            "v4_scheme": v4_scheme,
            "cert_fingerprints": cert_fps,
            "tool_output": apksigner_msg.strip() if apksigner_msg else None,
            "notice": None if sig_checked else "apksigner not found on PATH or Android SDK build-tools. Cryptographic signature validity cannot be asserted.",
        },
        "verified": overall_ok,
    }


# ============================================================================
# Action: install_verify
# ============================================================================

def handle_install_verify(params: dict) -> dict:
    apk_path = params.get("path") or params.get("apk_path")
    package = params.get("package") or params.get("package_name")
    activity = params.get("activity")
    serial = params.get("serial")

    if not apk_path:
        raise ValueError("install_verify requires 'path' (APK file path)")
    if not package:
        raise ValueError("install_verify requires 'package'")
    if not activity:
        raise ValueError("install_verify requires 'activity'")
    if not serial:
        raise ValueError("install_verify requires explicit 'serial' (selecting an implicit device is not permitted)")

    if not PACKAGE_REGEX.match(package):
        raise ValueError(f"Invalid Android package name format: '{package}'")
    if not ACTIVITY_REGEX.match(activity):
        raise ValueError(f"Invalid Android activity component format: '{activity}'")

    apk_path = os.path.abspath(apk_path)
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"Local APK not found: {apk_path}")

    # Preflight fresh output directory
    output_dir = params.get("output_dir")
    if output_dir:
        output_dir = os.path.abspath(output_dir)
        if os.path.exists(output_dir):
            raise FileExistsError(f"output_dir already exists: {output_dir} (fresh directory required)")
        os.makedirs(output_dir, exist_ok=False)

    shot_path = params.get("screenshot_path")
    if not shot_path and output_dir:
        shot_path = os.path.join(output_dir, f"{package}_screenshot.png")
    if shot_path:
        shot_path = os.path.abspath(shot_path)
        if os.path.exists(shot_path):
            raise FileExistsError(f"Screenshot path already exists: {shot_path} (overwriting is not permitted)")
        os.makedirs(os.path.dirname(shot_path), exist_ok=True)

    h = hashlib.sha256()
    with open(apk_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    local_sha = h.hexdigest()

    adb = resolve_tool_path("adb", params.get("adb_path"))
    if not adb:
        raise RuntimeError("adb tool not found on PATH. Install Android platform-tools to enable on-device verification.")

    adb_base = [adb, "-s", serial]

    # Device check: verify exact serial is connected and in 'device' state
    dev_res = subprocess.run([adb, "devices"], capture_output=True, text=True)
    if dev_res.returncode != 0:
        raise RuntimeError(f"adb devices failed: {dev_res.stderr or dev_res.stdout}")

    device_found = False
    for line in dev_res.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == serial:
            if parts[1] == "device":
                device_found = True
                break
            else:
                raise RuntimeError(f"Target device {serial} is connected but in '{parts[1]}' state (not 'device').")
    if not device_found:
        raise RuntimeError(f"Target device serial '{serial}' not found in active adb devices.")

    # Install APK without wiping data or clearing history
    eprint(f"[install_verify] Installing {apk_path} on device {serial}...")
    install_cmd = adb_base + ["install", "-r", "-t", "-d", apk_path]
    i_res = subprocess.run(install_cmd, capture_output=True, text=True)
    i_out = (i_res.stdout or "") + (i_res.stderr or "")
    if i_res.returncode != 0 or "Success" not in i_out:
        raise RuntimeError(f"adb install failed (rc={i_res.returncode}):\n{i_out.strip()}")

    # Confirm installed APK build identity by pulling base APK from device
    eprint(f"[install_verify] Verifying installed APK identity for {package}...")
    pm_path_res = subprocess.run(adb_base + ["shell", "pm", "path", package], capture_output=True, text=True)
    pm_lines = [ln.strip() for ln in pm_path_res.stdout.splitlines() if ln.startswith("package:")]

    if not pm_lines:
        raise RuntimeError(f"Package {package} not found on device after installation.")

    base_pkg_line = None
    if len(pm_lines) > 1:
        for pl in pm_lines:
            remote_p = pl.split("package:", 1)[1].strip()
            if remote_p.endswith("base.apk"):
                base_pkg_line = remote_p
                break
        if not base_pkg_line:
            raise RuntimeError(f"Split package detected ({len(pm_lines)} APKs) and standalone base APK cannot be identified.")
    else:
        base_pkg_line = pm_lines[0].split("package:", 1)[1].strip()

    temp_pull_dir = tempfile.mkdtemp(prefix="apk_verify_pull_")
    try:
        pulled_apk = os.path.join(temp_pull_dir, "base.apk")
        pull_res = subprocess.run(adb_base + ["pull", base_pkg_line, pulled_apk], capture_output=True, text=True)
        if pull_res.returncode != 0 or not os.path.exists(pulled_apk):
            raise RuntimeError(f"Failed to pull installed APK from device ({base_pkg_line}): {pull_res.stderr}")

        ph = hashlib.sha256()
        with open(pulled_apk, "rb") as pf:
            while chunk := pf.read(65536):
                ph.update(chunk)
        remote_sha = ph.hexdigest()

        if remote_sha != local_sha:
            raise RuntimeError(
                f"Installed APK hash mismatch! Local: {local_sha}, Pulled from device ({base_pkg_line}): {remote_sha}. "
                "The device is not running the intended build."
            )
    finally:
        shutil.rmtree(temp_pull_dir, ignore_errors=True)

    for perm in params.get("grant_permissions", []):
        if not PERMISSION_REGEX.match(perm):
            raise ValueError(f"Invalid permission name format: '{perm}'")
        p_name = perm if perm.startswith("android.permission.") else f"android.permission.{perm}"
        subprocess.run(adb_base + ["shell", "pm", "grant", package, p_name], capture_output=True)

    # Stop pre-existing process to ensure we verify fresh launch
    subprocess.run(adb_base + ["shell", "am", "force-stop", package], capture_output=True)
    time.sleep(1)

    comp = f"{package}/{activity}" if (activity.startswith(".") or "." in activity) else f"{package}/.{activity}"
    eprint(f"[install_verify] Launching {comp} with am start -W...")
    launch_res = subprocess.run(adb_base + ["shell", "am", "start", "-W", "-n", comp], capture_output=True, text=True)
    launch_out = (launch_res.stdout or "") + (launch_res.stderr or "")

    if launch_res.returncode != 0 or "Error:" in launch_out or "Exception:" in launch_out:
        raise RuntimeError(f"am start -W failed to launch {comp}:\n{launch_out.strip()}")

    time.sleep(3)

    wait_time = int(params.get("wait_seconds") or 10)
    pid1_res = subprocess.run(adb_base + ["shell", "pidof", package], capture_output=True, text=True)
    p1 = pid1_res.stdout.strip().split()

    time.sleep(wait_time)

    pid2_res = subprocess.run(adb_base + ["shell", "pidof", package], capture_output=True, text=True)
    p2 = pid2_res.stdout.strip().split()

    pid1 = p1[0] if p1 else None
    pid2 = p2[0] if p2 else None

    if not pid1 or not pid2:
        launch_status = "crash_on_launch"
    elif pid1 != pid2:
        launch_status = "crash_loop"
    else:
        launch_status = "stable"

    focus_res = subprocess.run(adb_base + ["shell", "dumpsys", "window"], capture_output=True, text=True)
    focus_lines = [ln.strip() for ln in focus_res.stdout.splitlines() if "mCurrentFocus" in ln or "mFocusedApp" in ln]
    focus_info = " | ".join(focus_lines)

    screenshot_saved = None
    if shot_path:
        shot_res = subprocess.run(adb_base + ["exec-out", "screencap", "-p"], capture_output=True)
        if shot_res.returncode != 0 or len(shot_res.stdout) < 8 or not shot_res.stdout.startswith(b"\x89PNG\r\n\x1a\n"):
            raise RuntimeError(f"Failed to capture screenshot via adb exec-out screencap -p: returncode={shot_res.returncode}")
        # Use exclusive creation mode 'xb' to guard against races
        with open(shot_path, "xb") as sf:
            sf.write(shot_res.stdout)
        screenshot_saved = shot_path

    fatal_hits = []
    log_saved = None
    logcat_ok = True
    if pid1:
        log_res = subprocess.run(adb_base + ["shell", "logcat", "-d", f"--pid={pid1}", "-v", "brief"], capture_output=True, text=True)
        if log_res.returncode != 0:
            logcat_ok = False
            eprint(f"[install_verify] logcat capture failed (rc={log_res.returncode}): {log_res.stderr}")
        log_content = log_res.stdout or ""
        fatal_regex = re.compile(r"FATAL EXCEPTION|SIGSEGV|SIGBUS|AndroidRuntime: FATAL|art.*art_sigsegv", re.I)
        fatal_hits = [ln for ln in log_content.splitlines() if fatal_regex.search(ln)]

        if output_dir:
            log_file = os.path.join(output_dir, f"{package}_pid_{pid1}.log")
            # Use exclusive creation mode 'x' to guard against races
            with open(log_file, "x", encoding="utf-8") as lf:
                lf.write(log_content)
            log_saved = log_file

    is_healthy = (launch_status == "stable") and logcat_ok and (len(fatal_hits) == 0)

    if launch_status == "stable":
        notice_text = (
            "Process launched and remained stable across 2 PID samples, but launch stability is NOT proof "
            "that modified features work correctly. Manual or targeted functional testing is required to "
            "verify actual patched feature behavior."
        )
    else:
        notice_text = f"Process failed launch stability check ({launch_status}). On-device launch was unstable or crashed."

    return {
        "action": "install_verify",
        "status": "ok" if is_healthy else "launch_failed_or_crashed",
        "package": package,
        "activity": activity,
        "device_serial": serial,
        "installed_apk_sha256": local_sha,
        "hash_verified": True,
        "launch_status": launch_status,
        "pid_sample_1": pid1,
        "pid_sample_2": pid2,
        "focus": focus_info,
        "fatal_signatures": fatal_hits[:20],
        "screenshot_path": screenshot_saved,
        "log_path": log_saved,
        "logcat_status": "ok" if logcat_ok else "failed",
        "feature_verified": False,
        "notice": notice_text,
    }


# ============================================================================
# Main Dispatcher
# ============================================================================

def main():
    try:
        raw_in = sys.stdin.read()
        if not raw_in.strip():
            raise ValueError("Empty request on stdin")
        request = json.loads(raw_in)
    except Exception as e:
        eprint(f"Error decoding request JSON: {e}")
        json.dump({"status": "error", "error": f"Invalid request JSON: {e}"}, sys.stdout)
        sys.exit(1)

    action = request.get("action")
    params = request.get("params") or {}

    try:
        if action == "diff":
            result = handle_diff(params)
        elif action == "repack":
            result = handle_repack(params)
        elif action == "sign":
            result = handle_sign(params)
        elif action == "verify":
            result = handle_verify(params)
        elif action == "install_verify":
            result = handle_install_verify(params)
        else:
            raise ValueError(f"Unknown action '{action}'")
        json.dump(result, sys.stdout)
        sys.exit(0)
    except Exception as e:
        eprint(f"Exception during action '{action}': {e}")
        json.dump({
            "status": "error",
            "error": str(e),
            "action": action,
        }, sys.stdout)
        sys.exit(1)


if __name__ == "__main__":
    main()
